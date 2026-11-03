# -*- coding: utf-8 -*-
"""Turn the TBox into a runtime check: validate, report, enforce.

This is the module the rest of the system talks to. It knows about policies
(strict vs lenient) and repair; it knows nothing about files.

Two entry points, two questions
-------------------------------
``validate(graph)``
    "What is wrong with this graph?" Always returns a report, never raises.
    Used by reports, by the CLI, and by anything that wants to show findings
    without stopping the pipeline.

``enforce(graph)``
    "Is this graph good enough to continue?" Raises
    :class:`~ontology_builder.core.errors.OntologyViolationError` under
    :attr:`ValidationPolicy.STRICT` when an ``ERROR``-severity issue exists, or
    returns a repaired copy when ``repair=True``.

The repair path is deliberately conservative and loudly logged, because it
changes the graph: it drops dangling endpoints, duplicate triples and
self-loops beyond the quota, and it **materialises the missing mirror edge of a
symmetric relation**. On the pilot graph that last step is the difference
between 244 and 252 edges, which would move every downstream number - so it is
off by default.

Single-edge validation (:meth:`OntologyValidator.validate_edge`) exists for the
prediction side of the system: a KGE model proposes ``(head, relation, tail)``,
the TBox refuses it. That is the point of putting the ontology in the runtime
path instead of in a document.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from ontology_builder.core.contracts import Severity
from ontology_builder.core.errors import DataContractError, OntologyViolationError
from ontology_builder.ontology.constraints import (
    DEFAULT_CONSTRAINTS,
    ConfidenceBandConstraint,
    Constraint,
    DomainRangeConstraint,
    SelfLoopConstraint,
    SymmetryConstraint,
    ValidationIssue,
)
from ontology_builder.ontology.tbox import DEFAULT_SCHEMA, OntologySchema
from ontology_builder.schema import (
    ConceptCategory,
    KnowledgeGraph,
    OntologyConcept,
    Relationship,
    RelationType,
)

LOGGER = logging.getLogger("ontology_builder.ontology")

#: How many findings per code a text report prints before summarising.
REPORT_LIMIT_PER_CODE = 5

#: Definition given to a concept that only exists inside an edge probe.
_PROBE_DEFINITION = "Edge-level probe; never persisted to disk."


class ValidationPolicy(str, Enum):
    """What :meth:`OntologyValidator.enforce` does when an ``ERROR`` is found.

    ``STRICT`` raises, ``LENIENT`` returns the report and lets the caller decide.
    There is no ``"repair"`` member on purpose: repairing is an argument
    (``repair=True``), not a policy, because it is the one option that changes
    the data.
    """

    STRICT = "strict"
    LENIENT = "lenient"


@dataclass(frozen=True)
class ValidationReport:
    """The result of one validation run, ready to serialise or print.

    Attributes:
        schema_name: which TBox produced the verdict.
        schema_version: which version of it - a stored report must be traceable
            back to the rules that judged it.
        issues: every finding, sorted by ``(severity, code, subject)`` so two
            runs over the same graph produce identical output.
        rules_evaluated: constraint codes that ran, in execution order, so a
            report distinguishes "clean" from "not checked".
        subjects_checked: ``len(nodes) + len(edges)`` - the denominator a reader
            needs in order to read the counts as a rate.
    """

    schema_name: str
    schema_version: str
    issues: tuple[ValidationIssue, ...] = ()
    rules_evaluated: tuple[str, ...] = ()
    subjects_checked: int = 0

    # -- slicing ----------------------------------------------------------
    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        """``ERROR`` findings - the ones a strict run refuses."""
        return tuple(issue for issue in self.issues if issue.severity is Severity.ERROR)

    @property
    def warnings(self) -> tuple[ValidationIssue, ...]:
        """``WARNING`` findings - reported, non-blocking."""
        return tuple(issue for issue in self.issues if issue.severity is Severity.WARNING)

    @property
    def infos(self) -> tuple[ValidationIssue, ...]:
        """``INFO`` findings - deliberate choices, not defects."""
        return tuple(issue for issue in self.issues if issue.severity is Severity.INFO)

    @property
    def ok(self) -> bool:
        """True when nothing rose to ``ERROR``.

        Warnings do not make a graph "not ok": the layer has to be usable on the
        graph the project actually ships.
        """
        return not self.errors

    def counts_by_code(self) -> dict[str, int]:
        """``code -> number of findings``, sorted by descending count then code."""
        counts: dict[str, int] = {}
        for issue in self.issues:
            counts[issue.code] = counts.get(issue.code, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    # -- rendering --------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """JSON form: verdict, counts and every finding."""
        return {
            "schema": {"name": self.schema_name, "version": self.schema_version},
            "ok": self.ok,
            "subjects_checked": self.subjects_checked,
            "rules_evaluated": list(self.rules_evaluated),
            "counts": {
                "error": len(self.errors),
                "warning": len(self.warnings),
                "info": len(self.infos),
                "by_code": self.counts_by_code(),
            },
            "issues": [issue.to_dict() for issue in self.issues],
        }

    def lines(self, limit_per_code: int = REPORT_LIMIT_PER_CODE) -> list[str]:
        """Fixed-width text block for the console.

        Groups findings by code and prints at most ``limit_per_code`` examples of
        each: 173 RELATED_TO findings in a terminal is noise, while "173 findings
        of code X" is information.
        """
        width = 78
        out = [
            "=" * width,
            "ONTOLOGY VALIDATION  %s v%s" % (self.schema_name, self.schema_version),
            "=" * width,
            "  subjects checked   : %d (concepts + edges)" % self.subjects_checked,
            "  rules evaluated    : %d (%s)"
            % (len(self.rules_evaluated), ", ".join(self.rules_evaluated)),
            "  findings           : %d error(s), %d warning(s), %d info(s)"
            % (len(self.errors), len(self.warnings), len(self.infos)),
        ]
        for code, count in self.counts_by_code().items():
            examples = [issue for issue in self.issues if issue.code == code]
            out.append("  %-22s %4d" % (code, count))
            for issue in examples[:limit_per_code]:
                out.append("      [%s] %s" % (issue.severity.value[0].upper(), issue.message))
                out.append("          on %s" % issue.subject)
            if count > limit_per_code:
                out.append("      ... %d more" % (count - limit_per_code))
        out.append("-" * width)
        out.append("  verdict            : %s" % ("PASS (no errors)" if self.ok else "FAIL"))
        return out


#: Constraints that make sense on a single candidate edge. Graph-wide checks
#: (unused relation, required category) would fire on a two-concept probe graph
#: for reasons that have nothing to do with the edge being judged.
EDGE_CONSTRAINTS: tuple[Constraint, ...] = (
    SelfLoopConstraint(),
    SymmetryConstraint(),
    DomainRangeConstraint(),
    ConfidenceBandConstraint(),
)


class OntologyValidator:
    """Applies a constraint set to a graph under a policy. Stateless and reusable.

    Args:
        schema: the TBox to judge against; defaults to ``PALANTIR_TBOX``.
        constraints: the checks to run; defaults to ``DEFAULT_CONSTRAINTS``.
            Pass a subset to answer a narrower question (``EDGE_CONSTRAINTS``
            for a single edge).
        policy: ``STRICT`` raises on findings of severity ``ERROR``, ``LENIENT``
            only reports.

    Raises:
        DataContractError: on an empty constraint sequence - a validator that
            checks nothing would report a clean graph, which is the worst
            possible failure mode for a validation layer.

    The validator holds configuration and no state: the same instance can judge
    ten graphs in a row, and nothing it does depends on what it saw before.
    """

    def __init__(
        self,
        schema: OntologySchema = DEFAULT_SCHEMA,
        constraints: Sequence[Constraint] | None = None,
        *,
        policy: ValidationPolicy = ValidationPolicy.STRICT,
    ) -> None:
        self._schema = schema
        self._constraints = tuple(DEFAULT_CONSTRAINTS if constraints is None else constraints)
        if not self._constraints:
            raise DataContractError("at least one constraint is required", constraints=0)
        self._policy = policy

    @property
    def schema(self) -> OntologySchema:
        """The TBox this validator judges against."""
        return self._schema

    @property
    def constraints(self) -> tuple[Constraint, ...]:
        """The checks this validator runs, in execution order."""
        return self._constraints

    @property
    def policy(self) -> ValidationPolicy:
        """What :meth:`enforce` does when an ``ERROR`` is found."""
        return self._policy

    def __repr__(self) -> str:
        return "<OntologyValidator schema=%r v%s policy=%s constraints=%d>" % (
            self._schema.name,
            self._schema.version,
            self._policy.value,
            len(self._constraints),
        )

    # -- validation -------------------------------------------------------
    def validate(self, graph: KnowledgeGraph) -> ValidationReport:
        """Run every constraint and collect the findings.

        Never raises on findings: a graph full of errors is a *result*, not an
        exception. Findings are sorted by ``(severity, code, subject, message)``
        so that two runs over the same graph produce the same report.

        Args:
            graph: the ABox to judge.

        Returns:
            A :class:`ValidationReport` carrying every finding, the codes that
            ran, and how many subjects were checked.
        """
        issues: list[ValidationIssue] = []
        for constraint in self._constraints:
            found = list(constraint.check(graph, self._schema))
            issues.extend(found)
            LOGGER.debug("constraint %-22s produced %d finding(s)", constraint.code, len(found))
        issues.sort(
            key=lambda issue: (issue.severity.rank, issue.code, issue.subject, issue.message)
        )
        report = ValidationReport(
            schema_name=self._schema.name,
            schema_version=self._schema.version,
            issues=tuple(issues),
            rules_evaluated=tuple(constraint.code for constraint in self._constraints),
            subjects_checked=len(graph.nodes) + len(graph.edges),
        )
        LOGGER.info(
            "validated %d concept(s), %d edge(s) against %s v%s: %d error(s), %d warning(s)",
            len(graph.nodes),
            len(graph.edges),
            self._schema.name,
            self._schema.version,
            len(report.errors),
            len(report.warnings),
        )
        return report

    # -- enforcement ------------------------------------------------------
    def enforce(
        self, graph: KnowledgeGraph, *, repair: bool = False
    ) -> tuple[KnowledgeGraph, ValidationReport]:
        """Judge the graph and decide whether the caller may continue.

        Args:
            graph: the ABox to judge. Never mutated, even when repaired.
            repair: when true and an ``ERROR`` exists, return a **repaired copy**
                instead of raising. Repairs are the conservative ones documented
                on :meth:`_repair`; anything they cannot fix still raises under
                ``STRICT``.

        Returns:
            ``(graph_to_use, report)``. Without ``repair`` and without errors this
            is the input object and a clean report, so the happy path costs one
            validation pass.

        Raises:
            OntologyViolationError: under ``STRICT`` when ``ERROR`` findings
                remain (either found directly, or left after a repair). The
                exception carries the full report.
        """
        report = self.validate(graph)
        if report.ok:
            return graph, report
        if not repair:
            if self._policy is ValidationPolicy.STRICT:
                raise OntologyViolationError(report)
            LOGGER.warning(
                "graph carries %d error(s); continuing because policy=%s",
                len(report.errors),
                self._policy.value,
            )
            return graph, report

        repaired = self._repair(graph)
        final = self.validate(repaired)
        LOGGER.warning(
            "repair applied: %d -> %d edge(s), %d -> %d finding(s), %d error(s) left",
            len(graph.edges),
            len(repaired.edges),
            len(report.issues),
            len(final.issues),
            len(final.errors),
        )
        if not final.ok and self._policy is ValidationPolicy.STRICT:
            raise OntologyViolationError(final)
        return repaired, final

    def _repair(self, graph: KnowledgeGraph) -> KnowledgeGraph:
        """Return a new graph with the fixable defects removed.

        Four repairs, none of which needs a judgement call:

        1. drop edges whose endpoint is undeclared;
        2. drop duplicate ``(source, relation, target)`` triples (first wins);
        3. drop self-loops beyond ``schema.max_self_loops``;
        4. add the missing mirror edge of every symmetric relation.

        Step 4 is the only one that *adds* data. It is what makes a repaired
        graph differ from the shipped one (244 -> 252 edges on the pilot), which
        is why ``repair`` defaults to ``False`` everywhere it is exposed.
        """
        known = {concept.identity for concept in graph.nodes}
        kept: list[Relationship] = []
        seen: set[tuple[str, str, str]] = set()
        dropped_dangling = 0
        dropped_duplicate = 0
        dropped_loops = 0
        loops = 0

        for edge in graph.edges:
            if (
                edge.source_concept.casefold() not in known
                or edge.target_concept.casefold() not in known
            ):
                dropped_dangling += 1
                continue
            if edge.identity in seen:
                dropped_duplicate += 1
                continue
            if edge.is_self_loop:
                loops += 1
                if loops > self._schema.max_self_loops:
                    dropped_loops += 1
                    continue
            seen.add(edge.identity)
            kept.append(edge)

        added_mirrors = 0
        keys = {edge.identity for edge in kept}
        for edge in list(kept):
            rule = self._schema.rules.get(edge.relation_type)
            if rule is None or not rule.symmetric or edge.is_self_loop:
                continue
            mirror = (
                edge.target_concept.casefold(),
                edge.relation_type.value,
                edge.source_concept.casefold(),
            )
            if mirror in keys:
                continue
            keys.add(mirror)
            added_mirrors += 1
            kept.append(
                Relationship(
                    source_concept=edge.target_concept,
                    target_concept=edge.source_concept,
                    relation_type=edge.relation_type,
                    confidence_score=edge.confidence_score,
                    evidence=edge.evidence,
                )
            )

        LOGGER.info(
            "repair: %d dangling, %d duplicate, %d self-loop(s) dropped; "
            "%d mirror edge(s) materialised",
            dropped_dangling,
            dropped_duplicate,
            dropped_loops,
            added_mirrors,
        )
        return KnowledgeGraph(nodes=list(graph.nodes), edges=kept, chunk_ids=list(graph.chunk_ids))

    # -- prediction gate --------------------------------------------------
    def validate_edge(
        self,
        head: str,
        relation: RelationType,
        tail: str,
        *,
        graph: KnowledgeGraph | None = None,
        categories: Mapping[str, ConceptCategory] | None = None,
        confidence: float | None = None,
    ) -> ValidationReport:
        """Judge one candidate edge ``head -[relation]-> tail``.

        This is the prediction gate: a KGE model proposes an edge, the TBox
        decides whether it is admissible. The edge goes through the *same*
        constraint classes as the whole graph (``EDGE_CONSTRAINTS``) on a
        two-concept probe graph, so a rule can never mean one thing here and
        another thing there.

        Args:
            head: source concept name; need not exist in ``graph``.
            relation: the proposed relation.
            tail: target concept name; need not exist in ``graph``.
            graph: the graph the edge is proposed *into*. Supplying it makes the
                check real - categories come from the real concepts and an
                existing mirror edge satisfies symmetry. Omit it only to test a
                rule in isolation.
            categories: fallback ``casefolded name -> category`` for names
                ``graph`` does not contain. Unknown names default to ``OTHER``,
                which is what the graph-wide check assumes too, so nothing is
                silently excused.
            confidence: proposed score. Defaults to the middle of the relation's
                band, so the confidence check cannot fire spuriously on an edge
                nobody scored yet.

        Returns:
            A report whose findings all concern this edge.

        Raises:
            DataContractError: when ``head`` or ``tail`` is blank - a nameless
                endpoint cannot be validated, and an empty result would read as
                "accepted".
        """
        if not head.strip() or not tail.strip():
            raise DataContractError("edge endpoints must be non-empty", head=head, tail=tail)

        resolved: dict[str, ConceptCategory] = dict(categories or {})
        known_concepts = graph.concept_index() if graph is not None else {}
        for identity, concept in known_concepts.items():
            resolved.setdefault(identity, concept.category)

        nodes: list[OntologyConcept] = []
        placed: set[str] = set()
        for name in (head, tail):
            key = name.casefold()
            if key in placed:
                continue
            placed.add(key)
            existing = known_concepts.get(key)
            if existing is not None:
                nodes.append(existing)
                continue
            nodes.append(
                OntologyConcept(
                    name=name,
                    definition=_PROBE_DEFINITION,
                    category=resolved.get(key, ConceptCategory.OTHER),
                )
            )

        rule = self._schema.rule(relation)
        score = confidence
        if score is None:
            score = sum(rule.confidence_band) / 2.0 if rule.confidence_band else 0.5
        probe = Relationship(
            source_concept=head,
            target_concept=tail,
            relation_type=relation,
            confidence_score=score,
        )

        edges: list[Relationship] = [probe]
        if graph is not None and rule.symmetric:
            mirror = (tail.casefold(), relation.value, head.casefold())
            for edge in graph.edges:
                if edge.identity == mirror:
                    edges.append(edge)
                    break

        probe_graph = KnowledgeGraph(nodes=nodes, edges=edges)
        issues: list[ValidationIssue] = []
        for constraint in EDGE_CONSTRAINTS:
            issues.extend(
                issue
                for issue in constraint.check(probe_graph, self._schema)
                if issue.subject == probe.describe()
            )
        issues.sort(
            key=lambda issue: (issue.severity.rank, issue.code, issue.subject, issue.message)
        )
        return ValidationReport(
            schema_name=self._schema.name,
            schema_version=self._schema.version,
            issues=tuple(issues),
            rules_evaluated=tuple(constraint.code for constraint in EDGE_CONSTRAINTS),
            subjects_checked=1,
        )
