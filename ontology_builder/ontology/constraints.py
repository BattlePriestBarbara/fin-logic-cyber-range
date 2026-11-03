# -*- coding: utf-8 -*-
"""Constraint checks: each rule class answers one question about the ABox.

Design
------
Every constraint is a small :class:`Constraint` subclass with a stable ``code``
(``"TBOX_SYMMETRY"``), a default severity, and a :meth:`Constraint.check` that
**reads** the graph and yields :class:`ValidationIssue` objects. The validator
owns the iteration, sorting and policy; the constraints own the logic.

Two properties every implementation must keep, because they are what make the
layer safe to run on a graph another stage is about to consume:

* **pure** - ``check`` never mutates the graph, its concepts, its edges or the
  schema (``test_constraints.py`` snapshots ``graph.model_dump()`` around the
  whole constraint set);
* **total** - a constraint yields findings, it does not raise. Anything a
  constraint cannot evaluate (a relation missing from the TBox) is skipped by
  design: a gap in the schema is not a violation of it.

Adding a rule means adding a class and appending it to ``DEFAULT_CONSTRAINTS``;
no existing code changes, which is why the base class exists at all.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar, Iterator, Mapping

from ontology_builder.core.contracts import Severity
from ontology_builder.schema import ConceptCategory, KnowledgeGraph, RelationType

if TYPE_CHECKING:  # pragma: no cover - annotation only
    from ontology_builder.ontology.tbox import OntologySchema

#: Confidence scores are rounded to 3 decimals by ``Relationship``; a band edge
#: compared with ``<=`` on a float needs a tolerance smaller than a rounding step.
_CONFIDENCE_EPS = 1e-9


@dataclass(frozen=True)
class ValidationIssue:
    """One finding, with enough context for a reader to act without rerunning.

    Attributes:
        code: stable machine key, e.g. ``"TBOX_SYMMETRY"``. Reports count by it,
            so it must not change once shipped.
        severity: :class:`Severity`; ``ERROR`` blocks a strict run.
        message: one sentence a human can act on.
        subject: what the finding is about - an edge as ``"A -[REL]-> B"`` or a
            concept name. Used as the stable sort key.
        relation: the relation involved, when there is one.
        context: free-form measurements (observed value, expected band, ...).
            Wrapped in a read-only mapping so an issue cannot be edited after the
            report that contains it was logged.
    """

    code: str
    severity: Severity
    message: str
    subject: str
    relation: RelationType | None = None
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("ValidationIssue.code cannot be empty")
        object.__setattr__(self, "severity", Severity.coerce(self.severity))
        object.__setattr__(self, "context", MappingProxyType(dict(self.context)))

    def to_dict(self) -> dict[str, Any]:
        """JSON form; ``relation`` becomes its string value."""
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "subject": self.subject,
            "relation": self.relation.value if self.relation is not None else None,
            "context": dict(self.context),
        }


class Constraint(ABC):
    """Base class for one ABox check.

    Subclasses set :attr:`code` and :attr:`default_severity` and implement
    :meth:`check`. The two helpers below exist so every issue has a stable
    ``subject`` shape: findings are sorted and de-duplicated on it.
    """

    code: ClassVar[str] = "CONSTRAINT"
    default_severity: ClassVar[Severity] = Severity.WARNING

    @abstractmethod
    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        """Yield one :class:`ValidationIssue` per violation. Must not mutate."""

    # -- helpers ----------------------------------------------------------
    def _issue(
        self,
        message: str,
        *,
        subject: str,
        severity: Severity | None = None,
        relation: RelationType | None = None,
        **context: Any,
    ) -> ValidationIssue:
        """Build an issue stamped with this constraint's code."""
        return ValidationIssue(
            code=self.code,
            severity=self.default_severity if severity is None else severity,
            message=message,
            subject=subject,
            relation=relation,
            context=context,
        )

    @staticmethod
    def _categories(graph: KnowledgeGraph) -> dict[str, ConceptCategory]:
        """``casefolded concept name -> category``; unknown names map to OTHER."""
        return {concept.identity: concept.category for concept in graph.nodes}

    @staticmethod
    def _category_of(categories: Mapping[str, ConceptCategory], name: str) -> ConceptCategory:
        """Category of ``name``, or OTHER when the concept is undeclared."""
        return categories.get(name.casefold(), ConceptCategory.OTHER)

    def __repr__(self) -> str:
        return "<%s code=%r>" % (type(self).__name__, self.code)


# ---------------------------------------------------------------------------
# Structural constraints - properties of the ABox itself, TBox independent
# ---------------------------------------------------------------------------
class DanglingEndpointConstraint(Constraint):
    """An edge points at a concept the graph never declares.

    Causes the other two structural checks to work on a name that has no
    category, so it is reported first and as an ``ERROR``.
    """

    code = "GRAPH_DANGLING"
    default_severity = Severity.ERROR

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        known = {concept.identity for concept in graph.nodes}
        for edge in graph.edges:
            missing = [
                name
                for name, key in (
                    (edge.source_concept, edge.source_concept.casefold()),
                    (edge.target_concept, edge.target_concept.casefold()),
                )
                if key not in known
            ]
            if missing:
                yield self._issue(
                    "edge endpoint(s) %s not declared as a concept" % ", ".join(missing),
                    subject=edge.describe(),
                    relation=edge.relation_type,
                    missing=missing,
                )


class SelfLoopConstraint(Constraint):
    """``a -[r]-> a``: usually a parsing artefact, occasionally meaningful.

    ``schema.max_self_loops`` sets how many are tolerated. The first ``max`` are
    reported as ``INFO`` (the quota was honoured), everything beyond as
    ``ERROR`` - which keeps a graph with a legitimate quota from being noisy
    while a graph that exceeds it still fails a strict run.
    """

    code = "GRAPH_SELF_LOOP"
    default_severity = Severity.ERROR

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        quota = schema.max_self_loops
        occurrence = 0
        for edge in graph.edges:
            if not edge.is_self_loop:
                continue
            occurrence += 1
            allowed = occurrence <= quota
            yield self._issue(
                "self-loop on %r (quota %d, occurrence %d)"
                % (edge.source_concept, quota, occurrence),
                subject=edge.describe(),
                severity=Severity.INFO if allowed else self.default_severity,
                relation=edge.relation_type,
                quota=quota,
                occurrence=occurrence,
            )


class DuplicateTripleConstraint(Constraint):
    """The same ``(source, relation, target)`` appears more than once.

    :meth:`KnowledgeGraph.merge` folds duplicates, so this only fires on a graph
    assembled by hand or by a future importer - which is exactly when it is
    worth knowing.
    """

    code = "GRAPH_DUPLICATE"
    default_severity = Severity.ERROR

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        counts = Counter(edge.identity for edge in graph.edges)
        for (source, relation, target), count in counts.items():
            if count < 2:
                continue
            yield self._issue(
                "triple appears %d times" % count,
                subject="%s -[%s]-> %s" % (source, relation, target),
                relation=RelationType(relation),
                count=count,
            )


# ---------------------------------------------------------------------------
# TBox constraints - the same edges, now judged against the schema
# ---------------------------------------------------------------------------
class SymmetryConstraint(Constraint):
    """A relation declared symmetric, on edges whose mirror image is missing.

    This is the layer's one hard, immediately useful rule: on the pilot graph it
    fires on 7 of 7 ``INTEGRATES_WITH`` edges, because the rule-based extractor
    emits each pair once and in one direction.
    """

    code = "TBOX_SYMMETRY"
    default_severity = Severity.ERROR

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        present: dict[RelationType, set[tuple[str, str]]] = {}
        for edge in graph.edges:
            present.setdefault(edge.relation_type, set()).add(
                (edge.source_concept.casefold(), edge.target_concept.casefold())
            )
        for relation, rule in schema.rules.items():
            if not rule.symmetric:
                continue
            keys = present.get(relation, set())
            for edge in graph.edges:
                if edge.relation_type != relation or edge.is_self_loop:
                    continue
                mirror = (edge.target_concept.casefold(), edge.source_concept.casefold())
                if mirror in keys:
                    continue
                yield self._issue(
                    "%s is symmetric but the mirror edge is missing" % relation.value,
                    subject=edge.describe(),
                    severity=rule.severity,
                    relation=relation,
                    missing="%s -[%s]-> %s"
                    % (edge.target_concept, relation.value, edge.source_concept),
                )


class DeclaredRelationUnusedConstraint(Constraint):
    """A relation in the vocabulary that no edge uses.

    Not an error - the vocabulary is a superset on purpose - but it is the
    cheapest signal that the extractor and the TBox have drifted apart. On the
    pilot corpus it names ``DEFINED_IN`` and ``PART_OF``.
    """

    code = "TBOX_UNUSED_RELATION"
    default_severity = Severity.WARNING

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        used = {edge.relation_type for edge in graph.edges}
        for relation in RelationType:
            if relation in used or relation in schema.declared_unused_ok:
                continue
            yield self._issue(
                "relation %s is declared but no edge uses it" % relation.value,
                subject=relation.value,
                relation=relation,
                described_in_tbox=relation in schema.rules,
            )


class ConfidenceBandConstraint(Constraint):
    """An edge whose score falls outside the band its relation normally occupies.

    Each relation occupies a fixed score (or two) because the lexicon, not the
    text, sets it. A score outside the band therefore means the *extractor*
    changed - a new rule, a different prompt, an LLM instead of the lexicon -
    which is exactly the drift this layer should surface. Severity comes from the
    relation's rule: ``INFO`` for RELATED_TO, whose drift is expected.
    """

    code = "TBOX_CONFIDENCE_BAND"
    default_severity = Severity.WARNING

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        for edge in graph.edges:
            rule = schema.rules.get(edge.relation_type)
            if rule is None or rule.confidence_band is None:
                continue
            low, high = rule.confidence_band
            score = edge.confidence_score
            if low - _CONFIDENCE_EPS <= score <= high + _CONFIDENCE_EPS:
                continue
            yield self._issue(
                "confidence %.3f outside the %s band [%.2f, %.2f]"
                % (score, edge.relation_type.value, low, high),
                subject=edge.describe(),
                severity=rule.severity,
                relation=edge.relation_type,
                confidence=score,
                band=[low, high],
            )


class DomainRangeConstraint(Constraint):
    """An edge joining categories the relation's rule does not allow.

    Severity is capped at ``WARNING`` even when the relation's own severity is
    ``ERROR``: measured on the pilot graph the dominant category pair covers only
    13-29% of a relation's edges, so a domain miss is a pattern break, not a
    contradiction. Only relations with an explicit ``domain``/``range`` are
    checked; ``None`` means "any" and costs nothing.
    """

    code = "TBOX_DOMAIN_RANGE"
    default_severity = Severity.WARNING

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        categories = self._categories(graph)
        for edge in graph.edges:
            rule = schema.rules.get(edge.relation_type)
            if rule is None or (rule.domain is None and rule.range is None):
                continue
            source = self._category_of(categories, edge.source_concept)
            target = self._category_of(categories, edge.target_concept)
            if rule.allows(source, target):
                continue
            violated = [
                side
                for side, ok in (
                    ("domain", rule.domain is None or source in rule.domain),
                    ("range", rule.range is None or target in rule.range),
                )
                if not ok
            ]
            severity = Severity.WARNING if rule.severity is Severity.ERROR else rule.severity
            yield self._issue(
                "category %s -> %s violates the %s %s"
                % (source.value, target.value, edge.relation_type.value, "/".join(violated)),
                subject=edge.describe(),
                severity=severity,
                relation=edge.relation_type,
                violated=violated,
                source_category=source.value,
                target_category=target.value,
            )


class RequiredCategoryConstraint(Constraint):
    """A category the schema says must exist, with no concept behind it.

    A missing OBJECT_TYPE or ACTION means the extraction covered the wrong part
    of the docs; the graph can still be internally consistent, so this is a
    ``WARNING``, not an error.
    """

    code = "TBOX_REQUIRED_CATEGORY"
    default_severity = Severity.WARNING

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        present = {concept.category for concept in graph.nodes}
        for category in sorted(schema.required_categories, key=lambda item: item.value):
            if category in present:
                continue
            yield self._issue(
                "required category %r has no concept" % category.value,
                subject=category.value,
                category=category.value,
            )


class FunctionalityConstraint(Constraint):
    """A functional ``(head, relation)`` pair pointing at two or more tails.

    No relation in ``PALANTIR_TBOX`` is functional today - the busiest head fans
    out to 16 tails - so this rule exists for schemas where it is meaningful
    (``DEFINED_IN`` for a single-source corpus, say) and stays silent for the
    pilot one. It is the reason ``functional`` lives on the rule rather than
    being hard-coded.
    """

    code = "TBOX_FUNCTIONAL"
    default_severity = Severity.WARNING

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        tails: dict[tuple[str, RelationType], set[str]] = {}
        for edge in graph.edges:
            rule = schema.rules.get(edge.relation_type)
            if rule is None or not rule.functional:
                continue
            tails.setdefault((edge.source_concept.casefold(), edge.relation_type), set()).add(
                edge.target_concept.casefold()
            )
        for (source, relation), found in sorted(
            tails.items(), key=lambda item: (item[0][0], item[0][1].value)
        ):
            if len(found) < 2:
                continue
            yield self._issue(
                "%d tails for a functional (head, relation)" % len(found),
                subject="%s -[%s]-> ..." % (source, relation.value),
                relation=relation,
                head=source,
                tails=sorted(found),
            )


def _back_edges(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Return ``(from, to)`` edges that close a directed cycle.

    Iterative depth-first search with three-colour marking over casefolded
    ``(source, target)`` pairs. Iterative rather than recursive because a
    corpus-sized graph should not be able to blow the interpreter stack.

    It also refuses to touch the structure it walks: the adjacency map is built
    locally, and children are appended with ``setdefault``, never by indexing a
    defaultdict inside the traversal - a bug that once turned a probe of this
    very graph into ``RuntimeError: dictionary changed size during iteration``
    (see ``test_constraints_never_mutate_the_graph``).
    """
    adjacency: dict[str, list[str]] = {}
    for source, target in pairs:
        if source == target:  # self-loops belong to SelfLoopConstraint
            continue
        adjacency.setdefault(source, []).append(target)
    for children in adjacency.values():
        children.sort()

    white, grey, black = 0, 1, 2
    colour: dict[str, int] = {node: white for node in adjacency}
    found: list[tuple[str, str]] = []
    for start in sorted(adjacency):
        if colour[start] != white:
            continue
        colour[start] = grey
        stack: list[tuple[str, Iterator[str]]] = [(start, iter(adjacency.get(start, ())))]
        while stack:
            node, children = stack[-1]
            descended = False
            for child in children:
                state = colour.get(child, white)
                if state == grey:
                    found.append((node, child))
                elif state == white:
                    colour[child] = grey
                    stack.append((child, iter(adjacency.get(child, ()))))
                    descended = True
                    break
            if not descended:
                colour[node] = black
                stack.pop()
    return found


class CycleConstraint(Constraint):
    """A directed cycle inside a relation declared ``acyclic``.

    ``DEPENDS_ON`` is the reason this exists: ``A depends on B`` and ``B depends
    on A`` cannot both be facts about a build order. Relations without
    ``acyclic`` are skipped, so the 124 mutually-RELATED_TO pairs of the pilot
    graph are not reported as 124 errors - they are expected there.
    """

    code = "TBOX_CYCLE"
    default_severity = Severity.WARNING

    def check(self, graph: KnowledgeGraph, schema: "OntologySchema") -> Iterator[ValidationIssue]:
        for relation, rule in schema.rules.items():
            if not rule.acyclic:
                continue
            pairs = [
                (edge.source_concept.casefold(), edge.target_concept.casefold())
                for edge in graph.edges
                if edge.relation_type == relation
            ]
            for source, target in _back_edges(pairs):
                yield self._issue(
                    "%s cycle: %s -> %s closes a loop" % (relation.value, source, target),
                    subject="%s -[%s]-> %s" % (source, relation.value, target),
                    severity=rule.severity,
                    relation=relation,
                    closes_cycle_over=target,
                )


#: Every check, in reporting order: structural first (they explain *why* a later
#: TBox finding looks the way it does), then the hard TBox rules, then the soft
#: ones. Append a new constraint here and it is picked up everywhere.
DEFAULT_CONSTRAINTS: tuple[Constraint, ...] = (
    DanglingEndpointConstraint(),
    SelfLoopConstraint(),
    DuplicateTripleConstraint(),
    SymmetryConstraint(),
    CycleConstraint(),
    DeclaredRelationUnusedConstraint(),
    DomainRangeConstraint(),
    FunctionalityConstraint(),
    ConfidenceBandConstraint(),
    RequiredCategoryConstraint(),
)
