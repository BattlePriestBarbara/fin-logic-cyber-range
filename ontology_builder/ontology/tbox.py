# -*- coding: utf-8 -*-
"""The TBox: what an edge is *allowed* to be.

A TBox (terminological box) is the schema half of an ontology: which relations
exist, which categories they may join, and which structural properties they
have. The ABox is the graph itself (``outputs/ontology_graph.json``). Stage 1
shipped the ABox and only the *vocabulary* of the TBox (the ``RelationType``
enum); this module adds the rest, and
:mod:`ontology_builder.ontology.validator` turns it into a runtime check.

Why most rules here are soft (measured, not assumed)
---------------------------------------------------
The 252-edge pilot graph was scanned before a single rule was written:

====================  ====  ==============  =========  ========  ===========
relation                 n  dominant pair   inverse-  2-step    confidence
                            (share/pairs)   present   closure   observed
====================  ====  ==============  =========  ========  ===========
RELATED_TO             173  0.17 / 53           72%       62%  0.55
PRODUCES                35  0.23 / 19           17%       24%  0.80
DEPENDS_ON              23  0.13 / 18           17%       23%  0.70/0.85
HAS_COMPONENT           14  0.29 / 10            0%        0%  0.85
INTEGRATES_WITH          7  0.29 /  6            0%        0%  0.90
DEFINED_IN               0  -                    -         -        -
PART_OF                  0  -                    -         -        -
====================  ====  ==============  =========  ========  ===========

Read the ``dominant pair`` column: the most frequent ``(source category,
target category)`` combination covers only 13-29% of a relation's edges, and
RELATED_TO spans 53 distinct pairs across the whole 8x8 category matrix. Pinning
domain/range to the observed majority would reject 71-87% of the edges on day
one. So the split is:

* **hard (``Severity.ERROR``)** - properties the graph either has or has not:
  symmetry of ``INTEGRATES_WITH``, no self-loops, no duplicate triples, all
  endpoints declared. Cheap to verify, and already valuable: **all 7**
  ``INTEGRATES_WITH`` edges lack their mirror image, and ``DEFINED_IN`` /
  ``PART_OF`` are declared by the vocabulary but never used.
* **soft (``Severity.WARNING`` / ``INFO``)** - domain/range, confidence bands,
  vocabulary usage. Reported, never blocking.

A rule that fires on 87% of the data is not a constraint, it is a histogram.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping

from ontology_builder.core.contracts import Severity
from ontology_builder.core.errors import DataContractError
from ontology_builder.schema import ConceptCategory, RelationType

if TYPE_CHECKING:  # pragma: no cover - annotation only
    from ontology_builder.schema import KnowledgeGraph

#: Share of a relation's edges a category must cover to enter the bootstrapped
#: domain/range (see :meth:`OntologySchema.from_graph`).
DEFAULT_SHARE_FLOOR = 0.20


@dataclass(frozen=True)
class RelationRule:
    """Everything the TBox says about one :class:`RelationType`.

    Attributes:
        relation: the relation this rule governs.
        domain: allowed source categories, or ``None`` for "any".
        range: allowed target categories, or ``None`` for "any".
        symmetric: the relation implies its own inverse (``a-r->b`` requires
            ``b-r->a``); violations are reported by ``SymmetryConstraint``.
        transitive: ``a-r->b`` and ``b-r->c`` should imply ``a-r->c``. Recorded
            for documentation only - closure is *not* enforced, because
            RELATED_TO already closes 62% of the time and materialising the
            remaining 38% would multiply the edge count.
        functional: ``(head, relation)`` points at most one tail.
        acyclic: the relation may not contain a directed cycle (``DEPENDS_ON``:
            a dependency loop is a modelling error, not a fact).
        confidence_band: inclusive ``(low, high)`` range the extractor's scores
            are expected to fall in; falling outside means extractor drift, not
            a bad edge. ``None`` when the corpus has never produced the relation.
        severity: how badly a violation of *this* rule hurts. ``ERROR`` for
            properties the graph must have, ``WARNING`` for soft patterns,
            ``INFO`` for catch-all relations where drift is expected.
        description: one line of provenance/reasoning, copied into reports.

    Raises:
        DataContractError: on a malformed band, a non-``RelationType``
            ``relation``, or a category set containing non-enum members.
    """

    relation: RelationType
    domain: frozenset[ConceptCategory] | None = None
    range: frozenset[ConceptCategory] | None = None
    symmetric: bool = False
    transitive: bool = False
    functional: bool = False
    acyclic: bool = False
    confidence_band: tuple[float, float] | None = None
    severity: Severity = Severity.WARNING
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.relation, RelationType):
            raise DataContractError(
                "relation must be a RelationType, got %r" % (self.relation,),
                relation=repr(self.relation),
            )
        # Tolerate "error"/"ERROR" at construction time; store the member.
        object.__setattr__(self, "severity", Severity.coerce(self.severity))
        for name in ("domain", "range"):
            value = getattr(self, name)
            if value is None:
                continue
            try:
                frozen = frozenset(value)
            except TypeError as exc:
                raise DataContractError(
                    "%s must be an iterable of ConceptCategory" % name, field=name
                ) from exc
            bad = [item for item in frozen if not isinstance(item, ConceptCategory)]
            if bad:
                raise DataContractError(
                    "%s contains non-ConceptCategory members: %r" % (name, bad), field=name
                )
            object.__setattr__(self, name, frozen)
        if self.confidence_band is not None:
            band = tuple(self.confidence_band)
            if len(band) != 2:
                raise DataContractError("confidence_band needs exactly two bounds", band=band)
            low, high = float(band[0]), float(band[1])
            if not (0.0 <= low <= high <= 1.0):
                raise DataContractError(
                    "confidence_band must satisfy 0 <= low <= high <= 1", band=band
                )
            object.__setattr__(self, "confidence_band", (low, high))

    def allows(self, source: ConceptCategory, target: ConceptCategory) -> bool:
        """True when ``source -[relation]-> target`` is inside domain and range."""
        if self.domain is not None and source not in self.domain:
            return False
        if self.range is not None and target not in self.range:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """JSON form for the validation report."""
        return {
            "relation": self.relation.value,
            "domain": sorted(c.value for c in self.domain) if self.domain is not None else None,
            "range": sorted(c.value for c in self.range) if self.range is not None else None,
            "symmetric": self.symmetric,
            "transitive": self.transitive,
            "functional": self.functional,
            "acyclic": self.acyclic,
            "confidence_band": list(self.confidence_band) if self.confidence_band else None,
            "severity": self.severity.value,
            "description": self.description,
        }


def _shared_categories(
    pairs: list[tuple[str, str]],
    categories: Mapping[str, ConceptCategory],
    index: int,
    floor: float,
) -> frozenset[ConceptCategory]:
    """Categories covering at least ``floor`` of ``pairs`` at position ``index``.

    ``index=0`` measures the source side (domain), ``index=1`` the target side
    (range). Unknown endpoints count as :attr:`ConceptCategory.OTHER`, so a
    dangling edge can never silently widen a domain.

    Module-level rather than a closure inside :meth:`OntologySchema.from_graph`
    on purpose: a closure over the loop variable is the kind of bug that only
    shows up when the loop body is refactored later.
    """
    total = len(pairs)
    if not total:
        return frozenset()
    counts = Counter(categories.get(pair[index], ConceptCategory.OTHER) for pair in pairs)
    return frozenset(cat for cat, count in counts.items() if count / total >= floor)


def _permissive(relation: RelationType) -> RelationRule:
    """Fallback rule for a relation the schema says nothing about.

    Permissive on purpose: a relation missing from the TBox is a *gap*, not a
    violation, and rejecting edges over a gap would make the layer unusable the
    moment a new relation is added.
    """
    return RelationRule(
        relation=relation,
        severity=Severity.INFO,
        description="not described by the TBox; no constraint applied",
    )


@dataclass(frozen=True)
class OntologySchema:
    """The TBox for one corpus: a rule per relation plus corpus-wide invariants.

    Attributes:
        name: short schema name, recorded in every report.
        version: bumped whenever a rule changes, so a stored report can be
            traced back to the rules that produced it.
        rules: ``RelationType -> RelationRule``. Missing relations fall back to
            :func:`_permissive`.
        required_categories: categories the graph must contain at least one
            concept of. Empty by default - a category rule is a statement about
            the corpus, not about the schema.
        max_self_loops: how many ``a -> a`` edges are tolerated (0 in practice).
        declared_unused_ok: relations allowed to have zero edges. Empty means
            "a declared relation that nothing uses is a warning".

    Raises:
        DataContractError: when a key is not a ``RelationType``, a value is not
            a ``RelationRule``, or a rule governs a different relation than its
            key (a mismatch that would silently disable the rule).
    """

    name: str
    version: str
    rules: Mapping[RelationType, RelationRule]
    required_categories: frozenset[ConceptCategory] = frozenset()
    max_self_loops: int = 0
    declared_unused_ok: frozenset[RelationType] = frozenset()

    def __post_init__(self) -> None:
        checked: dict[RelationType, RelationRule] = {}
        for key, rule in dict(self.rules).items():
            if not isinstance(key, RelationType):
                raise DataContractError(
                    "rules keys must be RelationType members, got %r" % (key,), key=repr(key)
                )
            if not isinstance(rule, RelationRule):
                raise DataContractError(
                    "rules values must be RelationRule instances, got %r" % (rule,),
                    relation=key.value,
                )
            if rule.relation is not key:
                raise DataContractError(
                    "rule.relation %r does not match its key %r" % (rule.relation.value, key.value),
                    key=key.value,
                )
            checked[key] = rule
        object.__setattr__(self, "rules", MappingProxyType(checked))
        object.__setattr__(self, "required_categories", frozenset(self.required_categories))
        object.__setattr__(self, "declared_unused_ok", frozenset(self.declared_unused_ok))
        if self.max_self_loops < 0:
            raise DataContractError("max_self_loops cannot be negative", value=self.max_self_loops)

    def rule(self, relation: RelationType) -> RelationRule:
        """Rule for ``relation``; a permissive placeholder when unspecified."""
        return self.rules.get(relation) or _permissive(relation)

    @property
    def relations(self) -> tuple[RelationType, ...]:
        """Relations with an explicit rule, in declaration order."""
        return tuple(rel for rel in RelationType if rel in self.rules)

    def to_dict(self) -> dict[str, Any]:
        """JSON form: the schema as it was applied, not as it was written."""
        return {
            "name": self.name,
            "version": self.version,
            "max_self_loops": self.max_self_loops,
            "required_categories": sorted(c.value for c in self.required_categories),
            "declared_unused_ok": sorted(r.value for r in self.declared_unused_ok),
            "rules": [rule.to_dict() for rule in self.rules.values()],
        }

    @classmethod
    def from_graph(
        cls,
        graph: "KnowledgeGraph",
        *,
        share_floor: float = DEFAULT_SHARE_FLOOR,
        symmetric_share: float = 0.9,
        closure_share: float = 0.9,
        name: str = "bootstrap",
        version: str = "0.0.0",
    ) -> "OntologySchema":
        """Derive a **soft-only** schema by measuring an existing graph.

        This bootstraps a TBox for a new corpus and lets the tests check that a
        schema fitted to the pilot graph agrees with the hand-written one on the
        facts that matter.

        Everything it emits is :attr:`Severity.WARNING`: a pattern measured on
        one corpus is a hypothesis, not a rule. Hard rules stay hand-written and
        reviewed, which is the whole point of having a TBox at all.

        Args:
            graph: the ABox to measure.
            share_floor: a category enters ``domain``/``range`` when it covers at
                least this share of the relation's edges. A relation whose
                categories are all below the floor gets ``None`` (unrestricted) -
                exactly the situation RELATED_TO is in (dominant share 0.17).
            symmetric_share: share of edges needing a mirror image before the
                relation is called symmetric.
            closure_share: share of closed 2-step paths before it is called
                transitive.
            name: schema name recorded in reports.
            version: schema version recorded in reports.

        Returns:
            An :class:`OntologySchema` with one rule per relation that actually
            appears in ``graph``.

        Raises:
            DataContractError: when a threshold is outside ``[0, 1]``.
        """
        for label, value in (
            ("share_floor", share_floor),
            ("symmetric_share", symmetric_share),
            ("closure_share", closure_share),
        ):
            if not 0.0 <= value <= 1.0:
                raise DataContractError("%s must be in [0, 1]" % label, **{label: value})

        categories = {concept.identity: concept.category for concept in graph.nodes}
        by_relation: dict[RelationType, list[tuple[str, str]]] = {}
        scores: dict[RelationType, list[float]] = {}
        for edge in graph.edges:
            pairs = by_relation.setdefault(edge.relation_type, [])
            pairs.append((edge.source_concept.casefold(), edge.target_concept.casefold()))
            scores.setdefault(edge.relation_type, []).append(edge.confidence_score)

        rules: dict[RelationType, RelationRule] = {}
        for relation in RelationType:
            pairs = by_relation.get(relation)
            if not pairs:
                continue
            total = len(pairs)
            keys = set(pairs)

            loops = [pair for pair in pairs if pair[0] == pair[1]]
            mirrored = sum(1 for src, tgt in pairs if src != tgt and (tgt, src) in keys)
            non_loop = sum(1 for src, tgt in pairs if src != tgt)
            symmetric = bool(non_loop) and mirrored / non_loop >= symmetric_share

            adjacency: dict[str, set[str]] = {}
            for src, tgt in pairs:
                adjacency.setdefault(src, set()).add(tgt)
            two_step = 0
            closed = 0
            for node in list(adjacency):  # list(): never mutate while iterating
                for mid in adjacency[node]:
                    for end in adjacency.get(mid, ()):
                        two_step += 1
                        if end in adjacency[node]:
                            closed += 1
            transitive = bool(two_step) and closed / two_step >= closure_share

            dominant = (
                max(
                    Counter(
                        (
                            categories.get(s, ConceptCategory.OTHER),
                            categories.get(t, ConceptCategory.OTHER),
                        )
                        for s, t in pairs
                    ).values()
                )
                / total
            )

            observed = scores[relation]
            rules[relation] = RelationRule(
                relation=relation,
                domain=_shared_categories(pairs, categories, 0, share_floor) or None,
                range=_shared_categories(pairs, categories, 1, share_floor) or None,
                symmetric=symmetric,
                transitive=transitive,
                confidence_band=(min(observed), max(observed)),
                severity=Severity.WARNING,
                description=(
                    "bootstrapped from %d edges: dominant category pair %.0f%%, "
                    "%d self-loop(s), %.0f%% mirrored, %.0f%% transitive closure"
                    % (
                        total,
                        100.0 * dominant,
                        len(loops),
                        100.0 * mirrored / non_loop if non_loop else 0.0,
                        100.0 * closed / two_step if two_step else 0.0,
                    )
                ),
            )
        return cls(name=name, version=version, rules=rules)


# ---------------------------------------------------------------------------
# The pilot corpus' TBox
# ---------------------------------------------------------------------------
#: TBox of the Palantir docs pilot corpus.
#:
#: Every flag and band below was set from the 252-edge measurement in this
#: module's docstring; each ``description`` names the measurement it came from.
#: The bands are drift detectors, so when the corpus grows they must be
#: re-fitted, not trusted: bump :attr:`OntologySchema.version` when you touch one.
#:
#: Two rules are deliberately absent:
#:
#: * no ``domain``/``range`` for RELATED_TO - 53 category pairs on 173 edges is
#:   the definition of "unconstrained";
#: * no ``functional`` anywhere - the busiest head fans out to 16 tails, so a
#:   cardinality rule would be fiction.
PALANTIR_TBOX = OntologySchema(
    name="palantir-docs",
    version="1.1.0",
    required_categories=frozenset(
        {
            ConceptCategory.OBJECT_TYPE,
            ConceptCategory.ACTION,
            ConceptCategory.PIPELINE,
            ConceptCategory.DATASET,
        }
    ),
    max_self_loops=0,
    # Stage 7 widened the shared vocabulary with four security relations, stage 8
    # with four finance ones, stage 9 with five tooling ones and stage 10 with
    # four business-logic ones. They are declared here (so
    # `set(PALANTIR_TBOX.relations) == set(RelationType)` still holds and no
    # relation falls back to a silent permissive rule) but listed as legitimately
    # unused: the Palantir corpus has no tool/artifact, endpoint/compliance,
    # capability/platform or process/control edges, and without this line
    # `DeclaredRelationUnusedConstraint` would add seventeen findings to a report
    # that is pinned at two.
    declared_unused_ok=frozenset(
        {
            RelationType.PRODUCES_ARTIFACT,
            RelationType.USES_ARTIFACT,
            RelationType.ENABLES,
            RelationType.HAS_VULNERABILITY,
            RelationType.EXPOSES,
            RelationType.PROCESSES,
            RelationType.VIOLATES,
            RelationType.LEADS_TO,
            RelationType.HAS_CAPABILITY,
            RelationType.RUNS_ON,
            RelationType.SUPPORTS_FORMAT,
            RelationType.SUBSTITUTES,
            RelationType.LIMITED_BY,
            RelationType.IMPLEMENTS,
            RelationType.REQUIRES_CONTROL,
            RelationType.LACKS_CONTROL,
            RelationType.LEADS_TO_VULNERABILITY,
        }
    ),
    rules={
        RelationType.HAS_COMPONENT: RelationRule(
            relation=RelationType.HAS_COMPONENT,
            domain=frozenset(
                {
                    ConceptCategory.OBJECT_TYPE,
                    ConceptCategory.APPLICATION,
                    ConceptCategory.PIPELINE,
                    ConceptCategory.OTHER,
                }
            ),
            confidence_band=(0.80, 0.90),
            description=(
                "a component is owned by a container: these are exactly the 4 source "
                "categories seen on all 14 edges, so the rule fires only on drift"
            ),
        ),
        RelationType.INTEGRATES_WITH: RelationRule(
            relation=RelationType.INTEGRATES_WITH,
            symmetric=True,
            confidence_band=(0.85, 0.95),
            severity=Severity.ERROR,
            description=(
                "integration is mutual; 0/7 edges of the pilot graph carry their "
                "mirror image, which is the layer's first real finding"
            ),
        ),
        RelationType.DEPENDS_ON: RelationRule(
            relation=RelationType.DEPENDS_ON,
            acyclic=True,
            confidence_band=(0.65, 0.90),
            description=(
                "a dependency loop is a modelling error, not a fact; 0.70/0.85 are "
                "the only two scores the extractor emits for this relation"
            ),
        ),
        RelationType.PRODUCES: RelationRule(
            relation=RelationType.PRODUCES,
            confidence_band=(0.75, 0.85),
            description=(
                "producer side left open on purpose: 19 category pairs over 35 edges, "
                "so there is no majority to encode"
            ),
        ),
        RelationType.PART_OF: RelationRule(
            relation=RelationType.PART_OF,
            transitive=True,
            acyclic=True,
            description="declared by the vocabulary but never produced by the pilot corpus",
        ),
        RelationType.DEFINED_IN: RelationRule(
            relation=RelationType.DEFINED_IN,
            description="declared by the vocabulary but never produced by the pilot corpus",
        ),
        RelationType.RELATED_TO: RelationRule(
            relation=RelationType.RELATED_TO,
            confidence_band=(0.50, 0.60),
            severity=Severity.INFO,
            description=(
                "catch-all: 53 category pairs over 173 edges, so no domain/range; "
                "INFO because drift here is expected rather than suspicious"
            ),
        ),
        # The stage-7 security vocabulary. Permissive and INFO on purpose: this
        # TBox judges the Palantir docs corpus, where these relations cannot
        # occur, so anything but "no rule applied" would be inventing a finding.
        # ``re_security/tbox.py`` is the TBox that actually constrains them.
        RelationType.PRODUCES_ARTIFACT: RelationRule(
            relation=RelationType.PRODUCES_ARTIFACT,
            severity=Severity.INFO,
            description="stage-7 security vocabulary; no Palantir edge uses it",
        ),
        RelationType.USES_ARTIFACT: RelationRule(
            relation=RelationType.USES_ARTIFACT,
            severity=Severity.INFO,
            description="stage-7 security vocabulary; no Palantir edge uses it",
        ),
        RelationType.ENABLES: RelationRule(
            relation=RelationType.ENABLES,
            severity=Severity.INFO,
            description="stage-7 security vocabulary; no Palantir edge uses it",
        ),
        RelationType.HAS_VULNERABILITY: RelationRule(
            relation=RelationType.HAS_VULNERABILITY,
            severity=Severity.INFO,
            description="stage-7 security vocabulary; no Palantir edge uses it",
        ),
        # The stage-8 finance vocabulary, same reasoning as the block above:
        # declared so every relation has a rule, INFO so the docs corpus cannot
        # acquire a finding it never had. ``fin_security/tbox.py`` is the TBox
        # that actually constrains these four.
        RelationType.EXPOSES: RelationRule(
            relation=RelationType.EXPOSES,
            severity=Severity.INFO,
            description="stage-8 finance vocabulary; no Palantir edge uses it",
        ),
        RelationType.PROCESSES: RelationRule(
            relation=RelationType.PROCESSES,
            severity=Severity.INFO,
            description="stage-8 finance vocabulary; no Palantir edge uses it",
        ),
        RelationType.VIOLATES: RelationRule(
            relation=RelationType.VIOLATES,
            severity=Severity.INFO,
            description="stage-8 finance vocabulary; no Palantir edge uses it",
        ),
        RelationType.LEADS_TO: RelationRule(
            relation=RelationType.LEADS_TO,
            severity=Severity.INFO,
            description="stage-8 finance vocabulary; no Palantir edge uses it",
        ),
        # And the stage-9 tooling vocabulary, for the third time: declared so
        # every relation has a rule, INFO so the docs corpus cannot acquire a
        # finding it never had. ``re_toolbox/tbox.py`` constrains these five.
        RelationType.HAS_CAPABILITY: RelationRule(
            relation=RelationType.HAS_CAPABILITY,
            severity=Severity.INFO,
            description="stage-9 tooling vocabulary; no Palantir edge uses it",
        ),
        RelationType.RUNS_ON: RelationRule(
            relation=RelationType.RUNS_ON,
            severity=Severity.INFO,
            description="stage-9 tooling vocabulary; no Palantir edge uses it",
        ),
        RelationType.SUPPORTS_FORMAT: RelationRule(
            relation=RelationType.SUPPORTS_FORMAT,
            severity=Severity.INFO,
            description="stage-9 tooling vocabulary; no Palantir edge uses it",
        ),
        RelationType.SUBSTITUTES: RelationRule(
            relation=RelationType.SUBSTITUTES,
            severity=Severity.INFO,
            description="stage-9 tooling vocabulary; no Palantir edge uses it",
        ),
        RelationType.LIMITED_BY: RelationRule(
            relation=RelationType.LIMITED_BY,
            severity=Severity.INFO,
            description="stage-9 tooling vocabulary; no Palantir edge uses it",
        ),
        # And the stage-10 business-logic vocabulary, for the fourth time:
        # declared so every relation has a rule (``set(PALANTIR_TBOX.relations)``
        # still equals ``set(RelationType)``), INFO so the docs corpus cannot
        # acquire a finding it never had. ``fin_logic_risk/tbox.py`` constrains
        # these four, and reuses stage-8 ``VIOLATES`` for its fifth edge.
        RelationType.IMPLEMENTS: RelationRule(
            relation=RelationType.IMPLEMENTS,
            severity=Severity.INFO,
            description="stage-10 business-logic vocabulary; no Palantir edge uses it",
        ),
        RelationType.REQUIRES_CONTROL: RelationRule(
            relation=RelationType.REQUIRES_CONTROL,
            severity=Severity.INFO,
            description="stage-10 business-logic vocabulary; no Palantir edge uses it",
        ),
        RelationType.LACKS_CONTROL: RelationRule(
            relation=RelationType.LACKS_CONTROL,
            severity=Severity.INFO,
            description="stage-10 business-logic vocabulary; no Palantir edge uses it",
        ),
        RelationType.LEADS_TO_VULNERABILITY: RelationRule(
            relation=RelationType.LEADS_TO_VULNERABILITY,
            severity=Severity.INFO,
            description="stage-10 business-logic vocabulary; no Palantir edge uses it",
        ),
    },
)

#: Schema used when a caller does not pass one.
DEFAULT_SCHEMA = PALANTIR_TBOX
