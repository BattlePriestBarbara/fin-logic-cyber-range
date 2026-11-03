# -*- coding: utf-8 -*-
"""Pydantic schema for the Palantir docs micro-ontology (stage 1 of 3).

The whole stage is deliberately dependency-light: `pydantic` for the schema,
`networkx` for the in-memory graph, nothing else. No Neo4j, no database.

Layout
------
    ontology_builder/            <- this package
    ontology_builder/schema.py   <- you are here (models + nx conversion)
    ontology_builder/extractor.py, llm_clients.py, pipeline.py, analyzer.py
    ontology_builder/scripts/    <- entry-point scripts (export chunks, visualise)
    ontology_builder/outputs/    <- ontology_graph.json, ontology_visualization.png

Strictness contract (important, measured on pydantic 2.13)
---------------------------------------------------------
Every model sets ``ConfigDict(strict=True, extra="forbid")``. That has two
consequences you must design around instead of fighting:

1. In **python mode** a raw string is *not* coerced into an Enum, and a dict is
   *not* coerced into a nested model. Build model instances:

       OntologyConcept(name="Action", definition="...", category=ConceptCategory.ACTION)

   ``int`` -> ``float`` *is* allowed, so ``confidence_score=1`` is fine.
2. In **JSON mode** (``KnowledgeGraph.model_validate_json``) the string
   ``"action"`` *is* matched against the enum values, because JSON has no enum
   type. So ``load_json()`` parses through ``model_validate_json``; it never does
   ``json.loads`` + ``model_validate``.

Untrusted payloads (an LLM answer) are therefore repaired in
``extractor.parse_graph_payload`` first and only then handed to the models.
"""

from __future__ import annotations

import json
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:  # `python ontology_builder/schema.py`
    sys.path.insert(0, str(_PROJECT_ROOT))

import networkx as nx
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

GRAPH_SCHEMA_VERSION = "1.0.0"

MAX_NAME_CHARS = 120
MAX_DEFINITION_CHARS = 600
MAX_ALIASES = 5
MAX_EVIDENCE_CHARS = 300

_WS_RE = re.compile(r"\s+")


def _clean(text: str) -> str:
    """Collapse every run of whitespace (incl. the docs' NBSP/zero-width) to one space."""
    return _WS_RE.sub(" ", text.replace("\u200b", "").replace("\xa0", " ")).strip()


# ---------------------------------------------------------------------------
# Controlled vocabularies
# ---------------------------------------------------------------------------
class ConceptCategory(str, Enum):
    """What kind of artefact a concept is.

    The eight Palantir values come first (stage 1); stages 7, 8, 9 and 10 append
    the domain classes of ``re_security/``, ``fin_security/``, ``re_toolbox/`` and
    ``fin_logic_risk/`` behind them.

    The values double as the node colour keys in `scripts/visualize_graph.py`,
    so they are stable strings, not localised labels.
    """

    OBJECT_TYPE = "object_type"
    ACTION = "action"
    PIPELINE = "pipeline"
    DATASET = "dataset"
    API = "api"
    APPLICATION = "application"
    WORKFLOW = "workflow"
    OTHER = "other"
    # -- stage 7: reverse-engineering security (see ``re_security/``) ---------
    # Appended *after* OTHER so the eight Palantir values keep their declaration
    # order: `values()` feeds the extractor prompt, and reordering it would
    # change the prompt (and therefore the extraction) of an unrelated corpus.
    TOOL = "tool"
    DEPENDENCY = "dependency"
    ARTIFACT = "artifact"
    TASK = "task"
    VULNERABILITY = "vulnerability"
    # -- stage 8: financial security (see ``fin_security/``) -------------------
    # Appended after the stage-7 block for the same reason again: declaration
    # order *is* prompt order (`extractor.build_prompt` joins `values()`), so
    # inserting anywhere else would rewrite the prompt of every other corpus.
    # ``VULNERABILITY`` is shared with stage 7 rather than duplicated: a flaw is
    # a flaw whether it ships in a package or behind an HTTP route.
    FINANCIAL_SYSTEM = "financial_system"
    API_ENDPOINT = "api_endpoint"
    DATA_ASSET = "data_asset"
    COMPLIANCE_RULE = "compliance_rule"
    # -- stage 9: reverse-engineering tooling (see ``re_toolbox/``) ------------
    # Appended at the tail again, for the reason stated twice above. ``TOOL`` and
    # ``ARTIFACT`` are *reused* from stage 7 rather than duplicated: stage 7 asks
    # what a tool is exposed to, stage 9 asks what a tool can do - the same two
    # classes, two questions.
    CAPABILITY = "capability"
    PLATFORM = "platform"
    LIMITATION = "limitation"
    # -- stage 10: financial business logic (see ``fin_logic_risk/``) ----------
    # Appended at the tail for the fourth time. Two members are enough because
    # three of the five stage-10 classes are *reused*: ``API_ENDPOINT`` already
    # names a route, and ``VULNERABILITY`` / ``COMPLIANCE_RULE`` already name a
    # flaw and a clause - a logic flaw is still a flaw. Only the two classes the
    # earlier stages had no word for are new: the *process* a route serves and
    # the *control* it is supposed to enforce.
    BUSINESS_PROCESS = "business_process"
    SECURITY_CONTROL = "security_control"

    @classmethod
    def values(cls) -> list[str]:
        """All legal values, in declaration order (used in prompts and reports)."""
        return [member.value for member in cls]

    @classmethod
    def coerce(cls, raw: object) -> "ConceptCategory":
        """Map a loose string ("Object Type", "objecttype", "entity") onto a member.

        Unknown input falls back to :attr:`OTHER` instead of raising: a category
        is a *label* on an extracted concept, and losing the concept because the
        model wrote "tool" would throw away real evidence.
        """
        if isinstance(raw, cls):
            return raw
        text = _clean(str(raw or "")).casefold().replace("-", "_").replace(" ", "_")
        text = _CATEGORY_ALIASES.get(text, text)
        try:
            return cls(text)
        except ValueError:
            return cls.OTHER


_CATEGORY_ALIASES: dict[str, str] = {
    "objecttype": "object_type",
    "object_types": "object_type",
    "object": "object_type",
    "entity": "object_type",
    "action_type": "action",
    "actiontype": "action",
    "actions": "action",
    "function": "action",
    "pipelines": "pipeline",
    "pipeline_builder": "pipeline",
    "dataset": "dataset",
    "data_set": "dataset",
    "datasource": "dataset",
    "table": "dataset",
    "interface": "api",
    "class": "api",
    "module": "api",
    "sdk": "api",
    "app": "application",
    "frontend": "application",
    "workflows": "workflow",
    "concept": "other",
    "component": "other",
    "service": "other",
    # Stage 7 added a Tool class, so the stage-1 alias that folded "tool" into
    # OTHER is gone - keeping it would make the new member unreachable through
    # `coerce()` while JSON input still resolved it, i.e. two paths disagreeing.
    "tools": "tool",
    "dependencies": "dependency",
    "library": "dependency",
    "artifacts": "artifact",
    "tasks": "task",
    "vulnerabilities": "vulnerability",
    "vuln": "vulnerability",
    # Stage 8: finance. Plural/informal spellings only - "api endpoint" and
    # "data asset" already normalise onto their enum values, so a line for them
    # would be dead code. "endpoint" alone is deliberately *not* mapped: on the
    # Palantir corpus it is a generic word, and stage 8 must not steal it.
    "financial_systems": "financial_system",
    "fin_system": "financial_system",
    "system_of_record": "financial_system",
    "api_endpoints": "api_endpoint",
    "endpoints": "api_endpoint",
    "rest_endpoint": "api_endpoint",
    "data_assets": "data_asset",
    "dataasset": "data_asset",
    "compliance_rules": "compliance_rule",
    "compliance": "compliance_rule",
    "regulation": "compliance_rule",
    "regulatory_requirement": "compliance_rule",
    # Stage 9: tooling. "skill" and "technique" are how an operator names a
    # capability; "constraint" and "caveat" are how a reviewer names a
    # limitation. Neither set collides with a Palantir class.
    "capabilities": "capability",
    "skill": "capability",
    "technique": "capability",
    "platforms": "platform",
    "operating_system": "platform",
    "host_os": "platform",
    "limitations": "limitation",
    "constraint": "limitation",
    "restriction": "limitation",
    "caveat": "limitation",
    # Stage 10: business logic. Plurals plus the two informal names a reviewer
    # actually writes; "control" on its own is deliberately *not* mapped - it is
    # a generic word elsewhere, the same reason stage 8 left "endpoint" alone.
    "business_processes": "business_process",
    "business_logic": "business_process",
    "security_controls": "security_control",
    "countermeasure": "security_control",
}


class RelationType(str, Enum):
    """Directed edge labels of the micro-ontology.

    Kept small on purpose: a lexical/LLM extractor that can pick from seven
    relations produces a readable graph, whereas a 40-relation vocabulary
    collapses into `RELATED_TO` noise.

    Twenty-four members, in five groups that never mix: the seven Palantir labels
    (stage 1), the four security labels added in stage 7 for ``re_security/``,
    the four finance labels added in stage 8 for ``fin_security/``, the five
    tooling labels added in stage 9 for ``re_toolbox/`` and the four business-logic
    labels added in stage 10 for ``fin_logic_risk/``. ``HAS_VULNERABILITY`` is
    shared by the two security domains and ``ENABLES`` by security and tooling - a
    capability "opens the door to" a later capability exactly as an artifact does
    to a task. A domain TBox lists the relations it governs, read with its own
    domain/range, and puts the rest into ``OntologySchema.declared_unused_ok``, so
    widening the shared vocabulary does **not** widen any single corpus' TBox.
    """

    HAS_COMPONENT = "HAS_COMPONENT"
    INTEGRATES_WITH = "INTEGRATES_WITH"
    DEFINED_IN = "DEFINED_IN"
    DEPENDS_ON = "DEPENDS_ON"
    PART_OF = "PART_OF"
    PRODUCES = "PRODUCES"
    RELATED_TO = "RELATED_TO"
    # -- stage 7: reverse-engineering security --------------------------------
    # ``DEPENDS_ON`` above is shared by both domains; these four are the ones
    # the security TBox governs (``re_security/tbox.py``).
    PRODUCES_ARTIFACT = "PRODUCES_ARTIFACT"
    USES_ARTIFACT = "USES_ARTIFACT"
    ENABLES = "ENABLES"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    # -- stage 8: financial security ------------------------------------------
    # Appended after the stage-7 block, so `values()` keeps every earlier member
    # at its earlier index (the extractor prompt is built from this list).
    EXPOSES = "EXPOSES"
    PROCESSES = "PROCESSES"
    VIOLATES = "VIOLATES"
    LEADS_TO = "LEADS_TO"
    # -- stage 9: reverse-engineering tooling ---------------------------------
    # Appended at the tail once more. ``ENABLES`` above is shared with this
    # domain; these five are the ones ``re_toolbox/tbox.py`` governs.
    HAS_CAPABILITY = "HAS_CAPABILITY"
    RUNS_ON = "RUNS_ON"
    SUPPORTS_FORMAT = "SUPPORTS_FORMAT"
    SUBSTITUTES = "SUBSTITUTES"
    LIMITED_BY = "LIMITED_BY"
    # -- stage 10: financial business logic -----------------------------------
    # Appended after the stage-9 block, for the same prompt-order reason. These
    # four are what makes the stage-10 graph reason about *absence*: a process
    # requires a control, a route lacks one, and that pair is the finding.
    # ``VIOLATES`` (stage 8) is reused for the clause edge rather than
    # re-declared as ``VIOLATES_COMPLIANCE``: same signature
    # (vulnerability -> compliance_rule), same reading, and a second id for one
    # meaning would split the vocabulary in two - the rule ``fin_security``
    # already wrote down. ``fin_logic_risk/tbox.py`` exports the prose name as
    # an alias so reports can still say ``VIOLATES_COMPLIANCE``.
    IMPLEMENTS = "IMPLEMENTS"
    REQUIRES_CONTROL = "REQUIRES_CONTROL"
    LACKS_CONTROL = "LACKS_CONTROL"
    LEADS_TO_VULNERABILITY = "LEADS_TO_VULNERABILITY"

    @classmethod
    def values(cls) -> list[str]:
        """All legal values, in declaration order."""
        return [member.value for member in cls]

    @classmethod
    def coerce(cls, raw: object) -> "RelationType":
        """Map a loose string ("integrates with", "related") onto a member.

        Unknown input falls back to :attr:`RELATED_TO`, the weakest label, so an
        odd verb degrades the edge's meaning instead of deleting it. Every such
        fallback is reported by `extractor.parse_graph_payload`.
        """
        if isinstance(raw, cls):
            return raw
        text = _clean(str(raw or "")).casefold().replace("-", "_").replace(" ", "_")
        text = _RELATION_ALIASES.get(text, text)
        try:
            return cls(text.upper())
        except ValueError:
            return cls.RELATED_TO


_RELATION_ALIASES: dict[str, str] = {
    "has_part": "HAS_COMPONENT",
    "contains": "HAS_COMPONENT",
    "includes": "HAS_COMPONENT",
    "composed_of": "HAS_COMPONENT",
    "integrates": "INTEGRATES_WITH",
    "connects_to": "INTEGRATES_WITH",
    "works_with": "INTEGRATES_WITH",
    "is_defined_in": "DEFINED_IN",
    "defined_by": "DEFINED_IN",
    "documented_in": "DEFINED_IN",
    "depends": "DEPENDS_ON",
    "requires": "DEPENDS_ON",
    "uses": "DEPENDS_ON",
    "is_part_of": "PART_OF",
    "belongs_to": "PART_OF",
    "outputs": "PRODUCES",
    "creates": "PRODUCES",
    # stage 7: the security vocabulary. The keys are already casefolded with
    # spaces turned into underscores, so "produces an artifact" reaches the
    # first entry without its own line.
    "produces_artifact": "PRODUCES_ARTIFACT",
    "produces_an_artifact": "PRODUCES_ARTIFACT",
    "outputs_artifact": "PRODUCES_ARTIFACT",
    "uses_artifact": "USES_ARTIFACT",
    "consumes_artifact": "USES_ARTIFACT",
    "consumes": "USES_ARTIFACT",
    "enables": "ENABLES",
    "has_vulnerability": "HAS_VULNERABILITY",
    "vulnerable_to": "HAS_VULNERABILITY",
    "affected_by": "HAS_VULNERABILITY",
    "related": "RELATED_TO",
    "relates_to": "RELATED_TO",
    "references": "RELATED_TO",
    # stage 8: the finance vocabulary. Only the verbs `coerce()` cannot reach on
    # its own: "exposes"/"processes"/"violates"/"leads to" already upper-case onto
    # their members, so a line per synonym would be dead weight.
    "expose": "EXPOSES",
    "serves": "EXPOSES",
    "process": "PROCESSES",
    "handles": "PROCESSES",
    "violate": "VIOLATES",
    "breaches": "VIOLATES",
    "violates_rule": "VIOLATES",
    "cascades_to": "LEADS_TO",
    "results_in": "LEADS_TO",
    # stage 9: the tooling vocabulary. `coerce()` already reaches
    # "has capability"/"runs on"/"substitutes"/"limited by" by upper-casing, so
    # only the synonyms an operator actually writes get a line. Note "handles"
    # is *not* reused here: stage 8 owns it (PROCESSES), and a later stage must
    # not silently re-point an earlier stage's word.
    "provides": "HAS_CAPABILITY",
    "offers": "HAS_CAPABILITY",
    "supports": "HAS_CAPABILITY",
    "is_capable_of": "HAS_CAPABILITY",
    "runs_under": "RUNS_ON",
    "available_on": "RUNS_ON",
    "hosted_on": "RUNS_ON",
    "parses": "SUPPORTS_FORMAT",
    "reads_format": "SUPPORTS_FORMAT",
    "accepts": "SUPPORTS_FORMAT",
    "understands": "SUPPORTS_FORMAT",
    "substitutes_for": "SUBSTITUTES",
    "replaces": "SUBSTITUTES",
    "alternative_to": "SUBSTITUTES",
    "equivalent_to": "SUBSTITUTES",
    "limited_to": "LIMITED_BY",
    "blocked_by": "LIMITED_BY",
    "cannot": "LIMITED_BY",
    "restricted_by": "LIMITED_BY",
}


class IntegrityReport(BaseModel):
    """Result of :meth:`KnowledgeGraph.check_integrity`.

    ``ok`` is false when an edge points at a concept that was never declared —
    the most common defect in raw LLM output, and the one that silently
    corrupts `to_networkx()` if it is not reported.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    dangling_edges: list[str] = Field(
        default_factory=list,
        description="'source -[TYPE]-> target' strings whose endpoint is undeclared",
    )
    isolated_concepts: list[str] = Field(
        default_factory=list, description="concepts with no incoming or outgoing edge"
    )
    self_loops: list[str] = Field(
        default_factory=list, description="edges whose source and target are the same concept"
    )

    @property
    def ok(self) -> bool:
        """True when nothing inside the graph needs repair."""
        return not self.dangling_edges


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
class OntologyConcept(BaseModel):
    """A Palantir concept extracted from one or more document chunks.

    Instances are the nodes of the knowledge graph and are identified by
    :attr:`identity` (a casefolded name), which is what :meth:`KnowledgeGraph.merge`
    uses to fold the same concept seen in ten chunks into one node.
    """

    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    name: str = Field(
        min_length=1,
        max_length=MAX_NAME_CHARS,
        description="Canonical concept name as written in the docs, e.g. 'Object Type'.",
    )
    definition: str = Field(
        min_length=1,
        max_length=MAX_DEFINITION_CHARS,
        description="One or two sentences, taken from the chunk, that define the concept.",
    )
    category: ConceptCategory = Field(
        description="Category of the concept; unknown categories are coerced to 'other'."
    )
    aliases: list[str] = Field(
        default_factory=list,
        max_length=MAX_ALIASES,
        description="Other spellings seen in the text (e.g. 'object types', 'ObjectType').",
    )

    @field_validator("name", "definition", mode="before")
    @classmethod
    def _normalise_text(cls, value: Any) -> Any:
        """Strip zero-width/whitespace padding before the length constraints run."""
        return _clean(value) if isinstance(value, str) else value

    @field_validator("name", mode="after")
    @classmethod
    def _strip_sentence_noise(cls, value: str) -> str:
        """Drop a trailing full stop; a concept name is a label, not a sentence."""
        return value.rstrip(" .,;:")

    @field_validator("aliases", mode="after")
    @classmethod
    def _tidy_aliases(cls, value: list[str]) -> list[str]:
        """De-duplicate case-insensitively, keep order, drop blanks."""
        out: list[str] = []
        seen: set[str] = set()
        for alias in value:
            alias = _clean(alias).rstrip(" .,;:")
            key = alias.casefold()
            if alias and key not in seen:
                seen.add(key)
                out.append(alias)
        return out[:MAX_ALIASES]

    @property
    def identity(self) -> str:
        """Case- and whitespace-insensitive key used for merging and lookups."""
        return self.name.casefold()


# ---------------------------------------------------------------------------
# Chunks (input side, not part of the graph)
# ---------------------------------------------------------------------------
class DocumentChunk(BaseModel):
    """One corpus chunk, as handed to an extractor.

    Mirrors what the retrieval stage already persisted (`chunk_id`, `doc_id`,
    `text`), so no re-chunking happens here.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    chunk_id: str = Field(min_length=1, description="Stable id, e.g. '/docs/foundry/ontology#000'.")
    source_doc: str = Field(min_length=1, description="Document path the chunk came from.")
    text_snippet: str = Field(min_length=1, description="The chunk text handed to the extractor.")
    heading_path: list[str] = Field(
        default_factory=list,
        description="Section headings above the chunk, outermost first.",
    )

    @field_validator("chunk_id", "source_doc", mode="before")
    @classmethod
    def _strip_identifiers(cls, value: Any) -> Any:
        """Identifiers are copied verbatim except for surrounding whitespace."""
        return value.strip() if isinstance(value, str) else value

    @field_validator("text_snippet", mode="before")
    @classmethod
    def _normalise_body(cls, value: Any) -> Any:
        """Collapse whitespace so prompts and sentence splitting stay stable."""
        return _clean(value) if isinstance(value, str) else value

    @property
    def section(self) -> str:
        """Heading path as a single 'A > B > C' string ('' when unknown)."""
        return " > ".join(self.heading_path)


# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------
class Relationship(BaseModel):
    """A directed, typed, weighted edge between two :class:`OntologyConcept` names.

    Endpoints are stored as *names* (not object references) so the schema stays
    flat, JSON-friendly and directly usable as an LLM response model.
    """

    model_config = ConfigDict(strict=True, extra="forbid", validate_assignment=True)

    source_concept: str = Field(
        min_length=1, max_length=MAX_NAME_CHARS, description="Name of the concept the edge leaves."
    )
    target_concept: str = Field(
        min_length=1, max_length=MAX_NAME_CHARS, description="Name of the concept the edge reaches."
    )
    relation_type: RelationType = Field(
        description="A RelationType value: the Palantir seven (HAS_COMPONENT, INTEGRATES_WITH, "
        "DEFINED_IN, DEPENDS_ON, PART_OF, PRODUCES, RELATED_TO) or the stage-7 security four "
        "(PRODUCES_ARTIFACT, USES_ARTIFACT, ENABLES, HAS_VULNERABILITY)."
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="How well the chunk's text supports this edge: >=0.85 means an explicit "
        "sentence states it, 0.5-0.84 means a list/structure implies it, <0.4 means a guess.",
    )
    evidence: str = Field(
        default="",
        max_length=MAX_EVIDENCE_CHARS,
        description="Verbatim sentence from the chunk that justifies the edge ('' if unknown).",
    )

    @field_validator("source_concept", "target_concept", mode="before")
    @classmethod
    def _normalise_endpoints(cls, value: Any) -> Any:
        """Trim endpoints so 'Action ' and 'Action' collapse onto the same node."""
        return _clean(value) if isinstance(value, str) else value

    @field_validator("evidence", mode="before")
    @classmethod
    def _normalise_evidence(cls, value: Any) -> Any:
        """Collapse whitespace and tolerate None coming from a lenient JSON payload."""
        if value is None:
            return ""
        return _clean(value) if isinstance(value, str) else ""

    @field_validator("confidence_score", mode="after")
    @classmethod
    def _round_confidence(cls, value: float) -> float:
        """Round to 3 decimals so merged/printed scores compare cleanly."""
        return round(value, 3)

    @property
    def identity(self) -> tuple[str, str, str]:
        """Key used by :meth:`KnowledgeGraph.merge` to de-duplicate parallel edges."""
        return (
            self.source_concept.casefold(),
            self.relation_type.value,
            self.target_concept.casefold(),
        )

    @property
    def is_self_loop(self) -> bool:
        """True when both endpoints are the same concept (kept, but reported)."""
        return self.source_concept.casefold() == self.target_concept.casefold()

    def describe(self) -> str:
        """Human-readable one-liner used in integrity reports and logs."""
        return "%s -[%s]-> %s" % (
            self.source_concept,
            self.relation_type.value,
            self.target_concept,
        )


# ---------------------------------------------------------------------------
# Graph container
# ---------------------------------------------------------------------------
class KnowledgeGraph(BaseModel):
    """The whole extracted ontology: a bag of concepts plus a bag of edges.

    This is both the LLM response model (stage 2) and the on-disk artefact
    (`outputs/ontology_graph.json`). Keeping one class for both means the prompt
    schema and the file format can never drift apart.

    Invariants enforced here
    ------------------------
    * concept names are unique (case-insensitively) — merging is an explicit
      operation (:meth:`merge`), not something validation does silently;
    * every field is strict, so a typo in a JSON key raises instead of being
      ignored.

    Dangling edges are *not* rejected (an LLM can produce them), but they are
    reported by :meth:`check_integrity` and removable via :meth:`prune_dangling`.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    nodes: list[OntologyConcept] = Field(
        default_factory=list, description="All concepts; each name appears once."
    )
    edges: list[Relationship] = Field(
        default_factory=list, description="All typed relationships between concepts."
    )
    chunk_ids: list[str] = Field(
        default_factory=list,
        description="Provenance: chunk ids whose text contributed to this graph.",
    )

    @model_validator(mode="after")
    def _unique_concept_names(self) -> "KnowledgeGraph":
        """Reject duplicate concept names instead of silently keeping both."""
        seen: dict[str, str] = {}
        duplicates: list[str] = []
        for concept in self.nodes:
            key = concept.identity
            if key in seen:
                if seen[key] not in duplicates:
                    duplicates.append(seen[key])
            else:
                seen[key] = concept.name
        if duplicates:
            raise ValueError(
                "duplicate concept names (merge them explicitly): %s" % ", ".join(duplicates)
            )
        return self

    # -- lookups ----------------------------------------------------------
    def concept_names(self) -> list[str]:
        """Concept names in declaration order."""
        return [concept.name for concept in self.nodes]

    def concept_index(self) -> dict[str, OntologyConcept]:
        """Map ``casefolded name -> concept`` for O(1) membership tests."""
        return {concept.identity: concept for concept in self.nodes}

    def mean_confidence(self) -> float:
        """Mean edge confidence, ``0.0`` for an edgeless graph (never NaN)."""
        if not self.edges:
            return 0.0
        return round(sum(edge.confidence_score for edge in self.edges) / len(self.edges), 4)

    def category_counts(self) -> dict[str, int]:
        """``category value -> number of concepts``, sorted by descending count."""
        counts: dict[str, int] = {}
        for concept in self.nodes:
            counts[concept.category.value] = counts.get(concept.category.value, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    # -- repair -----------------------------------------------------------
    def check_integrity(self) -> IntegrityReport:
        """Report dangling endpoints, isolated concepts and self-loops."""
        known = {concept.identity for concept in self.nodes}
        dangling = [
            edge.describe()
            for edge in self.edges
            if edge.source_concept.casefold() not in known
            or edge.target_concept.casefold() not in known
        ]
        touched: set[str] = set()
        for edge in self.edges:
            touched.add(edge.source_concept.casefold())
            touched.add(edge.target_concept.casefold())
        isolated = [c.name for c in self.nodes if c.identity not in touched]
        loops = [edge.describe() for edge in self.edges if edge.is_self_loop]
        return IntegrityReport(
            dangling_edges=dangling, isolated_concepts=isolated, self_loops=loops
        )

    def prune_dangling(self) -> "KnowledgeGraph":
        """Return a copy with every edge whose endpoint is undeclared removed."""
        known = {concept.identity for concept in self.nodes}
        kept = [
            edge
            for edge in self.edges
            if edge.source_concept.casefold() in known and edge.target_concept.casefold() in known
        ]
        return KnowledgeGraph(nodes=list(self.nodes), edges=kept, chunk_ids=list(self.chunk_ids))

    # -- merge ------------------------------------------------------------
    def merge(self, other: "KnowledgeGraph") -> "KnowledgeGraph":
        """Fold another graph into this one, returning a new instance.

        Rules (all deterministic, so a re-run reproduces the same file):

        * concepts are matched on casefolded name; the *longest* definition
          wins (a later chunk that spells the concept out beats an early one
          that only names it), aliases are unioned, the first category is kept;
        * edges are matched on ``(source, relation_type, target)``; the higher
          confidence wins and evidence is unioned, so re-reading a chunk can
          only strengthen an edge, never weaken it.
        """
        merged_concepts: dict[str, OntologyConcept] = {}
        for concept in [*self.nodes, *other.nodes]:
            previous = merged_concepts.get(concept.identity)
            if previous is None:
                merged_concepts[concept.identity] = concept
                continue
            definition = (
                previous.definition
                if len(previous.definition) >= len(concept.definition)
                else concept.definition
            )
            aliases = list(dict.fromkeys([*previous.aliases, *concept.aliases]))
            merged_concepts[concept.identity] = OntologyConcept(
                name=previous.name,
                definition=definition,
                category=previous.category,
                aliases=aliases,
            )

        merged_edges: dict[tuple[str, str, str], Relationship] = {}
        for edge in [*self.edges, *other.edges]:
            previous = merged_edges.get(edge.identity)
            if previous is None:
                merged_edges[edge.identity] = edge
                continue
            best = previous if previous.confidence_score >= edge.confidence_score else edge
            evidence = " ".join(dict.fromkeys(filter(None, [previous.evidence, edge.evidence])))[
                :MAX_EVIDENCE_CHARS
            ]
            merged_edges[edge.identity] = Relationship(
                source_concept=best.source_concept,
                target_concept=best.target_concept,
                relation_type=best.relation_type,
                confidence_score=best.confidence_score,
                evidence=evidence,
            )

        chunk_ids = list(dict.fromkeys([*self.chunk_ids, *other.chunk_ids]))
        return KnowledgeGraph(
            nodes=list(merged_concepts.values()),
            edges=list(merged_edges.values()),
            chunk_ids=chunk_ids,
        )

    @classmethod
    def merge_all(cls, graphs: Iterable["KnowledgeGraph"]) -> "KnowledgeGraph":
        """Left-fold :meth:`merge` over an iterable; empty input -> empty graph."""
        total = cls()
        for graph in graphs:
            total = total.merge(graph)
        return total

    # -- networkx ---------------------------------------------------------
    def to_networkx(
        self, *, attach_dangling: bool = True, collapse_parallel: bool = True
    ) -> nx.DiGraph:
        """Convert to a directed NetworkX graph (nodes = concepts, edges = relations).

        Args:
            attach_dangling: when an edge names a concept missing from
                :attr:`nodes`, add that name as a placeholder node (``category
                = 'other'``, ``placeholder = True``) instead of dropping the
                edge. With ``False`` a :class:`ValueError` is raised listing the
                offending edges — the strict option for pipelines that must
                never invent nodes.
            collapse_parallel: keep one edge per ``(source, target)`` pair
                (highest confidence wins) and record every relation type in the
                edge attribute ``relation_types``. With ``False`` a
                :class:`networkx.MultiDiGraph` is returned, so each relation
                keeps its own edge.

        Returns:
            ``nx.DiGraph`` (default) or ``nx.MultiDiGraph``. Isolated concepts
            are always present: nodes are added before any edge is examined.
        """
        graph: nx.Graph = nx.DiGraph() if collapse_parallel else nx.MultiDiGraph()
        canonical: dict[str, str] = {}
        for concept in self.nodes:
            graph.add_node(
                concept.name,
                name=concept.name,
                definition=concept.definition,
                category=concept.category.value,
                aliases=list(concept.aliases),
                placeholder=False,
            )
            canonical[concept.identity] = concept.name

        missing: list[str] = []
        for edge in self.edges:
            source = canonical.get(edge.source_concept.casefold())
            target = canonical.get(edge.target_concept.casefold())
            if source is None or target is None:
                if not attach_dangling:
                    missing.append(edge.describe())
                    continue
                for endpoint in (edge.source_concept, edge.target_concept):
                    if endpoint.casefold() not in canonical:
                        canonical[endpoint.casefold()] = endpoint
                        graph.add_node(
                            endpoint,
                            name=endpoint,
                            definition="",
                            category=ConceptCategory.OTHER.value,
                            aliases=[],
                            placeholder=True,
                        )
                source = canonical[edge.source_concept.casefold()]
                target = canonical[edge.target_concept.casefold()]

            attributes = {
                "relation_type": edge.relation_type.value,
                "relation_types": [edge.relation_type.value],
                "confidence_score": edge.confidence_score,
                "evidence": edge.evidence,
            }
            if not collapse_parallel:
                graph.add_edge(source, target, **attributes)
                continue
            if graph.has_edge(source, target):
                data = graph[source][target]
                data["relation_types"] = list(
                    dict.fromkeys([*data["relation_types"], edge.relation_type.value])
                )
                if edge.confidence_score > data["confidence_score"]:
                    data["relation_type"] = edge.relation_type.value
                    data["confidence_score"] = edge.confidence_score
                    data["evidence"] = edge.evidence
                continue
            graph.add_edge(source, target, **attributes)

        if missing:
            raise ValueError(
                "edges reference concepts missing from `nodes` (attach_dangling=False): %s"
                % "; ".join(missing)
            )
        graph.graph.update(
            {
                "schema_version": GRAPH_SCHEMA_VERSION,
                "n_concepts": len(self.nodes),
                "n_relationships": len(self.edges),
            }
        )
        return graph

    # -- serialisation ----------------------------------------------------
    def to_json_dict(self) -> dict[str, Any]:
        """Plain-JSON view (enums become their values, ready for ``json.dump``)."""
        return self.model_dump(mode="json")

    def save_json(self, path: "str | Path") -> Path:
        """Write the graph as UTF-8 JSON (indent=2, non-ASCII preserved)."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_json_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return target

    @classmethod
    def load_json(cls, path: "str | Path") -> "KnowledgeGraph":
        """Read a graph written by :meth:`save_json`.

        Parsing goes through ``model_validate_json`` on purpose: JSON mode is the
        only place where a string such as ``"object_type"`` is matched against
        :class:`ConceptCategory` under ``strict=True`` (see the module docstring).
        A ``{"graph": {...}}`` wrapper is unwrapped for convenience, and a UTF-8 BOM
        is tolerated (``utf-8-sig``): a hand-edited graph file is a normal thing.
        """
        text = Path(path).read_text(encoding="utf-8-sig")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("%s is not valid JSON: %s" % (path, exc)) from exc
        if (
            isinstance(payload, dict)
            and "nodes" not in payload
            and isinstance(payload.get("graph"), dict)
        ):
            payload = payload["graph"]
        return cls.model_validate_json(json.dumps(payload, ensure_ascii=False))

    # -- reporting --------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        """Counts used in logs and in the pipeline's stats file."""
        integrity = self.check_integrity()
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "concepts": len(self.nodes),
            "relationships": len(self.edges),
            "chunks": len(self.chunk_ids),
            "mean_confidence": self.mean_confidence(),
            "categories": self.category_counts(),
            "dangling_edges": len(integrity.dangling_edges),
            "isolated_concepts": len(integrity.isolated_concepts),
            "self_loops": len(integrity.self_loops),
        }


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s | %(message)s")
    log = logging.getLogger("ontology_builder.schema")

    demo = KnowledgeGraph(
        nodes=[
            OntologyConcept(
                name="Object Type",
                definition="An object type defines the structure of an object in the Ontology.",
                category=ConceptCategory.OBJECT_TYPE,
                aliases=["object types", "ObjectType"],
            ),
            OntologyConcept(
                name="Action Type",
                definition="An action type describes a write-back operation on an object.",
                category=ConceptCategory.ACTION,
            ),
            OntologyConcept(
                name="Pipeline",
                definition="A pipeline transforms datasets into new datasets.",
                category=ConceptCategory.PIPELINE,
            ),
        ],
        edges=[
            Relationship(
                source_concept="Object Type",
                target_concept="Action Type",
                relation_type=RelationType.HAS_COMPONENT,
                confidence_score=0.9,
                evidence="Each object type can define action types that modify it.",
            ),
            Relationship(
                source_concept="Action Type",
                target_concept="Pipeline",
                relation_type=RelationType.DEFINED_IN,
                confidence_score=0.55,
            ),
        ],
        chunk_ids=["demo#000"],
    )
    for key, value in demo.summary().items():
        log.info("%-18s %s", key, value)
    nx_graph = demo.to_networkx()
    log.info("networkx: %d nodes, %d edges", nx_graph.number_of_nodes(), nx_graph.number_of_edges())
    log.info(
        "json mode round-trip: %s",
        KnowledgeGraph.model_validate_json(json.dumps(demo.to_json_dict())).summary()["concepts"],
    )
