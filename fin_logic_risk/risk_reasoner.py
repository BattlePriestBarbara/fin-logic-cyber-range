# -*- coding: utf-8 -*-
"""Derive the business-logic risks of one route from what it *lacks* (task 10).

The question
------------
``Transfer_API`` implements ``Fund_Transfer_Process``, and that process requires
``Idempotency_Token``. A review found the route does not enforce it. Which flaws
does that permit, which clauses do those flaws break, and what is the fix?

The answer is a **set difference**, not a walk
----------------------------------------------
================================  ==============================================
step                                what it computes
================================  ==============================================
``api -IMPLEMENTS-> process``       the process whose definition of "correct"
                                    applies to this route
``process -REQUIRES_CONTROL-> c``   the *requirement set*
``api -LACKS_CONTROL-> c``          the *finding set*
``requirement - finding``           controls that are required and present:
                                    reported as satisfied, never as risk
``requirement & finding``           **the only cell that produces a finding**
``c -LEADS_TO_VULNERABILITY-> v``   what the absence of ``c`` permits
``v -VIOLATES_COMPLIANCE-> rule``   the clause the flaw breaks
================================  ==============================================

Why the intersection matters: a control the route lacks but no process requires is
a hygiene note (somebody built a control nobody asked for), and reporting it as a
risk would drown the real finding in noise. Conversely a control the process
requires and the route *has* is precisely the thing a checklist reviewer cannot
see, because nothing in the request/response evidence proves a control exists -
only the ontology's requirement edge does.

Risk is a function of the *shape* of the damage, not of a score
--------------------------------------------------------------
================  ==========================================================
``NONE``          no required control is missing: nothing to say
``LOW``           a required control is missing, but no flaw is modelled
                  downstream (a requirement with no known consequence)
``MEDIUM``        at least one flaw is derived, no clause broken
``HIGH``          exactly one clause broken
``CRITICAL``      two or more clauses broken
================  ==========================================================

A *clause* is the unit that costs money (a fine, a disclosure obligation, a
licence condition), so the ladder counts broken clauses first and derived flaws
second - the same "threshold on the expensive unit" rule stages 7 and 8 apply. The
function is total: every report gets exactly one level, and the level never
disagrees with the finding list because it is *derived* from it (``risk`` is a
property, not a stored field).

Why a scanner cannot produce this report
----------------------------------------
A DAST scanner sees one request and one response. Every fact this module needs is
*absent* from that pair: that a process exists, that it requires a token, and that
the receipt the server returned was produced twice for one intent. Absence has no
bytes to match. Section 1 of ``README.md`` argues this at length; the practical
consequence is that the input here is a *reviewed* graph (a human or an agent
established ``LACKS_CONTROL``), never a scan artefact.

Purity and determinism
----------------------
The graph is never mutated: adjacency is built into local dictionaries, exactly as
``ontology/constraints.py`` does it. Neighbours are deduplicated and sorted by
``(casefolded name, name)``, so two runs on the same graph produce the same gaps,
the same findings and the same sentences.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from fin_logic_risk.tbox import (
    FIN_LOGIC_TBOX,
    VIOLATES_COMPLIANCE,
    remediation_for,
    summary_lines,
)
from ontology_builder.core.errors import DataContractError
from ontology_builder.ontology import OntologyValidator, ValidationPolicy
from ontology_builder.schema import ConceptCategory, KnowledgeGraph, RelationType

#: Where the hand-authored benchmark lives, and the route it starts from.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_GRAPH = _PROJECT_ROOT / "data" / "fin_logic_micro_graph.json"
DEFAULT_API = "Transfer_API"

#: The requirement side: the route serves a process, the process needs a control.
IMPLEMENTS_FORWARD: tuple[RelationType, ...] = (RelationType.IMPLEMENTS,)
REQUIRES_FORWARD: tuple[RelationType, ...] = (RelationType.REQUIRES_CONTROL,)

#: The finding side: what a review established the route does not enforce.
GAP_FORWARD: tuple[RelationType, ...] = (RelationType.LACKS_CONTROL,)

#: The consequence of the absence, and the clause the consequence breaks.
CONSEQUENCE_FORWARD: tuple[RelationType, ...] = (RelationType.LEADS_TO_VULNERABILITY,)
COMPLIANCE_FORWARD: tuple[RelationType, ...] = (VIOLATES_COMPLIANCE,)


class RiskLevel(str, Enum):
    """How bad the missing control is, on the five-step ladder of the docstring.

    Ordered, not merely enumerated: ``rank`` is what a report sorts on, and
    sorting the *strings* would put ``"critical"`` before ``"high"``.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """0 for ``NONE`` .. 4 for ``CRITICAL``, so levels compare numerically."""
        return _RISK_RANK[self]

    @classmethod
    def values(cls) -> list[str]:
        """All levels, weakest first (used by the CLI's help text)."""
        return [member.value for member in cls]


_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def classify_logic_risk(
    gaps: Iterable["ControlGap"], findings: Iterable["LogicFinding"]
) -> RiskLevel:
    """Map the gaps and the derived findings onto a :class:`RiskLevel`.

    Kept as a free function rather than a method so a caller (or a test) can ask
    "what would this pair of lists mean?" without building a whole report.
    """
    required = [gap for gap in gaps if gap.is_required]
    if not required:
        return RiskLevel.NONE
    derived = list(findings)
    if not derived:
        return RiskLevel.LOW
    clauses = {clause for finding in derived for clause in finding.clauses}
    if len(clauses) >= 2:
        return RiskLevel.CRITICAL
    if len(clauses) == 1:
        return RiskLevel.HIGH
    return RiskLevel.MEDIUM


def _names_or_raise(label: str, values: Iterable[str]) -> tuple[str, ...]:
    """Coerce ``values`` to a tuple of non-blank names, rejecting duplicates.

    Case-insensitive de-duplication as a *rejection* rather than a silent fold: a
    report that lists the same control twice is a report a reader stops trusting,
    and folding it would hide the bug that produced it.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        name = raw.strip() if isinstance(raw, str) else ""
        if not name:
            raise DataContractError(
                "%s entries must be non-empty names" % label, got=repr(raw)
            )
        key = name.casefold()
        if key in seen:
            raise DataContractError("%s repeats %r" % (label, name), label=label, name=name)
        seen.add(key)
        out.append(name)
    return tuple(out)


@dataclass(frozen=True)
class ControlGap:
    """One control the target route does not enforce, and who required it.

    Attributes:
        control: control name as spelled in the graph.
        required_by: the business processes that require this control. Empty means
            the route lacks a control *nothing* requires - a hygiene note, not a
            finding (see :attr:`is_required`).
        derived: every flaw the graph says the absence of this control permits.
            Populated whether or not the gap is required, because dropping the
            evidence would make an unclaimed row look harmless.
        remediation: the fix, from :func:`fin_logic_risk.tbox.remediation_for`.

    Raises:
        DataContractError: on a blank control, a blank remediation, or duplicate
            entries in ``required_by`` / ``derived``.
    """

    control: str
    required_by: tuple[str, ...] = ()
    derived: tuple[str, ...] = ()
    remediation: str = ""

    def __post_init__(self) -> None:
        control = self.control.strip() if isinstance(self.control, str) else ""
        if not control:
            raise DataContractError("ControlGap.control must be a non-empty name")
        remediation = self.remediation.strip() if isinstance(self.remediation, str) else ""
        if not remediation:
            raise DataContractError(
                "ControlGap.remediation must be a non-empty fix", control=control
            )
        object.__setattr__(self, "control", control)
        object.__setattr__(self, "remediation", remediation)
        object.__setattr__(
            self, "required_by", _names_or_raise("ControlGap.required_by", self.required_by)
        )
        object.__setattr__(
            self, "derived", _names_or_raise("ControlGap.derived", self.derived)
        )

    @property
    def is_required(self) -> bool:
        """True when at least one process requires this control."""
        return bool(self.required_by)

    def to_dict(self) -> dict[str, Any]:
        """JSON form for ``--json`` output and for the tests to assert on."""
        return {
            "control": self.control,
            "required": self.is_required,
            "required_by": list(self.required_by),
            "derived": list(self.derived),
            "remediation": self.remediation,
        }

    def line(self) -> str:
        """One console row: the control, who requires it, what it permits, the fix."""
        return "  %-24s %-10s %-50s %s" % (
            self.control,
            "required" if self.is_required else "unclaimed",
            ", ".join(self.derived) or "none",
            self.remediation,
        )


@dataclass(frozen=True)
class LogicFinding:
    """One (missing control, permitted flaw) pair, with the clauses it breaks.

    This is the unit the acceptance criterion is written in: one sentence per
    finding, naming the route, the control it lacks, the flaw that follows, the
    clause that breaks and the fix.

    Attributes:
        target_api: the route the finding is about (canonical spelling).
        control: the control the route does not enforce.
        vulnerability: the flaw the absence permits.
        required_by: the processes that required ``control``; never empty, because
            a finding only exists where a requirement was unmet.
        clauses: the compliance terms ``vulnerability`` breaks. May be empty - the
            graph may know the flaw and not yet know the clause, and that case is
            reported as ``MEDIUM`` rather than silently promoted.
        remediation: the fix, copied from the gap so the sentence stands alone.

    Raises:
        DataContractError: on a blank name or fix, an empty ``required_by``, or
            duplicate clauses.
    """

    target_api: str
    control: str
    vulnerability: str
    required_by: tuple[str, ...]
    clauses: tuple[str, ...] = ()
    remediation: str = ""

    def __post_init__(self) -> None:
        for field_name in ("target_api", "control", "vulnerability", "remediation"):
            raw = getattr(self, field_name)
            value = raw.strip() if isinstance(raw, str) else ""
            if not value:
                raise DataContractError(
                    "LogicFinding.%s must be a non-empty name" % field_name
                )
            object.__setattr__(self, field_name, value)
        object.__setattr__(
            self,
            "required_by",
            _names_or_raise("LogicFinding.required_by", self.required_by),
        )
        if not self.required_by:
            raise DataContractError(
                "a finding needs at least one requiring process", control=self.control
            )
        object.__setattr__(
            self, "clauses", _names_or_raise("LogicFinding.clauses", self.clauses)
        )

    def sentence(self) -> str:
        """The one-line verdict, in the shape the acceptance criterion asks for.

        Written as one sentence rather than a key/value row because it is the
        sentence that goes into a ticket: a reader who quotes only this line must
        still know which route, which control, which flaw, which clause, and what
        to do next.
        """
        clauses = "、".join(self.clauses) if self.clauses else "未映射的合规条款"
        return "检测到 %s 缺失 %s，推导出存在 %s 风险，违反 %s，建议%s。" % (
            self.target_api,
            self.control,
            self.vulnerability,
            clauses,
            self.remediation,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON form, including the rendered sentence so a consumer has both."""
        return {
            "target_api": self.target_api,
            "control": self.control,
            "vulnerability": self.vulnerability,
            "required_by": list(self.required_by),
            "clauses": list(self.clauses),
            "remediation": self.remediation,
            "sentence": self.sentence(),
        }


@dataclass(frozen=True)
class RiskAssessmentReport:
    """What a missing control does to one route.

    Attributes:
        target_api: the route the assessment started from (canonical spelling).
        processes: the business processes the route implements, sorted.
        gaps: every control the route lacks, each carrying who required it, what
            it permits and the fix.
        findings: one entry per ``(missing required control, permitted flaw)``,
            ordered by control then flaw.
        satisfied: controls a process requires and the route does *not* lack. Kept
            because an assessment that lists only failures cannot be audited - the
            reader cannot tell a control that was checked and found present from
            one nobody looked at.
        total_nodes: concepts in the graph, so ``len(gaps) / total_nodes`` reads as
            a rate instead of a raw count.

    Raises:
        DataContractError: on a blank ``target_api``, duplicate process/control
            names, a finding whose route is not this route, a finding for a gap no
            process required, a control listed as both missing and satisfied, or a
            negative ``total_nodes``. A report that contradicts itself is worse
            than no report.
    """

    target_api: str
    processes: tuple[str, ...] = ()
    gaps: tuple[ControlGap, ...] = ()
    findings: tuple[LogicFinding, ...] = ()
    satisfied: tuple[str, ...] = ()
    total_nodes: int = 0

    def __post_init__(self) -> None:
        target_api = self.target_api.strip() if isinstance(self.target_api, str) else ""
        if not target_api:
            raise DataContractError("RiskAssessmentReport.target_api must be a non-empty name")
        object.__setattr__(self, "target_api", target_api)
        object.__setattr__(self, "processes", _names_or_raise("processes", self.processes))
        object.__setattr__(self, "satisfied", _names_or_raise("satisfied", self.satisfied))

        gaps = tuple(self.gaps)
        for gap in gaps:
            if not isinstance(gap, ControlGap):
                raise DataContractError(
                    "gaps must be ControlGap instances", got=type(gap).__name__
                )
        controls = _names_or_raise("gaps", tuple(gap.control for gap in gaps))
        known = {name.casefold() for name in controls}
        required = {gap.control.casefold() for gap in gaps if gap.is_required}
        object.__setattr__(self, "gaps", gaps)

        findings = tuple(self.findings)
        for finding in findings:
            if not isinstance(finding, LogicFinding):
                raise DataContractError(
                    "findings must be LogicFinding instances", got=type(finding).__name__
                )
            if finding.target_api.casefold() != target_api.casefold():
                raise DataContractError(
                    "a finding about another route cannot ride in this report",
                    expected=target_api,
                    got=finding.target_api,
                )
            if finding.control.casefold() not in known:
                raise DataContractError(
                    "a finding needs the gap it derives from", control=finding.control
                )
            if finding.control.casefold() not in required:
                raise DataContractError(
                    "a finding needs a gap some process required", control=finding.control
                )
        pairs = [
            (finding.control.casefold(), finding.vulnerability.casefold())
            for finding in findings
        ]
        if len(set(pairs)) != len(pairs):
            raise DataContractError("findings repeat a (control, vulnerability) pair")
        object.__setattr__(self, "findings", findings)

        overlap = {name.casefold() for name in self.satisfied} & known
        if overlap:
            raise DataContractError(
                "a control cannot be both missing and satisfied", controls=sorted(overlap)
            )
        if self.total_nodes < 0:
            raise DataContractError("total_nodes cannot be negative", value=self.total_nodes)

    # -- projections ------------------------------------------------------
    @property
    def required_gaps(self) -> tuple[ControlGap, ...]:
        """Gaps a process actually required: the ones that produce findings."""
        return tuple(gap for gap in self.gaps if gap.is_required)

    @property
    def unclaimed_gaps(self) -> tuple[ControlGap, ...]:
        """Gaps nothing required: reported, never turned into a finding."""
        return tuple(gap for gap in self.gaps if not gap.is_required)

    @property
    def missing_controls(self) -> tuple[str, ...]:
        """Names of the required-but-absent controls."""
        return tuple(gap.control for gap in self.required_gaps)

    @property
    def vulnerabilities(self) -> tuple[str, ...]:
        """Distinct flaws derived from the missing controls, sorted."""
        return tuple(
            sorted({item.vulnerability for item in self.findings}, key=str.casefold)
        )

    @property
    def clauses(self) -> tuple[str, ...]:
        """Distinct compliance terms broken, sorted."""
        return tuple(
            sorted(
                {clause for item in self.findings for clause in item.clauses},
                key=str.casefold,
            )
        )

    @property
    def next_steps(self) -> tuple[str, ...]:
        """Distinct fixes, in gap order - what the reader is asked to do."""
        out: list[str] = []
        for gap in self.required_gaps:
            if gap.remediation not in out:
                out.append(gap.remediation)
        return tuple(out)

    @property
    def risk(self) -> RiskLevel:
        """The ladder level, derived from the findings (never stored)."""
        return classify_logic_risk(self.gaps, self.findings)

    # -- rendering --------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """JSON form for ``--json`` output and for the tests to assert on."""
        return {
            "target_api": self.target_api,
            "risk": self.risk.value,
            "processes": list(self.processes),
            "missing_controls": list(self.missing_controls),
            "satisfied": list(self.satisfied),
            "vulnerabilities": list(self.vulnerabilities),
            "clauses": list(self.clauses),
            "next_steps": list(self.next_steps),
            "total_nodes": self.total_nodes,
            "gaps": [gap.to_dict() for gap in self.gaps],
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def gap_lines(self) -> list[str]:
        """The gap table: one row per control the route does not enforce."""
        out = ["  %-24s %-10s %-50s %s" % ("control", "kind", "permits", "fix")]
        if not self.gaps:
            out.append("    no control is missing")
            return out
        for gap in self.gaps:
            out.append(gap.line())
        return out

    def finding_lines(self) -> list[str]:
        """One sentence per finding - the part a ticket quotes."""
        if not self.findings:
            return ["  no flaw is derived from this route's gaps"]
        return ["  - %s" % finding.sentence() for finding in self.findings]

    def lines(self) -> list[str]:
        """Console summary: verdict first, then the numbers that support it."""
        return [
            "  api       : %s" % self.target_api,
            "  process   : %s" % (", ".join(self.processes) or "none"),
            "  risk      : %s" % self.risk.value.upper(),
            "  gaps      : %d required, %d unclaimed (over %d node(s))"
            % (len(self.required_gaps), len(self.unclaimed_gaps), self.total_nodes),
            "  flaw      : %s" % (", ".join(self.vulnerabilities) or "none"),
            "  clauses   : %s" % (", ".join(self.clauses) or "none"),
            "  satisfied : %s" % (", ".join(self.satisfied) or "none"),
            "  next step : %s" % ("; ".join(self.next_steps) or "none"),
        ]


def _adjacency(
    graph: KnowledgeGraph, *, forward: Iterable[RelationType]
) -> dict[str, tuple[str, ...]]:
    """``casefolded source -> sorted unique canonical neighbours``.

    ``graph`` is only read. Self-loops are skipped: a node that carries an edge to
    itself says nothing about which control a process requires, and letting it into
    the index would make a route its own neighbour. Parallel edges (same source,
    same target, different confidence) collapse into one neighbour, because the
    question here is *whether* a control is required, not how strongly.
    """
    forward_set = frozenset(forward)
    buckets: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.is_self_loop or edge.relation_type not in forward_set:
            continue
        buckets.setdefault(edge.source_concept.casefold(), set()).add(edge.target_concept)
    return {
        key: tuple(sorted(names, key=lambda name: (name.casefold(), name)))
        for key, names in buckets.items()
    }


def _definition_of(concepts: dict[str, Any], name: str) -> str:
    """The node's definition, or ``""`` when it is undeclared (a dangling edge)."""
    concept = concepts.get(name.casefold())
    return "" if concept is None else concept.definition


def analyze_logic_risk(graph: KnowledgeGraph, target_api: str) -> RiskAssessmentReport:
    """Derive the business-logic risk of one route from what it lacks.

    Reads the graph four times (requirement, gap, consequence, clause), then
    intersects requirement and gap. Nothing is mutated and nothing is inferred
    beyond the TBox' own edges: a flaw appears in the report only if the graph says
    the absence of a *required* control permits it.

    Args:
        graph: the business-logic ABox. Read only - adjacency is local.
        target_api: name of the route to assess, matched case-insensitively; the
            graph's canonical spelling is what the report carries.

    Returns:
        A :class:`RiskAssessmentReport` whose ``gaps`` list every control the route
        lacks and whose ``findings`` list the intersection with the requirement set.

    Raises:
        DataContractError: when ``graph`` is not a
            :class:`~ontology_builder.schema.KnowledgeGraph`, when ``target_api`` is
            blank, when it names no node in the graph - an empty report would read
            as "this route is fine", which is the most dangerous way to answer this
            question wrongly - or when it names a node that is not an
            ``API_Endpoint``. That last rule is the domain contract: an assessment
            starts at a route, so starting at ``Idempotency_Token`` or at
            ``Fund_Transfer_Process`` is a caller mistake, not a finding.
    """
    if not isinstance(graph, KnowledgeGraph):
        raise DataContractError(
            "analyze_logic_risk needs a KnowledgeGraph", got=type(graph).__name__
        )
    if not isinstance(target_api, str) or not target_api.strip():
        raise DataContractError("target_api must be a non-empty node name")

    concepts = graph.concept_index()
    key = target_api.strip().casefold()
    concept = concepts.get(key)
    if concept is None:
        raise DataContractError(
            "unknown API %r: it is not one of the graph's %d concepts"
            % (target_api.strip(), len(concepts)),
            candidates=sorted(item.name for item in graph.nodes)[:5],
        )
    if concept.category is not ConceptCategory.API_ENDPOINT:
        raise DataContractError(
            "the assessment starts at an API endpoint, and %r is a %s"
            % (concept.name, concept.category.value),
            source=concept.name,
            category=concept.category.value,
            candidates=sorted(
                item.name
                for item in graph.nodes
                if item.category is ConceptCategory.API_ENDPOINT
            ),
        )
    source = concept.name

    implements = _adjacency(graph, forward=IMPLEMENTS_FORWARD)
    requires = _adjacency(graph, forward=REQUIRES_FORWARD)
    lacks = _adjacency(graph, forward=GAP_FORWARD)
    permits = _adjacency(graph, forward=CONSEQUENCE_FORWARD)
    breaks = _adjacency(graph, forward=COMPLIANCE_FORWARD)

    # 1. requirement: which processes this route serves, and what they need.
    processes = implements.get(key, ())
    required: dict[str, str] = {}
    required_by: dict[str, list[str]] = {}
    for process in processes:
        for control in requires.get(process.casefold(), ()):
            canonical = required.setdefault(control.casefold(), control)
            owners = required_by.setdefault(canonical.casefold(), [])
            if process not in owners:
                owners.append(process)

    # 2. finding: which of those controls the review says the route does not have.
    missing = {control.casefold(): control for control in lacks.get(key, ())}

    # 3. the intersection, plus the consequences the graph attaches to it.
    gaps: list[ControlGap] = []
    for control_key in sorted(missing):
        control = missing[control_key]
        gaps.append(
            ControlGap(
                control=control,
                required_by=tuple(required_by.get(control_key, ())),
                derived=permits.get(control_key, ()),
                remediation=remediation_for(control, _definition_of(concepts, control)),
            )
        )

    findings: list[LogicFinding] = []
    for gap in gaps:
        if not gap.is_required:
            continue
        for vulnerability in gap.derived:
            findings.append(
                LogicFinding(
                    target_api=source,
                    control=gap.control,
                    vulnerability=vulnerability,
                    required_by=gap.required_by,
                    clauses=breaks.get(vulnerability.casefold(), ()),
                    remediation=gap.remediation,
                )
            )

    satisfied = tuple(
        control for control_key, control in sorted(required.items()) if control_key not in missing
    )

    return RiskAssessmentReport(
        target_api=source,
        processes=processes,
        gaps=tuple(gaps),
        findings=tuple(findings),
        satisfied=satisfied,
        total_nodes=len(graph.nodes),
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """The CLI flags, kept separate so a test can assert on them without running.

    ``--api`` defaults to the benchmark route so the acceptance command needs no
    arguments; every other default mirrors the stage-8 CLI (same graph-relative
    paths, same ``--no-validate`` escape hatch).
    """
    parser = argparse.ArgumentParser(
        prog="python -m fin_logic_risk.risk_reasoner",
        description=(
            "Derive the business-logic risk of one route from the controls it lacks: "
            "requirement & finding -> permitted flaw -> broken clause -> fix."
        ),
    )
    parser.add_argument(
        "--graph", default=str(DEFAULT_GRAPH), help="business-logic graph JSON"
    )
    parser.add_argument(
        "--api",
        default=DEFAULT_API,
        help="entry route to assess (case-insensitive, must be an api_endpoint)",
    )
    parser.add_argument(
        "--json", dest="json_out", default=None, metavar="PATH", help="also write the report"
    )
    parser.add_argument(
        "--no-validate", action="store_true", help="skip the TBox gate (not advised)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="print the verdict only, not the class table"
    )
    return parser


def _write_json(path: str | Path, payload: Any) -> Path:
    """Write UTF-8 JSON with a trailing newline; returns the path written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return target


def main(argv: list[str] | None = None) -> int:
    """Validate, assess, print the gaps, the findings and the verdict.

    Returns:
        ``0`` on a clean run, ``1`` when the graph violates ``FIN_LOGIC_TBOX`` (the
        assessment is refused: reasoning over an inadmissible ABox reports flaws the
        ontology does not sanction), ``2`` when the graph cannot be read, the target
        route does not exist, or it is not an API endpoint.
    """
    args = build_arg_parser().parse_args(argv)

    print("=" * 78)
    print(
        "FINANCIAL BUSINESS-LOGIC RISK REASONER  %s v%s"
        % (FIN_LOGIC_TBOX.name, FIN_LOGIC_TBOX.version)
    )
    print("=" * 78)
    graph_path = Path(args.graph)
    try:
        graph = KnowledgeGraph.load_json(graph_path)
    except (OSError, ValueError) as exc:
        print("  cannot read %s: %s" % (graph_path, exc))
        return 2
    print(
        "  graph     : %s (%d concepts, %d edges)"
        % (graph_path, len(graph.nodes), len(graph.edges))
    )

    if args.no_validate:
        print("  TBox gate : skipped (--no-validate)")
    else:
        verdict = OntologyValidator(
            schema=FIN_LOGIC_TBOX, policy=ValidationPolicy.LENIENT
        ).validate(graph)
        print(
            "  TBox gate : %d error(s), %d warning(s), %d info(s) against %s v%s"
            % (
                len(verdict.errors),
                len(verdict.warnings),
                len(verdict.infos),
                verdict.schema_name,
                verdict.schema_version,
            )
        )
        for issue in verdict.issues[:5]:
            print("      [%s] %s" % (issue.severity.value[0].upper(), issue.message))
        if verdict.errors:
            print("  refusing to reason: the graph breaks the TBox, so every finding")
            print("  below would describe a model the ontology does not sanction.")
            return 1

    if not args.quiet:
        for line in summary_lines():
            print(line)

    try:
        report = analyze_logic_risk(graph, args.api)
    except DataContractError as exc:
        print("  cannot assess: %s" % exc)
        return 2

    print("")
    print("  --- logic risk for %s ---" % report.target_api)
    for line in report.gap_lines():
        print(line)
    print("")
    for line in report.finding_lines():
        print(line)
    print("")
    for line in report.lines():
        print(line)
    if args.json_out:
        print("  report    : %s" % _write_json(args.json_out, report.to_dict()))
    return 0
