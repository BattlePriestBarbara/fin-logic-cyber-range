# -*- coding: utf-8 -*-
"""Turn what the ledger did into what the stage-10 ontology says it means.

The join, in one line
---------------------
Stage 10 computes ``required ∩ missing`` statically, over a hand-reviewed graph.
This module computes the same intersection *dynamically*, over observed postings:

```
missing_controls  =  what the arm does not enforce
observed_flaws    =  what the ledger actually did (duplicates, unsigned accepts)
findings          =  CONTROL_CONSEQUENCES[missing_control] ∩ observed_flaws
risk              =  classify_logic_risk(gaps, findings)   ← the stage-10 ladder
```

The last line is the point of the whole exercise: :func:`fin_logic_risk.
classify_logic_risk`, :class:`~fin_logic_risk.ControlGap` and
:class:`~fin_logic_risk.LogicFinding` are *reused*, not re-implemented. A dynamic
verification that scored itself with its own ladder could disagree with the
ontology and never notice; sharing the function makes a disagreement impossible to
hide - the two arms are scored by the same code.

Deliberately narrower than the static run
-----------------------------------------
The stage-10 graph says a missing idempotency token *permits* replay, duplicate
debit **and** a race. A single dynamic run only ever observes the ones its steps
provoke: a sequential replay produces no race, so it loses the clause that the race
would have added and lands one rung lower. That asymmetry is reported, not
smoothed away (see :attr:`RangeAssessment.ontology_gaps` and the README) - "the
static model is a superset of one run" is a property of the method, and hiding it
would be the dishonest version of a green test.

Flaws the ontology cannot express yet
-------------------------------------
An unsigned request being accepted is a real observation with no
``LEADS_TO_VULNERABILITY`` edge to carry it: the benchmark graph attaches all three
flaws to ``Idempotency_Token`` and none to ``Signature_Verification``. Rather than
invent a clause, the flaw is recorded in ``ontology_gaps`` and the risk falls back
to the clause-less branch of the ladder (``MEDIUM``). A range that can say "your
ontology is missing an edge" is more useful than one that reports a number.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Sequence

from fin_logic_cyber_range.ledger import ControlSet, Posting
from fin_logic_cyber_range.observability import AccessRecord
from fin_logic_cyber_range.scenario import Scenario
from fin_logic_risk import (
    ControlGap,
    LogicFinding,
    RiskLevel,
    classify_logic_risk,
    remediation_for,
)
from ontology_builder.core.errors import DataContractError

#: Control -> the flaws its absence permits, mirroring the ``LEADS_TO_VULNERABILITY``
#: edges of ``data/fin_logic_micro_graph.json``. ``Unsigned_Instruction_Accepted``
#: has no edge there yet, which is exactly why it appears in
#: :data:`MODELLED_FLAWS`'s complement below.
CONTROL_CONSEQUENCES: MappingProxyType[str, tuple[str, ...]] = MappingProxyType(
    {
        "Idempotency_Token": ("Replay_Attack", "Duplicate_Debit", "Race_Condition"),
        "Signature_Verification": ("Unsigned_Instruction_Accepted",),
    }
)

#: Flaw -> the clauses it breaks, mirroring the ``VIOLATES`` edges of the benchmark
#: graph. An empty tuple means "the ontology has no clause for this yet".
FLAW_CLAUSES: MappingProxyType[str, tuple[str, ...]] = MappingProxyType(
    {
        "Replay_Attack": ("Financial_Security_Level_3",),
        "Duplicate_Debit": ("Financial_Security_Level_3",),
        "Race_Condition": ("JR_T_0185_API_Spec",),
        "Unsigned_Instruction_Accepted": (),
    }
)

#: Controls the transfer process requires, i.e. the ``REQUIRES_CONTROL`` edges of
#: the benchmark graph. Held here as the dynamic mirror of that hand-authored set.
REQUIRED_CONTROLS = ("Idempotency_Token", "Signature_Verification")

#: Flaws the benchmark graph can explain. Anything outside this set is reported as
#: an ontology gap instead of being forced into a clause.


#: Flaws the benchmark graph can explain. Anything outside this set is reported as
#: an ontology gap instead of being forced into a clause.
MODELLED_FLAWS = frozenset(name for name, clauses in FLAW_CLAUSES.items() if clauses)


def _dedupe(items: list[str]) -> tuple[str, ...]:
    """Ordered de-duplication (the same id may be duplicated by two steps)."""
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return tuple(seen)


@dataclass(frozen=True)
class RangeAssessment:
    """What one arm of one scenario proved, scored on the stage-10 ladder.

    Attributes:
        scenario: the scenario's slug.
        mode: ``"vulnerable"``, ``"secure"`` or ``"partial"``.
        target_api: the ontology endpoint the run is mapped onto.
        process: the ontology business process that requires the controls.
        gaps: controls the process requires and this arm does not enforce.
        findings: one per (missing control, observed flaw) pair.
        flaws: every flaw observed, modelled or not, sorted.
        ontology_gaps: observed flaws the benchmark graph has no clause edge for.
        evidence: one line per observable fact behind a finding - the "why should I
            believe this" column.
        expected: the risk the scenario predicted for this arm.
        requests: how many requests the run sent, for the report's cost column.

    Raises:
        DataContractError: on a blank scenario/mode/endpoint/process, a negative
            request count, or a finding about another route than ``target_api``.
    """

    scenario: str
    mode: str
    target_api: str
    process: str
    gaps: tuple[ControlGap, ...] = ()
    findings: tuple[LogicFinding, ...] = ()
    flaws: tuple[str, ...] = ()
    ontology_gaps: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    expected: RiskLevel = RiskLevel.NONE
    requests: int = 0

    def __post_init__(self) -> None:
        for name in ("scenario", "mode", "target_api", "process"):
            raw = getattr(self, name)
            value = raw.strip() if isinstance(raw, str) else ""
            if not value:
                raise DataContractError("RangeAssessment.%s must be non-empty" % name)
            object.__setattr__(self, name, value)
        if self.requests < 0:
            raise DataContractError("RangeAssessment.requests cannot be negative")
        for finding in self.findings:
            if finding.target_api.casefold() != self.target_api.casefold():
                raise DataContractError(
                    "a finding is about another route",
                    finding=finding.target_api,
                    target_api=self.target_api,
                )

    @property
    def risk(self) -> RiskLevel:
        """The observed risk - computed by the stage-10 function, never stored."""
        return classify_logic_risk(self.gaps, self.findings)

    @property
    def passed(self) -> bool:
        """Whether the observed risk equals the prediction for this arm."""
        return self.risk is self.expected

    @property
    def controls_missing(self) -> tuple[str, ...]:
        """Spelling of :attr:`gaps`, for a table column."""
        return tuple(gap.control for gap in self.gaps)

    def verdict_line(self) -> str:
        """One line: scenario, arm, observed risk, predicted risk, verdict."""
        verdict = "PASS" if self.passed else "MISMATCH"
        return "  %-22s %-10s observed=%-8s predicted=%-8s %s  (%d request(s))" % (
            self.scenario,
            self.mode,
            self.risk.value,
            self.expected.value,
            verdict,
            self.requests,
        )

    def lines(self) -> list[str]:
        """The console block for this assessment, in reading order."""
        out = [self.verdict_line()]
        if self.controls_missing:
            out.append("    missing controls : %s" % ", ".join(self.controls_missing))
        else:
            out.append("    missing controls : none")
        for finding in self.findings:
            out.append("    finding          : %s" % finding.sentence())
        for line in self.evidence:
            out.append("    evidence         : %s" % line)
        if self.ontology_gaps:
            out.append(
                "    ontology gap     : %s - 基准图没有对应 LEADS_TO_VULNERABILITY / 条款边，"
                "已按无条款档计分" % ", ".join(self.ontology_gaps)
            )
        return out

    def to_dict(self) -> dict[str, Any]:
        """JSON form; ``risk`` and ``passed`` are included because they are derived."""
        return {
            "scenario": self.scenario,
            "mode": self.mode,
            "target_api": self.target_api,
            "process": self.process,
            "risk": self.risk.value,
            "expected": self.expected.value,
            "passed": self.passed,
            "requests": self.requests,
            "controls_missing": list(self.controls_missing),
            "flaws": list(self.flaws),
            "ontology_gaps": list(self.ontology_gaps),
            "gaps": [gap.to_dict() for gap in self.gaps],
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": list(self.evidence),
        }


def _duplicates(postings: Sequence[Posting]) -> dict[str, tuple[Posting, ...]]:
    """``instruction_id -> postings`` for every id that posted more than once."""
    grouped: dict[str, list[Posting]] = {}
    for posting in postings:
        grouped.setdefault(posting.instruction_id, []).append(posting)
    return {key: tuple(items) for key, items in grouped.items() if len(items) > 1}


def _sequential_repeats(scenario: Scenario) -> frozenset[str]:
    """Instruction ids the scenario submits more than once *without* concurrency."""
    counts: dict[str, int] = {}
    for step in scenario.steps:
        if step.action == "transfer":
            counts[step.instruction_id] = counts.get(step.instruction_id, 0) + step.repeat
    return frozenset(key for key, count in counts.items() if count > 1)


def assess(
    scenario: Scenario,
    *,
    controls: ControlSet,
    postings: Sequence[Posting],
    access: Sequence[AccessRecord],
) -> RangeAssessment:
    """Score one arm of one scenario against the stage-10 vocabulary.

    The function is pure with respect to the *server*: it takes the postings and the
    access records the run produced, so it can be tested with hand-built lists and
    cannot accidentally read live state.

    Args:
        scenario: the experiment, whose steps explain *why* a duplicate was a replay
            (sequential resend) or a race (released together).
        controls: the arm that produced the observations.
        postings: every posting the ledger wrote during the run.
        access: every :class:`~fin_logic_cyber_range.observability.AccessRecord` the
            gateway logged during the run.

    Returns:
        A :class:`RangeAssessment` whose ``risk`` is computed by
        :func:`fin_logic_risk.classify_logic_risk` - the same ladder the static
        reasoner uses.

    Raises:
        DataContractError: when ``scenario`` or ``controls`` is the wrong type.
    """
    if not isinstance(scenario, Scenario):
        raise DataContractError("assess needs a Scenario", got=type(scenario).__name__)
    if not isinstance(controls, ControlSet):
        raise DataContractError("assess needs a ControlSet", got=type(controls).__name__)

    duplicated = _duplicates(postings)
    concurrent_ids = frozenset(
        step.instruction_id for step in scenario.steps if step.concurrency > 1
    )
    replay_ids = _sequential_repeats(scenario)
    unsigned = tuple(item for item in access if item.accepted and not item.signature_present)

    flaws: list[str] = []
    evidence: list[str] = []
    for instruction_id in sorted(duplicated):
        items = duplicated[instruction_id]
        flaws.append("Duplicate_Debit")
        if instruction_id in concurrent_ids:
            flaws.append("Race_Condition")
        if instruction_id in replay_ids:
            flaws.append("Replay_Attack")
        rendered = "; ".join(
            "%s 记 %s（回执 %s）" % (item.posting_id, item.amount, item.receipt_id)
            for item in items
        )
        evidence.append("指令 %s 产生 %d 条分录：%s" % (instruction_id, len(items), rendered))
    if unsigned:
        flaws.append("Unsigned_Instruction_Accepted")
        evidence.append(
            "请求 %s 未携带签名头仍被受理并落账" % ", ".join("#%d" % item.seq for item in unsigned)
        )

    ordered_flaws = _dedupe(flaws)
    observed = set(ordered_flaws)
    missing = set(controls.missing())
    gaps = tuple(
        ControlGap(
            control=control,
            required_by=(scenario.process,),
            derived=CONTROL_CONSEQUENCES.get(control, ()),
            remediation=remediation_for(control),
        )
        for control in REQUIRED_CONTROLS
        if control in missing
    )
    findings = [
        LogicFinding(
            target_api=scenario.target_api,
            control=gap.control,
            vulnerability=flaw,
            required_by=(scenario.process,),
            clauses=FLAW_CLAUSES.get(flaw, ()),
            remediation=gap.remediation,
        )
        for gap in gaps
        for flaw in CONTROL_CONSEQUENCES.get(gap.control, ())
        if flaw in observed
    ]
    findings.sort(key=lambda item: (item.control.casefold(), item.vulnerability.casefold()))
    return RangeAssessment(
        scenario=scenario.name,
        mode=controls.mode,
        target_api=scenario.target_api,
        process=scenario.process,
        gaps=gaps,
        findings=tuple(findings),
        flaws=ordered_flaws,
        ontology_gaps=tuple(sorted(observed - MODELLED_FLAWS)),
        evidence=tuple(evidence),
        expected=scenario.expectation(controls.mode),
        requests=len(access),
    )
