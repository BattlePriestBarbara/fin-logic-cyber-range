# -*- coding: utf-8 -*-
"""Collect the runs into one artefact: console block, Markdown, JSON.

What the report is for
----------------------
Three questions, in the order a reader asks them:

1. **Did the prediction survive contact with the ledger?** One row per
   (scenario, arm) with observed risk, predicted risk and the verdict.
2. **Where do the two methods disagree?** The static stage-10 assessment and the
   dynamic union of findings are compared as *sets of (control, flaw) pairs*, so a
   flaw the ontology predicts but no scenario provokes shows up as ``未复现``, and a
   flaw the range observes but the graph cannot carry shows up as ``未建模``. A
   report that only printed "all green" would hide both.
3. **What was actually seen?** Evidence lines per arm - postings, ids, receipts -
   so the verdict is auditable without re-running anything.

Markdown is the format because this project's deliverables get pasted into
tickets and Word documents; the console block is the same data at a fixed width.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from fin_logic_cyber_range.runner import ScenarioRun
from fin_logic_risk import RiskAssessmentReport, RiskLevel
from ontology_builder.core.errors import DataContractError


def _pairs(items: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    """Sorted, de-duplicated ``(control, flaw)`` pairs."""
    return tuple(sorted({(control, flaw) for control, flaw in items}))


@dataclass(frozen=True)
class RangeReport:
    """Every run of one session, plus the static assessment it is compared against.

    Attributes:
        runs: one entry per (scenario, arm), in execution order.
        static: the stage-10 report for the same route, when the caller supplied
            one; ``None`` disables the comparison section instead of faking it.

    Raises:
        DataContractError: when ``runs`` holds something that is not a
            :class:`ScenarioRun`, or ``static`` is not a
            :class:`~fin_logic_risk.RiskAssessmentReport`.
    """

    runs: tuple[ScenarioRun, ...] = ()
    static: RiskAssessmentReport | None = None

    def __post_init__(self) -> None:
        runs = tuple(self.runs)
        for run in runs:
            if not isinstance(run, ScenarioRun):
                raise DataContractError(
                    "RangeReport.runs must hold ScenarioRun instances",
                    got=type(run).__name__,
                )
        object.__setattr__(self, "runs", runs)
        if self.static is not None and not isinstance(self.static, RiskAssessmentReport):
            raise DataContractError(
                "RangeReport.static must be a RiskAssessmentReport",
                got=type(self.static).__name__,
            )

    # -- verdicts ------------------------------------------------------------
    @property
    def passed(self) -> bool:
        """True when every run matched its scenario's prediction."""
        return all(run.passed for run in self.runs)

    @property
    def mismatches(self) -> tuple[ScenarioRun, ...]:
        """The runs whose observed risk disagreed with the prediction."""
        return tuple(run for run in self.runs if not run.passed)

    @property
    def worst_observed(self) -> RiskLevel:
        """The highest risk any arm produced (``NONE`` for an empty report)."""
        if not self.runs:
            return RiskLevel.NONE
        return max((run.assessment.risk for run in self.runs), key=lambda level: level.rank)

    def _dynamic_pairs(self) -> tuple[tuple[str, str], ...]:
        """``(control, flaw)`` for every observed finding, across both arms."""
        return _pairs(
            (finding.control, finding.vulnerability)
            for run in self.runs
            for finding in run.assessment.findings
        )

    def _static_pairs(self) -> tuple[tuple[str, str], ...]:
        """``(control, flaw)`` the static reasoner derived."""
        if self.static is None:
            return ()
        return _pairs((finding.control, finding.vulnerability) for finding in self.static.findings)

    # -- comparison ----------------------------------------------------------
    def comparison_lines(self) -> list[str]:
        """Static-vs-dynamic set comparison, one section of the report."""
        if self.static is None:
            return ["  (no static assessment supplied; comparison skipped)"]
        static = set(self._static_pairs())
        dynamic = set(self._dynamic_pairs())
        reproduced = sorted(static & dynamic)
        unobserved = sorted(static - dynamic)
        unmodelled = sorted(dynamic - static)

        def render(pairs: Sequence[tuple[str, str]]) -> str:
            return ", ".join("%s/%s" % pair for pair in pairs) or "none"

        return [
            "  静态推演        : risk=%-8s %d finding(s) from %s"
            % (self.static.risk.value, len(static), self.static.target_api),
            "  动态实测        : worst=%-7s %d finding(s) across %d run(s)"
            % (self.worst_observed.value, len(dynamic), len(self.runs)),
            "  两边都成立      : %s" % render(reproduced),
            "  静态有、本次未复现: %s" % render(unobserved),
            "  动态有、本体未建模: %s" % render(unmodelled),
        ]

    # -- renderers -----------------------------------------------------------
    def lines(self, *, verbose: bool = False) -> list[str]:
        """The whole console block: every run, then the comparison, then a verdict."""
        out: list[str] = []
        for run in self.runs:
            out.extend(run.lines(verbose=verbose))
            out.append("")
        out.append("  --- static vs dynamic ---")
        out.extend(self.comparison_lines())
        out.append("")
        out.append(
            "  结论            : %d/%d run(s) matched; worst observed %s"
            % (
                len(self.runs) - len(self.mismatches),
                len(self.runs),
                self.worst_observed.value,
            )
        )
        return out

    def markdown(self) -> str:
        """The same information as a Markdown document, ready to paste."""
        out = ["# 金融业务逻辑靶场报告", ""]
        out.append(
            "全部目标为 `127.0.0.1` 上的 mock 网关（或 compose 内部服务名），"
            "账户、金额、指令号均为合成数据。"
        )
        out.append("")
        out.append("## 1. 逐臂结果")
        out.append("")
        out.append("| 剧本 | 臂 | 请求数 | 实测风险 | 预测风险 | 判定 |")
        out.append("| --- | --- | ---: | --- | --- | --- |")
        for run in self.runs:
            out.append(
                "| `%s` | %s | %d | **%s** | %s | %s |"
                % (
                    run.scenario.name,
                    run.mode,
                    run.assessment.requests,
                    run.assessment.risk.value,
                    run.assessment.expected.value,
                    "PASS" if run.passed else "MISMATCH",
                )
            )
        out.append("")
        out.append("## 2. 发现与证据")
        out.append("")
        for run in self.runs:
            out.append("### `%s` / %s - %s" % (run.scenario.name, run.mode, run.scenario.title))
            out.append("")
            missing = run.assessment.controls_missing
            out.append("- 缺失控制：%s" % (", ".join("`%s`" % name for name in missing) or "无"))
            out.append(
                "- 观测到的问题类型：%s"
                % (", ".join("`%s`" % name for name in run.assessment.flaws) or "无")
            )
            if run.assessment.ontology_gaps:
                out.append(
                    "- 本体缺口：%s（基准图中没有对应的 `LEADS_TO_VULNERABILITY` / 条款边）"
                    % ", ".join("`%s`" % name for name in run.assessment.ontology_gaps)
                )
            for finding in run.assessment.findings:
                out.append("- 结论句：%s" % finding.sentence())
            for line in run.assessment.evidence:
                out.append("- 证据：%s" % line)
            out.append("")
        out.append("## 3. 静态推演 vs 动态实测")
        out.append("")
        for line in self.comparison_lines():
            out.append("- %s" % line.strip())
        out.append("")
        out.append("## 4. 结论")
        out.append("")
        out.append(
            "- %d/%d 个（剧本 × 臂）组合与本体预测一致，最高实测风险 **%s**。"
            % (
                len(self.runs) - len(self.mismatches),
                len(self.runs),
                self.worst_observed.value,
            )
        )
        if self.mismatches:
            out.append(
                "- 不一致组合：%s"
                % ", ".join("`%s`/%s" % (run.scenario.name, run.mode) for run in self.mismatches)
            )
        out.append("")
        return "\n".join(out) + "\n"

    def to_dict(self) -> dict[str, Any]:
        """JSON form: every run, plus both sides of the comparison as pair lists."""
        return {
            "passed": self.passed,
            "worst_observed": self.worst_observed.value,
            "runs": [run.to_dict() for run in self.runs],
            "static": None if self.static is None else self.static.to_dict(),
            "static_pairs": [list(pair) for pair in self._static_pairs()],
            "dynamic_pairs": [list(pair) for pair in self._dynamic_pairs()],
        }
