# -*- coding: utf-8 -*-
"""The command line: play every scenario against both arms and write a report.

    python scripts/run_logic_range.py
    python scripts/run_logic_range.py --scenario replay_transfer --mode secure
    python scripts/run_logic_range.py --json outputs/range.json --markdown outputs/range.md

Exit codes follow the rest of this project: ``0`` when every (scenario, arm) matched
its prediction, ``1`` when at least one mismatched *or* the benchmark graph breaks
its TBox (a comparison against a graph the ontology rejects would be a comparison
against nothing), ``2`` when the scenarios or the graph cannot be read.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from fin_logic_cyber_range.ledger import ControlSet
from fin_logic_cyber_range.report import RangeReport
from fin_logic_cyber_range.runner import ScenarioRun, run_scenario
from fin_logic_cyber_range.scenario import SCENARIO_DIR, Scenario, load_scenarios
from fin_logic_risk import (
    DEFAULT_API,
    DEFAULT_GRAPH,
    FIN_LOGIC_TBOX,
    RiskAssessmentReport,
    analyze_logic_risk,
)
from ontology_builder.core.errors import DataContractError
from ontology_builder.ontology import OntologyValidator, ValidationPolicy
from ontology_builder.schema import KnowledgeGraph

ARMS = {"vulnerable": ControlSet.vulnerable, "secure": ControlSet.secure}


def build_arg_parser() -> argparse.ArgumentParser:
    """The CLI surface, kept next to :func:`main` so the help cannot drift."""
    parser = argparse.ArgumentParser(
        prog="run_logic_range",
        description=(
            "Play the synthetic business-logic scenarios against a loopback mock "
            "gateway and compare the result with the fin_logic_risk ontology."
        ),
    )
    parser.add_argument(
        "--scenario",
        action="append",
        metavar="NAME",
        help="run only this scenario slug (repeatable); default: every file in the directory",
    )
    parser.add_argument(
        "--scenario-dir",
        default=str(SCENARIO_DIR),
        metavar="DIR",
        help="directory of scenario JSON files (default: data/cyber_range/scenarios)",
    )
    parser.add_argument(
        "--mode",
        choices=("vulnerable", "secure", "both"),
        default="both",
        help="which arm(s) to run (default: both)",
    )
    parser.add_argument(
        "--window-ms",
        type=int,
        default=20,
        metavar="MS",
        help="contention window for the unguarded arm, 0..500 (default: 20)",
    )
    parser.add_argument(
        "--graph",
        default=str(DEFAULT_GRAPH),
        metavar="PATH",
        help="stage-10 benchmark graph used for the static comparison",
    )
    parser.add_argument(
        "--api",
        default=DEFAULT_API,
        metavar="NAME",
        help="route in that graph (default: %(default)s)",
    )
    parser.add_argument("--json", dest="json_out", metavar="PATH", help="write the report as JSON")
    parser.add_argument(
        "--markdown", dest="markdown_out", metavar="PATH", help="write the report as Markdown"
    )
    parser.add_argument("--no-static", action="store_true", help="skip the static comparison")
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="skip the TBox gate on the benchmark graph (not advised)",
    )
    parser.add_argument("--verbose", action="store_true", help="print every access record")
    parser.add_argument("--quiet", action="store_true", help="only print the verdict lines")
    return parser


def _write_json(path: str | Path, payload: Any) -> Path:
    """Write UTF-8 JSON with a trailing newline; returns the path written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def _write_text(path: str | Path, text: str) -> Path:
    """Write UTF-8 text with a trailing newline; returns the path written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return target


def _select(scenarios: Sequence[Scenario], wanted: Sequence[str] | None) -> tuple[Scenario, ...]:
    """Filter scenarios by slug, case-insensitively.

    Raises:
        DataContractError: when a requested slug matches nothing - silently running
            the other scenarios would report success for an experiment the caller
            did not ask for.
    """
    if not wanted:
        return tuple(scenarios)
    index = {item.name.casefold(): item for item in scenarios}
    chosen: list[Scenario] = []
    for raw in wanted:
        key = raw.strip().casefold()
        if key not in index:
            raise DataContractError("no scenario named %r" % raw, candidates=sorted(index))
        chosen.append(index[key])
    return tuple(chosen)


def main(argv: list[str] | None = None) -> int:
    """Run the selected scenarios and print (and optionally write) the report.

    Returns:
        ``0`` when every (scenario, arm) matched, ``1`` on a mismatch or a TBox
        error in the benchmark graph, ``2`` when the inputs cannot be read.
    """
    args = build_arg_parser().parse_args(argv)
    if not 0 <= args.window_ms <= 500:
        print("  --window-ms must be 0..500, got %d" % args.window_ms)
        return 2

    print("=" * 78)
    print("FIN LOGIC CYBER RANGE  %s v%s" % (FIN_LOGIC_TBOX.name, FIN_LOGIC_TBOX.version))
    print("=" * 78)

    try:
        scenarios = _select(load_scenarios(args.scenario_dir), args.scenario)
    except DataContractError as exc:
        print("  cannot load scenarios: %s" % exc)
        return 2

    static: RiskAssessmentReport | None = None
    if args.no_static:
        print("  static    : skipped (--no-static)")
    else:
        try:
            graph = KnowledgeGraph.load_json(Path(args.graph))
        except (OSError, ValueError) as exc:
            print("  cannot read %s: %s" % (args.graph, exc))
            return 2
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
            if verdict.errors:
                for issue in verdict.errors[:5]:
                    print("      [E] %s" % issue.message)
                print("  refusing to compare: the graph breaks the TBox, so the static")
                print("  column would describe a model the ontology does not sanction.")
                return 1
        try:
            static = analyze_logic_risk(graph, args.api)
        except DataContractError as exc:
            print("  cannot assess %s: %s" % (args.api, exc))
            return 2
        print(
            "  static    : %s risk=%s, %d finding(s), %d control gap(s)"
            % (static.target_api, static.risk.value, len(static.findings), len(static.gaps))
        )

    print("  scenarios : %d from %s" % (len(scenarios), args.scenario_dir))
    for scenario in scenarios:
        print("    %-22s %s" % (scenario.name, scenario.title))
    arms = tuple(ARMS) if args.mode == "both" else (args.mode,)
    print("  arms      : %s  (loopback only, synthetic accounts, no retries)" % ", ".join(arms))
    print("")

    window = args.window_ms / 1000.0
    runs: list[ScenarioRun] = []
    for scenario in scenarios:
        for mode in arms:
            runs.append(run_scenario(scenario, ARMS[mode](), window_seconds=window))
    report = RangeReport(tuple(runs), static=static)

    if args.quiet:
        for run in report.runs:
            print(run.assessment.verdict_line())
        print("  结论            : %s" % ("PASS" if report.passed else "MISMATCH"))
    else:
        for line in report.lines(verbose=args.verbose):
            print(line)
    if args.json_out:
        print("  json      : %s" % _write_json(args.json_out, report.to_dict()))
    if args.markdown_out:
        print("  markdown  : %s" % _write_text(args.markdown_out, report.markdown()))
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    raise SystemExit(main())
