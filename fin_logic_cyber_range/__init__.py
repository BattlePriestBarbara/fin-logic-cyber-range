# -*- coding: utf-8 -*-
"""Stage 11: a local, synthetic cyber range that falsifies the stage-10 ontology.

Modules
-------
=========================  ==================================================
``safety``                 the loopback allow-list; every URL goes through it
``ledger``                 synthetic accounts, postings, the two control arms
``observability``          ``AccessRecord`` and the detection signals it raises
``gateway``                a ``http.server`` mock on ``127.0.0.1``, vulnerable
                           or secure
``scenario``               the experiment as data, loaded and validated
``runner``                 play a scenario over a socket, collect the result
``oracle``                 map observations onto ``ControlGap`` / ``LogicFinding``
                           and score them with the stage-10 ladder
``report``                 console / Markdown / JSON, plus the static-vs-dynamic
                           comparison
=========================  ==================================================

The rule this package follows
-----------------------------
Stage 10 said a missing control is a *negative* fact, and that negative facts need a
closed-world assumption to reason about. The range tests that claim: it makes the
missing control the independent variable, runs the same scenario with and without it,
and asks whether the ontology's predicted consequence actually happens. Nothing here
talks to a network, reads a real dataset, or persists state outside the process; the
accounts are ``ACC-SYNTH-*``, the gateway binds ``127.0.0.1``, and the only third
party is ``fin_logic_risk`` itself (the vocabulary under test).
"""
from __future__ import annotations

from fin_logic_cyber_range.gateway import (
    HEALTH_PATH,
    LEDGER_PATH,
    ROUTES,
    SIGNATURE_HEADER,
    TRANSFER_PATH,
    MockGatewayServer,
)
from fin_logic_cyber_range.ledger import (
    CONTROL_NAMES,
    LAB_SECRET,
    SYNTHETIC_ACCOUNTS,
    ControlSet,
    Instruction,
    LedgerRejection,
    Posting,
    SyntheticLedger,
    TransferOutcome,
    instruction_signature,
)
from fin_logic_cyber_range.observability import AccessRecord, ObservabilityLog
from fin_logic_cyber_range.oracle import (
    CONTROL_CONSEQUENCES,
    FLAW_CLAUSES,
    MODELLED_FLAWS,
    REQUIRED_CONTROLS,
    RangeAssessment,
    assess,
)
from fin_logic_cyber_range.report import RangeReport
from fin_logic_cyber_range.runner import (
    HttpResult,
    ScenarioRun,
    post_instruction,
    run_scenario,
    run_scenario_both_arms,
)
from fin_logic_cyber_range.safety import (
    BIND_HOST,
    LOCAL_HOSTS,
    SafetyViolation,
    ensure_bind_host,
    ensure_local_url,
    is_local_url,
    split_base_url,
)
from fin_logic_cyber_range.scenario import (
    ACTIONS,
    SCENARIO_DIR,
    Scenario,
    Step,
    load_scenario,
    load_scenarios,
    scenario_from_dict,
)

__all__ = [
    "ACTIONS",
    "AccessRecord",
    "BIND_HOST",
    "CONTROL_CONSEQUENCES",
    "CONTROL_NAMES",
    "ControlSet",
    "FLAW_CLAUSES",
    "HEALTH_PATH",
    "HttpResult",
    "Instruction",
    "LAB_SECRET",
    "LEDGER_PATH",
    "LOCAL_HOSTS",
    "LedgerRejection",
    "MODELLED_FLAWS",
    "MockGatewayServer",
    "ObservabilityLog",
    "Posting",
    "REQUIRED_CONTROLS",
    "ROUTES",
    "RangeAssessment",
    "RangeReport",
    "SIGNATURE_HEADER",
    "SCENARIO_DIR",
    "SYNTHETIC_ACCOUNTS",
    "SafetyViolation",
    "Scenario",
    "ScenarioRun",
    "Step",
    "SyntheticLedger",
    "TRANSFER_PATH",
    "TransferOutcome",
    "assess",
    "ensure_bind_host",
    "ensure_local_url",
    "instruction_signature",
    "is_local_url",
    "load_scenario",
    "load_scenarios",
    "post_instruction",
    "run_scenario",
    "run_scenario_both_arms",
    "scenario_from_dict",
    "split_base_url",
]

__version__ = "0.1.0"
