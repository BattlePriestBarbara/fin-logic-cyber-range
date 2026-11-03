# -*- coding: utf-8 -*-
"""Tests for the stage-11 range (``fin_logic_cyber_range/``).

What is checked, in this order:

* the **safety boundary** - the one property this package cannot get wrong: a
  public host, a privileged port, a non-``http`` scheme or userinfo in the URL must
  raise, and the harness must refuse to bind anything but ``127.0.0.1``;
* the **ledger** - one instruction posts once under the secure arm and twice under
  the unguarded one, a replay returns the stored receipt, a bad signature never
  touches the balance, and the reconciliation view sees what prevention missed;
* the **observation log** - the signals are derived from fields, not from prose, and
  numbering survives concurrent appends;
* the **scenarios** - the data contract: unknown keys, bad slugs and unbounded
  repetition are rejected instead of silently changing what the experiment means;
* the **oracle** - the dynamic score is produced by
  ``fin_logic_risk.classify_logic_risk``, so a disagreement with the ontology is
  impossible to hide; an unmodelled flaw is reported as an ontology gap;
* the **runner and the report** - over real loopback sockets, both arms, every
  shipped scenario, with the static-vs-dynamic comparison asserted as sets.

The integration tests use the real gateway on an ephemeral port (``port=0``) and
close it inside the test, so nothing leaks between cases; the contention window is
2 ms so the concurrent case stays fast while still being a real race.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fin_logic_cyber_range import cli, serve  # noqa: E402
from fin_logic_cyber_range.gateway import (  # noqa: E402
    HEALTH_PATH,
    LEDGER_PATH,
    MockGatewayServer,
)
from fin_logic_cyber_range.ledger import (  # noqa: E402
    CONTROL_NAMES,
    ControlSet,
    Instruction,
    LedgerRejection,
    Posting,
    SyntheticLedger,
    TransferOutcome,
    format_amount,
    instruction_signature,
)
from fin_logic_cyber_range.observability import (  # noqa: E402
    AccessRecord,
    ObservabilityLog,
)
from fin_logic_cyber_range.oracle import (  # noqa: E402
    MODELLED_FLAWS,
    REQUIRED_CONTROLS,
    RangeAssessment,
    assess,
)
from fin_logic_cyber_range.report import RangeReport  # noqa: E402
from fin_logic_cyber_range.runner import (  # noqa: E402
    HttpResult,
    post_instruction,
    run_scenario,
    run_scenario_both_arms,
)
from fin_logic_cyber_range.safety import (  # noqa: E402
    BIND_HOST,
    CONTAINER_BIND_ENV,
    LOCAL_HOSTS,
    SafetyViolation,
    ensure_bind_host,
    ensure_local_url,
    is_local_url,
    split_base_url,
)
from fin_logic_cyber_range.scenario import (  # noqa: E402
    MAX_REPEAT,
    MAX_WORKERS,
    SCENARIO_DIR,
    Scenario,
    Step,
    as_risk_level,
    load_scenario,
    load_scenarios,
    scenario_from_dict,
)
from fin_logic_risk import (  # noqa: E402
    DEFAULT_API,
    DEFAULT_GRAPH,
    RiskLevel,
    analyze_logic_risk,
)
from ontology_builder.core.errors import DataContractError  # noqa: E402
from ontology_builder.schema import KnowledgeGraph  # noqa: E402

WINDOW = 0.002


def instruction(
    signature: str | None = None, *, instruction_id: str = "INS-A0000001"
) -> Instruction:
    """A signed instruction the way a well-behaved client builds one."""
    return Instruction(
        instruction_id=instruction_id,
        amount="100.00",
        signature=(
            instruction_signature(instruction_id, "100.00") if signature is None else signature
        ),
    )


# ---------------------------------------------------------------- safety ----
def test_loopback_url_is_normalised():
    """Host case and an explicit port are normalised into one canonical spelling."""
    assert (
        ensure_local_url("HTTP://127.0.0.1:8080/mock/v1/transfer")
        == "http://127.0.0.1:8080/mock/v1/transfer"
    )
    assert ensure_local_url("http://LOCALHOST:9000/x") == "http://localhost:9000/x"


@pytest.mark.parametrize("host", ["127.0.0.1", "[::1]", "localhost", "mock-gateway"])
def test_local_hosts_are_allowed(host):
    """Every host on the allow-list passes, including the compose service names."""
    bare = host.strip("[]")
    assert bare in LOCAL_HOSTS
    assert is_local_url("http://%s:8080/mock/v1/transfer" % host)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/mock/v1/transfer",
        "http://8.8.8.8:8080/x",
        "http://bank.example.net:8443/api/v1/transfer",
        "https://127.0.0.1:8080/mock/v1/transfer",
        "ftp://127.0.0.1:8080/x",
        "http://user:secret@127.0.0.1:8080/x",
        "http://127.0.0.1:80/x",
        "http://127.0.0.1:8080/x?debug=1",
        "http://127.0.0.1:70000/x",
        "",
        "   ",
        None,
    ],
)
def test_anything_but_a_local_mock_is_refused(url):
    """A public host, a real domain, TLS, credentials, a privileged port, a query."""
    with pytest.raises(SafetyViolation):
        ensure_local_url(url)
    assert is_local_url(url) is False


def test_refusal_carries_the_allowed_hosts():
    """The error names the rule, so a user edits the scenario instead of guessing."""
    with pytest.raises(SafetyViolation) as excinfo:
        ensure_local_url("http://bank.example.net/x")
    assert "host" in excinfo.value.context
    assert sorted(LOCAL_HOSTS) == excinfo.value.context["allowed"]


def test_bind_host_must_be_the_loopback_literal():
    """``localhost`` is refused for binding: it depends on a hosts file."""
    assert ensure_bind_host(BIND_HOST) == "127.0.0.1"
    for bad in ("0.0.0.0", "localhost", "::", "192.168.1.10"):
        with pytest.raises(SafetyViolation):
            ensure_bind_host(bad)


def test_split_base_url_returns_host_and_port():
    """The runner needs a ``(host, port)`` pair for ``http.client``."""
    assert split_base_url("http://127.0.0.1:57529/mock/v1/transfer") == ("127.0.0.1", 57529)
    with pytest.raises(SafetyViolation):
        split_base_url("http://example.com:57529/x")


# ---------------------------------------------------------------- ledger ----
def test_format_amount_quantises_to_two_places():
    """Amounts are text on the wire and ``Decimal`` in the ledger."""
    assert format_amount("100") == "100.00"
    assert format_amount(100) == "100.00"
    assert format_amount("0.5") == "0.50"


@pytest.mark.parametrize("value", ["abc", "", "NaN", "Infinity", object()])
def test_format_amount_rejects_non_numbers(value):
    """A non-number is a caller bug, not a finding."""
    with pytest.raises(LedgerRejection):
        format_amount(value)


def test_signature_covers_id_and_amount():
    """Changing either field invalidates the signature - that is what the control checks."""
    base = instruction_signature("INS-A0000001", "100.00")
    assert base == instruction_signature("INS-A0000001", "100")
    assert base != instruction_signature("INS-A0000001", "101.00")
    assert base != instruction_signature("INS-A0000002", "100.00")
    assert len(base) == 32


def test_instruction_normalises_and_validates():
    """Ids are stripped, amounts quantised, and malformed instructions rejected."""
    parsed = Instruction(instruction_id="  INS-A0000001  ", amount="100")
    assert parsed.instruction_id == "INS-A0000001"
    assert format_amount(parsed.amount) == "100.00"
    assert parsed.to_payload()["amount"] == "100.00"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"instruction_id": ""},
        {"instruction_id": "x" * 65},
        {"instruction_id": "INS-1", "amount": "0"},
        {"instruction_id": "INS-1", "amount": "-5"},
        {"instruction_id": "INS-1", "amount": "1000000.00"},
        {"instruction_id": "INS-1", "debit_account": "6222-real-card"},
        {"instruction_id": "INS-1", "credit_account": "ACC-SYNTH-0001"},
    ],
)
def test_instruction_rejects_impossible_values(kwargs):
    """Blank ids, non-positive amounts, unknown accounts, identical legs."""
    with pytest.raises(LedgerRejection):
        Instruction(**kwargs)


def test_control_set_spellings_and_modes():
    """The ontology's spelling is the authority; the flags are the arm."""
    assert ControlSet.vulnerable().mode == "vulnerable"
    assert ControlSet.secure().mode == "secure"
    assert ControlSet(idempotency_token=True).mode == "partial"
    assert ControlSet.vulnerable().missing() == tuple(CONTROL_NAMES.values())
    assert ControlSet.secure().missing() == ()
    assert ControlSet.secure().to_dict()["enforced"] == [
        "Idempotency_Token",
        "Signature_Verification",
    ]


def test_unguarded_ledger_posts_twice():
    """The defect: one instruction, two postings, two receipts, one customer intent."""
    ledger = SyntheticLedger(ControlSet.vulnerable(), window_seconds=0)
    first = ledger.submit(instruction())
    second = ledger.submit(instruction())
    assert first.posting_id and second.posting_id
    assert not first.replayed and not second.replayed
    assert len(ledger.postings) == 2
    assert ledger.duplicated_instructions() == ("INS-A0000001",)
    assert format_amount(ledger.balance_of("ACC-SYNTH-0001")) == "800.00"
    assert format_amount(ledger.total_debited()) == "200.00"


def test_guarded_ledger_replays_the_stored_receipt():
    """The control: the second submission returns the first receipt, no new posting."""
    ledger = SyntheticLedger(ControlSet.secure(), window_seconds=0)
    first = ledger.submit(instruction())
    second = ledger.submit(instruction())
    assert first.receipt_id == second.receipt_id
    assert second.replayed is True
    assert second.posting_id == ""
    assert len(ledger.postings) == 1
    assert ledger.duplicated_instructions() == ()
    assert format_amount(ledger.balance_of("ACC-SYNTH-0001")) == "900.00"


def test_guarded_ledger_refuses_a_bad_signature():
    """A wrong signature never reaches the balance."""
    ledger = SyntheticLedger(ControlSet.secure(), window_seconds=0)
    outcome = ledger.submit(instruction(signature="0" * 32))
    assert outcome.status == 401
    assert outcome.accepted is False
    assert outcome.error == "signature_rejected"
    assert ledger.postings == ()
    assert format_amount(ledger.balance_of("ACC-SYNTH-0001")) == "1000.00"


def test_unguarded_ledger_accepts_an_unsigned_instruction():
    """The second control's failure mode: no signature header at all is fine."""
    ledger = SyntheticLedger(ControlSet.vulnerable(), window_seconds=0)
    outcome = ledger.submit(instruction(signature=""))
    assert outcome.status == 200
    assert outcome.accepted is True
    assert len(ledger.postings) == 1


def test_insufficient_funds_is_a_rejection_not_a_finding():
    """A 409 is the ledger working, not the business logic failing."""
    ledger = SyntheticLedger(ControlSet.vulnerable(), window_seconds=0)
    outcome = ledger.submit(Instruction(instruction_id="INS-B0000002", amount="5000.00"))
    assert outcome.status == 409
    assert outcome.error == "insufficient_funds"
    assert ledger.postings == ()


def test_snapshot_holds_the_observation_fields():
    """Balances, postings, duplicates and the arm - what the report reads back."""
    ledger = SyntheticLedger(ControlSet.vulnerable(), window_seconds=0)
    ledger.submit(instruction())
    snapshot = ledger.snapshot()
    assert snapshot["controls"]["mode"] == "vulnerable"
    assert snapshot["accepted_requests"] == 1
    assert len(snapshot["postings"]) == 1
    assert snapshot["duplicated_instructions"] == []
    assert snapshot["balances"]["ACC-SYNTH-0001"] == "900.00"


def test_negative_window_is_rejected():
    """A negative contention window would mean a negative sleep."""
    with pytest.raises(LedgerRejection):
        SyntheticLedger(ControlSet.vulnerable(), window_seconds=-0.1)


def test_posting_and_outcome_contracts():
    """Both value objects validate and render, and the JSON keys never vary."""
    posting = Posting(
        posting_id="PST-0001",
        instruction_id="INS-A0000001",
        receipt_id="RCP-0001",
        debit_account="ACC-SYNTH-0001",
        credit_account="ACC-SYNTH-0002",
        amount="100.00",
        sequence=1,
    )
    assert "PST-0001" in posting.line()
    assert posting.to_dict()["sequence"] == 1
    with pytest.raises(LedgerRejection):
        Posting(
            posting_id="",
            instruction_id="INS-A0000001",
            receipt_id="RCP-0001",
            debit_account="ACC-SYNTH-0001",
            credit_account="ACC-SYNTH-0002",
            amount="100.00",
            sequence=1,
        )
    with pytest.raises(LedgerRejection):
        Posting(
            posting_id="PST-0000",
            instruction_id="INS-A0000001",
            receipt_id="RCP-0001",
            debit_account="ACC-SYNTH-0001",
            credit_account="ACC-SYNTH-0002",
            amount="100.00",
            sequence=0,
        )
    accepted = TransferOutcome(status=200, accepted=True)
    assert accepted.ok
    assert accepted.to_dict()["status"] == 200
    assert TransferOutcome(status=401, accepted=False).ok is False


# --------------------------------------------------------- observability ----
def _access(seq: int = 1, **overrides: object) -> AccessRecord:
    """A well-formed access record with the boring fields filled in."""
    fields: dict[str, object] = {
        "method": "POST",
        "path": "/mock/v1/transfer",
        "instruction_id": "INS-A0000001",
        "status": 200,
        "accepted": True,
        "posted": True,
        "replayed": False,
        "signature_present": True,
        "duplicates_after": 0,
    }
    fields.update(overrides)
    return AccessRecord(seq=seq, **fields)  # type: ignore[arg-type]


def test_a_clean_request_raises_no_signal():
    """Correct behaviour must be quiet, or the detector is noise."""
    assert _access().signals() == ()


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"signature_present": False}, ("unsigned_accepted",)),
        ({"duplicates_after": 1}, ("duplicate_posting",)),
        ({"replayed": True, "posted": False}, ("idempotent_replay",)),
        ({"status": 401, "accepted": False, "posted": False}, ("rejected_request",)),
    ],
)
def test_signals_are_derived_from_fields(overrides, expected):
    """Each signal is one field, so a reader can reproduce the rule by eye."""
    assert _access(**overrides).signals() == expected


def test_signals_combine_and_sort():
    """Two problems in one request produce two signals, in a stable order."""
    record = _access(signature_present=False, duplicates_after=2)
    assert record.signals() == ("duplicate_posting", "unsigned_accepted")
    assert "unsigned_accepted" in record.line()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"seq": 0},
        {"path": ""},
        {"status": 99},
        {"duplicates_after": -1},
    ],
)
def test_access_record_rejects_impossible_values(kwargs):
    """A record that cannot exist must not be constructible."""
    with pytest.raises(DataContractError):
        _access(**kwargs)


def test_log_numbers_records_under_concurrency():
    """Twenty threads appending at once must still produce 1..20 exactly once."""
    log = ObservabilityLog()

    def append() -> None:
        log.record(
            method="POST",
            path="/mock/v1/transfer",
            instruction_id="INS-A0000001",
            status=200,
            accepted=True,
            posted=True,
            replayed=False,
            signature_present=True,
            duplicates_after=0,
        )

    threads = [threading.Thread(target=append) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(record.seq for record in log.records) == list(range(1, 21))
    assert len(log) == 20
    assert log.next_seq() == 21


def test_log_collects_counts_and_serialises():
    """``collect`` filters by signal, ``signal_counts`` aggregates, ``to_jsonl`` parses."""
    log = ObservabilityLog()
    log.record(
        method="POST",
        path="/mock/v1/transfer",
        instruction_id="INS-A0000001",
        status=200,
        accepted=True,
        posted=True,
        replayed=False,
        signature_present=False,
        duplicates_after=0,
    )
    log.record(
        method="POST",
        path="/mock/v1/transfer",
        instruction_id="INS-A0000001",
        status=200,
        accepted=True,
        posted=True,
        replayed=False,
        signature_present=True,
        duplicates_after=1,
    )
    assert len(log.collect(["duplicate_posting"])) == 1
    assert log.signal_counts() == {"duplicate_posting": 1, "unsigned_accepted": 1}
    assert len(log.to_jsonl().strip().splitlines()) == 2
    summary = log.summary()
    assert summary["requests"] == 2
    assert summary["posted"] == 2
    assert summary["rejected"] == 0
    assert json.loads(log.to_jsonl().splitlines()[1])["duplicates_after"] == 1


# -------------------------------------------------------------- scenario ----
def _scenario(**overrides: object) -> Scenario:
    """A minimal valid scenario; tests override one field at a time."""
    fields: dict[str, object] = {
        "name": "demo",
        "title": "示例剧本",
        "steps": (Step(instruction_id="INS-A0000001"),),
    }
    fields.update(overrides)
    return Scenario(**fields)  # type: ignore[arg-type]


def test_scenario_defaults_point_at_the_ontology():
    """An omitted field means the benchmark's own process, route and control."""
    scenario = _scenario()
    assert scenario.process == "Fund_Transfer_Process"
    assert scenario.target_api == "Transfer_API"
    assert scenario.control == "Idempotency_Token"
    assert scenario.endpoint == "/mock/v1/transfer"
    assert scenario.requests == 1
    assert scenario.sends_unsigned is False
    assert scenario.to_dict()["expect_secure"] == "none"


def test_scenario_derived_counts():
    """Distinct ids, request totals and the unsigned flag come from the steps."""
    scenario = _scenario(
        steps=(
            Step(instruction_id="INS-A0000001", repeat=3),
            Step(instruction_id="INS-B0000002", action="concurrent_transfer", workers=4),
            Step(instruction_id="INS-C0000003", action="unsigned_transfer"),
        )
    )
    assert scenario.instruction_ids == ("INS-A0000001", "INS-B0000002", "INS-C0000003")
    assert scenario.requests == 8
    assert scenario.sends_unsigned is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"name": "Bad-Name"},
        {"name": "x" * 49},
        {"title": "   "},
        {"steps": ()},
        {"endpoint": "mock/v1/transfer"},
        {"process": ""},
        {"expect_vulnerable": "hight"},
    ],
)
def test_scenario_rejects_a_broken_experiment(overrides):
    """A scenario that cannot be read unambiguously must not run."""
    with pytest.raises(DataContractError):
        _scenario(**overrides)


def test_expectation_needs_a_known_arm():
    """``partial`` has no prediction: guessing one would invent a result."""
    scenario = _scenario(expect_vulnerable="high", expect_secure="none")
    assert scenario.expectation("vulnerable") is RiskLevel.HIGH
    assert scenario.expectation("secure") is RiskLevel.NONE
    with pytest.raises(DataContractError):
        scenario.expectation("partial")


@pytest.mark.parametrize(
    "overrides",
    [
        {"action": "flood"},
        {"amount": ""},
        {"repeat": 0},
        {"repeat": MAX_REPEAT + 1},
        {"workers": 0},
        {"workers": MAX_WORKERS + 1},
    ],
)
def test_step_rejects_an_unbounded_or_unknown_action(overrides):
    """The bounds are the difference between a lab and a load generator."""
    fields: dict[str, object] = {"instruction_id": "INS-A0000001"}
    fields.update(overrides)
    with pytest.raises(DataContractError):
        Step(**fields)  # type: ignore[arg-type]


def test_step_rejects_a_blank_id():
    """The business id is what a duplicate-detection rule joins on: not blank."""
    with pytest.raises(DataContractError):
        Step(instruction_id="   ")


def test_step_derived_shape():
    """``signed``, ``concurrency`` and ``requests`` are what the runner branches on."""
    sequential = Step(instruction_id="INS-A0000001", repeat=2)
    assert sequential.signed and sequential.concurrency == 1 and sequential.requests == 2
    parallel = Step(instruction_id="INS-B0000002", action="concurrent_transfer", workers=5)
    assert parallel.concurrency == 5 and parallel.requests == 5
    unsigned = Step(instruction_id="INS-C0000003", action="unsigned_transfer")
    assert unsigned.signed is False and unsigned.requests == 1
    assert "sequential" in sequential.line()


def test_as_risk_level_coerces_known_names_only():
    """A level is accepted as enum or as its spelling, and nothing else."""
    assert as_risk_level(RiskLevel.CRITICAL) is RiskLevel.CRITICAL
    assert as_risk_level("HIGH") is RiskLevel.HIGH
    assert as_risk_level(None) is RiskLevel.NONE
    with pytest.raises(DataContractError):
        as_risk_level("severe")


def test_scenario_from_dict_rejects_structural_problems():
    """Missing keys, unknown keys, a non-list ``steps``, a bad step."""
    with pytest.raises(DataContractError):
        scenario_from_dict(["not", "an", "object"])
    with pytest.raises(DataContractError):
        scenario_from_dict({"name": "demo"})
    with pytest.raises(DataContractError):
        scenario_from_dict(
            {"name": "demo", "title": "t", "steps": [{"instruction_id": "INS-1"}], "extra": 1}
        )
    with pytest.raises(DataContractError):
        scenario_from_dict({"name": "demo", "title": "t", "steps": "nope"})
    with pytest.raises(DataContractError):
        scenario_from_dict({"name": "demo", "title": "t", "steps": []})
    with pytest.raises(DataContractError):
        scenario_from_dict({"name": "demo", "title": "t", "steps": ["nope"]})
    with pytest.raises(DataContractError):
        scenario_from_dict(
            {"name": "demo", "title": "t", "steps": [{"instruction_id": "INS-1", "x": 1}]}
        )


def test_load_scenario_reports_missing_and_broken_files(tmp_path):
    """A missing file and a non-JSON file are contract errors, not crashes."""
    with pytest.raises(DataContractError):
        load_scenario(tmp_path / "absent.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(DataContractError):
        load_scenario(broken)


def test_shipped_scenarios_load_and_are_ordered():
    """The three shipped files parse, and the directory is read in name order."""
    scenarios = load_scenarios()
    assert [item.name for item in scenarios] == [
        "concurrent_transfer",
        "replay_transfer",
        "unsigned_transfer",
    ]
    assert SCENARIO_DIR.is_dir()
    assert load_scenarios(SCENARIO_DIR)[0].requests >= 1


def test_empty_scenario_directory_is_an_error(tmp_path):
    """Silently running nothing would read as "no findings"."""
    with pytest.raises(DataContractError):
        load_scenarios(tmp_path)


# ---------------------------------------------------------------- oracle ----
def _posting(instruction_id: str, sequence: int, amount: str = "100.00") -> Posting:
    """A ledger posting, hand-built so the oracle can be tested without a socket."""
    return Posting(
        posting_id="PST-%04d" % sequence,
        instruction_id=instruction_id,
        receipt_id="RCP-%04d" % sequence,
        debit_account="ACC-SYNTH-0001",
        credit_account="ACC-SYNTH-0002",
        amount=amount,
        sequence=sequence,
    )


def test_sequential_replay_is_high_not_critical():
    """One clause is broken (level 3), so the ladder stops at ``HIGH``."""
    scenario = _scenario(
        steps=(Step(instruction_id="INS-A0000001", repeat=2),), expect_vulnerable="high"
    )
    assessment = assess(
        scenario,
        controls=ControlSet.vulnerable(),
        postings=(_posting("INS-A0000001", 1), _posting("INS-A0000001", 2)),
        access=(_access(1), _access(2)),
    )
    assert assessment.flaws == ("Duplicate_Debit", "Replay_Attack")
    assert assessment.risk is RiskLevel.HIGH
    assert assessment.passed is True
    assert len(assessment.findings) == 2
    assert assessment.controls_missing == ("Idempotency_Token", "Signature_Verification")
    assert "2 条分录" in " ".join(assessment.evidence)


def test_concurrency_reaches_critical():
    """Two clauses (level 3 and the API spec) - the ladder's top rung."""
    scenario = _scenario(
        steps=(Step(instruction_id="INS-B0000002", action="concurrent_transfer", workers=4),),
        expect_vulnerable="critical",
    )
    postings = tuple(_posting("INS-B0000002", index) for index in (1, 2, 3))
    assessment = assess(
        scenario,
        controls=ControlSet.vulnerable(),
        postings=postings,
        access=tuple(_access(index) for index in (1, 2, 3)),
    )
    assert "Race_Condition" in assessment.flaws
    assert assessment.risk is RiskLevel.CRITICAL
    assert assessment.passed is True


def test_unsigned_request_is_reported_as_an_ontology_gap():
    """Observed, mapped to the control, but with no clause the graph can carry."""
    scenario = _scenario(
        steps=(Step(instruction_id="INS-C0000003", action="unsigned_transfer"),),
        control="Signature_Verification",
        expect_vulnerable="medium",
    )
    assessment = assess(
        scenario,
        controls=ControlSet.vulnerable(),
        postings=(_posting("INS-C0000003", 1),),
        access=(_access(1, signature_present=False),),
    )
    assert assessment.flaws == ("Unsigned_Instruction_Accepted",)
    assert assessment.ontology_gaps == ("Unsigned_Instruction_Accepted",)
    assert "Unsigned_Instruction_Accepted" not in MODELLED_FLAWS
    assert assessment.findings[0].control == "Signature_Verification"
    assert assessment.risk is RiskLevel.MEDIUM
    assert assessment.passed is True
    assert any("ontology gap" in line for line in assessment.lines())


def test_secure_arm_scores_none():
    """No gaps, no findings: the guarded arm has nothing to report."""
    assessment = assess(
        _scenario(expect_secure="none"),
        controls=ControlSet.secure(),
        postings=(_posting("INS-A0000001", 1),),
        access=(_access(1),),
    )
    assert assessment.risk is RiskLevel.NONE
    assert assessment.gaps == ()
    assert assessment.findings == ()
    assert assessment.controls_missing == ()
    assert "none" in assessment.lines()[1]


def test_a_missed_prediction_is_visible():
    """One posting where two were predicted is a MISMATCH, not a quiet pass."""
    assessment = assess(
        _scenario(expect_vulnerable="critical"),
        controls=ControlSet.vulnerable(),
        postings=(_posting("INS-A0000001", 1),),
        access=(_access(1),),
    )
    assert assessment.passed is False
    assert "MISMATCH" in assessment.verdict_line()


def test_required_controls_are_the_graphs_two_edges():
    """The dynamic mirror of ``REQUIRES_CONTROL`` stays the two controls of stage 10."""
    assert REQUIRED_CONTROLS == ("Idempotency_Token", "Signature_Verification")


def test_assess_rejects_wrong_types():
    """A string is not a scenario, and a string is not an arm."""
    with pytest.raises(DataContractError):
        assess("nope", controls=ControlSet.vulnerable(), postings=(), access=())
    with pytest.raises(DataContractError):
        assess(_scenario(), controls="vulnerable", postings=(), access=())


def test_assessment_validates_its_own_fields():
    """A report that contradicts itself must not be constructible."""
    with pytest.raises(DataContractError):
        RangeAssessment(scenario="", mode="vulnerable", target_api="Transfer_API", process="P")
    with pytest.raises(DataContractError):
        RangeAssessment(
            scenario="s", mode="vulnerable", target_api="Transfer_API", process="P", requests=-1
        )


# --------------------------------------------------------------- gateway ----
def _exchange(base_url: str, method: str, path: str, body: bytes | None = None) -> tuple[int, dict]:
    """One raw exchange against a gateway, for the route-level tests."""
    from http.client import HTTPConnection

    host, port = split_base_url(base_url + path)
    connection = HTTPConnection(host, port, timeout=5.0)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        return response.status, payload
    finally:
        connection.close()


def test_gateway_health_and_ledger_routes():
    """The two read routes describe the arm and let a lab look at its own ledger."""
    with MockGatewayServer(ControlSet.vulnerable(), window_seconds=WINDOW) as gateway:
        assert gateway.base_url.startswith("http://127.0.0.1:")
        status, payload = _exchange(gateway.base_url, "GET", HEALTH_PATH)
        assert status == 200 and payload["status"] == "ok"
        assert payload["mode"] == "vulnerable"
        status, payload = _exchange(gateway.base_url, "GET", LEDGER_PATH)
        assert status == 200 and payload["postings"] == []
        assert gateway.mode == "vulnerable"


def test_gateway_refuses_unknown_routes_and_bodies():
    """404 for a route that does not exist, 400 for a body that is not JSON."""
    with MockGatewayServer(ControlSet.vulnerable(), window_seconds=WINDOW) as gateway:
        status, payload = _exchange(gateway.base_url, "GET", "/mock/v1/nope")
        assert status == 404 and payload["error"] == "unknown_route"
        status, payload = _exchange(gateway.base_url, "POST", "/mock/v1/transfer", b"not json")
        assert status == 400 and payload["error"] == "bad_body"
        status, payload = _exchange(gateway.base_url, "POST", "/mock/v1/transfer", b"[]")
        assert status == 400 and payload["error"] == "bad_body"
        status, payload = _exchange(gateway.base_url, "POST", "/mock/v1/transfer", b"{}")
        assert status == 400 and payload["error"] == "invalid_instruction"


def test_gateway_lifecycle_guards():
    """Binding elsewhere is a SafetyViolation; starting twice is a contract error."""
    with pytest.raises(SafetyViolation):
        MockGatewayServer(ControlSet.vulnerable(), host="0.0.0.0")
    gateway = MockGatewayServer(ControlSet.vulnerable(), window_seconds=WINDOW)
    with pytest.raises(LedgerRejection):
        gateway.url_for(HEALTH_PATH)  # not started yet
    gateway.start()
    try:
        with pytest.raises(LedgerRejection):
            gateway.start()
        with pytest.raises(LedgerRejection):
            gateway.url_for("/mock/v1/nope")
    finally:
        gateway.stop()
        gateway.stop()  # idempotent


# ---------------------------------------------------------------- runner ----
def test_runner_reproduces_the_replay_over_a_socket():
    """The vulnerable arm pays twice for one instruction, and the run says so."""
    scenario = load_scenario(SCENARIO_DIR / "replay_transfer.json")
    run = run_scenario(scenario, ControlSet.vulnerable(), window_seconds=WINDOW)
    assert run.passed is True
    assert run.assessment.risk is RiskLevel.HIGH
    assert len(run.ledger["postings"]) == 2
    assert run.base_url.startswith("http://127.0.0.1:")
    assert len(run.results) == 2
    assert all(result.status == 200 for result in run.results)
    assert "posting(s)" in "\n".join(run.lines(verbose=True))


def test_runner_secure_arm_replays_instead_of_posting():
    """The guarded arm answers 200 with the stored receipt and posts once."""
    scenario = load_scenario(SCENARIO_DIR / "replay_transfer.json")
    run = run_scenario(scenario, ControlSet.secure(), window_seconds=WINDOW)
    assert run.passed is True
    assert run.assessment.risk is RiskLevel.NONE
    assert len(run.ledger["postings"]) == 1
    assert any(result.payload.get("replayed") for result in run.results)
    assert any("idempotent_replay" in record.signals() for record in run.access)


def test_runner_concurrent_arm_races_then_is_blocked():
    """Eight simultaneous requests: many postings unguarded, one guarded."""
    scenario = load_scenario(SCENARIO_DIR / "concurrent_transfer.json")
    vulnerable = run_scenario(scenario, ControlSet.vulnerable(), window_seconds=WINDOW)
    secure = run_scenario(scenario, ControlSet.secure(), window_seconds=WINDOW)
    assert vulnerable.passed is True
    assert vulnerable.assessment.risk is RiskLevel.CRITICAL
    assert len(vulnerable.ledger["postings"]) > 1
    assert secure.passed is True
    assert secure.assessment.risk is RiskLevel.NONE
    assert len(secure.ledger["postings"]) == 1


def test_runner_unsigned_request_is_refused_by_the_secure_arm():
    """No signature header: accepted unguarded, ``401`` and no posting guarded."""
    scenario = load_scenario(SCENARIO_DIR / "unsigned_transfer.json")
    vulnerable = run_scenario(scenario, ControlSet.vulnerable(), window_seconds=WINDOW)
    secure = run_scenario(scenario, ControlSet.secure(), window_seconds=WINDOW)
    assert vulnerable.passed is True
    assert vulnerable.assessment.risk is RiskLevel.MEDIUM
    assert len(vulnerable.ledger["postings"]) == 1
    assert secure.passed is True
    assert secure.ledger["postings"] == []
    assert secure.results[0].status == 401


def test_runner_both_arms_helper():
    """The helper returns the unguarded arm first, then the guarded one."""
    scenario = load_scenario(SCENARIO_DIR / "replay_transfer.json")
    unguarded, guarded = run_scenario_both_arms(scenario, window_seconds=WINDOW)
    assert unguarded.mode == "vulnerable" and guarded.mode == "secure"


def test_runner_rejects_a_remote_target_and_a_non_scenario():
    """The client refuses a public base URL; the runner refuses a non-scenario."""
    with pytest.raises(SafetyViolation):
        post_instruction("http://example.com:8080", "/mock/v1/transfer", {})
    with pytest.raises(DataContractError):
        run_scenario("nope")


def test_http_result_shape():
    """Transport failures are data, and the JSON keys are stable."""
    assert HttpResult(status=200, payload={"accepted": True}).accepted is True
    failed = HttpResult(status=0, payload={}, error="connection refused")
    assert failed.to_dict() == {"status": 0, "accepted": False, "error": "connection refused"}
    assert failed.ok is False


# ---------------------------------------------------------------- report ----
@pytest.fixture(scope="module")
def replay_runs():
    """Both arms of the replay scenario, run once for the reporting tests."""
    scenario = load_scenario(SCENARIO_DIR / "replay_transfer.json")
    return run_scenario_both_arms(scenario, window_seconds=WINDOW)


@pytest.fixture(scope="module")
def static_report():
    """The stage-10 assessment of the same route, for the comparison section."""
    return analyze_logic_risk(KnowledgeGraph.load_json(DEFAULT_GRAPH), DEFAULT_API)


def test_empty_report_is_vacuously_passed():
    """No runs means nothing mismatched - but the comparison says it was skipped."""
    report = RangeReport()
    assert report.passed is True
    assert report.worst_observed is RiskLevel.NONE
    assert report.mismatches == ()
    assert "skipped" in "\n".join(report.comparison_lines())


def test_report_renders_a_table_and_a_markdown_document(replay_runs, static_report):
    """The Markdown carries the table, the verdict and the comparison heading."""
    report = RangeReport(replay_runs, static=static_report)
    assert report.passed is True
    assert report.worst_observed is RiskLevel.HIGH
    markdown = report.markdown()
    assert "| `replay_transfer` | vulnerable |" in markdown
    assert "| `replay_transfer` | secure |" in markdown
    assert "PASS" in markdown
    assert "## 3. 静态推演 vs 动态实测" in markdown
    assert report.to_dict()["worst_observed"] == "high"
    assert "\n".join(report.lines()).count("PASS") >= 2


def test_comparison_names_what_one_run_cannot_reproduce(replay_runs, static_report):
    """The static model is a superset of one sequential run, and the report says so."""
    report = RangeReport(replay_runs, static=static_report)
    lines = "\n".join(report.comparison_lines())
    assert "两边都成立" in lines
    assert "静态有、本次未复现: Idempotency_Token/Race_Condition" in lines
    assert "动态有、本体未建模: none" in lines


def test_comparison_lists_unmodelled_findings():
    """An unsigned run adds a pair no static edge carries."""
    scenario = load_scenario(SCENARIO_DIR / "unsigned_transfer.json")
    runs = (run_scenario(scenario, ControlSet.vulnerable(), window_seconds=WINDOW),)
    report = RangeReport(runs)
    pairs = ["%s/%s" % tuple(pair) for pair in report.to_dict()["dynamic_pairs"]]
    assert pairs == ["Signature_Verification/Unsigned_Instruction_Accepted"]


def test_report_validates_its_inputs():
    """A string is neither a run nor a static report."""
    with pytest.raises(DataContractError):
        RangeReport(runs=("nope",))
    with pytest.raises(DataContractError):
        RangeReport(static="nope")


# ------------------------------------------------------------------- cli ----
def test_cli_refuses_an_unknown_scenario(capsys):
    """Asking for a scenario that does not exist must not run the others."""
    assert cli.main(["--scenario", "absent", "--no-static", "--quiet"]) == 2
    assert "no scenario named" in capsys.readouterr().out


def test_cli_refuses_an_absurd_window(capsys):
    """The window is bounded before any server starts."""
    assert cli.main(["--window-ms", "9999"]) == 2
    assert "--window-ms" in capsys.readouterr().out


def test_cli_writes_json_and_markdown(tmp_path):
    """A green run exits 0 and leaves both artefacts behind."""
    json_out = tmp_path / "range.json"
    md_out = tmp_path / "range.md"
    code = cli.main(
        [
            "--scenario",
            "replay_transfer",
            "--mode",
            "secure",
            "--no-static",
            "--json",
            str(json_out),
            "--markdown",
            str(md_out),
        ]
    )
    assert code == 0
    assert json.loads(json_out.read_text(encoding="utf-8"))["passed"] is True
    assert "PASS" in md_out.read_text(encoding="utf-8")


def test_cli_returns_one_on_a_mismatch(tmp_path):
    """A scenario whose prediction the ledger contradicts exits 1."""
    scenario_file = tmp_path / "impossible.json"
    scenario_file.write_text(
        json.dumps(
            {
                "name": "impossible",
                "title": "预测必然落空",
                "expect_vulnerable": "critical",
                "steps": [{"action": "transfer", "instruction_id": "INS-D0000004"}],
            }
        ),
        encoding="utf-8",
    )
    code = cli.main(
        ["--scenario-dir", str(tmp_path), "--mode", "vulnerable", "--no-static", "--quiet"]
    )
    assert code == 1


def test_cli_runs_the_static_comparison(capsys):
    """The default path gates the graph through the TBox and prints the comparison."""
    code = cli.main(["--scenario", "unsigned_transfer", "--mode", "vulnerable"])
    out = capsys.readouterr().out
    assert code == 0
    assert "TBox gate" in out
    assert "静态推演" in out


def test_cli_reports_an_unreadable_graph(tmp_path, capsys):
    """A missing or non-JSON graph exits 2 instead of comparing against nothing."""
    assert cli.main(["--graph", str(tmp_path / "absent.json"), "--quiet"]) == 2
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cli.main(["--graph", str(broken), "--quiet"]) == 2
    assert "cannot read" in capsys.readouterr().out


def test_cli_refuses_a_graph_that_breaks_the_tbox(tmp_path, capsys):
    """A self-loop edge is a TBox error, so the comparison is refused with exit 1."""
    graph = {
        "nodes": [{"name": "Transfer_API", "definition": "a route", "category": "api_endpoint"}],
        "edges": [
            {
                "source_concept": "Transfer_API",
                "target_concept": "Transfer_API",
                "relation_type": "LACKS_CONTROL",
                "confidence_score": 0.5,
                "evidence": "deliberately a self-loop",
            }
        ],
        "chunk_ids": ["range#bad"],
    }
    path = tmp_path / "bad_graph.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    assert cli.main(["--graph", str(path), "--quiet"]) == 1
    assert "refusing to compare" in capsys.readouterr().out


def test_cli_reports_an_unknown_starting_route(capsys):
    """A route that is not in the graph exits 2 instead of reporting "nothing found"."""
    assert cli.main(["--api", "NoSuch_API", "--quiet"]) == 2
    assert "cannot assess" in capsys.readouterr().out


# ------------------------------------------------------- safety / serve ----
def test_container_bind_needs_the_explicit_opt_in(monkeypatch):
    """``0.0.0.0`` is refused on a workstation and allowed only inside the image."""
    monkeypatch.delenv(CONTAINER_BIND_ENV, raising=False)
    with pytest.raises(SafetyViolation):
        ensure_bind_host("0.0.0.0")
    monkeypatch.setenv(CONTAINER_BIND_ENV, "1")
    assert ensure_bind_host("0.0.0.0") == "0.0.0.0"


def test_serve_rejects_out_of_range_arguments(capsys):
    """The two numeric knobs are bounded before a socket exists."""
    assert serve.main(["--window-ms", "9999"]) == 2
    assert serve.main(["--port", "80"]) == 2
    assert "--window-ms" in capsys.readouterr().out


class _RefusingGateway:
    """A stand-in for :class:`MockGatewayServer` that refuses to bind."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise SafetyViolation("refusing to bind here", host="0.0.0.0")


def test_serve_reports_a_refused_bind(monkeypatch, capsys):
    """A gateway that refuses to bind exits 2 with the boundary message."""
    monkeypatch.setattr(serve, "MockGatewayServer", _RefusingGateway)
    assert serve.main(["--port", "18080"]) == 2
    assert "refusing to bind" in capsys.readouterr().out


def test_serve_serves_until_interrupted(monkeypatch):
    """The container entry point really serves, and shuts down on interrupt."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    seen: dict[str, object] = {}

    def fake_wait() -> None:
        status, payload = _exchange("http://127.0.0.1:%d" % port, "GET", HEALTH_PATH)
        seen["status"] = status
        seen["mode"] = payload["mode"]
        raise KeyboardInterrupt

    monkeypatch.setattr(serve, "_wait_forever", fake_wait)
    assert serve.main(["--mode", "secure", "--port", str(port)]) == 0
    assert seen == {"status": 200, "mode": "secure"}
