# -*- coding: utf-8 -*-
"""Run one scenario against one arm: real sockets, loopback only, bounded work.

The client
----------
``http.client`` from the standard library, one connection per request (the gateway
closes after each response on purpose - see :mod:`fin_logic_cyber_range.gateway`).
Every URL passes through :func:`~fin_logic_cyber_range.safety.ensure_local_url`
before a socket is created, so the runner cannot reach a host the package does not
already allow; a scenario's ``endpoint`` is a path, never a URL, which removes the
last place a user could paste one in.

Concurrency, and why the barrier
--------------------------------
"Two requests at the same time" is only true if both threads are past their setup
when the first one is sent. A naive ``ThreadPoolExecutor.map`` starts them one after
another, and on a fast machine the first may finish before the last starts - the race
then never happens and the experiment silently becomes a sequential replay.
:func:`_fire_together` therefore parks every worker on a :class:`threading.Barrier`
and releases them together, with a timeout so a broken worker cannot hang the run.

Cost is bounded by the scenario format itself (``workers <= 32``, ``repeat <= 8``),
and nothing retries: a run makes exactly the requests the file describes, so the
number of log lines is something a reader can predict from the scenario.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.client import HTTPConnection
from typing import Any

from fin_logic_cyber_range.gateway import SIGNATURE_HEADER, MockGatewayServer
from fin_logic_cyber_range.ledger import ControlSet, Instruction, instruction_signature
from fin_logic_cyber_range.observability import AccessRecord
from fin_logic_cyber_range.oracle import RangeAssessment, assess
from fin_logic_cyber_range.safety import ensure_local_url, split_base_url
from fin_logic_cyber_range.scenario import Scenario
from ontology_builder.core.errors import DataContractError

REQUEST_TIMEOUT = 5.0
BARRIER_TIMEOUT = 5.0


@dataclass(frozen=True)
class HttpResult:
    """One exchange, flattened to what the report needs.

    Attributes:
        status: HTTP status, or ``0`` when the socket itself failed.
        payload: decoded JSON body (``{}`` when there was none).
        error: transport-level failure text, empty on success.
    """

    status: int
    payload: dict[str, Any]
    error: str = ""

    @property
    def ok(self) -> bool:
        """True for a 2xx status with a decoded body."""
        return 200 <= self.status < 300

    @property
    def accepted(self) -> bool:
        """Whether the gateway reported the instruction as accepted."""
        return bool(self.payload.get("accepted"))

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {"status": self.status, "accepted": self.accepted, "error": self.error}


def post_instruction(
    base_url: str,
    endpoint: str,
    body: dict[str, Any],
    *,
    signature: str = "",
    timeout: float = REQUEST_TIMEOUT,
) -> HttpResult:
    """POST one JSON body to ``base_url + endpoint``.

    Args:
        base_url: normalized gateway base URL (``http://127.0.0.1:<port>``).
        endpoint: route path, e.g. ``/mock/v1/transfer``.
        body: JSON-serialisable request body.
        signature: value for the signature header; empty means "send none", which
            is what the unsigned scenario needs.
        timeout: socket timeout in seconds.

    Returns:
        An :class:`HttpResult`; transport failures are *data* (``status=0``), not
        exceptions, so one refused connection cannot abort a whole run.

    Raises:
        SafetyViolation: when ``base_url + endpoint`` is not a local mock.
    """
    url = ensure_local_url(base_url.rstrip("/") + endpoint)
    host, port = split_base_url(url)
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if signature:
        headers[SIGNATURE_HEADER] = signature
    connection = HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("POST", endpoint, body=json.dumps(body), headers=headers)
        response = connection.getresponse()
        status = response.status
        raw = response.read()
    except OSError as exc:
        return HttpResult(status=0, payload={}, error=str(exc))
    finally:
        connection.close()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return HttpResult(status=status, payload={}, error="non-JSON response: %s" % exc)
    if not isinstance(payload, dict):
        return HttpResult(status=status, payload={}, error="response is not a JSON object")
    return HttpResult(status=status, payload=payload)


def _fire_together(
    base_url: str,
    endpoint: str,
    body: dict[str, Any],
    *,
    signature: str,
    workers: int,
) -> list[HttpResult]:
    """Send ``workers`` identical requests, released by a barrier, and collect them."""
    barrier = threading.Barrier(workers)
    collected: list[HttpResult | None] = [None] * workers

    def worker(index: int) -> None:
        try:
            barrier.wait(timeout=BARRIER_TIMEOUT)
        except threading.BrokenBarrierError:
            pass  # a slow sibling should not cost us the whole run
        collected[index] = post_instruction(base_url, endpoint, body, signature=signature)

    threads = [
        threading.Thread(
            target=worker, args=(index,), name="range-client-%02d" % index, daemon=True
        )
        for index in range(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=REQUEST_TIMEOUT * 2)
    return [item for item in collected if item is not None]


@dataclass(frozen=True)
class ScenarioRun:
    """One scenario, one arm: the requests, the observation log and the verdict.

    Attributes:
        scenario: the experiment that was run.
        mode: ``"vulnerable"``, ``"secure"`` or ``"partial"``.
        base_url: the loopback base URL the arm served on.
        results: one :class:`HttpResult` per request, in send order.
        access: the gateway's own observation log for the run.
        assessment: the scored verdict.
        ledger: JSON snapshot of the ledger at the end of the run.
    """

    scenario: Scenario
    mode: str
    base_url: str
    results: tuple[HttpResult, ...]
    access: tuple[AccessRecord, ...]
    assessment: RangeAssessment
    ledger: dict[str, Any]

    @property
    def passed(self) -> bool:
        """Whether the observed risk matched the scenario's prediction."""
        return self.assessment.passed

    def lines(self, *, verbose: bool = False) -> list[str]:
        """The console block for one run.

        Args:
            verbose: also print every access record - useful when a run mismatches,
                noisy when it does not.
        """
        out = [
            "  %s  [%s]  %s" % (self.scenario.name, self.mode, self.scenario.title),
            "    endpoint      : %s%s" % (self.base_url, self.scenario.endpoint),
        ]
        for step in self.scenario.steps:
            out.append(step.line())
        out.extend(self.assessment.lines())
        balances = ", ".join(
            "%s=%s" % (name, value)
            for name, value in sorted(self.ledger.get("balances", {}).items())
        )
        postings = self.ledger.get("postings", [])
        out.append("    ledger        : %d posting(s), balances %s" % (len(postings), balances))
        if verbose:
            for record in self.access:
                out.append(record.line())
        return out

    def to_dict(self) -> dict[str, Any]:
        """JSON form: the scenario, the verdict, the log and the ledger."""
        return {
            "scenario": self.scenario.to_dict(),
            "mode": self.mode,
            "base_url": self.base_url,
            "passed": self.passed,
            "assessment": self.assessment.to_dict(),
            "responses": [item.to_dict() for item in self.results],
            "access": [item.to_dict() for item in self.access],
            "ledger": self.ledger,
        }


def run_scenario(
    scenario: Scenario,
    controls: ControlSet | None = None,
    *,
    window_seconds: float = 0.02,
) -> ScenarioRun:
    """Start an arm, play the scenario's steps, stop the arm, score the result.

    The server lives exactly as long as the run: it is started, used, and closed
    inside this function, so a failed assertion in a test cannot leak a listener.

    Args:
        scenario: what the client does.
        controls: the arm to serve; defaults to :meth:`ControlSet.vulnerable`.
        window_seconds: contention window forwarded to the ledger - ignored by the
            secure arm, whose gate lock covers the whole check-and-post.

    Returns:
        A :class:`ScenarioRun` with the responses, the access log, the ledger
        snapshot and the assessment.

    Raises:
        DataContractError: when ``scenario`` is not a :class:`Scenario`.
    """
    if not isinstance(scenario, Scenario):
        raise DataContractError("run_scenario needs a Scenario", got=type(scenario).__name__)
    arm = controls if controls is not None else ControlSet.vulnerable()
    results: list[HttpResult] = []
    with MockGatewayServer(arm, window_seconds=window_seconds) as gateway:
        base_url = gateway.base_url
        for step in scenario.steps:
            body = Instruction(
                instruction_id=step.instruction_id,
                amount=step.amount,
                debit_account=step.debit_account,
                credit_account=step.credit_account,
            ).to_payload()
            signature = (
                instruction_signature(step.instruction_id, step.amount) if step.signed else ""
            )
            if step.concurrency > 1:
                results.extend(
                    _fire_together(
                        base_url,
                        scenario.endpoint,
                        body,
                        signature=signature,
                        workers=step.concurrency,
                    )
                )
            else:
                for _ in range(step.repeat):
                    results.append(
                        post_instruction(base_url, scenario.endpoint, body, signature=signature)
                    )
        access = gateway.log.records
        ledger = gateway.ledger.snapshot()
        assessment = assess(scenario, controls=arm, postings=gateway.ledger.postings, access=access)
    return ScenarioRun(
        scenario=scenario,
        mode=arm.mode,
        base_url=base_url,
        results=tuple(results),
        access=access,
        assessment=assessment,
        ledger=ledger,
    )


def run_scenario_both_arms(
    scenario: Scenario, *, window_seconds: float = 0.02
) -> tuple[ScenarioRun, ScenarioRun]:
    """Run the unguarded arm and the guarded arm back to back, in that order."""
    return (
        run_scenario(scenario, ControlSet.vulnerable(), window_seconds=window_seconds),
        run_scenario(scenario, ControlSet.secure(), window_seconds=window_seconds),
    )
