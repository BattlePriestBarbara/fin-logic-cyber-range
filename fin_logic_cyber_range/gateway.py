# -*- coding: utf-8 -*-
"""A mock transfer gateway built on ``http.server`` - the thing under test.

Three routes, and the third one is the only interesting one
-----------------------------------------------------------
======================  ======  =================================================
route                   verb    answer
======================  ======  =================================================
``/mock/v1/health``     GET     ``{"status": "ok", "mode": ...}``; proves the
                                harness is up before a scenario runs
``/mock/v1/ledger``     GET     balances, postings, duplicated instructions - the
                                *observation* endpoint, which exists because a
                                laboratory is allowed to look at its own ledger
``/mock/v1/transfer``   POST    the business route: build an ``Instruction`` from
                                the body, hand it to the ledger, report what
                                happened
======================  ======  =================================================

The gateway itself decides nothing. It parses, delegates to
:class:`~fin_logic_cyber_range.ledger.SyntheticLedger`, and logs. Every control is a
branch inside the ledger, which is what makes "same scenario, one flag flipped" a
one-line change rather than two code paths that drift.

Two deliberate simplifications
------------------------------
* **HTTP/1.1 with ``Connection: close``.** Keep-alive would let a ``http.client``
  instance reuse a socket across the concurrent run, and a pooled connection makes
  "N simultaneous requests" quietly serialise. Closing per response keeps the
  concurrency real and the code short.
* **A 64 KiB body cap.** A lab request is a few hundred bytes; anything larger is
  a bug in the caller, and reading it unbounded would be the only unbounded buffer
  in this package.

Binding
-------
:func:`~fin_logic_cyber_range.safety.ensure_bind_host` is called before the socket
exists, so ``0.0.0.0`` is not a configuration option - it is a ``SafetyViolation``.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from fin_logic_cyber_range.ledger import (
    DEFAULT_CREDIT,
    DEFAULT_DEBIT,
    ControlSet,
    Instruction,
    LedgerRejection,
    SyntheticLedger,
    format_amount,
)
from fin_logic_cyber_range.observability import AccessRecord, ObservabilityLog
from fin_logic_cyber_range.safety import BIND_HOST, ensure_bind_host

TRANSFER_PATH = "/mock/v1/transfer"
HEALTH_PATH = "/mock/v1/health"
LEDGER_PATH = "/mock/v1/ledger"
ROUTES = (HEALTH_PATH, LEDGER_PATH, TRANSFER_PATH)

#: Header a well-behaved client puts its signature in. Named ``X-Lab-`` so a
#: captured request cannot be mistaken for a real scheme's header.
SIGNATURE_HEADER = "X-Lab-Signature"

MAX_BODY_BYTES = 64 * 1024


class GatewayState:
    """What handler threads share: the ledger under test and the observation log.

    Args:
        controls: the arm being measured.
        window_seconds: forwarded to :class:`SyntheticLedger`.
    """

    def __init__(self, controls: ControlSet, *, window_seconds: float = 0.02) -> None:
        self.controls = controls
        self.ledger = SyntheticLedger(controls, window_seconds=window_seconds)
        self.log = ObservabilityLog()

    @property
    def mode(self) -> str:
        """``"vulnerable"``, ``"secure"`` or ``"partial"``."""
        return self.controls.mode

    def health(self) -> dict[str, Any]:
        """The liveness answer, including which controls this arm enforces."""
        return {
            "status": "ok",
            "mode": self.mode,
            "controls": self.controls.to_dict(),
            "routes": list(ROUTES),
        }

    def ledger_view(self) -> dict[str, Any]:
        """The observation endpoint's payload."""
        return self.ledger.snapshot()

    def record(
        self,
        *,
        method: str,
        path: str,
        instruction_id: str,
        status: int,
        accepted: bool,
        posted: bool,
        replayed: bool,
        signature_present: bool,
    ) -> AccessRecord:
        """Append this request to the observation log and return the record."""
        return self.log.record(
            method=method,
            path=path,
            instruction_id=instruction_id,
            status=status,
            accepted=accepted,
            posted=posted,
            replayed=replayed,
            signature_present=signature_present,
            duplicates_after=len(self.ledger.duplicated_instructions()),
        )


class _MockGatewayHandler(BaseHTTPRequestHandler):
    """One class per request: parse, delegate, log, answer. No business logic."""

    server_version = "MockGateway/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    #: Injected by :class:`MockGatewayServer` as a class attribute, which is how
    #: ``http.server`` is designed to carry state (one handler instance per request).
    state: GatewayState

    # -- verbs ---------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - the name is the framework's contract
        """Answer the two read routes, 404 anything else."""
        path = urlsplit(self.path).path
        if path == HEALTH_PATH:
            self._send(200, self.state.health())
        elif path == LEDGER_PATH:
            self._send(200, self.state.ledger_view())
        else:
            self._send(404, {"error": "unknown_route", "path": path, "routes": list(ROUTES)})

    def do_POST(self) -> None:  # noqa: N802 - framework hook
        """The business route: submit one instruction."""
        path = urlsplit(self.path).path
        if path != TRANSFER_PATH:
            self._send(404, {"error": "unknown_route", "path": path, "routes": list(ROUTES)})
            return
        payload, problem = self._read_json()
        signature = self.headers.get(SIGNATURE_HEADER, "") or ""
        if payload is None:
            self.state.record(
                method="POST",
                path=path,
                instruction_id="",
                status=400,
                accepted=False,
                posted=False,
                replayed=False,
                signature_present=bool(signature),
            )
            self._send(400, {"error": "bad_body", "detail": problem or "unreadable body"})
            return
        try:
            instruction = Instruction(
                instruction_id=payload.get("instruction_id", ""),
                amount=payload.get("amount", "0"),
                debit_account=payload.get("debit_account", DEFAULT_DEBIT),
                credit_account=payload.get("credit_account", DEFAULT_CREDIT),
                signature=signature,
            )
        except LedgerRejection as exc:
            self.state.record(
                method="POST",
                path=path,
                instruction_id=str(payload.get("instruction_id", "")),
                status=400,
                accepted=False,
                posted=False,
                replayed=False,
                signature_present=bool(signature),
            )
            self._send(400, {"error": "invalid_instruction", "detail": str(exc)})
            return

        outcome = self.state.ledger.submit(instruction)
        self.state.record(
            method="POST",
            path=path,
            instruction_id=instruction.instruction_id,
            status=outcome.status,
            accepted=outcome.accepted,
            posted=bool(outcome.posting_id),
            replayed=outcome.replayed,
            signature_present=bool(signature),
        )
        body: dict[str, Any] = dict(outcome.to_dict())
        body["instruction_id"] = instruction.instruction_id
        body["amount"] = format_amount(instruction.amount)
        body["balance"] = format_amount(self.state.ledger.balance_of(instruction.debit_account))
        body["duplicated_instructions"] = list(self.state.ledger.duplicated_instructions())
        self._send(outcome.status, body)

    # -- plumbing ------------------------------------------------------------
    def log_message(self, format: str, *args: Any) -> None:
        """Silence ``stderr``: the observation log is the record, not the console."""

    def _read_json(self) -> tuple[dict[str, Any] | None, str | None]:
        """Read and decode the body; ``(payload, None)`` or ``(None, reason)``."""
        raw_length = self.headers.get("Content-Length") or "0"
        try:
            length = int(raw_length)
        except ValueError:
            return None, "Content-Length is not a number"
        if length <= 0:
            return None, "empty body"
        if length > MAX_BODY_BYTES:
            return None, "body larger than %d bytes" % MAX_BODY_BYTES
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return None, "body is not UTF-8 JSON (%s)" % exc
        if not isinstance(payload, dict):
            return None, "body must be a JSON object"
        return payload, None

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        """Write one JSON response and close the connection."""
        body = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


class _ThreadingServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` with the two flags a lab server wants.

    ``daemon_threads`` so a hung client cannot keep the process alive, and
    ``allow_reuse_address`` so back-to-back runs on the same port in a container do
    not need a wait.
    """

    daemon_threads = True
    allow_reuse_address = True


class MockGatewayServer:
    """A gateway on ``127.0.0.1:<random port>``, started and stopped explicitly.

    Usable as a context manager, which is how the runner uses it: the socket exists
    exactly as long as the scenario runs, so a failing assertion cannot leak a
    listener into the next test.

    Args:
        controls: the arm being measured; defaults to
            :meth:`ControlSet.vulnerable`.
        window_seconds: forwarded to the ledger.
        host: must be ``127.0.0.1`` (:class:`~fin_logic_cyber_range.safety.SafetyViolation`
            otherwise).
        port: ``0`` asks the OS for a free port - the default, so two harnesses can
            run side by side.

    Raises:
        SafetyViolation: when ``host`` is not the loopback address.
    """

    def __init__(
        self,
        controls: ControlSet | None = None,
        *,
        window_seconds: float = 0.02,
        host: str = BIND_HOST,
        port: int = 0,
    ) -> None:
        ensure_bind_host(host)
        self.state = GatewayState(
            controls if controls is not None else ControlSet.vulnerable(),
            window_seconds=window_seconds,
        )
        handler = type("MockGatewayHandler", (_MockGatewayHandler,), {"state": self.state})
        self._httpd = _ThreadingServer((host, port), handler)
        self._thread: threading.Thread | None = None
        self.base_url = ""

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> str:
        """Bind, start serving on a background thread, return the base URL.

        Raises:
            DataContractError: when called twice - a second ``start`` would leave
                the first server unreachable and unreferenced.
        """
        if self._thread is not None:
            raise LedgerRejection("this gateway is already serving %s" % self.base_url)
        host, port = self._httpd.server_address[:2]
        self.base_url = "http://%s:%d" % (ensure_bind_host(str(host)), int(port))
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="mock-gateway", daemon=True
        )
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        """Stop serving and close the socket; safe to call twice."""
        if self._thread is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5.0)
        self._thread = None

    def __enter__(self) -> "MockGatewayServer":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # -- views ---------------------------------------------------------------
    @property
    def controls(self) -> ControlSet:
        """The arm this gateway enforces."""
        return self.state.controls

    @property
    def mode(self) -> str:
        """``"vulnerable"``, ``"secure"`` or ``"partial"``."""
        return self.state.mode

    @property
    def ledger(self) -> SyntheticLedger:
        """The ledger behind the route, for post-run assertions."""
        return self.state.ledger

    @property
    def log(self) -> ObservabilityLog:
        """The observation log, for the report's "what did we see" section."""
        return self.state.log

    def url_for(self, path: str) -> str:
        """Absolute URL of ``path`` on this gateway.

        Raises:
            DataContractError: on a blank path or one that is not a known route -
                the runner builds every URL through here, so a typo in a scenario
                fails before a request is sent.
        """
        route = path.strip() if isinstance(path, str) else ""
        if route not in ROUTES:
            raise LedgerRejection(
                "%r is not a route of this gateway" % path, candidates=list(ROUTES)
            )
        if not self.base_url:
            raise LedgerRejection("start() the gateway before asking for a URL")
        return self.base_url + route
