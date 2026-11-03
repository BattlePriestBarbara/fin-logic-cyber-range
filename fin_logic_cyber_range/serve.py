# -*- coding: utf-8 -*-
"""Run one arm in the foreground - the entry point the container uses.

    python -m fin_logic_cyber_range.serve --mode vulnerable --port 8080
    python -m fin_logic_cyber_range.serve --mode secure --port 8080

Nothing here is needed for the normal (in-process) workflow: :mod:`runner` starts
and stops its own gateway. This module exists so ``deploy/cyber_range`` can hold a
long-running container, and it is deliberately the only place that keeps a server
alive after ``start()``.

Binding follows :mod:`fin_logic_cyber_range.safety`: ``127.0.0.1`` on a workstation,
``0.0.0.0`` only when ``RANGE_ALLOW_CONTAINER_BIND=1`` is set (the image sets it,
because Docker's port forwarding cannot reach a process bound to the container's
loopback). The port a container publishes is bound to ``127.0.0.1`` on the host by
the compose file, so the switch never widens what the host exposes.
"""
from __future__ import annotations

import argparse
import threading

from fin_logic_cyber_range.gateway import MockGatewayServer
from fin_logic_cyber_range.ledger import ControlSet
from fin_logic_cyber_range.safety import (
    BIND_HOST,
    CONTAINER_BIND_ENV,
    SafetyViolation,
    container_bind_allowed,
)

MODES = {"vulnerable": ControlSet.vulnerable, "secure": ControlSet.secure}


def build_arg_parser() -> argparse.ArgumentParser:
    """The two knobs a container needs: which arm, and which port."""
    parser = argparse.ArgumentParser(
        prog="python -m fin_logic_cyber_range.serve",
        description="Serve one synthetic transfer gateway arm on this machine or pod.",
    )
    parser.add_argument("--mode", choices=sorted(MODES), default="vulnerable")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--window-ms",
        type=int,
        default=20,
        help="contention window for the unguarded arm, 0..500 (default: 20)",
    )
    return parser


def _wait_forever() -> None:
    """Block until the process is interrupted.

    A one-line function on purpose: the test suite replaces it, and a replaced
    ``threading.Event().wait`` is the only way to exercise :func:`main`'s shutdown
    path without spawning a process.
    """
    threading.Event().wait()


def main(argv: list[str] | None = None) -> int:
    """Serve until interrupted.

    Returns:
        ``0`` after a clean shutdown, ``2`` when the bind address or port is
        refused by the safety boundary.
    """
    args = build_arg_parser().parse_args(argv)
    if not 0 <= args.window_ms <= 500:
        print("  --window-ms must be 0..500, got %d" % args.window_ms)
        return 2
    if not 1024 <= args.port <= 65535:
        print("  --port must be 1024..65535, got %d" % args.port)
        return 2
    host = "0.0.0.0" if container_bind_allowed() else BIND_HOST
    try:
        server = MockGatewayServer(
            MODES[args.mode](), window_seconds=args.window_ms / 1000.0, host=host, port=args.port
        )
        base_url = server.start()
    except SafetyViolation as exc:
        print("  refusing to bind: %s" % exc)
        print("  (set %s=1 only inside a container)" % CONTAINER_BIND_ENV)
        return 2

    print("mock gateway  : %s" % base_url)
    print("arm           : %s" % server.mode)
    print("controls      : %s" % (", ".join(server.controls.enforced()) or "none"))
    print("synthetic only: accounts %s" % ", ".join(sorted(_accounts())))
    print("stop with Ctrl-C")
    try:
        _wait_forever()
    except KeyboardInterrupt:
        print("")
        print("stopping")
    finally:
        server.stop()
    return 0


def _accounts() -> tuple[str, ...]:
    """The synthetic account names, for the banner (imported lazily: no side effects)."""
    from fin_logic_cyber_range.ledger import SYNTHETIC_ACCOUNTS

    return tuple(SYNTHETIC_ACCOUNTS)


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
