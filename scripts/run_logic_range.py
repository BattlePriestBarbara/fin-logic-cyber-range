# -*- coding: utf-8 -*-
"""Play the synthetic business-logic scenarios (stage 11).

    python scripts/run_logic_range.py
    python scripts/run_logic_range.py --scenario replay_transfer --mode secure
    python scripts/run_logic_range.py --mode vulnerable --verbose
    python scripts/run_logic_range.py --json outputs/range.json --markdown outputs/range.md

Prints, in order:

1. the TBox verdict on the benchmark graph - the comparison is refused on a graph
   the ontology rejects, because the static column would then describe a model
   nobody sanctions;
2. the static assessment of ``Transfer_API`` (stage 10) and the scenarios that will
   be played;
3. for each (scenario, arm): the steps, the observed risk, the predicted risk, the
   verdict, one finding sentence per (missing control, observed flaw), and the
   evidence lines that back them;
4. the static-vs-dynamic set comparison: what both agree on, what the graph
   predicts but one run cannot provoke, and what the run saw that the graph has no
   edge for;
5. optionally the paths of the JSON and Markdown artefacts.

Everything runs on ``127.0.0.1`` against a mock gateway started and stopped inside
the process; the accounts are ``ACC-SYNTH-*`` and the amounts are invented. See
``fin_logic_cyber_range/README.md`` for the safety boundary and for why the work is
bounded (no retries, at most 32 concurrent requests, at most 8 repetitions).
"""
from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fin_logic_cyber_range.cli import build_arg_parser, main  # noqa: E402

__all__ = ["build_arg_parser", "main"]

if __name__ == "__main__":
    raise SystemExit(main())
