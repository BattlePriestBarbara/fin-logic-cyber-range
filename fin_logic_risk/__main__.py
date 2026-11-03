# -*- coding: utf-8 -*-
"""``python -m fin_logic_risk``: run the reasoner over the benchmark graph.

A three-line entry point rather than a third module. The CLI lives in
:mod:`fin_logic_risk.risk_reasoner` so that ``import fin_logic_risk`` never grows
an argument parser; this file only decides that ``python -m fin_logic_risk`` means
"run it". (It is a separate module - not a ``__main__`` guard inside
``risk_reasoner`` - because ``python -m fin_logic_risk.risk_reasoner`` would make
runpy import the package, which already imports that module, and CPython warns
about exactly that.)
"""
from __future__ import annotations

from fin_logic_risk.risk_reasoner import main

if __name__ == "__main__":  # pragma: no cover - the tests call main() directly
    raise SystemExit(main())
