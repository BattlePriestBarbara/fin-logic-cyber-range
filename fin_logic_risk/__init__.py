# -*- coding: utf-8 -*-
"""Stage 10: a business-logic risk ontology for financial API surfaces.

Two modules, no third one:

==========================  ====================================================
``fin_logic_risk.tbox``       five classes + ``FIN_LOGIC_TBOX``
``fin_logic_risk.risk_reasoner``
                            ``analyze_logic_risk`` and the report it returns
==========================  ====================================================

Everything else is reused, not copied: the graph model and the widened
vocabularies come from :mod:`ontology_builder.schema`, the constraint layer from
:mod:`ontology_builder.ontology`, the typed errors from
:mod:`ontology_builder.core`. Stage 7 asked what a tool is exposed to, stage 8 what
a route leaks, stage 9 what a tool can do, and stage 10 what a route *cannot do
because nobody built it* - one framework, four questions.

Nothing here imports ``re_security``, ``fin_security`` or ``re_toolbox``, and none
of them imports this package: domains may share a framework, but no domain may
depend on another. Stage 10 reuses stage-8 *vocabulary* (``API_ENDPOINT``,
``VULNERABILITY``, ``COMPLIANCE_RULE``, ``VIOLATES``) without importing stage-8
*code*, which is the same distinction stages 8 and 9 drew.

Importing this package pulls in pydantic only, exactly like ``ontology_builder``;
the CLI lives in :mod:`fin_logic_risk.risk_reasoner` and prints, it does not draw.
"""
from __future__ import annotations

from fin_logic_risk.risk_reasoner import (
    COMPLIANCE_FORWARD,
    CONSEQUENCE_FORWARD,
    DEFAULT_API,
    DEFAULT_GRAPH,
    GAP_FORWARD,
    IMPLEMENTS_FORWARD,
    REQUIRES_FORWARD,
    ControlGap,
    LogicFinding,
    RiskAssessmentReport,
    RiskLevel,
    analyze_logic_risk,
    classify_logic_risk,
)
from fin_logic_risk.tbox import (
    CLASSES_BY_NAME,
    CONTROL_REMEDIATION,
    FIN_LOGIC_CLASSES,
    FIN_LOGIC_RELATIONS,
    FIN_LOGIC_TBOX,
    FOREIGN_RELATIONS,
    VIOLATES_COMPLIANCE,
    OntologyClass,
    class_of,
    remediation_for,
    summary_lines,
)

__all__ = [
    "CLASSES_BY_NAME",
    "COMPLIANCE_FORWARD",
    "CONSEQUENCE_FORWARD",
    "CONTROL_REMEDIATION",
    "DEFAULT_API",
    "DEFAULT_GRAPH",
    "FIN_LOGIC_CLASSES",
    "FIN_LOGIC_RELATIONS",
    "FIN_LOGIC_TBOX",
    "FOREIGN_RELATIONS",
    "GAP_FORWARD",
    "IMPLEMENTS_FORWARD",
    "REQUIRES_FORWARD",
    "VIOLATES_COMPLIANCE",
    "ControlGap",
    "LogicFinding",
    "OntologyClass",
    "RiskAssessmentReport",
    "RiskLevel",
    "analyze_logic_risk",
    "class_of",
    "classify_logic_risk",
    "remediation_for",
    "summary_lines",
]

__version__ = "0.1.0"
