# -*- coding: utf-8 -*-
"""Layer 0: value objects, typed failures and ports shared by every stage.

Dependency rule (enforced by ``test_architecture.py``, not by hope)
------------------------------------------------------------------
``core`` imports **nothing** from the rest of the package at runtime and nothing
third-party. The domain models (:mod:`ontology_builder.schema`) appear here only
under ``typing.TYPE_CHECKING``, so a Protocol can mention ``KnowledgeGraph``
without dragging pydantic into the import graph.

    core/errors.py      typed failures
    core/contracts.py   Severity, ArtifactRef, GraphRef
    core/reports.py     MetricSet, CalibrationAssessment, SignificanceReport,
                        LinkPredictionReport - what the services return
    core/ports.py       GraphRepository, ArtifactStore, CalibrationService,
                        SignificanceService, KGEEngine

Direction of dependency for the whole refactor:

    core  <-  ontology  <-  services  <-  adapters  <-  runtime

Anything pointing the other way is an architecture defect, and the AST test in
``test_architecture.py`` fails the build on it.
"""
from __future__ import annotations

from ontology_builder.core.contracts import (
    ArtifactRef,
    GraphRef,
    Severity,
)
from ontology_builder.core.errors import (
    DataContractError,
    InsufficientDataError,
    MissingDependencyError,
    OntologyBuilderError,
    OntologyViolationError,
)
from ontology_builder.core.ports import (
    ArtifactStore,
    CalibrationService,
    GraphRepository,
    KGEEngine,
    SignificanceService,
)
from ontology_builder.core.reports import (
    REPORT_SCHEMA_VERSION,
    CalibrationAssessment,
    LinkPredictionReport,
    MetricSet,
    PredictionGateReport,
    ReportMeta,
    SignificanceReport,
)

__all__ = [
    "ArtifactRef",
    "ArtifactStore",
    "CalibrationAssessment",
    "CalibrationService",
    "DataContractError",
    "GraphRef",
    "GraphRepository",
    "InsufficientDataError",
    "KGEEngine",
    "LinkPredictionReport",
    "MetricSet",
    "MissingDependencyError",
    "OntologyBuilderError",
    "OntologyViolationError",
    "PredictionGateReport",
    "REPORT_SCHEMA_VERSION",
    "ReportMeta",
    "Severity",
    "SignificanceReport",
    "SignificanceService",
]
