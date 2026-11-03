# -*- coding: utf-8 -*-
"""Layer 1: the ontology constraint layer (TBox + validator).

    ontology/tbox.py         what an edge is allowed to be  (RelationRule, OntologySchema)
    ontology/constraints.py  one class per rule            (Constraint, ValidationIssue)
    ontology/validator.py    policy, report, enforcement    (OntologyValidator)

The layer answers one question for everything downstream: *given this TBox, is
this graph (or this candidate edge) admissible?* It reads a
:class:`~ontology_builder.schema.KnowledgeGraph` and never writes one, never
touches the filesystem and never prints.

Phase 1+2 of the refactor only builds it; wiring it into ``pipeline.py``,
``analyzer.py`` and the KGE gate happens once the services exist, so that the
constraint layer is finished and tested before anything depends on it.
"""
from __future__ import annotations

from ontology_builder.ontology.constraints import (
    DEFAULT_CONSTRAINTS,
    ConfidenceBandConstraint,
    Constraint,
    CycleConstraint,
    DanglingEndpointConstraint,
    DeclaredRelationUnusedConstraint,
    DomainRangeConstraint,
    DuplicateTripleConstraint,
    FunctionalityConstraint,
    RequiredCategoryConstraint,
    SelfLoopConstraint,
    SymmetryConstraint,
    ValidationIssue,
)
from ontology_builder.ontology.tbox import (
    DEFAULT_SCHEMA,
    DEFAULT_SHARE_FLOOR,
    PALANTIR_TBOX,
    OntologySchema,
    RelationRule,
)
from ontology_builder.ontology.validator import (
    EDGE_CONSTRAINTS,
    OntologyValidator,
    ValidationPolicy,
    ValidationReport,
)

__all__ = [
    "DEFAULT_CONSTRAINTS",
    "DEFAULT_SCHEMA",
    "DEFAULT_SHARE_FLOOR",
    "EDGE_CONSTRAINTS",
    "PALANTIR_TBOX",
    "ConfidenceBandConstraint",
    "Constraint",
    "CycleConstraint",
    "DanglingEndpointConstraint",
    "DeclaredRelationUnusedConstraint",
    "DomainRangeConstraint",
    "DuplicateTripleConstraint",
    "FunctionalityConstraint",
    "OntologySchema",
    "OntologyValidator",
    "RelationRule",
    "RequiredCategoryConstraint",
    "SelfLoopConstraint",
    "SymmetryConstraint",
    "ValidationIssue",
    "ValidationPolicy",
    "ValidationReport",
]
