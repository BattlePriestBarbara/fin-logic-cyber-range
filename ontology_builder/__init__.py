# -*- coding: utf-8 -*-
"""Local Ontology/knowledge-graph builder for the Palantir docs corpus.

Six stages, one package, no service dependencies at import time:

=========  =========================  =============================================
stage      module                     output
=========  =========================  =============================================
1 schema   `schema.py`                strict pydantic models + `nx.DiGraph` conversion
2 extract  `extractor.py`             chunks -> `KnowledgeGraph` (mock / rule / LLM)
           `llm_clients.py`           swappable LLM transports (instructor, Ollama)
           `pipeline.py`              batch run, merge, per-chunk statistics
3 analyse  `analyzer.py`              degree/hub/component/clustering report
           `scripts/visualize_graph.py`  PNG with size/colour/alpha encodings
4 stats    `stats_analysis.py`        calibration bins (ECE), permutation test
5 embed    `kge_data.py`              triples, transductive 8:1:1 split, filter index
           `kge_experiment.py`        pykeen TransE/RotatE trainer (the experiment)
6 services `services/`                the same maths as ports: `CalibrationService`,
                                      `SignificanceService`, `KGEEngine` (torch)
           `scripts/run_advanced_analysis.py`  all three, with JSON + PNG artefacts
=========  =========================  =============================================

The constraint layer lives in `ontology/` and turns the TBox into a runtime check
(`OntologySchema`, 10 `Constraint` classes, `OntologyValidator`); it builds on
`core/` for typed errors and value objects, and `scripts/validate_graph.py` is its
CLI. `core/` also defines the service ports and the value objects the services
return.

Layers 0-3 of the service refactor (``core`` -> ``ontology`` -> ``services``) are
deliberately **not** re-exported here, so ``import ontology_builder`` still pulls
in only pydantic and networkx - never numpy, torch or matplotlib. Importing
``ontology_builder.services`` adds numpy (and torch only when a model is trained).

Nothing here writes outside `ontology_builder/`; the corpus is read from
`retrieval/data/index/bm25_index.json` (or any shard directory) and never mutated.
"""

from ontology_builder.schema import (
    GRAPH_SCHEMA_VERSION,
    ConceptCategory,
    DocumentChunk,
    IntegrityReport,
    KnowledgeGraph,
    OntologyConcept,
    RelationType,
    Relationship,
)

__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "ConceptCategory",
    "DocumentChunk",
    "IntegrityReport",
    "KnowledgeGraph",
    "OntologyConcept",
    "RelationType",
    "Relationship",
]

__version__ = "1.0.0"
