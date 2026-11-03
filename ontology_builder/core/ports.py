# -*- coding: utf-8 -*-
"""Ports: the seams where the pure layers meet the outside world.

These are :class:`typing.Protocol` (structural), matching the existing
``Labeler`` / ``TextClient`` precedent, so an adapter never has to inherit from
anything - it just has to have the right methods. ``@runtime_checkable`` lets
tests assert with ``isinstance`` that a fake really satisfies the port.

The **production implementations land in phase 4** (``adapters/``):

============================  ==========================================
``JsonGraphRepository``       ``KnowledgeGraph.load_json`` / ``save_json``
``FileArtifactStore``         json/text/png under ``outputs/`` and ``logs/``
============================  ==========================================

Until then the only implementations are the fakes in ``test_contracts.py``,
which is deliberate: the port shape is pinned by a test before any real
implementation can bend it.

The three **service** ports (``CalibrationService``, ``SignificanceService``,
``KGEEngine``) are different: they are implemented in phase 3, in
:mod:`ontology_builder.services`, and the fakes still exist to keep the contract
honest. A service port describes *one* method taking a whole graph and returning
a value object from :mod:`ontology_builder.core.reports`; anything narrower
(a metric, a bin) is a detail the port does not expose.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, Protocol, Sequence, runtime_checkable

from ontology_builder.core.contracts import ArtifactRef, GraphRef
from ontology_builder.core.reports import (
    CalibrationAssessment,
    LinkPredictionReport,
    PredictionGateReport,
    SignificanceReport,
)

if TYPE_CHECKING:  # pragma: no cover - keeps this module import-time dependency-free
    from ontology_builder.schema import KnowledgeGraph


@runtime_checkable
class GraphRepository(Protocol):
    """Load and store a whole :class:`KnowledgeGraph`.

    The repository is the only place that knows about file formats: a service
    that needs a graph calls this, never ``KnowledgeGraph.load_json``.
    """

    def load(self, ref: GraphRef) -> "KnowledgeGraph":
        """Read the graph at ``ref``.

        Raises:
            FileNotFoundError: when the path does not exist.
            ValueError: when the file is unreadable or fails validation.
        """
        ...

    def save(self, graph: "KnowledgeGraph", ref: GraphRef) -> ArtifactRef:
        """Write ``graph`` to ``ref`` and describe what landed on disk."""
        ...


@runtime_checkable
class ArtifactStore(Protocol):
    """Write the three artefact kinds the pipeline produces.

    Every method returns an :class:`ArtifactRef`, so the caller can record a
    manifest entry (path + size + hash) without opening the file again.
    """

    def write_json(self, name: str, payload: Mapping[str, Any]) -> ArtifactRef:
        """Serialise ``payload`` as UTF-8 JSON (``ensure_ascii=False``)."""
        ...

    def write_text(self, name: str, lines: Sequence[str]) -> ArtifactRef:
        """Write pre-rendered text, one entry per line."""
        ...

    def write_figure(self, name: str, figure: Any) -> ArtifactRef:
        """Persist a matplotlib figure (the ``Any`` keeps matplotlib out of here)."""
        ...


@runtime_checkable
class CalibrationService(Protocol):
    """Score how far ``confidence_score`` is from a probability.

    One method, whole graph in, one :class:`CalibrationAssessment` out: the
    caller never sees bins, numpy arrays or epsilon constants.
    """

    def assess_calibration(self, graph: "KnowledgeGraph") -> CalibrationAssessment:
        """Measure calibration of the graph's edge confidences.

        Raises:
            InsufficientDataError: when the graph has too few edges to bin.
        """
        ...


@runtime_checkable
class SignificanceService(Protocol):
    """Test whether hub-hub edges are more confident than the rest."""

    def test_hub_significance(
        self, graph: "KnowledgeGraph", hub_names: Sequence[str]
    ) -> SignificanceReport:
        """Run the permutation test that the given hubs' edges are typical.

        Raises:
            InsufficientDataError: when no edge connects two of the named hubs.
        """
        ...


@runtime_checkable
class KGEEngine(Protocol):
    """Prepare, train, evaluate and project a knowledge-graph embedding model.

    ``dataset`` and ``outcome`` are the engine's own types (``Any`` here on
    purpose): core must not grow a dependency on torch just to name them.
    """

    def prepare(self, graph: "KnowledgeGraph", **options: Any) -> Any:
        """Turn a graph into triples, a transductive split and a filter index."""
        ...

    def train(self, dataset: Any, model_name: str | None = None) -> Any:
        """Fit one model; returns an outcome carrying the best checkpoint."""
        ...

    def evaluate(self, outcome: Any, dataset: Any) -> LinkPredictionReport:
        """Filtered and raw link-prediction metrics on the test split."""
        ...

    def predict_new_edges(
        self, outcome: Any, dataset: Any, graph: "KnowledgeGraph", *, top_k: int = 10
    ) -> PredictionGateReport:
        """Propose edges the graph does not contain, then let the TBox veto them.

        The graph is passed explicitly because the gate judges a candidate against
        the ABox it would be added to: a symmetric proposal is admissible only
        with its mirror, and a category rule needs the real concepts. Returns the
        accepted edges, the rejected ones and the histogram of veto codes.
        """
        ...

    def project(self, outcome: Any, dataset: Any, *, method: str = "tsne") -> Any:
        """Project entity embeddings to 2-D for the visualisation."""
        ...
