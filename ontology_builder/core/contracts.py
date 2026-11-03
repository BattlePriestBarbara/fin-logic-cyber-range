# -*- coding: utf-8 -*-
"""Value objects passed between layers.

Standard library only (``dataclasses``, ``enum``, ``pathlib``) so that anything
downstream - including a future HTTP wrapper - can import these without pulling
pydantic, numpy or torch.

Two of them exist for a specific reason:

``Severity``
    Every validation finding has one. It is an enum rather than a string because
    the validator sorts findings by severity, and sorting by the string
    ``"warning"`` would put warnings before errors alphabetically.

``ArtifactRef``
    A file the pipeline wrote, identified by content, not just by path
    (``bytes`` + ``sha256``). "The numbers are reproducible" is a claim; a
    manifest of hashes is the evidence, and it costs one line per artefact.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from ontology_builder.core.errors import DataContractError

#: ``str`` values rather than an Enum: the set is open (a future ``csv`` export
#: needs no new type) and a Literal still gets checked by mypy.
ArtifactKind = Literal["json", "text", "png"]

_ARTIFACT_KINDS: frozenset[str] = frozenset({"json", "text", "png"})
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class Severity(str, Enum):
    """How much a validation finding matters.

    ``ERROR`` blocks a strict run; ``WARNING`` is surfaced and ignored;
    ``INFO`` documents a deliberate choice (e.g. an allowed self-loop quota) and
    is never noise a reader is expected to act on.
    """

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Sort key: 0 for ERROR .. 2 for INFO (most severe first)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def coerce(cls, raw: object) -> "Severity":
        """Accept a member, ``"error"``, or ``"ERROR"``.

        Raises:
            DataContractError: for anything else. Unlike
                :meth:`ConceptCategory.coerce`, this does **not** fall back to a
                default: silently downgrading an ERROR to a WARNING would hide
                the failures the layer exists to report.
        """
        if isinstance(raw, cls):
            return raw
        text = str(raw or "").strip().casefold()
        try:
            return cls(text)
        except ValueError as exc:
            raise DataContractError(
                "unknown severity %r; expected one of %s" % (raw, [m.value for m in cls]),
                severity=raw,
            ) from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.ERROR: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
}


@dataclass(frozen=True)
class ArtifactRef:
    """A file the pipeline produced, identified by content.

    Attributes:
        path: absolute path of the artefact.
        kind: ``"json"``, ``"text"`` or ``"png"``.
        bytes: size on disk, in bytes.
        sha256: lowercase hex digest of the file content.

    Raises:
        DataContractError: on an unknown ``kind``, a negative size, or a digest
            that is not 64 lowercase hex characters.
    """

    path: Path
    kind: ArtifactKind
    bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if self.kind not in _ARTIFACT_KINDS:
            raise DataContractError(
                "unknown artifact kind %r; expected one of %s"
                % (self.kind, sorted(_ARTIFACT_KINDS)),
                kind=self.kind,
            )
        if self.bytes < 0:
            raise DataContractError("artifact size cannot be negative", bytes=self.bytes)
        if not _HEX64_RE.match(self.sha256):
            raise DataContractError(
                "sha256 must be 64 lowercase hex characters", sha256=self.sha256
            )

    def to_dict(self) -> dict[str, Any]:
        """JSON form for the run manifest."""
        return {
            "path": str(self.path),
            "kind": self.kind,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class GraphRef:
    """Where a graph lives - a path today, an object-store key later.

    Wrapping the path keeps the *location* out of the services: they receive a
    loaded :class:`~ontology_builder.schema.KnowledgeGraph` and never build a
    path themselves.
    """

    path: Path

    @classmethod
    def of(cls, value: str | Path) -> "GraphRef":
        """Accept a ``str`` or a ``Path``; store a ``Path``."""
        return cls(Path(value))

    def __str__(self) -> str:
        return str(self.path)
