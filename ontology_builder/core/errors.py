# -*- coding: utf-8 -*-
"""Typed failures for the ontology builder.

Why a hierarchy instead of ``ValueError("bad thing: %r" % x)``
-------------------------------------------------------------
The experiment scripts raise bare ``ValueError`` 25 times (measured: 25
``pytest.raises(ValueError)`` in ``test_*.py``). That is acceptable in a script
and wrong in a service: a caller cannot separate "you passed nonsense", "the
data cannot support this statistic" and "the graph violates the ontology"
without matching on the message text.

:class:`DataContractError` therefore inherits from **both**
:class:`OntologyBuilderError` and :class:`ValueError`. New code raises the typed
class; the 25 existing assertions keep passing untouched, so the migration stays
incremental instead of a flag day.

Hierarchy
---------
    OntologyBuilderError            root; carries structured ``context``
    +-- DataContractError           bad input at a boundary (is a ValueError)
    |   +-- InsufficientDataError   too few observations for the statistic
    +-- MissingDependencyError      an optional backend (torch, pykeen) is absent
    +-- OntologyViolationError      the graph breaks the TBox; carries the report

Nothing here imports the rest of the package: an exception module that can pull
in pydantic is an exception module you cannot import from anywhere.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps this module dependency-free
    from ontology_builder.ontology.validator import ValidationReport


class OntologyBuilderError(Exception):
    """Base of every domain error; carries structured context for the log line.

    ``context`` exists so a call site can log ``exc.context`` next to the message
    instead of re-parsing a formatted string, and so a test can assert on values
    rather than on prose.
    """

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self._context: Mapping[str, object] = MappingProxyType(dict(context))

    @property
    def context(self) -> Mapping[str, object]:
        """Keyword context passed at raise time, read-only."""
        return self._context

    def __str__(self) -> str:
        base = super().__str__()
        if not self._context:
            return base
        rendered = ", ".join("%s=%r" % (key, self._context[key]) for key in sorted(self._context))
        return "%s [%s]" % (base, rendered)


class DataContractError(OntologyBuilderError, ValueError):
    """The caller handed a service something it cannot legally work with.

    Deliberately also a :class:`ValueError`: every existing ``pytest.raises(
    ValueError)`` keeps working while new code raises the typed class.
    """


class InsufficientDataError(DataContractError):
    """There are fewer observations than the statistic needs to mean anything."""


class MissingDependencyError(OntologyBuilderError, ImportError):
    """An optional heavyweight backend is not installed.

    Also an :class:`ImportError` on purpose: callers that already catch
    ``ImportError`` around an optional import keep working, while a caller that
    wants to distinguish "the extra was not installed" from "your data is
    unusable" can catch this class specifically.
    """


class OntologyViolationError(OntologyBuilderError):
    """The graph breaks the ontology (TBox) and the policy is strict.

    The full :class:`~ontology_builder.ontology.validator.ValidationReport` rides
    along in :attr:`report`; the message is a digest so a bare ``str(exc)`` in a
    log is still actionable.
    """

    def __init__(self, report: "ValidationReport", *, limit: int = 3) -> None:
        self.report = report
        errors = report.errors
        shown = "; ".join("%s on %s" % (issue.code, issue.subject) for issue in errors[:limit])
        omitted = len(errors) - limit
        suffix = "" if omitted <= 0 else " (+%d more)" % omitted
        super().__init__(
            "%d ontology violation(s): %s%s" % (len(errors), shown, suffix),
            schema=report.schema_name,
            version=report.schema_version,
            errors=len(errors),
        )
