# -*- coding: utf-8 -*-
"""The observation segment: what the range saw, as data rather than console text.

Why this is a module and not ``print(...)``
-------------------------------------------
Task 11 asks a question beyond "does the bug reproduce": *would a defensible
monitoring pipeline have noticed?* A print statement cannot answer that, because
noticing is a function of the **fields** captured. So every request produces one
:class:`AccessRecord` with the full field set - including the two fields a real
gateway's access log usually omits (whether a signature was present at all, and how
many postings the instruction has *after* this request). The detection signals in
:meth:`AccessRecord.signals` are derived from those fields, so a reader can check
the claim "this is detectable" against the record rather than against prose.

Signal vocabulary
-----------------
=========================  ==========================================  ===========
signal                     condition                                   kind
=========================  ==========================================  ===========
``duplicate_posting``      an instruction has 2+ postings after this    detective
                           request (the T+1 reconciliation question)
``unsigned_accepted``      a 2xx accepted a request carrying no         detective
                           signature header at all
``idempotent_replay``      the handler returned a stored receipt        benign -
                           (``replayed``)                               proof the
                                                                        control works
``rejected_request``       a 4xx/5xx the client did not expect          noise
=========================  ==========================================  ===========

``idempotent_replay`` is deliberately logged as a *good* signal: in the secure arm
it is the evidence that the control fired, and a monitoring rule that alarmed on it
would page somebody for correct behaviour.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any, Iterable

from ontology_builder.core.errors import DataContractError


@dataclass(frozen=True)
class AccessRecord:
    """One request, as the gateway would log it.

    Attributes:
        seq: 1-based arrival order, monotonic per gateway instance. Not a
            timestamp: two runs must produce comparable records.
        method: HTTP verb, upper-case.
        path: route the request named.
        instruction_id: business id carried in the body, or ``""`` when the body
            was unparseable - the field a duplicate-detection rule joins on.
        status: HTTP status actually returned.
        accepted: whether a posting exists because of this request.
        posted: whether *this* request wrote a posting (false on replay/reject).
        replayed: whether the handler recognised the instruction id.
        signature_present: whether the header was sent at all; the value is only
            ever compared, never logged.
        duplicates_after: how many instructions are duplicated once this request
            has been handled - the running value of the reconciliation check.

    Raises:
        DataContractError: on a non-positive ``seq``, a blank method/path, a status
            outside ``100..599``, or a negative ``duplicates_after``.
    """

    seq: int
    method: str
    path: str
    instruction_id: str
    status: int
    accepted: bool
    posted: bool
    replayed: bool
    signature_present: bool
    duplicates_after: int

    def __post_init__(self) -> None:
        if not isinstance(self.seq, int) or self.seq <= 0:
            raise DataContractError("AccessRecord.seq starts at 1", seq=repr(self.seq))
        for name in ("method", "path"):
            raw = getattr(self, name)
            value = raw.strip() if isinstance(raw, str) else ""
            if not value:
                raise DataContractError("AccessRecord.%s must be non-empty" % name)
            object.__setattr__(self, name, value)
        if not 100 <= self.status <= 599:
            raise DataContractError("AccessRecord.status is not an HTTP status", status=self.status)
        if self.duplicates_after < 0:
            raise DataContractError(
                "AccessRecord.duplicates_after cannot be negative",
                duplicates_after=self.duplicates_after,
            )

    def signals(self) -> tuple[str, ...]:
        """The detection signals this single record raises, sorted."""
        found: list[str] = []
        if self.accepted and not self.signature_present:
            found.append("unsigned_accepted")
        if self.duplicates_after:
            found.append("duplicate_posting")
        if self.replayed:
            found.append("idempotent_replay")
        if self.status >= 400:
            found.append("rejected_request")
        return tuple(sorted(found))

    def line(self) -> str:
        """One console line, fixed-width so two runs line up."""
        flags = ",".join(self.signals()) or "-"
        return "    #%02d %-4s %-22s %-3d accepted=%-5s posted=%-5s sig=%-5s [%s]" % (
            self.seq,
            self.method,
            self.path,
            self.status,
            self.accepted,
            self.posted,
            self.signature_present,
            flags,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON form, signals included so a log consumer needs no rules."""
        return {
            "seq": self.seq,
            "method": self.method,
            "path": self.path,
            "instruction_id": self.instruction_id,
            "status": self.status,
            "accepted": self.accepted,
            "posted": self.posted,
            "replayed": self.replayed,
            "signature_present": self.signature_present,
            "duplicates_after": self.duplicates_after,
            "signals": list(self.signals()),
        }


class ObservabilityLog:
    """An append-only, thread-safe list of :class:`AccessRecord`.

    Thread safety matters on the concurrent scenario, where several handler threads
    append at once and a ``list.append`` racing with a ``len`` would number two
    records identically. ``seq`` is therefore assigned under the same lock as the
    append, in :meth:`record`.
    """

    def __init__(self) -> None:
        self._records: list[AccessRecord] = []
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._records)

    @property
    def records(self) -> tuple[AccessRecord, ...]:
        """Every record, in arrival order."""
        return tuple(self._records)

    def next_seq(self) -> int:
        """The sequence number the next record will receive (1-based)."""
        with self._lock:
            return len(self._records) + 1

    def record(self, **fields: Any) -> AccessRecord:
        """Build and append one record, assigning ``seq`` inside the lock."""
        with self._lock:
            entry = AccessRecord(seq=len(self._records) + 1, **fields)
            self._records.append(entry)
            return entry

    def collect(self, signals: Iterable[str]) -> tuple[AccessRecord, ...]:
        """Records raising at least one of ``signals``, in arrival order."""
        wanted = {item for item in signals}
        return tuple(item for item in self._records if wanted & set(item.signals()))

    def signal_counts(self) -> dict[str, int]:
        """``signal -> how many records raised it``, keys sorted."""
        counts: dict[str, int] = {}
        for entry in self._records:
            for signal in entry.signals():
                counts[signal] = counts.get(signal, 0) + 1
        return dict(sorted(counts.items()))

    def to_jsonl(self) -> str:
        """One JSON object per line (the shape a log shipper wants)."""
        return "".join(
            json.dumps(item.to_dict(), ensure_ascii=False) + "\n" for item in self._records
        )

    def summary(self) -> dict[str, Any]:
        """Counts a report header can print without re-walking the records."""
        return {
            "requests": len(self._records),
            "accepted": sum(1 for item in self._records if item.accepted),
            "posted": sum(1 for item in self._records if item.posted),
            "rejected": sum(1 for item in self._records if item.status >= 400),
            "signals": self.signal_counts(),
        }
