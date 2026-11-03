# -*- coding: utf-8 -*-
"""A synthetic ledger: two made-up accounts, a handful of made-up instructions.

What this file is not
---------------------
It is not a bank, not a ledger engine, and not connected to anything. The account
numbers are ``ACC-SYNTH-*``, the balances start at a round number, the instruction
ids are ``INS-*`` and the secret below is published in this docstring on purpose.
Nothing here can be pointed at a real system, because there is no configuration
that names one.

Why the ledger owns the "contention window"
-------------------------------------------
A vulnerable handler decides "not seen before" and then posts, and the gap between
the decision and the post is what a concurrent duplicate slips through. On modern
hardware that gap is tens of microseconds, so an unmodified reproducer is flaky:
sometimes one posting, sometimes two, and a flaky finding is a finding nobody
fixes. :class:`SyntheticLedger` therefore takes ``window_seconds`` and sleeps in
the *vulnerable* path only - the secure path takes the gate lock before it reads
anything, so widening the window changes nothing for it. That asymmetry is the
point of the experiment, not a trick inside it: the window is the same defect a
reviewer describes as "check-then-act without a lock", made observable.

Determinism
-----------
Ids are sequences (``PST-0001``, ``RCP-0001``), not timestamps, and the account
set is fixed. Two runs of one scenario therefore produce byte-identical posting
lists, which is what lets the report diff two runs at all.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any, Mapping

from ontology_builder.core.errors import DataContractError

#: The two synthetic accounts, and their synthetic opening balances. A test that
#: needs a third account must add it here rather than inventing one inline, so
#: "which accounts exist" has exactly one answer in the package.
SYNTHETIC_ACCOUNTS: Mapping[str, Decimal] = MappingProxyType(
    {
        "ACC-SYNTH-0001": Decimal("1000.00"),
        "ACC-SYNTH-0002": Decimal("0.00"),
    }
)

DEFAULT_DEBIT = "ACC-SYNTH-0001"
DEFAULT_CREDIT = "ACC-SYNTH-0002"

#: The shared secret the mock gateway checks a signature against. Public, in the
#: source, labelled synthetic: it authenticates nothing outside this process, and
#: writing that down is cheaper than a reader wondering whether it leaks something.
LAB_SECRET = "synthetic-lab-secret-not-a-key"

#: Largest instruction the lab accepts, so a scenario cannot "prove" a flaw by
#: moving an absurd amount through a toy ledger.
MAX_AMOUNT = Decimal("100000.00")

#: ``ControlSet`` flag -> the control name as spelled in the stage-10 graph. The
#: mapping lives here so the report, the oracle and the ledger cannot drift apart
#: on spelling: the ontology's vocabulary is the authority, this is its index.
CONTROL_NAMES: Mapping[str, str] = MappingProxyType(
    {
        "idempotency_token": "Idempotency_Token",
        "signature_verification": "Signature_Verification",
    }
)


class LedgerRejection(DataContractError):
    """An instruction the ledger will not even look at (malformed, not a finding)."""


def format_amount(value: Decimal | str | int) -> str:
    """Render an amount as ``"1234.50"``.

    Raises:
        LedgerRejection: when the value is not a finite number.
    """
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise LedgerRejection("amount is not a number", amount=repr(value), error=str(exc))
    if not amount.is_finite():
        raise LedgerRejection("amount must be finite", amount=repr(value))
    return str(amount.quantize(Decimal("0.01")))


def instruction_signature(
    instruction_id: str, amount: Decimal | str | int, *, secret: str = LAB_SECRET
) -> str:
    """The signature a well-behaved client attaches to one instruction.

    A truncated SHA-256 over ``secret|id|amount``: enough to make the control
    checkable (flip the amount and the signature stops matching), not a scheme
    anyone should copy. The lab's question is "does the handler verify this field
    at all", and any digest answers that question equally well.

    Args:
        instruction_id: the instruction the signature is over.
        amount: the amount, rendered through :func:`format_amount` so ``"100"``
            and ``Decimal("100")`` sign the same instruction.
        secret: the shared secret; the default is the published lab value.

    Returns:
        32 hex characters.
    """
    message = "%s|%s" % (str(instruction_id).strip(), format_amount(amount))
    return hashlib.sha256(("%s|%s" % (secret, message)).encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class ControlSet:
    """Which controls the mock gateway enforces - the experiment's free variable.

    ``ControlSet.vulnerable()`` and ``ControlSet.secure()`` are the two arms of
    every comparison: the same scenario, the same ledger, one flag flipped. Nothing
    in the runner knows a "mode" string; it receives one of these and the ledger
    behaves accordingly, so the two arms cannot drift apart in code.

    Attributes:
        idempotency_token: whether the handler remembers an instruction id and
            replays the stored receipt instead of posting twice.
        signature_verification: whether the handler checks the request signature
            before it touches the ledger.
    """

    idempotency_token: bool = False
    signature_verification: bool = False

    @classmethod
    def vulnerable(cls) -> "ControlSet":
        """Neither control: what a ``LACKS_CONTROL`` edge in the stage-10 graph says."""
        return cls()

    @classmethod
    def secure(cls) -> "ControlSet":
        """Both controls: the "after the fix" arm."""
        return cls(idempotency_token=True, signature_verification=True)

    @property
    def mode(self) -> str:
        """``"secure"``, ``"vulnerable"``, or ``"partial"`` for a mixed set."""
        if not self.missing():
            return "secure"
        if len(self.missing()) == len(CONTROL_NAMES):
            return "vulnerable"
        return "partial"

    def enforced(self) -> tuple[str, ...]:
        """Enforced controls, spelled as the ontology spells them."""
        return tuple(CONTROL_NAMES[flag] for flag in CONTROL_NAMES if getattr(self, flag))

    def missing(self) -> tuple[str, ...]:
        """Absent controls, spelled as the ontology spells them."""
        return tuple(CONTROL_NAMES[flag] for flag in CONTROL_NAMES if not getattr(self, flag))

    def to_dict(self) -> dict[str, Any]:
        """JSON form: the mode plus both spellings of every control."""
        return {
            "mode": self.mode,
            "enforced": list(self.enforced()),
            "missing": list(self.missing()),
        }


@dataclass(frozen=True)
class Instruction:
    """One transfer instruction, already validated against the synthetic accounts.

    Raises:
        LedgerRejection: on a blank or over-long id, a non-positive or oversized
            amount, an account outside :data:`SYNTHETIC_ACCOUNTS`, or a debit that
            equals its credit. These are malformed inputs, not findings - a
            scenario that cannot even form an instruction has nothing to assert.
    """

    instruction_id: str
    amount: Decimal = Decimal("100.00")
    debit_account: str = DEFAULT_DEBIT
    credit_account: str = DEFAULT_CREDIT
    signature: str = ""

    def __post_init__(self) -> None:
        raw_id = self.instruction_id
        instruction_id = raw_id.strip() if isinstance(raw_id, str) else ""
        if not instruction_id:
            raise LedgerRejection("instruction_id must be a non-empty id", got=repr(raw_id))
        if len(instruction_id) > 64:
            raise LedgerRejection("instruction_id is longer than 64 characters")
        object.__setattr__(self, "instruction_id", instruction_id)
        amount = Decimal(format_amount(self.amount))
        if amount <= 0:
            raise LedgerRejection("amount must be positive", amount=str(amount))
        if amount > MAX_AMOUNT:
            raise LedgerRejection("amount exceeds the lab ceiling", amount=str(amount))
        object.__setattr__(self, "amount", amount)
        for name in ("debit_account", "credit_account"):
            raw = getattr(self, name)
            account = raw.strip() if isinstance(raw, str) else ""
            if account not in SYNTHETIC_ACCOUNTS:
                raise LedgerRejection(
                    "%s is not a synthetic account" % name,
                    account=account,
                    candidates=sorted(SYNTHETIC_ACCOUNTS),
                )
            object.__setattr__(self, name, account)
        if self.debit_account == self.credit_account:
            raise LedgerRejection("an instruction needs two different accounts")
        raw_sig = self.signature
        object.__setattr__(self, "signature", raw_sig.strip() if isinstance(raw_sig, str) else "")

    def to_payload(self) -> dict[str, Any]:
        """The JSON body the runner POSTs (the signature travels in a header)."""
        return {
            "instruction_id": self.instruction_id,
            "amount": format_amount(self.amount),
            "debit_account": self.debit_account,
            "credit_account": self.credit_account,
        }


@dataclass(frozen=True)
class Posting:
    """One ledger posting, i.e. one movement of synthetic money.

    ``sequence`` is a monotonically increasing counter, not a timestamp: the report
    diff two runs, and a wall clock would make every run differ.

    Raises:
        LedgerRejection: on a blank id or a non-positive sequence.
    """

    posting_id: str
    instruction_id: str
    receipt_id: str
    debit_account: str
    credit_account: str
    amount: str
    sequence: int

    def __post_init__(self) -> None:
        for name in ("posting_id", "instruction_id", "receipt_id", "amount"):
            raw = getattr(self, name)
            value = raw.strip() if isinstance(raw, str) else ""
            if not value:
                raise LedgerRejection("Posting.%s must be non-empty" % name)
            object.__setattr__(self, name, value)
        if self.sequence <= 0:
            raise LedgerRejection("Posting.sequence starts at 1", sequence=self.sequence)

    def line(self) -> str:
        """One console line: sequence, posting id, amount and the account pair."""
        return "    #%02d %-8s %s -> %s  %s %s  (instruction %s, receipt %s)" % (
            self.sequence,
            self.posting_id,
            self.debit_account,
            self.credit_account,
            self.amount,
            "CNY",
            self.instruction_id,
            self.receipt_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "posting_id": self.posting_id,
            "instruction_id": self.instruction_id,
            "receipt_id": self.receipt_id,
            "debit_account": self.debit_account,
            "credit_account": self.credit_account,
            "amount": self.amount,
            "sequence": self.sequence,
        }


@dataclass(frozen=True)
class TransferOutcome:
    """What the gateway answered for one request, as the runner sees it.

    Attributes:
        status: HTTP status code.
        accepted: whether a posting exists because of this request.
        receipt_id: the receipt the ledger returned (empty when rejected).
        posting_id: the posting this request created (empty on replay or reject).
        error: machine-readable reason when ``accepted`` is false.
        replayed: true when the handler recognised the instruction and returned
            the stored receipt instead of posting - the signature of a *working*
            idempotency control.
    """

    status: int
    accepted: bool
    receipt_id: str = ""
    posting_id: str = ""
    error: str = ""
    replayed: bool = False

    @property
    def ok(self) -> bool:
        """True for a 2xx status."""
        return 200 <= self.status < 300

    def to_dict(self) -> dict[str, Any]:
        """JSON form; keys are always present so a diff shows only value changes."""
        return {
            "status": self.status,
            "accepted": self.accepted,
            "receipt_id": self.receipt_id,
            "posting_id": self.posting_id,
            "error": self.error,
            "replayed": self.replayed,
        }


class SyntheticLedger:
    """The mock ledger: two balances, a posting list, one optional receipt table.

    Args:
        controls: which gates the gateway honours; defaults to
            :meth:`ControlSet.vulnerable`.
        window_seconds: sleep inserted between "have I seen this instruction?" and
            "post it" in the *vulnerable* path only. The module docstring explains
            why widening the race window is a measurement decision, not a shortcut.

    Concurrency contract: every mutation happens under ``_mutex``, so the ledger
    never corrupts a balance. The defect reproduced here is not a corrupted balance
    - it is *two valid postings for one instruction*, a business-level invariant
    that :meth:`duplicated_instructions` reads back the way a T+1 reconciliation
    job would.

    Raises:
        LedgerRejection: when ``window_seconds`` is negative.
    """

    def __init__(self, controls: ControlSet | None = None, *, window_seconds: float = 0.02) -> None:
        self.controls = controls if controls is not None else ControlSet.vulnerable()
        if window_seconds < 0:
            raise LedgerRejection(
                "window_seconds cannot be negative", window_seconds=window_seconds
            )
        self.window_seconds = float(window_seconds)
        self._balances: dict[str, Decimal] = dict(SYNTHETIC_ACCOUNTS)
        self._postings: list[Posting] = []
        self._receipts: dict[str, str] = {}
        self._mutex = threading.Lock()
        self._gate = threading.Lock()
        self._receipt_seq = 0
        self._accepted = 0

    # -- reads ---------------------------------------------------------------
    @property
    def postings(self) -> tuple[Posting, ...]:
        """Every posting, in the order it was written."""
        return tuple(self._postings)

    def balance_of(self, account: str) -> Decimal:
        """Current balance of a synthetic account (``Decimal("0.00")`` if unknown)."""
        return self._balances.get(account, Decimal("0.00"))

    def postings_for(self, instruction_id: str) -> tuple[Posting, ...]:
        """Every posting written for one instruction id, oldest first."""
        key = instruction_id.strip()
        return tuple(item for item in self._postings if item.instruction_id == key)

    def duplicated_instructions(self) -> tuple[str, ...]:
        """Instruction ids that posted more than once - the reconciliation verdict.

        This is the *detective* control of the experiment: it does not need to know
        whether idempotency was implemented, it only asks whether the ledger holds
        two postings for one instruction. A T+1 reconciliation job asks exactly
        this question, which is why the range can detect a duplicate even when the
        gateway cannot prevent it.
        """
        counts: dict[str, int] = {}
        for posting in self._postings:
            counts[posting.instruction_id] = counts.get(posting.instruction_id, 0) + 1
        return tuple(sorted(key for key, count in counts.items() if count > 1))

    def total_debited(self, account: str = DEFAULT_DEBIT) -> Decimal:
        """Sum of the postings that left ``account``."""
        return sum(
            (posting_amount(item) for item in self._postings if item.debit_account == account),
            Decimal("0.00"),
        )

    def snapshot(self) -> dict[str, Any]:
        """The observability view: controls, balances, postings, duplicates."""
        balances = {name: format_amount(value) for name, value in sorted(self._balances.items())}
        return {
            "controls": self.controls.to_dict(),
            "balances": balances,
            "accepted_requests": self._accepted,
            "postings": [item.to_dict() for item in self._postings],
            "duplicated_instructions": list(self.duplicated_instructions()),
        }

    # -- writes --------------------------------------------------------------
    def submit(self, instruction: Instruction) -> TransferOutcome:
        """Apply one instruction, honouring exactly the controls in ``controls``.

        The three paths are deliberately shaped differently, because the difference
        *is* the finding:

        * signature control on: a bad signature is refused before the ledger is
          touched (``401``, no posting);
        * idempotency control on: the check and the post happen inside one lock, so
          a concurrent duplicate waits and then reads the stored receipt (``200``,
          ``replayed=True``, no second posting);
        * neither: the decision is "nothing tells me otherwise", the window sleeps,
          and the post happens - twice, if two requests got that far.
        """
        if self.controls.signature_verification and not self._signature_ok(instruction):
            return TransferOutcome(status=401, accepted=False, error="signature_rejected")
        if self.controls.idempotency_token:
            with self._gate:
                return self._post(instruction, remember=True)
        if self.window_seconds:
            time.sleep(self.window_seconds)
        return self._post(instruction, remember=False)

    def _signature_ok(self, instruction: Instruction) -> bool:
        """Constant-time comparison of the request signature with the expected one."""
        expected = instruction_signature(instruction.instruction_id, instruction.amount)
        return hmac.compare_digest(instruction.signature, expected)

    def _post(self, instruction: Instruction, *, remember: bool) -> TransferOutcome:
        """Check the balance and write the posting; the only mutating path."""
        with self._mutex:
            if remember:
                known = self._receipts.get(instruction.instruction_id)
                if known is not None:
                    return TransferOutcome(
                        status=200, accepted=True, receipt_id=known, replayed=True
                    )
            if instruction.amount > self._balances[instruction.debit_account]:
                return TransferOutcome(status=409, accepted=False, error="insufficient_funds")
            self._balances[instruction.debit_account] -= instruction.amount
            self._balances[instruction.credit_account] += instruction.amount
            self._accepted += 1
            self._receipt_seq += 1
            receipt_id = "RCP-%04d" % self._receipt_seq
            sequence = len(self._postings) + 1
            posting = Posting(
                posting_id="PST-%04d" % sequence,
                instruction_id=instruction.instruction_id,
                receipt_id=receipt_id,
                debit_account=instruction.debit_account,
                credit_account=instruction.credit_account,
                amount=format_amount(instruction.amount),
                sequence=sequence,
            )
            self._postings.append(posting)
            if remember:
                self._receipts[instruction.instruction_id] = receipt_id
            return TransferOutcome(
                status=200,
                accepted=True,
                receipt_id=receipt_id,
                posting_id=posting.posting_id,
            )


def posting_amount(posting: Posting) -> Decimal:
    """The ``Decimal`` amount of a :class:`Posting` (its field is a string for JSON)."""
    return Decimal(posting.amount)
