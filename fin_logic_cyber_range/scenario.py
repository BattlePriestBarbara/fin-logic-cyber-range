# -*- coding: utf-8 -*-
"""Scenarios as data: what the client does, and what the ontology predicts.

Why the experiment is a file and not a function
-----------------------------------------------
A reviewable experiment has to be readable before it runs. Keeping the steps in
JSON under ``data/cyber_range/scenarios/`` makes "we now send the same instruction
three times instead of two" a one-line diff in a data file, and gives the safety
boundary something concrete to check at load time: a scenario naming a non-local
endpoint is rejected before a socket exists.

Actions
-------
=====================  ==================================================
action                 what the runner does
=====================  ==================================================
``transfer``           one signed request per repetition, same instruction id -
                       the timeout-resend shape a client produces
``concurrent_transfer``
                       ``workers`` requests with the same id released together
                       - the double-tap / retry-storm shape
``unsigned_transfer``  one request with no signature header at all
=====================  ==================================================

Repetitions and workers are bounded (``1..8`` and ``1..32``): an unbounded loop in
a file a user can edit is how a laboratory becomes a load generator aimed at
something else, and the point of a concurrency finding is that *two* requests
suffice.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fin_logic_cyber_range.ledger import DEFAULT_CREDIT, DEFAULT_DEBIT
from fin_logic_cyber_range.safety import ensure_local_url
from fin_logic_risk import RiskLevel
from ontology_builder.core.errors import DataContractError


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = _PROJECT_ROOT / "data" / "cyber_range" / "scenarios"

ACTIONS = ("transfer", "concurrent_transfer", "unsigned_transfer")
MAX_REPEAT = 8
MAX_WORKERS = 32
DEFAULT_ENDPOINT = "/mock/v1/transfer"

_REQUIRED_KEYS = frozenset({"name", "title", "steps"})
_OPTIONAL_KEYS = frozenset(
    {
        "description",
        "process",
        "target_api",
        "control",
        "endpoint",
        "expect_vulnerable",
        "expect_secure",
    }
)
_STEP_KEYS = frozenset(
    {"action", "instruction_id", "amount", "debit_account", "credit_account", "repeat", "workers"}
)


@dataclass(frozen=True)
class Step:
    """One client action in a scenario.

    Attributes:
        action: one of :data:`ACTIONS`.
        instruction_id: the business id every request in this step carries. Two
            steps may share an id on purpose - that *is* the replay.
        amount: amount as text, so the JSON and the signature agree byte for byte.
        debit_account: synthetic payer.
        credit_account: synthetic payee.
        repeat: sequential requests ``transfer`` sends (``1..8``).
        workers: simultaneous requests ``concurrent_transfer`` releases (``1..32``).

    Raises:
        DataContractError: on an unknown action, a blank id or amount, a
            non-positive or unbounded ``repeat``/``workers``.
    """

    instruction_id: str
    action: str = "transfer"
    amount: str = "100.00"
    debit_account: str = DEFAULT_DEBIT
    credit_account: str = DEFAULT_CREDIT
    repeat: int = 1
    workers: int = 4

    def __post_init__(self) -> None:
        action = self.action.strip() if isinstance(self.action, str) else ""
        if action not in ACTIONS:
            raise DataContractError(
                "%r is not a scenario action" % self.action, candidates=list(ACTIONS)
            )
        object.__setattr__(self, "action", action)
        raw_id = self.instruction_id
        instruction_id = raw_id.strip() if isinstance(raw_id, str) else ""
        if not instruction_id:
            raise DataContractError("Step.instruction_id must be a non-empty id")
        object.__setattr__(self, "instruction_id", instruction_id)
        amount = self.amount.strip() if isinstance(self.amount, str) else ""
        if not amount:
            raise DataContractError("Step.amount must be a non-empty decimal string")
        object.__setattr__(self, "amount", amount)
        if not 1 <= self.repeat <= MAX_REPEAT:
            raise DataContractError("Step.repeat must be 1..%d" % MAX_REPEAT, repeat=self.repeat)
        if not 1 <= self.workers <= MAX_WORKERS:
            raise DataContractError(
                "Step.workers must be 1..%d" % MAX_WORKERS, workers=self.workers
            )

    @property
    def signed(self) -> bool:
        """Whether this step sends a valid signature header."""
        return self.action != "unsigned_transfer"

    @property
    def concurrency(self) -> int:
        """Simultaneous requests this step releases (1 for sequential steps)."""
        return self.workers if self.action == "concurrent_transfer" else 1

    @property
    def requests(self) -> int:
        """Total requests this step sends."""
        return self.workers if self.action == "concurrent_transfer" else self.repeat

    def line(self) -> str:
        """One console line describing the step."""
        return "    %-20s %-18s %8s x%-2d signed=%-5s (%s)" % (
            self.action,
            self.instruction_id,
            self.amount,
            self.requests,
            self.signed,
            "concurrent" if self.concurrency > 1 else "sequential",
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "action": self.action,
            "instruction_id": self.instruction_id,
            "amount": self.amount,
            "debit_account": self.debit_account,
            "credit_account": self.credit_account,
            "repeat": self.repeat,
            "workers": self.workers,
        }


def as_risk_level(
    value: RiskLevel | str | None, *, default: RiskLevel = RiskLevel.NONE
) -> RiskLevel:
    """Coerce a scenario field to a :class:`RiskLevel`.

    Raises:
        DataContractError: when the value is a string naming no level - a typo like
            ``"hight"`` must not silently become ``NONE``, because ``NONE`` is an
            *assertion* ("nothing should happen") and would turn a broken scenario
            into a passing one.
    """
    if value is None:
        return default
    if isinstance(value, RiskLevel):
        return value
    text = value.strip() if isinstance(value, str) else ""
    for member in RiskLevel:
        if text.casefold() == member.value:
            return member
    raise DataContractError("%r is not a risk level" % (value,), candidates=RiskLevel.values())


@dataclass(frozen=True)
class Scenario:
    """One reviewable experiment: a client script plus the prediction it falsifies.

    Attributes:
        name: slug (``[a-z0-9_]``) - the key a report row is identified by.
        title: human-readable title, Chinese like the rest of this project's prose.
        steps: the client actions, in order; never empty.
        description: one paragraph on what business situation the steps imitate.
        process: the stage-10 ``Business_Process`` the route serves.
        target_api: the stage-10 ``API_Endpoint`` the scenario claims to exercise.
            "Claims" is literal: the mock route is not that API, and the mapping is
            the hypothesis under test.
        control: the ``Security_Control`` whose absence the scenario is about.
        endpoint: path on the mock gateway; validated as a safe local path.
        expect_vulnerable: risk the ontology predicts for the unguarded arm.
        expect_secure: risk predicted once both controls are on - normally
            ``NONE``, and asserted separately rather than assumed.

    Raises:
        DataContractError: on a blank or malformed name, a missing title, no steps,
            an endpoint that is not a plain local path, or an unknown expectation.
    """

    name: str
    title: str
    steps: tuple[Step, ...]
    description: str = ""
    process: str = "Fund_Transfer_Process"
    target_api: str = "Transfer_API"
    control: str = "Idempotency_Token"
    endpoint: str = DEFAULT_ENDPOINT
    expect_vulnerable: RiskLevel = RiskLevel.NONE
    expect_secure: RiskLevel = RiskLevel.NONE

    def __post_init__(self) -> None:
        name = self.name.strip() if isinstance(self.name, str) else ""
        if not name:
            raise DataContractError("Scenario.name must be a non-empty slug")
        if len(name) > 48 or not all(char.isalnum() or char == "_" for char in name):
            raise DataContractError(
                "Scenario.name must be a slug of letters, digits and underscores", name=name
            )
        object.__setattr__(self, "name", name)
        title = self.title.strip() if isinstance(self.title, str) else ""
        if not title:
            raise DataContractError("Scenario.title must be a non-empty title", scenario=name)
        object.__setattr__(self, "title", title)
        steps = tuple(self.steps)
        if not steps:
            raise DataContractError("a scenario needs at least one step", scenario=name)
        for step in steps:
            if not isinstance(step, Step):
                raise DataContractError(
                    "Scenario.steps must be Step instances", got=type(step).__name__
                )
        object.__setattr__(self, "steps", steps)
        endpoint = self.endpoint.strip() if isinstance(self.endpoint, str) else ""
        ensure_local_url("http://127.0.0.1:8080%s" % endpoint)
        object.__setattr__(self, "endpoint", endpoint)
        for field_name in ("process", "target_api", "control"):
            raw = getattr(self, field_name)
            value = raw.strip() if isinstance(raw, str) else ""
            if not value:
                raise DataContractError(
                    "Scenario.%s must name an ontology concept" % field_name, scenario=name
                )
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "description", self.description.strip())
        object.__setattr__(self, "expect_vulnerable", as_risk_level(self.expect_vulnerable))
        object.__setattr__(self, "expect_secure", as_risk_level(self.expect_secure))

    # -- derived facts -------------------------------------------------------
    @property
    def instruction_ids(self) -> tuple[str, ...]:
        """Distinct instruction ids, in first-seen order."""
        seen: list[str] = []
        for step in self.steps:
            if step.instruction_id not in seen:
                seen.append(step.instruction_id)
        return tuple(seen)

    @property
    def requests(self) -> int:
        """Total requests the whole scenario sends."""
        return sum(step.requests for step in self.steps)

    @property
    def sends_unsigned(self) -> bool:
        """Whether any step omits the signature - i.e. the signature invariant applies."""
        return any(not step.signed for step in self.steps)

    def expectation(self, mode: str) -> RiskLevel:
        """The predicted risk for ``mode`` (``"vulnerable"`` or ``"secure"``).

        Raises:
            DataContractError: for any other mode, rather than guessing one.
        """
        if mode == "vulnerable":
            return self.expect_vulnerable
        if mode == "secure":
            return self.expect_secure
        raise DataContractError("no expectation for mode %r" % mode, scenario=self.name)

    def to_dict(self) -> dict[str, Any]:
        """JSON form; expectations are spelled as level values, not ranks."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "process": self.process,
            "target_api": self.target_api,
            "control": self.control,
            "endpoint": self.endpoint,
            "expect_vulnerable": self.expect_vulnerable.value,
            "expect_secure": self.expect_secure.value,
            "requests": self.requests,
            "steps": [step.to_dict() for step in self.steps],
        }


def scenario_from_dict(payload: Any, *, source: str = "<memory>") -> Scenario:
    """Build a :class:`Scenario` from a decoded JSON object.

    Unknown keys are an error, not a warning: a typo in ``expect_vulnerble`` would
    otherwise leave the prediction at its ``NONE`` default and turn a real finding
    into a silently passing test.

    Args:
        payload: the decoded JSON value; must be an object.
        source: where it came from, for the error message.

    Raises:
        DataContractError: on a non-object, a missing required key, an unknown key,
            an empty ``steps`` list, an unknown step key, or a step whose value has
            the wrong type.
    """
    if not isinstance(payload, dict):
        raise DataContractError(
            "a scenario file must hold a JSON object", source=source, got=type(payload).__name__
        )
    keys = set(payload)
    missing = sorted(_REQUIRED_KEYS - keys)
    if missing:
        raise DataContractError("scenario is missing required keys", source=source, missing=missing)
    unknown = sorted(keys - _REQUIRED_KEYS - _OPTIONAL_KEYS)
    if unknown:
        raise DataContractError(
            "scenario has unknown keys",
            source=source,
            unknown=unknown,
            candidates=sorted(_REQUIRED_KEYS | _OPTIONAL_KEYS),
        )
    raw_steps = payload["steps"]
    if not isinstance(raw_steps, list) or not raw_steps:
        raise DataContractError("scenario steps must be a non-empty list", source=source)
    steps: list[Step] = []
    for index, raw_step in enumerate(raw_steps, start=1):
        if not isinstance(raw_step, dict):
            raise DataContractError(
                "step %d must be an object" % index, source=source, got=type(raw_step).__name__
            )
        extra = sorted(set(raw_step) - _STEP_KEYS)
        if extra:
            raise DataContractError(
                "step %d has unknown keys" % index, source=source, unknown=extra
            )
        try:
            steps.append(Step(**raw_step))
        except TypeError as exc:
            raise DataContractError("step %d is malformed: %s" % (index, exc), source=source)
    fields = {key: value for key, value in payload.items() if key != "steps"}
    try:
        return Scenario(steps=tuple(steps), **fields)
    except TypeError as exc:
        raise DataContractError("scenario is malformed: %s" % exc, source=source)


def load_scenario(path: str | Path) -> Scenario:
    """Read one scenario JSON file.

    Raises:
        DataContractError: when the file is missing, not UTF-8, not JSON, or does
            not form a valid scenario.
    """
    target = Path(path)
    if not target.is_file():
        raise DataContractError("scenario file does not exist", path=str(target))
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise DataContractError("cannot read scenario file", path=str(target), error=str(exc))
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DataContractError("scenario file is not JSON", path=str(target), error=str(exc))
    return scenario_from_dict(payload, source=str(target))


def load_scenarios(directory: str | Path = SCENARIO_DIR) -> tuple[Scenario, ...]:
    """Read every ``*.json`` scenario in ``directory``, ordered by name.

    Raises:
        DataContractError: when the directory is missing or holds no scenario.
    """
    root = Path(directory)
    if not root.is_dir():
        raise DataContractError("scenario directory does not exist", path=str(root))
    found = [load_scenario(path) for path in sorted(root.glob("*.json"))]
    if not found:
        raise DataContractError("no scenario files in the directory", path=str(root))
    return tuple(sorted(found, key=lambda item: item.name))
