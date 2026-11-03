# -*- coding: utf-8 -*-
"""Value objects for what the analysis services return.

These live in ``core`` rather than in ``services`` so that a caller can type a
result, serialise it, or assert on it without importing numpy, torch or
matplotlib. They are frozen dataclasses with a ``to_dict()``: a service returns
one of these, the CLI writes it as JSON, and a test compares fields instead of
parsing console text.

Why not reuse the dataclasses in ``stats_analysis`` / ``kge_experiment``?
-----------------------------------------------------------------------
Two of them (``CalibrationReport``, ``PermutationResult``) are already the right
shape, but they are return values of *experiment scripts* that import numpy at
module scope. A report type that core code cannot import is not a contract, so
the four below are the stable surface; the numeric payload that is genuinely
opaque (one row per calibration bin) is carried as a plain mapping copied from
the stats layer, and core never interprets it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ontology_builder.core.errors import DataContractError

#: Tolerance for the range checks: ECE is a weighted mean of absolute gaps, so it
#: can land a few ulps outside [0, 1] on adversarial input and still be right.
_EPS = 1e-9

#: Version stamp every generated report carries. Bumped when a reader could be
#: misled by old files: a report without this key is from the era before the
#: advanced stage moved to ``logs/advanced/``, and its sibling baseline was
#: computed under different filters.
REPORT_SCHEMA_VERSION = "2.0"

_HEX_DIGITS = frozenset("0123456789abcdef")


def _check_unit(name: str, value: float) -> None:
    """Raise unless ``value`` is a probability in [0, 1]."""
    if not isinstance(value, (int, float)) or not -_EPS <= float(value) <= 1.0 + _EPS:
        raise DataContractError("%s must be a probability in [0, 1], got %r" % (name, value))


def _check_count(name: str, value: int, minimum: int = 0) -> None:
    """Raise unless ``value`` is an integer count of at least ``minimum``."""
    if not isinstance(value, int) or value < minimum:
        raise DataContractError("%s must be an int >= %d, got %r" % (name, minimum, value))


@dataclass(frozen=True)
class MetricSet:
    """The four link-prediction numbers, always quoted together.

    ``n_queries`` counts *ranked queries*, which is twice ``n_test``: every test
    triple is ranked once with the tail hidden and once with the head hidden.

    Raises:
        DataContractError: when a metric falls outside [0, 1] or a count is
            negative - a metric set that cannot exist is a bug upstream, not a
            number worth formatting.
    """

    mrr: float
    hits_at_1: float
    hits_at_3: float
    hits_at_10: float
    mean_rank: float = 0.0
    n_queries: int = 0

    def __post_init__(self) -> None:
        for name in ("mrr", "hits_at_1", "hits_at_3", "hits_at_10"):
            _check_unit(name, getattr(self, name))
        _check_count("n_queries", self.n_queries)
        if self.mean_rank < 0.0:
            raise DataContractError("mean_rank cannot be negative, got %r" % (self.mean_rank,))

    def to_dict(self) -> dict[str, Any]:
        """JSON form; six decimals is more than any of these numbers deserve."""
        return {
            "mrr": round(self.mrr, 6),
            "hits_at_1": round(self.hits_at_1, 6),
            "hits_at_3": round(self.hits_at_3, 6),
            "hits_at_10": round(self.hits_at_10, 6),
            "mean_rank": round(self.mean_rank, 6),
            "n_queries": self.n_queries,
        }

    def line(self) -> str:
        """One-line rendering used in the console summary and the report."""
        return "MRR %.4f  H@1 %.4f  H@3 %.4f  H@10 %.4f  MR %.2f" % (
            self.mrr,
            self.hits_at_1,
            self.hits_at_3,
            self.hits_at_10,
            self.mean_rank,
        )


@dataclass(frozen=True)
class CalibrationAssessment:
    """How well ``confidence_score`` behaves like a probability.

    ``bins`` carries one JSON-ready row per confidence interval, produced by the
    stats layer (``CalibrationBin.to_dict()``). It is passed through untranslated
    on purpose: the definition of a bin belongs to the code that computes ECE,
    and core has no business re-deriving it.

    Raises:
        DataContractError: on a negative count, an empty binning, an ECE outside
            [0, 1], or a non-positive temperature.
    """

    proxy: str
    n: int
    n_bins: int
    occupied_bins: int
    ece: float
    mce: float
    brier: float
    base_rate: float
    mean_confidence: float
    verdict: str
    formula: str = "ECE = sum_{m=1}^{M} (|B_m| / n) * |acc(B_m) - conf(B_m)|"
    bins: tuple[Mapping[str, Any], ...] = ()
    temperature: float | None = None
    ece_after_temperature: float | None = None

    def __post_init__(self) -> None:
        _check_count("n", self.n)
        _check_count("n_bins", self.n_bins, minimum=1)
        _check_count("occupied_bins", self.occupied_bins)
        for name in ("ece", "mce", "brier", "base_rate", "mean_confidence"):
            _check_unit(name, getattr(self, name))
        if self.occupied_bins > self.n_bins:
            raise DataContractError(
                "occupied_bins (%d) cannot exceed n_bins (%d)" % (self.occupied_bins, self.n_bins)
            )
        if self.temperature is not None and self.temperature <= 0.0:
            raise DataContractError("temperature must be > 0, got %r" % (self.temperature,))

    @property
    def overconfident(self) -> bool:
        """True when predictions sit above the observed base rate."""
        return self.mean_confidence > self.base_rate

    def to_dict(self) -> dict[str, Any]:
        """JSON form, including the formula so the log is self-explanatory."""
        return {
            "proxy_label": self.proxy,
            "n": self.n,
            "n_bins": self.n_bins,
            "occupied_bins": self.occupied_bins,
            "ece": round(self.ece, 6),
            "mce": round(self.mce, 6),
            "brier": round(self.brier, 6),
            "base_rate": round(self.base_rate, 6),
            "mean_confidence": round(self.mean_confidence, 6),
            "bias": round(self.mean_confidence - self.base_rate, 6),
            "verdict": self.verdict,
            "formula": self.formula,
            "temperature": None if self.temperature is None else round(self.temperature, 6),
            "ece_after_temperature": (
                None if self.ece_after_temperature is None else round(self.ece_after_temperature, 6)
            ),
            "bins": [dict(row) for row in self.bins],
        }

    def lines(self) -> list[str]:
        """Reliability table plus the headline numbers, as fixed-width text."""
        out = [
            "  bin              n   weight     conf      acc       gap   contrib",
            "  " + "-" * 70,
        ]
        for row in self.bins:
            if not row["count"]:
                out.append(
                    "  %-14s %3d   %6.3f        -        -         -   (empty)"
                    % (row["range"], 0, 0.0)
                )
                continue
            out.append(
                "  %-14s %3d   %6.3f   %.3f    %.3f   %+8.3f   %7.4f"
                % (
                    row["range"],
                    row["count"],
                    row["weight"],
                    row["mean_confidence"],
                    row["empirical_accuracy"],
                    row["gap"],
                    row["contribution_to_ece"],
                )
            )
        out.append("  " + "-" * 70)
        headline = "  ECE = %.4f   MCE = %.4f   Brier = %.4f   base_rate = %.4f   n = %d" % (
            self.ece,
            self.mce,
            self.brier,
            self.base_rate,
            self.n,
        )
        out.append(headline)
        if self.temperature is not None and self.ece_after_temperature is not None:
            out.append(
                "  temperature scaling: T = %.4f   ECE %.4f -> %.4f"
                % (self.temperature, self.ece, self.ece_after_temperature)
            )
        out.append("  proxy label: %s   verdict: %s" % (self.proxy, self.verdict))
        return out


@dataclass(frozen=True)
class SignificanceReport:
    """Outcome of the permutation test on hub-hub edge confidence.

    ``rejected`` is the *decision* at ``alpha``; ``p_value`` is the evidence, and
    ``min_achievable_p = 1 / (B + 1)`` is the floor the permutation count allows -
    quoting a p-value at that floor as if it were ``< 0.0001`` would overstate a
    1000-shuffle test.

    Raises:
        DataContractError: on a p-value or alpha outside [0, 1], a negative
            permutation count, or a zero-sized group.
    """

    hubs: tuple[str, ...]
    hub_edges: tuple[str, ...]
    group_a_size: int
    group_b_size: int
    group_a_mean: float
    group_b_mean: float
    observed_difference: float
    p_value: float
    n_permutations: int
    seed: int
    alpha: float
    effect_size: float
    ci_low: float
    ci_high: float
    null_mean: float
    null_std: float
    min_achievable_p: float
    alternative: str = "two-sided"
    missing_hubs: tuple[str, ...] = ()
    statistic: str = "mean(confidence | hub-hub) - mean(confidence | other)"

    def __post_init__(self) -> None:
        _check_unit("p_value", self.p_value)
        _check_unit("alpha", self.alpha)
        _check_count("n_permutations", self.n_permutations, minimum=1)
        _check_count("group_a_size", self.group_a_size, minimum=1)

    @property
    def rejected(self) -> bool:
        """True when H0 is rejected at ``alpha`` (``p < alpha``)."""
        return self.p_value < self.alpha

    def conclusion(self) -> str:
        """One sentence carrying the decision, the evidence and the effect size."""
        decision = "reject H0" if self.rejected else "fail to reject H0"
        return (
            "p = %.4f, %s at alpha = %.2f (difference %+.4f, Cohen's d %+.2f, "
            "%d vs %d edges)"
            % (
                self.p_value,
                decision,
                self.alpha,
                self.observed_difference,
                self.effect_size,
                self.group_a_size,
                self.group_b_size,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON form; the null-distribution shape is kept so the test is auditable."""
        return {
            "statistic": self.statistic,
            "alternative": self.alternative,
            "hubs": list(self.hubs),
            "missing_hubs": list(self.missing_hubs),
            "hub_hub_edges": list(self.hub_edges),
            "group_a_size": self.group_a_size,
            "group_b_size": self.group_b_size,
            "group_a_mean": round(self.group_a_mean, 6),
            "group_b_mean": round(self.group_b_mean, 6),
            "observed_difference": round(self.observed_difference, 6),
            "p_value": round(self.p_value, 6),
            "min_achievable_p": round(self.min_achievable_p, 6),
            "n_permutations": self.n_permutations,
            "seed": self.seed,
            "alpha": self.alpha,
            "significant_at_alpha": self.rejected,
            "effect_size_cohens_d": round(self.effect_size, 6),
            "bootstrap_ci95": [round(self.ci_low, 6), round(self.ci_high, 6)],
            "null_distribution": {
                "mean": round(self.null_mean, 6),
                "std": round(self.null_std, 6),
            },
            "conclusion": self.conclusion(),
        }

    def lines(self) -> list[str]:
        """Fixed-width summary for the console."""
        null_line = "  null distribution     : mean %+.4f  sd %.4f  (B = %d, seed = %d)" % (
            self.null_mean,
            self.null_std,
            self.n_permutations,
            self.seed,
        )
        observed = "  observed difference   : %+.4f  (hubs %.4f vs rest %.4f)" % (
            self.observed_difference,
            self.group_a_mean,
            self.group_b_mean,
        )
        return [
            null_line,
            observed,
            "  p-value               : %.4f   (floor %.4f, alpha %.2f)"
            % (
                self.p_value,
                self.min_achievable_p,
                self.alpha,
            ),
            "  decision              : %s" % ("REJECT H0" if self.rejected else "retain H0"),
        ]


@dataclass(frozen=True)
class LinkPredictionReport:
    """What one trained embedding model scored, with the protocol that produced it.

    ``filtered`` is the headline number and ``raw`` is reported next to it
    because the gap between them is itself informative: a large gap means many
    test queries have other known-true answers, i.e. the model is being asked
    multi-answer questions rather than being punished by a bug.

    Raises:
        DataContractError: when the split sizes are negative or the protocol
            string is empty (a metrics table without its protocol is not citable).
    """

    model: str
    filtered: MetricSet
    raw: MetricSet
    chance: MetricSet
    n_test: int
    protocol: str
    split: Mapping[str, int] = field(default_factory=dict)
    config: Mapping[str, Any] = field(default_factory=dict)
    epochs_run: int = 0
    best_epoch: int = 0
    stopped_early: bool = False
    train_seconds: float = 0.0
    history: tuple[Mapping[str, Any], ...] = ()
    #: Which split produced ``filtered``: ``"transductive"`` (the phase-5 protocol)
    #: or ``"symmetric_pair_safe"``. Quoting a metric without its split protocol is
    #: how two incomparable numbers end up in one table.
    split_protocol: str = "transductive"
    #: True when every symmetric positive/reverse pair sits in one split.
    pair_safe: bool = False
    #: Metrics over the TBox-admissible candidate pool, and the random baseline
    #: computed on **that same pool**. Both or neither: a constrained number with
    #: the unrestricted baseline subtracted from it would invent a lift.
    constrained: MetricSet | None = None
    constrained_chance: MetricSet | None = None
    #: Mean number of candidates left per query by the gate (``|E|`` minus vetoes).
    constrained_pool: float = 0.0
    #: Queries that vanished because the gate rejected the true answer itself.
    constrained_skipped: int = 0
    #: The gate's own tally (accepted/rejected and reasons), copied from the report.
    gate: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _check_count("n_test", self.n_test, minimum=1)
        if not str(self.protocol).strip():
            raise DataContractError("protocol must describe the evaluation setting")
        for name, size in self.split.items():
            _check_count("split[%r]" % name, size)
        _check_count("constrained_skipped", self.constrained_skipped)
        if self.constrained_pool < 0.0:
            raise DataContractError(
                "constrained_pool cannot be negative, got %r" % (self.constrained_pool,)
            )
        if (self.constrained is None) != (self.constrained_chance is None):
            raise DataContractError(
                "constrained metrics and their random baseline are quoted together or not at all"
            )

    @property
    def lift_over_chance(self) -> float:
        """Filtered MRR minus the MRR of a model that ranks at random."""
        return self.filtered.mrr - self.chance.mrr

    @property
    def filtering_gain(self) -> float:
        """Filtered minus raw MRR: how much of the raw score was other true edges."""
        return self.filtered.mrr - self.raw.mrr

    def to_dict(self) -> dict[str, Any]:
        """JSON form: headline metrics, the split, the config and the history."""
        payload: dict[str, Any] = {
            "model": self.model,
            "protocol": self.protocol,
            "split_protocol": self.split_protocol,
            "pair_safe": self.pair_safe,
            "n_test": self.n_test,
            "split": dict(self.split),
            "config": dict(self.config),
            "filtered": self.filtered.to_dict(),
            "raw": self.raw.to_dict(),
            "chance": self.chance.to_dict(),
            "lift_over_chance": round(self.lift_over_chance, 6),
            "filtering_gain": round(self.filtering_gain, 6),
            "constrained": None if self.constrained is None else self.constrained.to_dict(),
            "constrained_chance": (
                None if self.constrained_chance is None else self.constrained_chance.to_dict()
            ),
            "constrained_pool": round(self.constrained_pool, 4),
            "constrained_skipped": self.constrained_skipped,
            "gate": dict(self.gate),
            "epochs_run": self.epochs_run,
            "best_epoch": self.best_epoch,
            "stopped_early": self.stopped_early,
            "train_seconds": round(self.train_seconds, 3),
            "history": [dict(row) for row in self.history],
        }
        return payload

    def lines(self) -> list[str]:
        """Console summary: filtered, raw, chance and the early-stopping verdict."""
        rows = [
            "  %-6s filtered  %s" % (self.model, self.filtered.line()),
            "         raw       %s" % self.raw.line(),
            "         chance    %s  (random scorer, same filters)" % self.chance.line(),
        ]
        if self.constrained is not None and self.constrained_chance is not None:
            rows.append(
                "      constrained  %s  (TBox-admissible pool, %.1f candidates/query)"
                % (self.constrained.line(), self.constrained_pool)
            )
            rows.append(
                "         chance    %s  (random scorer, same admissible pool)"
                % self.constrained_chance.line()
            )
        rows.append(
            "         epochs %d/%s%s, best epoch %d, %.1fs"
            % (
                self.epochs_run,
                self.config.get("epochs", "?"),
                " (early stop)" if self.stopped_early else "",
                self.best_epoch,
                self.train_seconds,
            )
        )
        return rows


@dataclass(frozen=True)
class ReportMeta:
    """The provenance stamp every generated report starts with.

    A metrics table without this block is not reproducible: the same pipeline over
    ``ontology_graph.json`` and over ``ontology_graph_canonical.json`` produces
    different splits, different chance baselines and different numbers, and both
    files sat in the same directory. Recording the path *and* the content hash
    means a reader can tell which graph a report describes even after either file
    is regenerated.

    Raises:
        DataContractError: when the version or path is blank, the hash is not a
            64-character hex digest, or a count is not a non-negative integer.
    """

    input_graph: str
    graph_sha256: str
    seed: int
    edge_count: int
    schema_version: str = REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not str(self.schema_version).strip():
            raise DataContractError("schema_version must not be blank")
        if not str(self.input_graph).strip():
            raise DataContractError("input_graph must name the file the numbers came from")
        digest = str(self.graph_sha256).strip().lower()
        if len(digest) != 64 or not set(digest) <= _HEX_DIGITS:
            raise DataContractError(
                "graph_sha256 must be a 64-character hex digest, got %r" % (self.graph_sha256,)
            )
        _check_count("seed", self.seed)
        _check_count("edge_count", self.edge_count, minimum=1)

    def to_dict(self) -> dict[str, Any]:
        """JSON form: the five keys a reader checks before reading any metric."""
        return {
            "schema_version": self.schema_version,
            "input_graph": self.input_graph,
            "graph_sha256": self.graph_sha256,
            "seed": self.seed,
            "edge_count": self.edge_count,
        }

    def lines(self) -> list[str]:
        """Console lines: which graph, and its fingerprint."""
        return [
            "  schema %s   seed %d   edges %d" % (self.schema_version, self.seed, self.edge_count),
            "  input  %s" % self.input_graph,
            "  sha256 %s" % self.graph_sha256,
        ]


@dataclass(frozen=True)
class PredictionGateReport:
    """What the TBox let through, what it vetoed, and why.

    The counters are the report's own audit: ``accepted + rejected == proposed``
    and ``sum(rejection_reasons.values()) == rejected`` are enforced in
    ``__post_init__``, because a histogram that does not add up is the usual way a
    filtered evaluation turns out to have filtered something other than what the
    text claims.

    ``non_blocking_codes`` records the ERROR-level findings that were *not* applied
    as vetoes and why - a symmetric proposal is admissible even though its mirror
    is missing, since admitting it is what obliges the caller to write both.

    Raises:
        DataContractError: when the counters do not reconcile or a count is
            negative.
    """

    proposed: int
    accepted: int
    rejected: int
    rejection_reasons: Mapping[str, int] = field(default_factory=dict)
    warning_reasons: Mapping[str, int] = field(default_factory=dict)
    per_relation: Mapping[str, int] = field(default_factory=dict)
    mirrors_required: int = 0
    schema_name: str = ""
    schema_version: str = ""
    non_blocking_codes: tuple[str, ...] = ()
    edges: tuple[Mapping[str, Any], ...] = ()
    rejected_edges: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        for name in ("proposed", "accepted", "rejected", "mirrors_required"):
            _check_count(name, getattr(self, name))
        if self.accepted + self.rejected != self.proposed:
            raise DataContractError(
                "the gate counters do not reconcile: %d accepted + %d rejected != %d proposed"
                % (self.accepted, self.rejected, self.proposed)
            )
        for name, histogram in (
            ("rejection_reasons", self.rejection_reasons),
            ("warning_reasons", self.warning_reasons),
            ("per_relation", self.per_relation),
        ):
            for key, count in histogram.items():
                _check_count("%s[%r]" % (name, key), count)
        if sum(self.rejection_reasons.values()) != self.rejected:
            raise DataContractError(
                "rejection_reasons sum to %d, but %d edges were rejected"
                % (sum(self.rejection_reasons.values()), self.rejected)
            )

    @property
    def acceptance_rate(self) -> float:
        """Accepted share of the proposals; ``1.0`` when nothing was proposed."""
        return 1.0 if self.proposed == 0 else self.accepted / self.proposed

    @property
    def top_reason(self) -> str:
        """The most frequent veto code, or ``""`` when nothing was vetoed."""
        if not self.rejection_reasons:
            return ""
        return max(sorted(self.rejection_reasons), key=lambda code: self.rejection_reasons[code])

    def to_dict(self) -> dict[str, Any]:
        """JSON form: the counters, both histograms and the surviving edges."""
        return {
            "proposed": self.proposed,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "acceptance_rate": round(self.acceptance_rate, 6),
            "rejection_reasons": dict(sorted(self.rejection_reasons.items())),
            "warning_reasons": dict(sorted(self.warning_reasons.items())),
            "per_relation": dict(sorted(self.per_relation.items())),
            "mirrors_required": self.mirrors_required,
            "schema_name": self.schema_name,
            "schema_version": self.schema_version,
            "non_blocking_codes": list(self.non_blocking_codes),
            "edges": [dict(edge) for edge in self.edges],
            "rejected_edges": [dict(edge) for edge in self.rejected_edges],
        }

    def lines(self) -> list[str]:
        """Console summary: how many survived and which rule did the vetoing."""
        return [
            "  gate: %d proposed -> %d accepted, %d rejected (%.1f%% accepted)"
            % (self.proposed, self.accepted, self.rejected, 100.0 * self.acceptance_rate),
            "  vetoes: %s" % (dict(sorted(self.rejection_reasons.items())) or "none"),
            "  recorded but not blocking: %s" % (", ".join(self.non_blocking_codes) or "none"),
            "  mirrors still owed: %d" % self.mirrors_required,
        ]
