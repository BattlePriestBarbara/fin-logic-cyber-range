# -*- coding: utf-8 -*-
"""The financial business-logic TBox: five classes, five relations (task 10).

What this file is
-----------------
Stage 8 modelled *damage*: a route carries a flaw, the flaw exposes a dataset and
breaks a clause. Stage 10 models what stage 8 could not express - **a missing
control**, i.e. something that is not in the graph because nobody built it:

* the graph states the **requirement** (``Business_Process`` -[``REQUIRES_CONTROL``]
  -> ``Security_Control``);
* the graph states the **finding** (``API_Endpoint`` -[``LACKS_CONTROL``] ->
  ``Security_Control``);
* the reasoner intersects the two, and only that pair produces a risk. A control
  the process never asked for is a hygiene note, not a finding.

That intersection is the whole point. A walk over edges cannot produce it, because
the two edges live on different nodes and mean opposite things ("must have" vs
"does not have"); :mod:`fin_logic_risk.risk_reasoner` computes the set difference.

Classes
-------
=====================  ===================  =========================================
class                   category             what it is
=====================  ===================  =========================================
API_Endpoint            ``api_endpoint``      one route with its own authz path (S8)
Business_Process        ``business_process``  the process a route serves, e.g. Transfer
Security_Control        ``security_control``  a mechanism the process relies on
Logic_Vulnerability     ``vulnerability``     a logic flaw (S7/S8, reused)
Compliance_Term         ``compliance_rule``   a clause a flaw breaks (S8, reused)
=====================  ===================  =========================================

Three of the five categories are *reused* from stages 7 and 8. A logic flaw is
still a flaw and a clause is still a clause; re-declaring them under new ids is
the one thing ``fin_security``'s migration checklist forbids, because it splits
the vocabulary into two spellings of one idea. Only the two classes the framework
had no word for - a *process* and a *control* - are new members.

Relations
---------
==============================  ===========================  =========================
relation                         domain -> range              reading
==============================  ===========================  =========================
``IMPLEMENTS``                   api_endpoint -> process      "serves this process"
``REQUIRES_CONTROL``             process -> control           "cannot be correct
                                                              without this control"
``LACKS_CONTROL``                api_endpoint -> control      "was reviewed and does
                                                              not enforce it"
``LEADS_TO_VULNERABILITY``       control -> vulnerability     "**lacking** it
                                                              permits this flaw"
``VIOLATES_COMPLIANCE``          vulnerability -> rule        "breaks this clause"
==============================  ===========================  =========================

``LEADS_TO_VULNERABILITY`` is the one edge whose subject is an *absence*, and that
asymmetry is deliberate rather than sloppy: the flaw does not follow from the
control existing, it follows from the control being missing on a specific route.
Attaching the consequence to the control keeps the graph finite (one edge per
control, not one per ``(route, control)`` pair) and puts the "only when missing"
condition in the reasoner, which is exactly where the intersection already lives.
Read every ``LEADS_TO_VULNERABILITY`` in this domain as
"absence of the source permits the target".

``VIOLATES_COMPLIANCE`` is a *name*, not a new member: it is
``RelationType.VIOLATES`` (stage 8), which already reads vulnerability ->
compliance_rule with the same domain/range. The alias exists so the graph's prose
and the reports can say ``VIOLATES_COMPLIANCE`` while the vocabulary keeps one id
for one meaning.

Three deliberate omissions, all load-bearing for the reasoner:

* **no confidence bands.** A band detects *extractor* drift
  (``ConfidenceBandConstraint``); this graph is hand-authored
  (``data/fin_logic_micro_graph.json``, 9 nodes), so a band would only fire on the
  person editing the JSON;
* **no ``functional`` / ``symmetric`` / ``transitive`` closure.** ``REQUIRES_CONTROL``
  is ``acyclic`` (a process that requires itself is a modelling error) and
  ``LEADS_TO_VULNERABILITY`` is ``acyclic`` (a flaw that permits itself says
  nothing), but nothing is materialised: the two-hop chain is computed by the
  reasoner, never stored as an edge;
* **``LACKS_CONTROL`` is not a negation operator.** It is a plain edge with a
  negative verb. Modelling "no such edge" as the positive case (control present)
  is what lets the reasoner treat ``required - missing`` as the satisfied set
  without a second closed-world assumption anywhere else in the graph.

Why ``declared_unused_ok`` subtracts this TBox' own relations
------------------------------------------------------------
``DeclaredRelationUnusedConstraint`` walks the whole shared vocabulary, so without
the exemption every run on this graph would report twenty "declared but unused"
warnings for relations that belong to the Palantir, security, finance and tooling
corpora. Computing the complement (rather than listing the twenty) means the next
widening shows up here automatically, exactly as the three earlier domains do it.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from ontology_builder.core.contracts import Severity
from ontology_builder.ontology.tbox import OntologySchema, RelationRule
from ontology_builder.schema import ConceptCategory, RelationType


@dataclass(frozen=True)
class OntologyClass:
    """One class of the business-logic ontology, as a category plus a definition.

    Attributes:
        name: the class name a reader uses in prose (``"Business_Process"``).
        category: the :class:`ConceptCategory` a node of this class carries. The
            category, not the name, is what the constraints and the reasoner
            branch on - a graph file stores the category value, so renaming a
            class never invalidates stored data.
        definition: one sentence, in the same shape as
            :class:`~ontology_builder.schema.OntologyConcept.definition` so it can
            be copied into a node verbatim.
        reused: whether the category comes from an earlier stage. Recorded because
            the migration checklist treats a reused member as a *decision*, and a
            reader of the class table should see which ones were decisions.
    """

    name: str
    category: ConceptCategory
    definition: str
    reused: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON form for the report the CLI prints."""
        return {
            "class": self.name,
            "category": self.category.value,
            "definition": self.definition,
            "reused": self.reused,
        }


#: The five classes, in the order the story is told: a route serves a process,
#: the process needs controls, one of them is missing, and the flaw it permits
#: breaks a clause. ``Logic_Vulnerability`` and ``Compliance_Term`` are the
#: stage-7/8 categories, reused.
FIN_LOGIC_CLASSES: tuple[OntologyClass, ...] = (
    OntologyClass(
        name="API_Endpoint",
        category=ConceptCategory.API_ENDPOINT,
        definition="One route of the bank's API surface, with its own authentication path.",
        reused=True,
    ),
    OntologyClass(
        name="Business_Process",
        category=ConceptCategory.BUSINESS_PROCESS,
        definition=(
            "A business process a route serves, such as Transfer or Login, that states "
            "what 'correct' means for that route."
        ),
    ),
    OntologyClass(
        name="Security_Control",
        category=ConceptCategory.SECURITY_CONTROL,
        definition=(
            "A mechanism a process relies on for correctness, such as an idempotency "
            "token, a rate limit or a signature check."
        ),
    ),
    OntologyClass(
        name="Logic_Vulnerability",
        category=ConceptCategory.VULNERABILITY,
        definition=(
            "A business-logic flaw such as a race condition, a replay or a broken "
            "access-control ordering - a flaw, so the stage-7 category applies."
        ),
        reused=True,
    ),
    OntologyClass(
        name="Compliance_Term",
        category=ConceptCategory.COMPLIANCE_RULE,
        definition="A clause of a law or standard that a logic flaw breaks.",
        reused=True,
    ),
)

#: casefolded class name -> class, so a caller can look one up by prose name.
CLASSES_BY_NAME: Mapping[str, OntologyClass] = MappingProxyType(
    {entry.name.casefold(): entry for entry in FIN_LOGIC_CLASSES}
)

#: The clause edge under this domain's own name. **Not** a vocabulary member:
#: ``VIOLATES`` (stage 8) already reads vulnerability -> compliance_rule, and a
#: second id for one signature would split the vocabulary in two.
VIOLATES_COMPLIANCE: RelationType = RelationType.VIOLATES

#: The relations this TBox governs, in the order the reasoner walks them:
#: requirement first (route -> process -> control), then the finding, then the
#: consequence and the clause it breaks.
FIN_LOGIC_RELATIONS: tuple[RelationType, ...] = (
    RelationType.IMPLEMENTS,
    RelationType.REQUIRES_CONTROL,
    RelationType.LACKS_CONTROL,
    RelationType.LEADS_TO_VULNERABILITY,
    VIOLATES_COMPLIANCE,
)

#: Everything in the shared vocabulary that belongs to another corpus (the
#: Palantir labels of stage 1 and the security/finance/tooling labels of stages
#: 7-9). Computed rather than listed: widening the shared vocabulary must not
#: silently widen this exemption, and the subtraction makes a new member show up
#: here at once.
FOREIGN_RELATIONS: frozenset[RelationType] = (
    frozenset(RelationType) - frozenset(FIN_LOGIC_RELATIONS)
)

_ENDPOINTS = frozenset({ConceptCategory.API_ENDPOINT})
_PROCESSES = frozenset({ConceptCategory.BUSINESS_PROCESS})
_CONTROLS = frozenset({ConceptCategory.SECURITY_CONTROL})
_VULNERABILITIES = frozenset({ConceptCategory.VULNERABILITY})
_RULES = frozenset({ConceptCategory.COMPLIANCE_RULE})

#: The business-logic TBox: five classes, five relations, no confidence bands.
#:
#: ``version`` is ``0.1.0`` on purpose - the graph it judges is a nine-node
#: benchmark with one injected missing control, not a measured corpus. A report
#: stamped ``fin-logic-risk v0.1.0`` is therefore a structural claim, not an audit.
FIN_LOGIC_TBOX = OntologySchema(
    name="fin-logic-risk",
    version="0.1.0",
    required_categories=frozenset(entry.category for entry in FIN_LOGIC_CLASSES),
    max_self_loops=0,
    declared_unused_ok=FOREIGN_RELATIONS,
    rules={
        RelationType.IMPLEMENTS: RelationRule(
            relation=RelationType.IMPLEMENTS,
            domain=_ENDPOINTS,
            range=_PROCESSES,
            acyclic=True,
            severity=Severity.WARNING,
            description=(
                "a route serves a process; acyclic because a process cannot serve the "
                "route that serves it, and the edge is where the requirement enters "
                "the graph"
            ),
        ),
        RelationType.REQUIRES_CONTROL: RelationRule(
            relation=RelationType.REQUIRES_CONTROL,
            domain=_PROCESSES,
            range=_CONTROLS,
            acyclic=True,
            severity=Severity.WARNING,
            description=(
                "the requirement half of the intersection: what 'correct' means for the "
                "process, and acyclic because a control cannot require the process it "
                "protects"
            ),
        ),
        RelationType.LACKS_CONTROL: RelationRule(
            relation=RelationType.LACKS_CONTROL,
            domain=_ENDPOINTS,
            range=_CONTROLS,
            severity=Severity.WARNING,
            description=(
                "the finding half: what a review established the route does not "
                "enforce. Not flagged acyclic because domain/range already make a loop "
                "impossible (a route is not a control), and a rule that cannot fire is "
                "noise in a report"
            ),
        ),
        RelationType.LEADS_TO_VULNERABILITY: RelationRule(
            relation=RelationType.LEADS_TO_VULNERABILITY,
            domain=_CONTROLS,
            range=_VULNERABILITIES,
            acyclic=True,
            severity=Severity.WARNING,
            description=(
                "read as 'the absence of this control permits this flaw'; acyclic "
                "because a control whose absence permits a flaw that permits the "
                "absence of the same control is not a statement about a bank"
            ),
        ),
        VIOLATES_COMPLIANCE: RelationRule(
            relation=VIOLATES_COMPLIANCE,
            domain=_VULNERABILITIES,
            range=_RULES,
            severity=Severity.WARNING,
            description=(
                "a logic flaw breaks a clause: the reporting edge, and the only one "
                "whose finding a regulator would recognise"
            ),
        ),
    },
)


#: ``casefolded control -> the fix this domain recommends``.
#:
#: Domain knowledge, not graph data, for the same reason a ``RelationRule`` is:
#: the fix for a missing control is what a reviewer knows, not what a JSON file
#: says. Keyed by name because a fix is per control (an idempotency token and a
#: signature check are not interchangeable), with :func:`remediation_for` falling
#: back to the node's definition so an unknown control still produces an
#: actionable line instead of an empty one.
CONTROL_REMEDIATION: Mapping[str, str] = MappingProxyType(
    {
        "idempotency_token": "增加唯一请求 ID 校验",
        "signature_verification": "补齐签名校验",
        "rate_limit": "增加请求频率限制",
        "nonce": "增加一次性随机数校验",
        "state_machine_guard": "补充状态机流转校验",
        "reconciliation_job": "增加 T+1 对账兜底",
    }
)


def remediation_for(control: str, definition: str = "") -> str:
    """The fix for a missing ``control``, as a phrase ``建议`` can precede.

    Args:
        control: control name as spelled in the graph.
        definition: the control node's definition, used only when the table has no
            entry for this control - a graph may legitimately introduce a control
            this module has never heard of, and losing the fix column for it would
            be worse than a longer sentence.

    Returns:
        A non-empty phrase: the table entry, else ``"补齐 <control>（<definition>）"``,
        else ``"补齐 <control> 控制"``.
    """
    name = control.strip()
    known = CONTROL_REMEDIATION.get(name.casefold())
    if known:
        return known
    note = definition.strip()
    if note:
        return "补齐 %s（%s）" % (name, note)
    return "补齐 %s 控制" % name


def class_of(category: ConceptCategory) -> OntologyClass | None:
    """The business-logic class a category stands for, or ``None`` when it is not ours."""
    for entry in FIN_LOGIC_CLASSES:
        if entry.category is category:
            return entry
    return None


def summary_lines() -> list[str]:
    """The class/relation table, for the CLI header and the README.

    Kept next to the rules it describes so the two cannot drift, and returned as
    plain strings so the caller decides where they go (the CLI prints them; the
    tests assert on them).
    """
    lines = [
        "  classes: %d, relations: %d" % (len(FIN_LOGIC_CLASSES), len(FIN_LOGIC_RELATIONS))
    ]
    for entry in FIN_LOGIC_CLASSES:
        suffix = " (reused)" if entry.reused else ""
        lines.append(
            "    %-18s %-17s %s%s"
            % (entry.name, entry.category.value, entry.definition, suffix)
        )
    for relation in FIN_LOGIC_RELATIONS:
        rule = FIN_LOGIC_TBOX.rule(relation)
        domain = ",".join(sorted(item.value for item in rule.domain)) if rule.domain else "any"
        reach = ",".join(sorted(item.value for item in rule.range)) if rule.range else "any"
        lines.append("    %-22s %-18s -> %s" % (relation.value, domain, reach))
    return lines
