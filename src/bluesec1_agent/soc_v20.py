"""v20: explicit evidence-state machine for the forensic SOC investigation.

This module has no power to assign a malicious verdict, create graph identifiers, or
execute retrieved commands. Its responsibility is to keep evidence acquisition
separate from final interpretation, and invalidate stale reviews when observed
facts change. No hard-coded challenge/task IDs are used.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from bluesec1_agent.soc_v19 import SOCV19, Inspection
from bluesec1_agent.soc_v18 import Lead


STAGES = ("ACQUIRE", "CORRELATE", "DECIDE", "VERIFY", "SUBMIT")


@dataclass
class ForensicCaseState:
    """Finite-state controller; revisions refer to real observed graph content."""

    engine: SOCV19
    stage: str = "ACQUIRE"
    minimum_acquisitions: int = 6
    maximum_acquisitions: int = 14
    verified_revision: str | None = None
    challenge_revision: str | None = None
    last_revision: str = ""
    phase_history: list[str] = field(default_factory=lambda: ["ACQUIRE"])
    decision_attempts: int = 0

    @staticmethod
    def revision(memory: Any) -> str:
        """Observed data, not model text, drive review invalidation.

        Include property changes, decoded scripts, and edges. UUIDs are never
        generated; the digest is a local bookkeeping marker only.
        """
        graph = sorted((str(k), str(v[0]), str(v[1]), str(v[2]))
                       for k, v in memory.graph_edges.items())
        nodes = sorted((str(k), v) for k, v in memory.observed_nodes.items())
        data = json.dumps([graph, nodes], ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:20]

    def move(self, stage: str) -> None:
        if stage not in STAGES:
            raise ValueError(f"Unknown investigation stage: {stage}")
        if self.stage != stage:
            self.stage = stage
            self.phase_history.append(stage)

    def update(self, memory: Any) -> bool:
        """Reopen stale decisions only when real graph evidence changes."""
        current = self.revision(memory)
        changed = bool(self.last_revision) and current != self.last_revision
        if changed and self.stage in {"DECIDE", "VERIFY", "SUBMIT"}:
            self.move("CORRELATE")
        self.last_revision = current
        return changed

    def select_acquisition(
        self, memory: Any, tools: set[str], *, step_index: int, max_steps: int,
        force_finish: bool = False,
    ) -> Inspection | None:
        """Acquire grounded facts ahead of any LLM final recommendation.

        Limit work both by an absolute budget and marginal information gain.
        When no verified useful lead exists, never synthesize a lookup; advance
        to decision even if minimum acquisitions could not be reached.
        """
        self.update(memory)
        if force_finish or step_index >= max_steps - 3:
            self.move("DECIDE")
            return None
        if self.stage not in {"ACQUIRE", "CORRELATE"}:
            return None
        count = len(memory.calls_made)
        self.move("CORRELATE")
        candidate = self.engine.next_inspection(
            memory, tools, max_steps=min(self.maximum_acquisitions, max_steps - 3),
            minimum_steps=self.minimum_acquisitions,
        )
        if candidate is None and count < self.minimum_acquisitions and "get_relation" in tools:
            # v19 deliberately discards untyped relation IDs: their score is 5,
            # below its information-gain cutoff. But get_entity only reveals
            # relation_ids, *without* relation types. Refusing all of them makes
            # autonomous acquisition stop after a single process read.
            # Read at most the first few ACTUAL edges owned by a non-hub actor.
            unknown = [
                (memory.discovery_order.get(rid, 10**9), rid)
                for rid, owner in memory.relation_owner.items()
                if rid in memory.known_ids and rid not in memory.fetched_ids
                and rid not in memory.rejected_ids
                and rid not in memory.relation_types
                and owner[1] not in {"host", "windows_user", "linux_user", "linux_group"}
                and (owner[0] in memory.focus_ids or
                     owner[0] in memory.fetched_ids)
            ]
            if unknown:
                rid = min(unknown)[1]
                candidate = Inspection(
                    Lead("get_relation", {"relation_id": rid,
                        "reasoning": "Resolve the actual unseen actor/action/target relation before final analysis."},
                        "resolve previously unknown relation type", 8),
                    "Provenance: identify a returned but untyped relation", "causal-acquisition")
        if candidate is not None:
            # Strong last-minute hypotheses justify a few extra lookups, but
            # generic inventory associations must not use the entire budget.
            lead = candidate.lead
            if lead.tool in {"get_entity", "get_relation", "get_ad_object_info"}:
                ident = next((v for k, v in lead.arguments.items() if k.endswith("_id")), None)
                if not isinstance(ident, str) or ident not in memory.known_ids:
                    candidate = None
            if candidate is not None:
                key = memory.cache_key(lead.tool, lead.arguments)
                if key in memory.cache:
                    candidate = None
        if candidate is not None:
            self.move("ACQUIRE")
            return candidate
        self.move("DECIDE")
        return None

    def mark_reviewed(self, memory: Any) -> None:
        self.verified_revision = self.revision(memory)
        self.move("VERIFY")

    def review_current(self, memory: Any) -> bool:
        return self.verified_revision == self.revision(memory)

    def challenge_current(self, memory: Any) -> bool:
        return self.challenge_revision == self.revision(memory)

    def mark_challenged(self, memory: Any) -> None:
        self.challenge_revision = self.revision(memory)

    def decision_instructions(self, memory: Any) -> str:
        findings = self.engine.findings(memory)
        high = [f.text() for f in findings if f.severity >= 7][:7]
        return (
            "V20 DECISION STAGE. The data collection stage is complete or bounded "
            "by information gain; do not pretend unknown facts are absent. "
            "Compare H_attack and H_normal against the same verified source/action/target "
            "chain. If claiming legitimate authorized use, identify the actual checked "
            "behavior and its target; SYSTEM, signer, internal IP and a friendly path "
            "alone are not proof. Do not label a suspicious indicator malicious without "
            "supported effects and causality. Cite existing entity/relation IDs and actual "
            "property fields. Return finish_investigation.\n"
            "Observed SOC hypotheses (NOT predetermined verdicts):\n"
            + ("\n".join(high) if high else "No high-priority rule fired; use the observed graph.")
        )
