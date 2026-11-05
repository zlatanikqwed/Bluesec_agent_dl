"""v16 decision support: a verified, uncertainty-preserving causal evidence ledger.

This module deliberately does NOT classify by task, host, account, process name,
port, IP or artifact type. The model still decides malicious/benign. It provides
an auditable fact table, a grounded next-question policy and checks whether a
benign conclusion actually cites observed consequences (not just actor identity).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Data attributes that describe an observable operation, rather than a signer's
# reputation or the general role/privilege of a process/account.
OPERATION_FIELDS = frozenset({
    "cmdline", "command", "command_line", "script_text", "script_block_text",
    "command_text", "arguments", "value_data", "operation", "action",
    "path", "file_path", "target_path", "name", "task_name", "service_name",
    "dst_ip", "dst_port", "src_ip", "src_port", "remote_ip", "remote_port",
    "query", "write_mode", "target_user", "account", "command_line_decoded",
    "cmdline_decoded", "script_text_decoded", "parent_image", "image_path",
})
ENTITY_HUBS = frozenset({"host", "windows_user", "linux_user", "ad_object"})
INVENTORY_EDGES = frozenset({"hosts", "runs_process", "member_of", "belongs_to"})


@dataclass(frozen=True)
class VerifiedEffect:
    relation_id: str
    kind: str
    actor_id: str
    target_id: str
    weight: int
    distance: int
    target_opened: bool
    actor_label: str
    target_label: str

    def statement(self) -> str:
        status = "opened" if self.target_opened else "NOT OPENED — effect unknown"
        return (f"EVENT {self.relation_id}: {self.actor_id} --{self.kind}--> "
                f"{self.target_id}; target {status}. "
                f"ACTOR {self.actor_label[:180]}; TARGET {self.target_label[:180]}")


class EvidenceWorkbench:
    """Build factual checklists from the CURRENT investigated graph only."""

    def __init__(self, director: Any) -> None:
        self.director = director

    @staticmethod
    def _label(memory: Any, identifier: str) -> str:
        node = memory.observed_nodes.get(identifier, {})
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        values = []
        for k in ("cmdline", "command", "script_text", "operation", "action", "path",
                  "file_path", "value_data", "dst_ip", "dst_port", "task_name",
                  "name", "image_path", "user"):
            if props.get(k) not in (None, ""):
                values.append(f"{k}={str(props[k])[:130]}")
            if len(values) >= 3:
                break
        return "; ".join(values) or memory.index.get(identifier, "not yet examined")

    def effects(self, memory: Any, *, limit: int = 14) -> list[VerifiedEffect]:
        dist = self.director.causal_distance(memory)
        result = []
        for rid, (kind, actor, target) in memory.graph_edges.items():
            if kind.lower() in INVENTORY_EDGES:
                continue
            proximity = min(dist.get(actor, 9), dist.get(target, 9))
            if proximity > 4:
                # An isolated search hit does not prove a causal part of the alert.
                continue
            weight = self.director.consequence_weight(kind)
            target_type = memory.entity_types.get(target, "")
            opened = (target in memory.fetched_ids or target in memory.trigger_ids
                      or target_type in ENTITY_HUBS)
            result.append(VerifiedEffect(
                relation_id=rid, kind=kind, actor_id=actor, target_id=target,
                weight=weight, distance=proximity, target_opened=opened,
                actor_label=self._label(memory, actor),
                target_label=self._label(memory, target),
            ))
        result.sort(key=lambda e: (-e.weight, not e.target_opened, e.distance,
                                   memory.discovery_order.get(e.relation_id, 999999)))
        return result[:limit]

    @staticmethod
    def _cites_effect(submission: dict[str, Any], effect: VerifiedEffect,
                      memory: Any) -> bool:
        """Citation coverage is about the changed object/event, not a trusted actor."""
        for item in submission.get("legitimacy_evidence") or []:
            if not isinstance(item, dict):
                continue
            nid = item.get("relation_id") or item.get("entity_id")
            fields = set(item.get("property_fields") or [])
            if nid == effect.relation_id and fields & {
                "type", "source_id", "target_id", "operation", "action", "timestamp"
            }:
                return True
            if nid == effect.target_id and fields & OPERATION_FIELDS:
                return True
        return False

    def uncovered(self, memory: Any, submission: dict[str, Any],
                  *, limit: int = 3) -> list[VerifiedEffect]:
        if submission.get("verdict") != "benign":
            return []
        return [e for e in self.effects(memory, limit=16)
                if e.weight >= 4 and not self._cites_effect(submission, e, memory)][:limit]

    def next_lead(self, memory: Any, available_tools: set[str],
                  *, for_benign: bool = True) -> tuple[str, dict[str, str], str] | None:
        """Open the consequence of a VERIFIED event before walking generic graph links.

        All returned UUIDs must already appear in known_ids. No arbitrary search
        queries and no fixed list of suspicious products or scenarios.
        """
        effects = self.effects(memory, limit=20)
        for effect in effects:
            target = effect.target_id
            if (effect.weight < 4 or effect.target_opened
                    or "get_entity" not in available_tools
                    or target not in memory.known_ids
                    or target in memory.rejected_ids
                    or target in memory.relation_ids
                    or memory.entity_types.get(target) in ENTITY_HUBS):
                continue
            return ("get_entity", {
                "entity_id": target,
                "reasoning": (f"Inspect target of VERIFIED {effect.kind} relation "
                              f"{effect.relation_id}; determine its real state, "
                              "command and consequence, and compare attack vs normal.")
            }, f"unexamined effect {effect.kind} -> {target}")
        # Only open relation IDs actually disclosed by an entity or trigger.
        for candidate in self.director.rank_frontier(memory):
            ident = candidate.identifier
            if (candidate.tool not in available_tools or ident not in memory.known_ids
                    or ident in memory.fetched_ids or ident in memory.rejected_ids):
                continue
            if candidate.tool == "get_entity" and memory.entity_types.get(ident) in ENTITY_HUBS:
                continue
            arg = {"get_relation": "relation_id", "get_entity": "entity_id",
                   "get_ad_object_info": "ad_object_id"}.get(candidate.tool)
            if not arg:
                continue
            return (candidate.tool, {arg: ident, "reasoning": candidate.question},
                    f"verified candidate {candidate.tool} {ident}")
        return None

    def digest(self, memory: Any, *, limit: int = 7) -> str:
        effects = self.effects(memory, limit=limit)
        lines = ["VERIFIED CAUSAL EFFECTS (not classifications):"]
        lines.extend("- " + e.statement() for e in effects)
        if not effects:
            lines.append("- No behavioral relation opened yet; unknown does NOT imply benign.")
        lines.append("H_attack: identify observed harmful operation AND effect, not tool reputation.")
        lines.append("H_normal: identify observed same operation/effect AND coherent normal cause/scope.")
        lines.append("Signing, internal IP, and privileged username support NEITHER hypothesis by themselves.")
        lines.append("Missing authorization documentation is NOT affirmative attack evidence.")
        return "\n".join(lines)

    def final_claim_check(self, memory: Any, submission: dict[str, Any]) -> str:
        """A neutral question list for an LLM factual check, never a hard verdict."""
        if submission.get("verdict") != "benign":
            return "For malicious, cite direct actions; do not infer their outcome from names."
        effects = self.effects(memory, limit=12)
        uncovered = self.uncovered(memory, submission, limit=3)
        lines = []
        for effect in uncovered:
            lines.append("UNCOVERED ACTION: " + effect.statement())
        if not effects:
            lines.append("No tested behavioral effect exists yet. Absence of observed effects is UNKNOWN.")
        if effects and not uncovered:
            lines.append("All top known behavioral effects are cited, but citation is NOT authorization.")
        lines.append("Does a POSITIVELY OBSERVED coherent normal workflow explain THESE effects, "
                     "or was normal intent merely inferred from identity, signing, or missing harm? "
                     "Separately test whether an attack explanation has concrete evidence.")
        return "\n".join(lines)

    def dossier_messages(self, memory: Any, left: dict[str, Any], right: dict[str, Any]
                        ) -> list[dict[str, str]]:
        """Tie break focuses on comparing falsifiable facts rather than voting."""
        return [{"role": "system", "content": (
            "You are an independent SOC evidence judge. Return only a schema-valid "
            "finish_investigation. Do NOT choose by majority, verbosity or trusted "
            "program/account name. The source evidence is the VERIFIED graph below. "
            "Cite only observed IDs/fields. A signature/username alone cannot "
            "authorize a particular operation; a suspicious tool alone cannot "
            "prove an attack. Lack of a formal ticket or an unobserved effect "
            "is not evidence of an attack or proof of benign operation. "
            "Choose whichever hypothesis accounts for the actual connected facts."
        )}, {"role": "user", "content": (
            self.digest(memory, limit=12) + "\n\n" +
            "ANALYSIS A:\n" + __import__("json").dumps(left, ensure_ascii=False)[:3200]
            + "\nANALYSIS B:\n" + __import__("json").dumps(right, ensure_ascii=False)[:3200]
            + "\n\n" + self.final_claim_check(memory, left)
            + "\n" + self.final_claim_check(memory, right)
            + "\nExplain observed operations, effects and what remains unproven."
        )}]
