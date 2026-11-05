"""Deterministic incident crawler.

The example agent let the LLM navigate the graph, which caused blundering and
overload. This module inverts that: CODE walks the graph from the trigger along
the edges that carry evidence, to a bounded depth, collecting a complete case
file. The LLM is then called once on the finished case file to decide the verdict
and name the artifacts. Navigation is removed from the model entirely.
"""

from __future__ import annotations

import json
from collections import deque
from typing import Any

from loguru import logger

from bluesec1_agent.agent import (
    _is_external_ip,
    decode_encoded_commands,
    parse_json_strings,
)

# Relations worth following from a process/file/user, in priority order. Each maps
# to why we care. Hub edges (hosts, runs_process, accepted_connection_from from a
# host) are deliberately excluded — they explode and carry no verdict signal.
EVIDENCE_RELATIONS: dict[str, str] = {
    "win_process_create": "spawned a child process",
    "parent_of": "parent/child process link",
    "wrote_file": "wrote a file",
    "deleted_file": "deleted a file",
    "read_file": "read a file",
    "connected_to": "opened a network connection",
    "invoked_cmdlet": "ran a PowerShell cmdlet",
    "executed_script": "executed a script",
    "started_service": "started a service",
    "created_service": "created a service",
    "created_scheduled_task": "created a scheduled task",
    "ran_scheduled_task": "ran a scheduled task",
    "set_registry_value": "set a registry value",
    "loaded_image": "loaded a module",
    "created_pipe": "created a named pipe",
    "connected_to_pipe": "connected to a named pipe",
    "payload_references": "references a payload",
    "added_to_group": "added an account to a group",
    "opened_share_session": "opened an SMB share session",
}

# Entity types that are hubs — we read them but do not expand all their relations.
HUB_ENTITY_TYPES = {"host", "windows_user", "linux_user", "user", "ad_object"}

# Fields we keep from an entity's properties for the case file (the rest is noise).
KEEP_PROPS = (
    "image_path", "cmdline", "cmdline_decoded", "parent_image", "user", "integrity_level",
    "md5", "sha256", "signed", "signer", "original_filename", "file_description",
    "path", "file_path", "name", "hostname", "ip", "os", "role",
    "dst_ip", "remote_ip", "dst_port", "remote_port", "direction", "protocol",
    "script_text", "script_block_text", "command", "key_path", "value_name", "value_data",
    "service_name", "binary_path", "task_name", "sam_account_name", "group",
    "username", "group_memberships", "is_privileged", "share_path", "pipe_name",
)


class CaseFile:
    """Everything the crawl discovered, structured for the verdict model."""

    def __init__(self) -> None:
        self.entities: dict[str, dict[str, Any]] = {}  # id -> trimmed entity
        self.edges: list[dict[str, Any]] = []  # [{type, source, target, note}]
        self.calls = 0

    def add_entity(self, node: dict[str, Any]) -> None:
        nid = node.get("id") or node.get("entity_id")
        if not isinstance(nid, str) or nid in self.entities:
            return
        props = node.get("properties") if isinstance(node.get("properties"), dict) else node
        trimmed = {k: props[k] for k in KEEP_PROPS if props.get(k) not in (None, "", [], {})}
        self.entities[nid] = {"id": nid, "type": node.get("type", "?"), "properties": trimmed}

    def add_edge(self, rel: dict[str, Any]) -> None:
        self.edges.append({
            "type": rel.get("type", "?"),
            "source": rel.get("source_id", ""),
            "target": rel.get("target_id", ""),
            "note": EVIDENCE_RELATIONS.get(str(rel.get("type")), ""),
        })

    def render(self) -> str:
        """A compact, readable case file for the verdict prompt."""
        lines = ["ENTITIES:"]
        for nid, e in self.entities.items():
            props = ", ".join(f"{k}={str(v)[:160]}" for k, v in e["properties"].items())
            lines.append(f"  [{nid}] {e['type']}: {props}")
        lines.append("\nRELATIONS (what happened):")
        for edge in self.edges:
            s = self.entities.get(edge["source"], {}).get("type", edge["source"][:8])
            t = self.entities.get(edge["target"], {}).get("type", edge["target"][:8])
            lines.append(
                f"  {s}[{edge['source'][:8]}] --{edge['type']}--> {t}[{edge['target'][:8]}]"
            )
        return "\n".join(lines)


class GraphCrawler:
    """Walk the graph from the trigger along evidence edges, breadth-first."""

    def __init__(self, session: Any, *, max_calls: int = 28, max_depth: int = 3) -> None:
        self.session = session
        self.max_calls = max_calls
        self.max_depth = max_depth

    async def crawl(self, observation: dict[str, Any]) -> CaseFile:
        case = CaseFile()
        obs = decode_encoded_commands(
            parse_json_strings(
                {k: v for k, v in observation.items() if k != "available_tools"}
            )
        )
        # frontier holds (entity_id, depth, relation_ids_to_read).
        frontier: deque[tuple[str, int, list[str]]] = deque()
        visited_seed: set[str] = set()
        # Open each trigger entity first (non-hub first), queue its relations.
        triggers = _trigger_entities(obs)
        triggers.sort(key=lambda e: str(e.get("type")) in HUB_ENTITY_TYPES)
        for ent in triggers:
            tid = ent["id"]
            if tid in visited_seed:
                continue
            visited_seed.add(tid)
            full = await self._get_entity(tid)
            case.calls += 1
            node = full if full is not None else ent
            case.add_entity(node)
            if node.get("type") not in HUB_ENTITY_TYPES:
                frontier.append((tid, 0, _ordered_relation_ids(node)))

        # Entities discovered as relation endpoints but not yet fetched. We open
        # these BEFORE going deeper so the case file has the entity on each edge end
        # (the file the process wrote, the host it connected to), not just the edge.
        pending_entities: deque[tuple[str, int]] = deque()

        while (frontier or pending_entities) and case.calls < self.max_calls:
            # Priority 1: open endpoint entities already discovered, so no edge is
            # left dangling without the entity it points to.
            if pending_entities:
                node_id, depth = pending_entities.popleft()
                if node_id in visited_seed:
                    continue
                visited_seed.add(node_id)
                entity = await self._get_entity(node_id)
                case.calls += 1
                if entity is None:
                    continue
                case.add_entity(entity)
                # Expand non-hub endpoints one more hop by queueing their relations.
                if entity.get("type") not in HUB_ENTITY_TYPES and depth < self.max_depth:
                    frontier.append((node_id, depth, _ordered_relation_ids(entity)))
                continue

            # Priority 2: read the relations of an already-opened entity.
            node_id, depth, rel_ids = frontier.popleft()
            for i, rid in enumerate(rel_ids):
                if case.calls >= self.max_calls:
                    # Save the rest for later rather than dropping them.
                    frontier.appendleft((node_id, depth, rel_ids[i:]))
                    break
                rel = await self._get_relation(rid)
                case.calls += 1
                if rel is None or str(rel.get("type")) not in EVIDENCE_RELATIONS:
                    continue
                case.add_edge(rel)
                for endpoint in (rel.get("source_id"), rel.get("target_id")):
                    if isinstance(endpoint, str) and endpoint not in visited_seed:
                        pending_entities.append((endpoint, depth + 1))

        # Seed the first frontier: open each trigger entity, queue its relations.
        logger.info("Crawl collected {} entities, {} edges in {} calls.",
                    len(case.entities), len(case.edges), case.calls)
        return case

    async def _get_entity(self, entity_id: str) -> dict[str, Any] | None:
        for tool, arg in (("get_entity", "entity_id"), ("get_ad_object_info", "ad_object_id")):
            try:
                resp = await self.session.call_tool(tool, {arg: entity_id, "reasoning": "crawl"})
            except Exception:
                continue
            node = _result_of(resp)
            if isinstance(node, dict) and node.get("id") and not node.get("error"):
                return node
        return None

    async def _get_relation(self, relation_id: str) -> dict[str, Any] | None:
        try:
            resp = await self.session.call_tool(
                "get_relation", {"relation_id": relation_id, "reasoning": "crawl"}
            )
        except Exception:
            return None
        return _result_of(resp)


def _trigger_entities(obs: dict[str, Any]) -> list[dict[str, Any]]:
    ents = obs.get("trigger_entities")
    if not isinstance(ents, list):
        alert = obs.get("alert_text")
        ents = alert.get("trigger_entities") if isinstance(alert, dict) else None
    out = []
    for e in ents or []:
        if isinstance(e, dict) and (e.get("id") or e.get("entity_id")):
            out.append({"id": e.get("id") or e.get("entity_id"), **e})
    return out


def _ordered_relation_ids(entity: dict[str, Any]) -> list[str]:
    rel = entity.get("relation_ids")
    ids: list[str] = []
    if isinstance(rel, dict):
        for key in ("outgoing", "incoming"):
            v = rel.get(key)
            if isinstance(v, list):
                ids.extend(i for i in v if isinstance(i, str))
    elif isinstance(rel, list):
        ids.extend(i for i in rel if isinstance(i, str))
    return ids


def _result_of(resp: Any) -> dict[str, Any] | None:
    """Pull the parsed entity/relation out of a ToolCallResult, mirroring the
    proven extraction in SimpleSGRAgent._tool_feedback."""
    info = getattr(resp, "info", None) or {}
    raw = info.get("tool_result")
    if raw is None:
        obs = getattr(resp, "observation", None) or {}
        if isinstance(obs, dict):
            raw = obs.get("last_tool_result", obs)
            if isinstance(raw, dict):
                raw = {k: v for k, v in raw.items() if k not in {"alert_text", "available_tools"}}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw, dict):
        return None
    return decode_encoded_commands(parse_json_strings(raw))


# Suspicious observations the code derives from the finished case file, so the
# verdict model is handed conclusions, not raw data to interpret.
def derive_findings(case: CaseFile) -> list[str]:
    findings: list[str] = []
    for e in case.entities.values():
        p = e["properties"]
        blob = json.dumps(p, ensure_ascii=False).lower()
        if "vssadmin" in blob and "delete" in blob and "shadow" in blob:
            findings.append(f"[{e['id'][:8]}] deletes volume shadow copies — ransomware prep")
        if any(x in blob for x in ("frombase64", "downloadstring", "iex ", "-enc ")):
            findings.append(f"[{e['id'][:8]}] encoded/download-and-run payload")
        if any(x in blob for x in ("mimikatz", "sekurlsa", "lsass.dmp", "ntds.dit")):
            findings.append(f"[{e['id'][:8]}] credential theft (lsass/ntds/mimikatz)")
        dst = str(p.get("dst_ip") or p.get("remote_ip") or "")
        if dst and _is_external_ip(dst):
            findings.append(f"[{e['id'][:8]}] connects to EXTERNAL ip {dst}")
        for ext in (".lockbit", ".loginblob", ".kirbi", ".locked"):
            if ext in blob:
                findings.append(f"[{e['id'][:8]}] ransom/stage extension {ext}")
    # process-tree anomalies from edges
    by_id = case.entities
    for edge in case.edges:
        if edge["type"] in ("win_process_create", "parent_of"):
            parent = by_id.get(edge["source"], {}).get("properties", {})
            child = by_id.get(edge["target"], {}).get("properties", {})
            pi = str(parent.get("image_path", "")).lower()
            ci = str(child.get("image_path", "")).lower()
            if any(w in pi for w in ("w3wp", "httpd", "sqlservr", "tomcat")) and any(
                s in ci for s in ("cmd.exe", "powershell", "pwsh")
            ):
                findings.append(f"web/db server {pi} spawned shell {ci} — web shell/RCE")
    return list(dict.fromkeys(findings))  # dedupe, keep order
