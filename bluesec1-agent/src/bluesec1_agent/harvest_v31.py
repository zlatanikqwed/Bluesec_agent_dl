"""Bounded public-evidence harvesting for the original investigator.

This module deliberately DOES NOT classify alerts or write incident-response
artifacts. The original v31 decision, review and submission pipeline remains
responsible for those tasks. No runtime rewards, labels or evaluator metadata
are read or used to steer the search.
"""
from __future__ import annotations

import base64
import copy
import heapq
import ipaddress
import json
import ntpath
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from loguru import logger

from bluesec1_agent.models import SearchRequest, RelationSearchType
from bluesec1_agent.inbound_evidence import logon_details, confirmed_remote_login
from bluesec1_agent.phaseL_evidence import (
    script_name_from_command, scheduled_task_sources, is_protection_process,
    interactive_trigger, interactive_source_ips,
)
from bluesec1_agent.response_mapper import ObservedGraph, malicious_process_set, SYSTEM_IMAGE, _private


_EFFECT_RELATIONS = (
    "wrote_file", "created_service", "set_registry_value",
    "created_scheduled_task", "added_to_group",
)
_FILE_RE = re.compile(
    r'(?:[A-Za-z]:\\|\\\\)[^\s"\'<>|]+\.(?:exe|dll|ps1|vbs|bat|cmd|js|lnk|msi|py|sys)',
    re.I,
)
_IP_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
_PRIVATE_META = {"runtime_reward", "reward", "quality_score", "efficiency_score",
                 "ground_truth_only", "evaluation", "log_sources"}
# Kernel pseudo-processes do not have a disk-backed executable image.
_PSEUDO_IMAGES = {"system", "registry", "memcompression"}
_RELATION_SEARCH_TYPES = set(RelationSearchType.__args__)


def _disk_image(value: object) -> str:
    """Only search for a filename when the image is an actual path with suffix."""
    text = str(value or "").strip().strip('"')
    if not text or text.casefold() in _PSEUDO_IMAGES:
        return ""
    if not (ntpath.isabs(text) or re.match(r"^[A-Za-z]:[\\/]", text)):
        return ""
    name = ntpath.basename(text)
    if not re.search(r"\.(?:exe|dll|sys|com|scr|ps1|bat|cmd)$", name, re.I):
        return ""
    return text


def _services_for_image(raw: Any, image: str) -> Any:
    """Keep only returned service entities matching the actual trigger image."""
    expected = image.strip().strip('"').replace('/', '\\').casefold()
    if not expected:
        return raw
    if isinstance(raw, list):
        return [v for item in raw if (v := _services_for_image(item, image)) is not None]
    if not isinstance(raw, dict):
        return raw
    if raw.get("type") == "windows_service":
        props = raw.get("properties") or {}
        command = str(props.get("binary_path") or props.get("image_path") or "")
        command = command.replace('/', '\\').casefold().strip()
        if command.startswith('"') and '"' in command[1:]:
            binary = command.split('"', 2)[1]
        else:
            binary = command.split(" ", 1)[0]
        if binary != expected:
            return None
    return {key: _services_for_image(value, image) if isinstance(value, (dict, list)) else value
            for key, value in raw.items()}


def _parent_is_services(props: dict[str, Any], graph: ObservedGraph, trigger: str) -> bool:
    """Confirm a services.exe parent from observed process properties or graph."""
    for field in ("parent_image", "parent_image_path", "parent_process_image"):
        if ntpath.basename(str(props.get(field) or "").strip('"')).casefold() == "services.exe":
            return True
    parent_pid = props.get("parent_pid")
    for ent in graph.entities.values():
        p = ent.get("properties") or {}
        if (parent_pid is not None and ent.get("type") == "windows_process" and
                p.get("pid") == parent_pid and
                ntpath.basename(str(p.get("image_path") or "")).casefold() == "services.exe"):
            return True
    return any(ntpath.basename(str(graph.props(str(r.get("source_id"))).get("image_path") or "")).casefold() == "services.exe"
               for r in graph.inc(trigger, {"win_process_create", "parent_of"}))


def _pagination(raw: Any, args: dict[str, Any]) -> int | None:
    """Only paginate on a server hint, or a full first page (10 hits)."""
    if args.get("page_id", 1) != 1 or not isinstance(raw, dict):
        return None
    for key in ("next_page_id", "next_page", "nextPageId"):
        try:
            n = int(raw.get(key))
            if n == 2:
                return n
        except (ValueError, TypeError):
            pass
    for key in ("results", "items", "entities", "relations"):
        if isinstance(raw.get(key), list) and len(raw[key]) >= 10:
            return 2
    return None



def _public(value: Any) -> Any:
    """Exclude evaluator-only fields; log source labels are not evidence."""
    if isinstance(value, list):
        return [_public(v) for v in value]
    if isinstance(value, dict):
        return {k: _public(v) for k, v in value.items() if k not in _PRIVATE_META}
    return value



def _decode_b64_props(value: Any) -> Any:
    """Decode public PowerShell EncodedCommand inside retrieved entity fields."""
    if isinstance(value, list):
        return [_decode_b64_props(item) for item in value]
    if not isinstance(value, dict):
        return value
    out = {k: _decode_b64_props(v) for k, v in value.items()}
    for key in ("cmdline", "command_line", "command"):
        text = out.get(key)
        if not isinstance(text, str) or "_decoded" in out:
            continue
        match = re.search(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{24,})", text, re.I)
        if match:
            try:
                decoded = base64.b64decode(match.group(1) + "=" * (-len(match.group(1)) % 4)).decode("utf-16-le")
                if any(ch.isalpha() for ch in decoded):
                    out[key + "_decoded"] = decoded[:1600]
            except (ValueError, UnicodeDecodeError):
                pass
    return out

def _window(props: dict[str, Any]) -> dict[str, str] | None:
    value = props.get("start_time")
    if not isinstance(value, str):
        return None
    try:
        start = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if start.tzinfo is None:
            return None
        return {"from": (start - timedelta(minutes=2)).isoformat(),
                "to": (start + timedelta(minutes=60)).isoformat()}
    except ValueError:
        return None


def _session_12h_window(props: dict[str, Any]) -> dict[str, str] | None:
    """Twelve-hour session window including post-trigger child execution."""
    value = props.get("start_time")
    if not isinstance(value, str):
        return None
    try:
        start = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if start.tzinfo is None:
            return None
        return {"from": (start - timedelta(minutes=15)).isoformat(),
                "to": (start + timedelta(hours=11, minutes=45)).isoformat()}
    except ValueError:
        return None


def _ips(value: Any) -> set[str]:
    text = json.dumps(value, default=str) if not isinstance(value, str) else value
    result = set()
    for s in _IP_RE.findall(text):
        try:
            ip = ipaddress.ip_address(s)
            if not ip.is_unspecified and not ip.is_multicast and not ip.is_loopback:
                result.add(s)
        except ValueError:
            pass
    return result


def _host_ip(graph: ObservedGraph, trigger_id: str) -> str:
    """Known local host IP, never guessed from remote connection addresses."""
    host_id = (graph.entities.get(trigger_id) or {}).get("host_id")
    prop = graph.props(str(host_id or ""))
    for field in ("ip", "ip_address", "ipv4", "primary_ip"):
        for ip in sorted(_ips(prop.get(field) or "")):
            return ip
    return ""


def _network_hits_on_edges(raw: Any, ids: set[str]) -> Any:
    """Keep ONLY connection entities referenced by the trigger-chain edges.

    A host-wide scoped search may include unrelated concurrent sessions. Those
    must not leak into the guard, LLM or benign evidence as case evidence.
    """
    if isinstance(raw, list):
        return [item for x in raw if (item := _network_hits_on_edges(x, ids)) is not None]
    if not isinstance(raw, dict):
        return raw
    if raw.get("type") == "network_connection" and raw.get("id") not in ids:
        return None
    return {key: _network_hits_on_edges(val, ids) if isinstance(val, dict)
            else _network_hits_on_edges(val, ids) if isinstance(val, list) else val
            for key, val in raw.items()}


def _file_queries(graph: ObservedGraph, trigger_id: str) -> list[str]:
    paths: list[str] = []
    participants = malicious_process_set(graph, [trigger_id])
    for pid in participants:
        p = graph.props(pid)
        image = str(p.get("image_path") or "")
        cmd = str(p.get("cmdline") or "")
        # Do not waste searches on standard signed system binaries.
        if _disk_image(image) and any(s in image.lower() for s in
                         ("\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\", "\\downloads\\")):
            paths.append(ntpath.basename(image))
        for path in _FILE_RE.findall(cmd):
            if any(s in path.lower() for s in
                   ("\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\", "\\downloads\\")) \
                   or path.lower().endswith((".ps1", ".vbs", ".js")):
                paths.append(ntpath.basename(path))
    return list(dict.fromkeys(t for t in paths if len(t) >= 5))[:3]


def _trigger(graph: ObservedGraph) -> str | None:
    return next((s for s in graph.trigger_ids if graph.etype(s) == "windows_process"), None)


@dataclass
class HarvestResult:
    calls: int = 0
    completed: bool = False
    terminal: Any = None
    discovered_entities: int = 0
    discovered_relations: int = 0
    # Evidence for the model: bounded, factual, and never a prefilled answer.
    digest: str = ""
    searches: list[dict[str, Any]] = field(default_factory=list)


class EvidenceHarvester:
    """Search-first collection with a strict shared platform-call budget.

    The unscoped UUID query is deliberately probed, not assumed to return
    relationships. If it yields no outgoing edges, bounded typed fallback is
    possible. No evaluator labels or reward values participate in decisions.
    """

    def __init__(self, *, budget: int = 10, service_probe: bool = False,
                 inbound_probe: bool = False, evidence_probe: str = "") -> None:
        self.budget = max(1, min(budget, 10))
        self.service_probe = service_probe
        self.inbound_probe = inbound_probe
        self.evidence_probe = evidence_probe

    async def collect(
        self,
        session: Any,
        observation: dict[str, Any],
        available: set[str],
        on_evidence: Callable[[str, dict[str, Any], Any], None],
    ) -> HarvestResult:
        graph = ObservedGraph()
        graph.absorb_alert({"alert_text": _public(observation.get("alert_text", {}))})
        trigger = _trigger(graph)
        result = HarvestResult()
        if not trigger or "search" not in available:
            return result

        tr_props = graph.props(trigger)
        logon = str(tr_props.get("logon_id") or "").strip()
        system = logon.casefold() in {"0x3e7", "0x3e4", "0x3e5", "0x0"}
        sid = str(tr_props.get("user_sid") or "").strip()
        work: list[tuple[int, int, str, dict[str, Any]]] = []
        queued: set[str] = set()
        done: set[str] = set()
        serial = 0
        children_opened: set[str] = set()
        children_queued: set[str] = set()
        suspicious_children: set[str] = set()
        child_uuid_probes = 0
        effect_targets: set[str] = set()
        effects_per_type: dict[str, int] = {}
        typed_refs: set[str] = set()
        peer_ips: set[str] = set()
        seen_files: set[str] = set()
        session_queued = False
        network_calls_queued = 0
        network_pages_queued = 0
        peer_hosts_queued = 0
        child_entity_retry: set[str] = set()
        first_probe_done = False
        service_probe_queued = False
        inbound_probe_queued = False
        phaseL_probed: set[str] = set()
        probe_pages: set[str] = set()
        start_counts = len(graph.entities), len(graph.relations)

        def key_for(tool: str, args: dict[str, Any]) -> str:
            return json.dumps((tool, {k: v for k, v in args.items() if k != "reasoning"}),
                              sort_keys=True, default=str)

        def enqueue(priority: int, tool: str, args: dict[str, Any]) -> bool:
            nonlocal serial
            if tool not in available:
                return False
            args = dict(args)
            if tool == "search":
                try:
                    args = SearchRequest.model_validate({"tool": "search", **args}).model_dump(
                        by_alias=True, exclude={"tool"}, exclude_none=True, mode="json")
                except ValueError:
                    return False
            k = key_for(tool, args)
            if k in done or k in queued:
                return False
            queued.add(k)
            heapq.heappush(work, (priority, serial, tool, args))
            serial += 1
            return True

        def find(priority: int, query: str, reason: str,
                 scope: str | None = None, *, page: int = 1,
                 window: dict[str, str] | None = None) -> bool:
            if len(query.strip()) < 5:
                return False
            args: dict[str, Any] = {"query": query, "page_id": page, "reasoning": reason}
            if scope:
                args["scope"] = {"kind": "relation" if scope in _RELATION_SEARCH_TYPES else "entity",
                                 "type": scope}
            if window:
                args["time_window"] = window
            return enqueue(priority, "search", args)

        def open_entity(priority: int, nid: str, reason: str) -> bool:
            return enqueue(priority, "get_entity", {"entity_id": nid, "reasoning": reason})

        def spawn_edges(nid: str) -> list[dict[str, Any]]:
            return list(graph.out(nid, {"win_process_create", "created_process", "parent_of"}))

        def known_children(nid: str) -> list[str]:
            ids = [r.get("target_id") for r in spawn_edges(nid)]
            ids = [i for i in ids if isinstance(i, str) and i != nid]
            # A search can include complete processes but omit their spawn
            # relation. Only use same-host, same-session, PID-matched children.
            p = graph.props(nid)
            for cid, ent in graph.entities.items():
                cp = ent.get("properties") or {}
                if (ent.get("type") == "windows_process" and cid != nid and
                    p.get("pid") is not None and cp.get("parent_pid") == p.get("pid") and
                    ent.get("host_id") == graph.entities.get(nid, {}).get("host_id") and
                    (not logon or str(cp.get("logon_id") or "") == logon)):
                    ids.append(cid)
            return list(dict.fromkeys(ids))

        def schedule() -> None:
            nonlocal session_queued, network_calls_queued, network_pages_queued
            nonlocal peer_hosts_queued, child_uuid_probes, service_probe_queued, inbound_probe_queued
            # Deterministic order: trigger UUID -> principal -> peer/network
            # -> children -> effects.  Don't consume the first calls on kids
            # already visible in the initial alert before resolving the UUID.
            if not first_probe_done:
                return

            if not system and len(sid) >= 5 and sid.casefold() not in {"s-1-5-18", "s-1-5-19", "s-1-5-20"}:
                find(1, sid, "identity: resolve non-built-in principal", "windows_user")
            # Shared acquisition across ALL Phase I report variants, so the
            # service-response experiment changes only the submitted artifact.
            image = _disk_image(tr_props.get("image_path"))
            if (self.service_probe and not service_probe_queued and image and
                    _parent_is_services(tr_props, graph, trigger)):
                service_probe_queued = True
                find(2, ntpath.basename(image),
                     "service: match trigger binary to services.exe child", "windows_service")

            # Phase L independent experimental probes. Only the chosen arm
            # schedules extra work. They retain the same strict 8-call budget.
            if self.evidence_probe == "scheduled_task":
                for source in scheduled_task_sources(graph, trigger)[:1]:
                    if source not in graph.entities or not all(graph.props(source).get(k) for k in ("task_name", "action_target")):
                        open_entity(2, source, "phaseL: open authorizing scheduled task")
                # Some runtimes initially expose only incoming typed relation IDs.
                rel_ids = (graph.entities.get(trigger) or {}).get("relation_ids") or {}
                if isinstance(rel_ids, dict):
                    for key, ids in rel_ids.items():
                        if key.casefold() not in {"in:ran_scheduled_task", "incoming:ran_scheduled_task"}:
                            continue
                        for rid in ids if isinstance(ids, list) else []:
                            rid = rid if isinstance(rid, str) else rid.get("id") if isinstance(rid, dict) else None
                            if isinstance(rid, str) and rid not in graph.relations and rid not in phaseL_probed:
                                if enqueue(2, "get_relation", {"relation_id": rid,
                                    "reasoning": "phaseL: hydrate incoming ran_scheduled_task"}):
                                    phaseL_probed.add(rid)
                                break
            elif self.evidence_probe == "script_file":
                script_name = script_name_from_command(
                    tr_props.get("cmdline") or tr_props.get("command_line"))
                if script_name and script_name.casefold() not in phaseL_probed:
                    phaseL_probed.add(script_name.casefold())
                    find(2, script_name, "phaseL: locate commanded .ps1", "windows_file")
            elif self.evidence_probe == "interactive_logon":
                if interactive_trigger(graph, trigger) and logon and not system:
                    if "login" not in phaseL_probed:
                        phaseL_probed.add("login")
                        find(2, logon, "phaseL: interactive session source", "logged_on_to")
                    local_ip = _host_ip(graph, trigger)
                    for ip in interactive_source_ips(graph, trigger)[:2]:
                        if (ip != local_ip and ip not in graph.hosts_by_ip() and
                                ip not in phaseL_probed):
                            if find(2, ip, "phaseL: resolve interactive logon source", "host"):
                                phaseL_probed.add(ip)
            elif self.evidence_probe in {"agent_handles", "agent_handles_nocite"}:
                if is_protection_process(graph, trigger):
                    for edge in list(graph.out(trigger, {"opened_handle"}))[:2]:
                        dst = edge.get("target_id")
                        if isinstance(dst, str) and dst not in phaseL_probed:
                            if open_entity(2, dst, "phaseL: inspect opened_handle target"):
                                phaseL_probed.add(dst)
                    # Typed outbound handle references (one bounded relation).
                    rel_ids = (graph.entities.get(trigger) or {}).get("relation_ids") or {}
                    if isinstance(rel_ids, dict):
                        for key, ids in rel_ids.items():
                            if key.casefold() != "out:opened_handle":
                                continue
                            for rid in ids if isinstance(ids, list) else []:
                                rid = rid if isinstance(rid, str) else rid.get("id") if isinstance(rid, dict) else None
                                if isinstance(rid, str) and rid not in graph.relations and rid not in phaseL_probed:
                                    if enqueue(2, "get_relation", {"relation_id": rid,
                                        "reasoning": "phaseL: resolve opened_handle edge"}):
                                        phaseL_probed.add(rid)
                                    break

            # Phase J: remotely initiated logons carry a source_ip which is
            # different from a network peer's destination. Spend one scoped
            # lookup for WinRM-style alerts even when children already exist;
            # the generic session/child-search fallback remains suppressed.
            parent_image = str(tr_props.get("parent_image") or
                               tr_props.get("parent_image_path") or "").casefold()
            image_path = str(tr_props.get("image_path") or "").casefold()
            cmd = str(tr_props.get("cmdline") or tr_props.get("command_line") or "").casefold()
            remote_hint = ("wsmprovhost" in parent_image or
                           "winrm" in parent_image or
                           ("powershell" in image_path and "-nologo" in cmd) or
                           any(e.get("type") == "logged_on_to" for e in graph.relations.values()))
            if (self.inbound_probe and not inbound_probe_queued and
                    not system and len(logon) >= 5 and
                    (remote_hint or any(r.get("type") == "accepted_connection_from"
                                        for r in graph.out(trigger)))):
                inbound_probe_queued = True
                find(2, logon, "inbound: resolve remote logon source_ip",
                     "logged_on_to")

            participants = malicious_process_set(graph, [trigger]) | set(children_queued)
            conn_edges = [r for r in graph.relations.values()
                          if r.get("source_id") in participants and
                          r.get("type") in {"connected_to", "accepted_connection_from"}]
            trigger_out = list(graph.out(trigger))
            trigger_conn = [e for e in trigger_out
                            if e.get("type") in {"connected_to", "accepted_connection_from"}]
            # Only NETWORK-DOMINANT SYSTEM triggers get a second connection
            # page.  Count the graph edges (not generic host-wide hits).
            network_dominant = (system and len(trigger_conn) >= 2 and
                                len(trigger_conn) * 2 >= max(1, len(trigger_out)))
            local_ip = _host_ip(graph, trigger)
            if (network_dominant and local_ip and network_pages_queued == 0 and
                    find(2, local_ip, "connections: hydrate linked SYSTEM sessions", "network_connection")):
                network_pages_queued = 1

            # First open confirmed children (not unrelated session processes).
            # At most three get_entity child calls across all generations.
            parents = [trigger, *list(children_opened)]
            for parent in parents:
                for child in known_children(parent):
                    if len(children_queued) >= 3:
                        break
                    if child not in children_queued:
                        if open_entity(4, child, "child: open out:win_process_create target"):
                            children_queued.add(child)

            # Some runtimes return typed outgoing relation IDs, rather than
            # hydrated relation objects. Resolve only the spawn relations.
            for parent in parents:
                ent = graph.entities.get(parent) or {}
                rel_ids = ent.get("relation_ids") or {}
                if not isinstance(rel_ids, dict):
                    continue
                for k, values in rel_ids.items():
                    if k.casefold() not in {"out:win_process_create", "out:created_process"}:
                        continue
                    for value in values if isinstance(values, list) else []:
                        rid = value if isinstance(value, str) else value.get("id") if isinstance(value, dict) else None
                        if (isinstance(rid, str) and rid not in graph.relations and
                                rid not in typed_refs and len(typed_refs) < 3):
                            if enqueue(4, "get_relation", {"relation_id": rid,
                                "reasoning": "child: resolve typed out:win_process_create edge"}):
                                typed_refs.add(rid)

            # Some entities expose *typed* IDs for other outgoing effects as
            # well. They need one get_relation to reveal the target; never
            # enumerate untyped outgoing IDs or incoming hub edges.
            typed_effects = {"out:wrote_file": 2, "out:added_to_group": 1,
                             "out:created_service": 1, "out:started_service": 1,
                             "out:opened_handle": 1, "out:deleted_file": 1,
                             "out:executed_script": 1}
            per_edge_type: dict[str, int] = {}
            for pid in parents:
                rel_ids = (graph.entities.get(pid) or {}).get("relation_ids") or {}
                if not isinstance(rel_ids, dict):
                    continue
                for direction, values in rel_ids.items():
                    typ = direction.casefold()
                    if typ not in typed_effects:
                        continue
                    if typ == "out:executed_script":
                        image = str(graph.props(pid).get("image_path") or "").lower()
                        if not re.search(r"(?:^|[\\/])(powershell|pwsh)(?:\.exe)?$", image):
                            continue
                        if any(graph.out(pid, {"wrote_file", "created_service",
                                               "added_to_group", "set_registry_value"})):
                            continue
                    for ref in values if isinstance(values, list) else []:
                        rid = ref if isinstance(ref, str) else ref.get("id") if isinstance(ref, dict) else None
                        if (not isinstance(rid, str) or rid in graph.relations or
                                rid in typed_refs or len(typed_refs) >= 5 or
                                per_edge_type.get(typ, 0) >= typed_effects[typ]):
                            continue
                        if enqueue(2 if typ == "out:executed_script" else 5, "get_relation", {
                            "relation_id": rid,
                            "reasoning": f"effect:{typ[4:]}: resolve typed outgoing edge"}):
                            typed_refs.add(rid)
                            per_edge_type[typ] = per_edge_type.get(typ, 0) + 1

            # Session search is strictly a fallback when trigger has no spawn
            # edges, after the unscoped probe has had a chance to find them.
            if (first_probe_done and not session_queued and not system and
                not spawn_edges(trigger) and len(logon) >= 5):
                session_queued = True
                find(7, logon, "session: no observed spawn edges; look for children over 12h",
                     "windows_process", window=_session_12h_window(tr_props))

            # A UUID page might return no hydrated outgoing edges. Make just
            # two typed, high-value probes rather than exhaust relation types.
            if first_probe_done and not list(graph.out(trigger)) and not known_children(trigger):
                find(7, trigger, "child: typed process-spawn fallback", "win_process_create")
                find(8, trigger, "effect:wrote_file: typed file-write fallback", "wrote_file")

            # Prefer effects/targets over broad exploration. All relation
            # targets must be adjacent to the trigger chain, never a hub.
            participants = malicious_process_set(graph, [trigger]) | set(children_queued)
            caps = {"added_to_group": 2, "created_service": 2, "started_service": 2,
                    "wrote_file": 3, "opened_handle": 2, "deleted_file": 2,
                    "set_registry_value": 1, "created_scheduled_task": 1}
            priority = {"added_to_group": 5, "created_service": 5, "started_service": 5,
                        "wrote_file": 5, "opened_handle": 6, "deleted_file": 6,
                        "set_registry_value": 6, "created_scheduled_task": 6}
            # Sort by expected relevance, NOT arbitrary relation UUID ordering.
            for typ in sorted(caps, key=lambda t: priority[t]):
                for pid in [trigger, *sorted(participants - {trigger})]:
                    for edge in graph.out(pid, {typ}):
                        dst = edge.get("target_id")
                        if not isinstance(dst, str) or dst in effect_targets:
                            continue
                        if effects_per_type.get(typ, 0) >= caps[typ]:
                            break
                        # deleted_file is useful for archive provenance. Where
                        # properties exist, exclude ordinary non-archive files.
                        if typ == "deleted_file":
                            path = str(graph.props(dst).get("path") or
                                       graph.props(dst).get("file_path") or "")
                            if path and not re.search(r"\.(zip|7z|rar|cab|tar|gz)$", path, re.I):
                                continue
                        if open_entity(priority[typ], dst, f"effect:{typ}: open causal target"):
                            effect_targets.add(dst)
                            effects_per_type[typ] = effects_per_type.get(typ, 0) + 1

            # Suspicious children: their own UUID probe may reveal additional
            # file writes and grandchildren without a blind session scan.
            for child in sorted(children_queued):
                if (child not in children_opened or child in suspicious_children or
                        child_uuid_probes >= 2):
                    continue
                image = _disk_image(graph.props(child).get("image_path"))
                if image and not SYSTEM_IMAGE.search(image):
                    if find(6, child, "child: inspect non-system executable's writes/spawns"):
                        child_uuid_probes += 1
                    suspicious_children.add(child)

            # Directly observed connections can be more decisive than another
            # generic child process. Resolve one linked endpoint EARLY, then
            # spend a second call resolving its peer host if the IP is new.
            # Preserve the two-page SYSTEM batch path for relay cases.
            unresolved_connections = []
            for edge in conn_edges:
                cp = graph.props(str(edge.get("target_id") or ""))
                relevant = (("source_ip", "src_ip", "remote_ip")
                            if edge.get("type") == "accepted_connection_from"
                            else ("dst_ip", "remote_ip", "destination_ip"))
                found = set().union(*(_ips(str(cp.get(f) or "")) for f in relevant))
                peer_ips.update(found)
                if not found and isinstance(edge.get("target_id"), str):
                    unresolved_connections.append(edge)
            if (network_calls_queued < 1 and unresolved_connections and
                    (not network_dominant or not local_ip)):
                # connected_to generally reveals the external destination.
                for edge in sorted(unresolved_connections,
                                   key=lambda e: (e.get("type") != "connected_to",
                                                  e.get("source_id") != trigger)):
                    if open_entity(2, edge["target_id"], "connections: obtain peer IP"):
                        network_calls_queued += 1
                        break

            # When a PowerShell process has an explicit executed_script edge
            # but no other observed effects, read the script_text before
            # accepting a benign model verdict. Also works for observed
            # PowerShell children of cmd.exe, not just the trigger itself.
            script_candidates = [trigger, *sorted(participants - {trigger})]
            for pid in script_candidates:
                props = graph.props(pid)
                exe = str(props.get("image_path") or props.get("image") or "").casefold()
                if not re.search(r"(?:^|[\\/])(powershell|pwsh)(?:\.exe)?$", exe):
                    continue
                strong_effects = any(graph.out(pid, {"wrote_file", "created_service",
                    "added_to_group", "set_registry_value", "created_scheduled_task"}))
                if strong_effects:
                    continue
                for edge in graph.out(pid, {"executed_script"}):
                    target = edge.get("target_id")
                    existing = graph.props(str(target or ""))
                    if (isinstance(target, str) and
                            not (existing.get("script_text") or existing.get("script_block_text") or
                                 existing.get("script_text_decoded")) and
                            open_entity(2, target, "script: inspect observed PowerShell script_text")):
                        break
                # One script per relevant PowerShell process is sufficient.

            # Phase K: remote-login source fields are stored under
            # logon_properties (not only properties). This high-value host
            # lookup precedes ordinary peer/child searches and consumes the
            # existing Harvest budget; do not consult reward to choose it.
            host_id = graph.entities.get(trigger, {}).get("host_id")
            actor_ids = {uid for uid, entity in graph.entities.items()
                         if entity.get("type") == "windows_user" and sid and
                         str(graph.props(uid).get("sid") or
                             graph.props(uid).get("user_sid") or "") == sid}
            inbound_ips = set()
            for edge in graph.relations.values():
                if edge.get("type") not in {"logged_on_to", "authenticated_to", "successful_logon"}:
                    continue
                data = logon_details(edge)
                session_value = str(data.get("logon_id") or data.get("session_id") or "").casefold()
                linked = (edge.get("target_id") == host_id and
                          edge.get("source_id") in actor_ids)
                matched = (session_value == logon.casefold()) if session_value else linked
                if matched and confirmed_remote_login(edge):
                    inbound_ips.update(_ips(data.get("source_ip") or data.get("src_ip") or ""))
            for ip in sorted(inbound_ips, key=lambda i: (_private(i) is not False, i)):
                if peer_hosts_queued >= 2:
                    break
                if ip != local_ip and ip not in seen_files and ip not in graph.hosts_by_ip():
                    if find(2, ip, "inbound: resolve confirmed source IP", "host"):
                        seen_files.add(ip)
                        peer_hosts_queued += 1
            peer_ips.update(inbound_ips)
            # External destinations precede private lateral peers when only
            # two host lookups fit. _private handles documented TEST-NET IPs.
            for ip in sorted(peer_ips, key=lambda ip: (_private(ip) is not False, ip)):
                if peer_hosts_queued >= 2:
                    break
                if ip != local_ip and ip not in seen_files and ip not in graph.hosts_by_ip():
                    # Never waste a call re-resolving an observed host.
                    # Prioritise this before child/effect calls.
                    if find(3, ip, "peer: resolve observed remote IP", "host"):
                        seen_files.add(ip)
                        peer_hosts_queued += 1

            # No unconditional trigger get_entity or redundant filename scan.
            # Exact suspicious file names are a final grounded fallback.
            for filename in _file_queries(graph, trigger):
                if filename.casefold() not in seen_files:
                    if find(6, filename, "file: resolve suspected executable", "windows_file"):
                        seen_files.add(filename.casefold())
            if not system and len(logon) >= 5 and not spawn_edges(trigger):
                # A session query is a fallback, not an unconditional expense:
                # a typed win_process_create from the UUID probe is better.
                find(7, logon, "session: remote logon source (spawn edges absent)",
                     "logged_on_to")

        find(0, trigger, "id: collect trigger's outgoing relations (unscoped)")
        # Alert may already contain outgoing edges; don't defer their targets
        # until the unscoped probe if they're explicitly present.
        schedule()
        while work and result.calls < self.budget:
            _, _, tool, args = heapq.heappop(work)
            k = key_for(tool, args)
            queued.discard(k)
            if (tool == "search" and args.get("query") == trigger and
                    (args.get("scope") or {}).get("type") == "win_process_create" and
                    known_children(trigger)):
                continue
            # A later UUID page can supply spawn edges after a low-priority
            # session fallback was queued. Do not spend the call anyway.
            if (tool == "search" and args.get("query") == logon and
                    (args.get("scope") or {}).get("type") in
                    {"windows_process", "logged_on_to"} and spawn_edges(trigger) and
                    not str(args.get("reasoning") or "").startswith("inbound:")):
                continue
            if k in done:
                continue
            done.add(k)
            response = await session.call_tool(tool, args)
            result.calls += 1
            if getattr(response, "task_result", None) is not None:
                on_evidence(tool, args, response)
                result.terminal = response.task_result
                return result
            raw = (getattr(response, "info", None) or {}).get("tool_result")
            if raw is None:
                raw = (getattr(response, "observation", None) or {}).get("last_tool_result")
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except (ValueError, TypeError):
                    raw = {}
            raw = _decode_b64_props(_public(raw)) if isinstance(raw, (list, dict)) else {}
            original_page = _pagination(raw, args) if tool == "search" else None
            if (tool == "search" and (args.get("scope") or {}).get("type") == "windows_service"
                    and str(args.get("reasoning") or "").startswith("service:")):
                raw = _services_for_image(raw, _disk_image(tr_props.get("image_path")))
            if tool == "search" and (args.get("scope") or {}).get("type") == "network_connection":
                linked = {str(e.get("target_id")) for e in graph.relations.values()
                          if e.get("type") in {"connected_to", "accepted_connection_from"} and
                          e.get("source_id") in (malicious_process_set(graph, [trigger]) | {trigger})}
                raw = _network_hits_on_edges(raw, linked)
            # Keep all public facts in v31's memory, but never reward, grader
            # labels, or data from unrelated network sessions.
            if isinstance(getattr(response, "info", None), dict):
                clean_info = {**response.info, "tool_result": raw}
                if hasattr(response, "model_copy"):
                    response = response.model_copy(update={"info": clean_info})
                else:
                    response = copy.copy(response)
                    response.info = clean_info
            on_evidence(tool, args, response)
            before = len(graph.entities), len(graph.relations)
            graph.absorb(raw)
            after = len(graph.entities), len(graph.relations)
            if tool == "get_entity" and args.get("entity_id") in children_queued:
                child_id = args["entity_id"]
                children_opened.add(child_id)
                # An empty/partial get_entity response cannot prove the process
                # image or execution context. One bounded typed UUID fallback.
                if (not graph.props(child_id).get("image_path") and
                        child_id not in child_entity_retry):
                    child_entity_retry.add(child_id)
                    find(2, child_id, "child: retry incomplete child entity via search",
                         "windows_process")
            if tool == "search":
                scope = (args.get("scope") or {}).get("type")
                result.searches.append({"query": args["query"], "scope": scope,
                                        "found": sum(after) - sum(before)})
                if args["query"] == trigger and scope is None and args.get("page_id", 1) == 1:
                    first_probe_done = True
                page = original_page
                if (page and scope == "network_connection" and network_pages_queued < 2 and
                        _host_ip(graph, trigger) == args["query"]):
                    if find(2, args["query"], "connections: hydrate second SYSTEM page",
                            "network_connection", page=page):
                        network_pages_queued += 1
                if page and (scope == "windows_process" or
                             (scope is None and args["query"] == trigger)):
                    find(5, args["query"], "id: continuation page of trigger/children",
                         scope, page=page, window=args.get("time_window"))
                if (scope == "windows_process" and before == after and args.get("time_window")):
                    # Preserve 12h window rather than an unlimited, low-value retry.
                    pass
            schedule()
            logger.info("V31+Harvest {}/{} {} {}: {} -> {}", result.calls, self.budget,
                        tool, str(args.get("scope") or args.get("query") or
                                  args.get("entity_id") or args.get("relation_id"))[:70],
                        before, after)
        result.completed = True
        result.discovered_entities = len(graph.entities) - start_counts[0]
        result.discovered_relations = len(graph.relations) - start_counts[1]
        result.digest = self._digest(graph, trigger)
        return result

    @staticmethod
    def _digest(graph: ObservedGraph, trigger: str, max_chars: int = 4800) -> str:
        """Summarize attributable findings; retain full evidence separately in memory."""
        tp = graph.props(trigger)
        logon = str(tp.get("logon_id") or "")
        sid = str(tp.get("user_sid") or "")
        host = graph.entities[trigger].get("host_id")
        participants = malicious_process_set(graph, [trigger])
        relevant: list[str] = [trigger]
        relevant.extend(sorted(participants - {trigger}))
        # The parent may supply a decisive EncodedCommand even when it is not a
        # descendant. Include an actually opened parent in the LLM digest.
        for procid in list(participants):
            p = graph.props(procid)
            for parent_id, parent in graph.entities.items():
                parent_props = parent.get("properties") or {}
                if (parent.get("type") == "windows_process" and
                        parent.get("host_id") == graph.entities.get(procid, {}).get("host_id") and
                        p.get("parent_pid") is not None and
                        parent_props.get("pid") == p.get("parent_pid")):
                    relevant.append(parent_id)
        for uid, ent in graph.entities.items():
            p = ent.get("properties") or {}
            if (ent.get("type") == "windows_user" and sid and
                    str(p.get("sid") or p.get("user_sid") or "") == sid):
                relevant.append(uid)
            elif ent.get("type") == "host" and uid != host:
                relevant.append(uid)
            elif (ent.get("type") in {"powershell_script", "powershell_cmdlet_invocation",
                                      "windows_file"}
                  and any(r.get("target_id") == uid and r.get("source_id") in participants
                          and r.get("type") == "executed_script"
                          for r in graph.relations.values())):
                relevant.append(uid)
            elif ent.get("type") == "windows_file":
                path = str(p.get("path") or "").lower()
                cmds = [str(graph.props(cid).get("cmdline") or "").lower() for cid in participants]
                if path and (any(path in c for c in cmds) or
                             any(r.get("target_id") == uid and r.get("source_id") in participants
                                 for r in graph.relations.values())):
                    relevant.append(uid)
            elif ent.get("type") in ("windows_service", "registry_key", "scheduled_task"):
                if uid in scheduled_task_sources(graph, trigger):
                    relevant.append(uid)
                if any(r.get("target_id") == uid and r.get("source_id") in participants
                       for r in graph.relations.values()):
                    relevant.append(uid)
        fields = ("pid", "parent_pid", "logon_id", "user", "user_sid", "image_path",
                  "cmdline", "cmdline_decoded", "command_line_decoded", "path", "hostname", "ip", "username", "group_memberships",
                  "service_name", "task_name", "action_target", "name", "key_path", "value_data", "logon_type",
                  "script_text", "script_text_decoded")
        nodes = []
        for nid in dict.fromkeys(relevant):
            n = graph.entities.get(nid)
            if n is None:
                continue
            p = n.get("properties") or {}
            nodes.append({"id": nid, "type": n.get("type"), "host_id": n.get("host_id"),
                          "props": {k: str(p[k])[:190] for k in fields if k in p and p[k] is not None}})
        edges = [{"type": r.get("type"), "from": r.get("source_id"), "to": r.get("target_id")}
                 for r in graph.relations.values()
                 if r.get("source_id") in participants or r.get("target_id") in participants]
        summary = {"trigger": trigger, "host": host, "logon_id": logon,
                   "session_processes": sorted(participants), "entities": nodes[:28],
                   "causal_relations": edges[:18],
                   "note": "Discovered entities are evidence, not proof of maliciousness."}
        # Fit 8k context: preserve core process properties, not every entity.
        while len(json.dumps(summary, ensure_ascii=False)) > max_chars and len(summary["entities"]) > 1:
            summary["entities"].pop()
        while len(json.dumps(summary, ensure_ascii=False)) > max_chars and summary["causal_relations"]:
            summary["causal_relations"].pop()
        return json.dumps(summary, ensure_ascii=False, separators=(",", ":"))[:max_chars]
