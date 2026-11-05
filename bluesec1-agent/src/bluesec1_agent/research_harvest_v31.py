"""Opt-in, reward-blind graph census for Practice research, NOT score optimization.

The exploration policy uses ONLY alert/tool evidence. Its tool-call rewards are
passed directly to the existing offline audit writer, never read by this module.
Phase F's bounded normal EvidenceHarvester remains the default.
"""
from __future__ import annotations

import copy
import heapq
import json
import ntpath
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable

from loguru import logger

from bluesec1_agent.harvest_v31 import (
    EvidenceHarvester, HarvestResult, _decode_b64_props, _disk_image,
    _ips, _network_hits_on_edges, _pagination, _parent_is_services,
    _public, _services_for_image, _trigger,
)
from bluesec1_agent.models import SearchRequest, RelationSearchType
from bluesec1_agent.response_mapper import ObservedGraph, malicious_process_set

_NETWORK = {"connected_to", "accepted_connection_from", "listened_on", "sent_data_to", "received_data_from"}
_SPAWN = {"win_process_create", "created_process", "parent_of"}
# Many relation families deliberately included, to measure their actual utility
# in Practice.  This is an offline-research run, not a hardcoded answer policy.
_ORDER = {
    "added_to_group": 1, "created_service": 1, "started_service": 1,
    "modified_service": 1, "wrote_file": 1, "executed_file": 1,
    "created_scheduled_task": 1, "set_registry_value": 1,
    "win_process_create": 1, "created_process": 1, "parent_of": 1,
    "executed_script": 1, "opened_handle": 2, "accessed_process": 2,
    "deleted_file": 2, "loaded_image": 2, "opened_share_session": 2,
    "connected_to": 2, "accepted_connection_from": 2,
}
_REL_TYPES = set(RelationSearchType.__args__)


def _norm_result(response: Any) -> dict[str, Any] | list[Any]:
    raw = (getattr(response, "info", None) or {}).get("tool_result")
    if raw is None:
        raw = (getattr(response, "observation", None) or {}).get("last_tool_result")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    return _decode_b64_props(_public(raw)) if isinstance(raw, (dict, list)) else {}


@dataclass
class ResearchStatus:
    indexed_processes: int = 0
    opened_targets: int = 0
    covered_edge_types: tuple[str, ...] = ()


class ResearchHarvester:
    """Explore a connected two-generation neighborhood with ~20 tool calls.

    Prioritize causal effects/peers, but collect across relation categories.
    A relation may identify a child or parent, but not license unrelated
    host-wide traversal. Only opened processes at depth <=2 are expanded.
    """

    def __init__(self, *, budget: int = 20):
        self.budget = max(1, min(int(budget), 24))

    async def collect(self, session: Any, observation: dict[str, Any], available: set[str],
                      on_evidence: Callable[[str, dict[str, Any], Any], None]) -> HarvestResult:
        graph = ObservedGraph()
        graph.absorb_alert({"alert_text": _public(observation.get("alert_text", {}))})
        trigger = _trigger(graph)
        out = HarvestResult()
        if not trigger or "search" not in available:
            return out
        tp = graph.props(trigger)
        host_id = (graph.entities.get(trigger) or {}).get("host_id")
        queue: list[tuple[int, int, str, dict[str, Any]]] = []
        queued: set[str] = set()
        done: set[str] = set()
        serial = 0
        opened: set[str] = set()
        depth: dict[str, int] = {trigger: 0}
        # Separate count of expansions by edge family for the offline summary.
        edge_kinds: set[str] = set()
        service_name = ntpath.basename(_disk_image(tp.get("image_path")))
        parent_pid = tp.get("parent_pid")
        first_uuid_done = False
        session_queued = False
        service_queued = False
        parent_lookup_queued = False
        peer_queued: set[str] = set()
        count_before = (len(graph.entities), len(graph.relations))

        def key(t: str, a: dict[str, Any]) -> str:
            return json.dumps([t, {k: v for k, v in a.items() if k != "reasoning"}], sort_keys=True)

        def add(priority: int, tool: str, args: dict[str, Any]) -> bool:
            nonlocal serial
            if tool not in available:
                return False
            if tool == "search":
                try:
                    args = SearchRequest.model_validate({"tool": tool, **args}).model_dump(
                        exclude={"tool"}, by_alias=True, exclude_none=True, mode="json")
                except ValueError:
                    return False
            k = key(tool, args)
            if k in done or k in queued:
                return False
            queued.add(k)
            heapq.heappush(queue, (priority, serial, tool, args))
            serial += 1
            return True

        def find(prio: int, query: str, category: str, scope: str | None = None,
                 page: int = 1) -> bool:
            if len(query.strip()) < 5:
                return False
            args: dict[str, Any] = {"query": query, "page_id": page,
                                    "reasoning": f"research_{category}: read case-linked evidence"}
            if scope:
                args["scope"] = {"kind": "relation" if scope in _REL_TYPES else "entity",
                                 "type": scope}
            return add(prio, "search", args)

        def entity(prio: int, nid: str, kind: str) -> bool:
            if not nid or nid in opened:
                return False
            return add(prio, "get_entity", {"entity_id": nid,
                                            "reasoning": f"research_{kind}: open graph target"})

        def relation(prio: int, rid: str, kind: str) -> bool:
            if rid in graph.relations:
                return False
            return add(prio, "get_relation", {"relation_id": rid,
                                              "reasoning": f"research_relation_{kind}: hydrate typed edge"})

        def matched_parent(candidate: str) -> bool:
            p = graph.props(candidate)
            return (graph.etype(candidate) == "windows_process" and p.get("pid") == parent_pid
                    and (not host_id or graph.entities[candidate].get("host_id") == host_id))

        def compute_depth() -> None:
            # Depth -1 is the parent of the trigger; 1 and 2 are descendants.
            for r in graph.relations.values():
                if r.get("type") in _SPAWN and r.get("target_id") == trigger:
                    nid = str(r.get("source_id"))
                    if nid not in depth:
                        depth[nid] = -1
            for nid in graph.entities:
                if nid != trigger and matched_parent(nid):
                    depth[nid] = -1
            for d in (0, 1):
                for root, rd in list(depth.items()):
                    if rd != d:
                        continue
                    pid = graph.props(root).get("pid")
                    for r in graph.out(root, _SPAWN):
                        child = r.get("target_id")
                        if isinstance(child, str) and child != root:
                            depth.setdefault(child, d + 1)
                    for nid, e in graph.entities.items():
                        p = e.get("properties") or {}
                        if (e.get("type") == "windows_process" and pid is not None and
                                p.get("parent_pid") == pid and
                                (not host_id or e.get("host_id") == host_id)):
                            depth.setdefault(nid, d + 1)

        def schedule() -> None:
            nonlocal session_queued, service_queued, parent_lookup_queued
            if not first_uuid_done:
                return
            compute_depth()
            # Unlike normal scoring, the research census opens the trigger
            # itself once to obtain typed relation IDs that an unscoped
            # search may have omitted.
            entity(2, trigger, "trigger")
            if not parent_lookup_queued and parent_pid is not None and not any(d == -1 for d in depth.values()):
                parent_image = str(tp.get("parent_image") or tp.get("parent_image_path") or "")
                if ntpath.basename(parent_image) and find(2, ntpath.basename(parent_image),
                                                          "parent", "windows_process"):
                    parent_lookup_queued = True
            if not service_queued and service_name and _parent_is_services(tp, graph, trigger):
                if find(2, service_name, "service", "windows_service"):
                    service_queued = True
            sid = str(tp.get("user_sid") or "")
            if len(sid) >= 5 and sid.casefold() not in {"s-1-5-18", "s-1-5-19", "s-1-5-20"}:
                find(2, sid, "identity", "windows_user")
            roots = [(nid, d) for nid, d in depth.items() if -1 <= d <= 2]
            # First hydrate/process the actual trigger family.
            for nid, d in roots:
                if nid != trigger:
                    entity(3 if d <= 1 else 5, nid, "child" if d >= 0 else "parent")
                if d <= 1:
                    find(3 if d <= 0 else 5, nid, "uuid")
            participants = set(depth)
            for nid, d in roots:
                if nid not in graph.entities:
                    continue
                ref_ids = (graph.entities.get(nid) or {}).get("relation_ids") or {}
                if isinstance(ref_ids, dict):
                    for direction, refs in ref_ids.items():
                        if not isinstance(refs, list):
                            continue
                        if not direction.startswith("out:") and not (
                                nid == trigger and direction.startswith("in:win_process_create")):
                            continue
                        family = direction.split(":", 1)[-1]
                        for ref in refs:
                            rid = ref if isinstance(ref, str) else ref.get("id") if isinstance(ref, dict) else None
                            if isinstance(rid, str):
                                relation(2 + _ORDER.get(family, 3), rid, family)
                for r in graph.out(nid):
                    rtype = str(r.get("type") or "")
                    edge_kinds.add(rtype)
                    dst = r.get("target_id")
                    if not isinstance(dst, str) or dst == nid:
                        continue
                    # Expand only process ancestors/descendants. Targets of other
                    # relation types are opened but never recursively expanded.
                    if rtype in _SPAWN and d >= 2:
                        continue
                    if rtype in _SPAWN and d <= 1:
                        depth.setdefault(dst, d + 1)
                    entity(3 + _ORDER.get(rtype, 4), dst,
                           "connection" if rtype in _NETWORK else f"effect_{rtype}")
            # Get properties for observed connection objects, then find a host
            # for EVERY attributable remote IP (not unrelated host traffic).
            for r in graph.relations.values():
                if r.get("source_id") not in participants or r.get("type") not in _NETWORK:
                    continue
                target = str(r.get("target_id") or "")
                cp = graph.props(target)
                fields = (("source_ip", "src_ip", "remote_ip")
                          if r.get("type") == "accepted_connection_from" else
                          ("dst_ip", "remote_ip", "destination_ip"))
                ips = set()
                for field in fields:
                    ips.update(_ips(str(cp.get(field) or "")))
                for ip in sorted(ips):
                    if ip not in peer_queued and ip not in graph.hosts_by_ip():
                        if find(4, ip, "peer", "host"):
                            peer_queued.add(ip)
            # Only after direct evidence: low-yield fallback to session graph.
            if not session_queued and not any(depth.get(nid) in {1, 2} for nid in depth) and \
                    len(str(tp.get("logon_id") or "")) >= 5 and str(tp.get("logon_id")).lower() not in {"0x3e7", "0x3e4", "0x3e5"}:
                session_queued = True
                find(9, str(tp["logon_id"]), "session", "windows_process")

        find(0, trigger, "uuid")
        while queue and out.calls < self.budget:
            _, _, tool, args = heapq.heappop(queue)
            k = key(tool, args)
            queued.discard(k)
            if k in done:
                continue
            done.add(k)
            response = await session.call_tool(tool, args)
            out.calls += 1
            if getattr(response, "task_result", None) is not None:
                on_evidence(tool, args, response)
                out.terminal = response.task_result
                return out
            raw = _norm_result(response)
            page = _pagination(raw, args) if tool == "search" else None
            scope = (args.get("scope") or {}).get("type") if tool == "search" else None
            if scope == "windows_service" and str(args.get("reasoning") or "").startswith("research_service:"):
                raw = _services_for_image(raw, _disk_image(tp.get("image_path")))
            if scope == "windows_process" and str(args.get("reasoning") or "").startswith("research_parent:"):
                # A basename search may match many processes. Only parent PID
                # on the trigger's host is causally linked to this alert.
                def only_parent(value: Any) -> Any:
                    if isinstance(value, list):
                        return [item for x in value if (item := only_parent(x)) is not None]
                    if not isinstance(value, dict):
                        return value
                    if value.get("type") == "windows_process":
                        p = value.get("properties") or {}
                        if (p.get("pid") != parent_pid or (host_id and value.get("host_id") != host_id)):
                            return None
                    return {f: only_parent(v) if isinstance(v, (dict, list)) else v
                            for f, v in value.items()}
                raw = only_parent(raw)
            # Keep unrelated host-wide sessions out of adjudication.
            if scope == "network_connection":
                linked = {str(r.get("target_id")) for r in graph.relations.values()
                          if r.get("source_id") in depth and r.get("type") in _NETWORK}
                raw = _network_hits_on_edges(raw, linked)
            if isinstance(getattr(response, "info", None), dict):
                clean_info = {**response.info, "tool_result": raw}
                if hasattr(response, "model_copy"):
                    response = response.model_copy(update={"info": clean_info})
                else:
                    response = copy.copy(response)
                    response.info = clean_info
            # on_evidence writes reward into audit only; do not inspect it here.
            on_evidence(tool, args, response)
            graph.absorb(raw)
            if tool == "get_entity":
                opened.add(str(args.get("entity_id")))
            if tool == "search":
                if args["query"] == trigger and scope is None and args.get("page_id") == 1:
                    first_uuid_done = True
                out.searches.append({"query": args["query"], "scope": scope})
                if page and args.get("page_id") == 1:
                    # Permit bounded page 2, but do not starve higher yield
                    # graph targets: continuation is a low priority census.
                    add(8, "search", {**args, "page_id": page})
            schedule()
            logger.info("Research Harvest {}/{} {} {} | nodes={} edges={}",
                        out.calls, self.budget, tool,
                        str(args.get("query") or args.get("entity_id") or
                            args.get("relation_id"))[:54],
                        len(graph.entities), len(graph.relations))
        out.completed = True
        out.discovered_entities = len(graph.entities) - count_before[0]
        out.discovered_relations = len(graph.relations) - count_before[1]
        out.digest = EvidenceHarvester._digest(graph, trigger)
        logger.info("Research graph census: {} calls, {} new entities, {} new relations, relation types {}",
                    out.calls, out.discovered_entities, out.discovered_relations,
                    sorted(edge_kinds))
        return out
