"""Phase H report ablations and Phase I combined/controlled experiments.

Phase H arms alter exactly one response dimension after normal mapping.
Phase I arms share one optional deterministic service lookup with the same
8-call Harvest budget. Combined combines validated report changes; follow-up
arms each add exactly one response action type on top of that common baseline.
No runtime rewards or hidden labels are used for decisions.
"""
from __future__ import annotations

import ipaddress
import ntpath
import re
from copy import deepcopy
from typing import Any

from bluesec1_agent.inbound_evidence import logon_details, confirmed_remote_login
from bluesec1_agent.phaseL_evidence import (
    scheduled_task_sources, script_name_from_command, interactive_trigger,
    interactive_source_ips, is_protection_process,
)
from bluesec1_agent.response_mapper import (
    FILE_TYPES, PROCESS_TYPES, USER_TYPES, ObservedGraph,
    benign_anchor_evidence, malicious_process_set, _private,
)

PHASE_L_MODES = frozenset({
    "scheduled_task", "script_file", "interactive_logon",
    "agent_handles", "agent_handles_nocite",
})

# Phase M: randomized report probe, applied in agent.py after this module.
PROBE_MODES = frozenset({"random_probe", "explore_probe", "role_policy", "benign_probe", "benign_probe2"})

MODES = frozenset({
    "control", "malicious_files", "malicious_block", "benign_entities", "fact_reasoning",
    "combined", "internal_source", "service_persistence", "archive_files",
    "baseline_archives", "inbound_sources", "service_persistence_v2", "inbound_guard",
}) | PHASE_L_MODES | PROBE_MODES
FILE_EXT = re.compile(r"\.(?:exe|dll|com|scr|msi|zip|rar|7z|tar|gz|cab|iso)$", re.I)


def _norm_path(value: Any) -> str:
    return str(value or "").replace("/", "\\").strip(' "').casefold()


def _unique_actions(actions: list[dict[str, Any]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    results = []
    for item in actions:
        if not isinstance(item, dict):
            continue
        nid, kind = item.get("entity_id"), item.get("kind")
        if isinstance(nid, str) and isinstance(kind, str) and (nid, kind) not in seen:
            seen.add((nid, kind))
            results.append({"entity_id": nid, "kind": kind})
    return results


def _add_files_and_service(sub: dict[str, Any], graph: ObservedGraph) -> None:
    """Experimental *additional* actions, only for actually opened objects."""
    procs = malicious_process_set(graph, graph.trigger_ids)
    actions = _unique_actions(sub.get("ir_artifacts") or [])
    for proc_id in sorted(procs):
        for rel in graph.out(proc_id, {"wrote_file"}):
            file_id = rel["target_id"]
            if file_id not in graph.entities or graph.etype(file_id) not in FILE_TYPES:
                continue
            props = graph.props(file_id)
            path = str(props.get("path") or props.get("file_path") or props.get("filename") or "")
            if props.get("is_executable") is True or FILE_EXT.search(path):
                actions.append({"entity_id": file_id, "kind": "file_to_delete"})

    # Generic service scenario: an observed process starts with -service and an
    # opened service's binary_path matches this process image. A matching service
    # must also be observed as started/created or have the services.exe parent.
    observed_services = {id for id, item in graph.entities.items()
                         if item.get("type") == "windows_service"}
    for proc_id in sorted(procs):
        props = graph.props(proc_id)
        cmd = str(props.get("cmdline") or props.get("command_line") or "")
        binary = _norm_path(props.get("image_path"))
        if not binary or not re.search(r"(?:^|\s)-service(?:\s|$)", cmd, re.I):
            continue
        parent_image = _norm_path(props.get("parent_image"))
        by_service_parent = ntpath.basename(parent_image) == "services.exe"
        # parent_pid fallback when parent_image is missing
        if not by_service_parent:
            by_service_parent = any(
                ntpath.basename(_norm_path(graph.props(parent_id).get("image_path"))) == "services.exe"
                and graph.props(parent_id).get("pid") is not None
                and graph.props(parent_id).get("pid") == props.get("parent_pid")
                for parent_id, ent in graph.entities.items()
                if ent.get("type") == "windows_process" and
                   ent.get("host_id") == graph.entities[proc_id].get("host_id")
            )
        linked_services = {
            rel["target_id"] for anchor in procs | {proc_id}
            for rel in graph.out(anchor, {"created_service", "started_service", "modified_service"})
        }
        for service_id in sorted(observed_services):
            service = graph.props(service_id)
            svc_path = _norm_path(service.get("binary_path") or service.get("image_path"))
            # Service ImagePath can have the '-service' argument appended.
            if (svc_path == binary or svc_path.startswith(binary + " ")) and (
                    by_service_parent or service_id in linked_services):
                actions.append({"entity_id": service_id, "kind": "persistence_to_remove"})
    sub["ir_artifacts"] = _unique_actions(actions)


def _external_connected_hosts(graph: ObservedGraph) -> list[tuple[str, str]]:
    """An actually opened external peer of the trigger's causal process chain."""
    procs = malicious_process_set(graph, graph.trigger_ids)
    external_ips = set()
    for proc_id in procs:
        for rel in graph.out(proc_id, {"connected_to", "sent_data_to", "accepted_connection_from", "received_data_from"}):
            connection_id = rel["target_id"]
            if graph.etype(connection_id) != "network_connection" or connection_id not in graph.entities:
                continue
            props = graph.props(connection_id)
            keys = ("src_ip", "source_ip") if rel["type"] in {
                "accepted_connection_from", "received_data_from"
            } else ("dst_ip", "destination_ip", "remote_ip")
            ip = next((str(props[k]) for k in keys if props.get(k)), "")
            if _private(ip) is False:
                try:
                    external_ips.add(str(ipaddress.ip_address(ip)))
                except ValueError:
                    pass
    found = []
    for hid, ent in graph.entities.items():
        if ent.get("type") != "host" or hid in graph.trigger_ids:
            continue
        props = graph.props(hid)
        addr = str(props.get("ip") or props.get("ip_address") or "")
        try:
            normalized = str(ipaddress.ip_address(addr))
        except ValueError:
            continue
        if normalized in external_ips:
            found.append((normalized, hid))
    return sorted(set(found))


def _block_external_hosts(sub: dict[str, Any], graph: ObservedGraph) -> None:
    # Arm B tests host-targeted blocks, NOT connection-targeted blocks. Maintain
    # the same two-block cap and one per unique external IP.
    existing = [a for a in _unique_actions(sub.get("ir_artifacts") or [])
                if a["kind"] != "network_block"]
    peers = _external_connected_hosts(graph)
    sub["ir_artifacts"] = existing + [
        {"entity_id": hid, "kind": "network_block"} for _ip, hid in peers[:2]
    ]


def _benign_entities(sub: dict[str, Any], graph: ObservedGraph, limit: int) -> None:
    allowed = {"host", "ad_object", "windows_service"} | USER_TYPES | FILE_TYPES
    selected = benign_anchor_evidence(graph, limit=max(50, len(graph.entities)))
    sub["legitimacy_evidence"] = [
        item for item in selected
        if graph.etype(item.get("entity_id", "")) in allowed
        and item.get("entity_id") not in graph.trigger_ids
        and item.get("property_fields")
    ][:limit]


# Phase I (on the Phase F budget): report-only additions validated by Phase H.
EXECUTABLE_EXT = re.compile(r"\.(?:exe|dll|com|scr|msi)$", re.I)
ARCHIVE_EXT = re.compile(r"\.(?:zip|rar|7z|tar|gz|cab|iso)$", re.I)
PHASE_I_MODES = frozenset({"combined", "internal_source", "service_persistence", "archive_files",
                           "baseline_archives", "inbound_sources", "service_persistence_v2", "inbound_guard"}) | PHASE_L_MODES


def _observed_written_files(graph: ObservedGraph, pattern: re.Pattern[str]) -> list[str]:
    """Opened file entities written by the observed causal process chain only."""
    procs = malicious_process_set(graph, graph.trigger_ids)
    ids = set()
    for pid in procs:
        for rel in graph.out(pid, {"wrote_file"}):
            nid = rel.get("target_id")
            if nid not in graph.entities or graph.etype(nid) not in FILE_TYPES:
                continue
            props = graph.props(nid)
            path = str(props.get("path") or props.get("file_path") or
                       props.get("filename") or "")
            if path and pattern.search(path):
                ids.add(nid)
    return sorted(ids)


def _add_written_files(sub: dict[str, Any], graph: ObservedGraph,
                       pattern: re.Pattern[str]) -> None:
    actions = _unique_actions(sub.get("ir_artifacts") or [])
    for nid in _observed_written_files(graph, pattern):
        actions.append({"entity_id": nid, "kind": "file_to_delete"})
    sub["ir_artifacts"] = _unique_actions(actions)


def _omit_benign_scripts(sub: dict[str, Any], graph: ObservedGraph) -> None:
    """Change only script citations, preserve every other already-ranked anchor."""
    sub["legitimacy_evidence"] = [
        item for item in sub.get("legitimacy_evidence") or []
        if not (item.get("anchor") == "entity" and
                graph.etype(item.get("entity_id", "")) in
                {"powershell_script", "powershell_cmdlet_invocation"})
    ]


def _command_image(value: Any) -> str:
    """Extract full executable path from quoted OR unquoted ImagePath + args."""
    cmd = str(value or "").replace("/", "\\").strip()
    if cmd.startswith('"'):
        return _norm_path(cmd[1:].split('"', 1)[0])
    # A service's unquoted ImagePath can contain spaces in directory names.
    match = re.match(r"^(.+?\.(?:exe|com|scr))(?:\s|$)", cmd, re.I)
    return _norm_path(match.group(1) if match else cmd)


def _opened_service_matches_process(graph: ObservedGraph) -> list[str]:
    """Open service with matching *full executable path* started by services.exe.

    A missing -service flag on process cmdline is not a reason to discard a
    verified services.exe child when that flag is present on Service ImagePath.
    A basename-only match is never enough.
    """
    services = [(sid, _command_image(graph.props(sid).get("binary_path") or
                                      graph.props(sid).get("image_path")))
                for sid, ent in graph.entities.items()
                if ent.get("type") == "windows_service"]
    matched = set()
    for pid in malicious_process_set(graph, graph.trigger_ids):
        props = graph.props(pid)
        image = _norm_path(props.get("image_path"))
        cmd = str(props.get("cmdline") or props.get("command_line") or "")
        if not image or not ntpath.isabs(image):
            continue
        parent_images = [props.get("parent_image"), props.get("parent_image_path"),
                         props.get("parent_process_image")]
        parent_ok = any(ntpath.basename(_norm_path(p)) == "services.exe"
                        for p in parent_images)
        if not parent_ok:
            parent_pid = props.get("parent_pid")
            for parent_id, node in graph.entities.items():
                if (node.get("type") == "windows_process" and
                        parent_pid is not None and
                        graph.props(parent_id).get("pid") == parent_pid and
                        node.get("host_id") == graph.entities.get(pid, {}).get("host_id") and
                        ntpath.basename(_norm_path(graph.props(parent_id).get("image_path"))) == "services.exe"):
                    parent_ok = True
                    break
        if not parent_ok:
            parent_ok = any(ntpath.basename(_norm_path(graph.props(e.get("source_id", "")).get("image_path"))) ==
                                "services.exe"
                            for e in graph.inc(pid, {"win_process_create", "parent_of"}))
        if not parent_ok:
            continue
        for sid, svc_image in services:
            svc_cmd = str(graph.props(sid).get("binary_path") or "")
            marker = bool(re.search(r"(?:^|\s)-service(?:\s|$)", cmd, re.I) or
                          re.search(r"(?:^|\s)-service(?:\s|$)", svc_cmd, re.I))
            if svc_image == image and marker:
                matched.add(sid)
    return sorted(matched)


def _add_service_persistence(sub: dict[str, Any], graph: ObservedGraph) -> None:
    actions = _unique_actions(sub.get("ir_artifacts") or [])
    for sid in _opened_service_matches_process(graph):
        actions.append({"entity_id": sid, "kind": "persistence_to_remove"})
    sub["ir_artifacts"] = _unique_actions(actions)


def _internal_login_source_hosts(graph: ObservedGraph) -> list[str]:
    """Resolve host only if an observed authenticated remote logon names its IP.

    Do not treat any ordinary TCP peer or an unverified inbound connection as
    evidence of compromise of the *source* host.
    """
    procs = malicious_process_set(graph, graph.trigger_ids)
    sessions = {str(graph.props(pid).get("logon_id") or "").casefold()
                for pid in procs} - {"", "0x3e7", "0x0"}
    source_ips = set()
    for rel in graph.relations.values():
        if rel.get("type") not in {"logged_on_to", "authenticated_to", "successful_logon"}:
            continue
        data = logon_details(rel)
        session = str(data.get("logon_id") or data.get("session_id") or "").casefold()
        if session and session not in sessions:
            continue
        if not session and rel.get("source_id") not in procs and rel.get("target_id") not in procs:
            continue
        if not confirmed_remote_login(rel):
            continue
        ip = str(data.get("source_ip") or data.get("src_ip") or "")
        if _private(ip) is True:
            source_ips.add(ip)
    if not source_ips:
        return []
    local_hosts = {graph.entities[pid].get("host_id") for pid in procs if pid in graph.entities}
    return sorted(
        hid for hid, ent in graph.entities.items()
        if ent.get("type") == "host" and hid not in local_hosts
        and str(graph.props(hid).get("ip") or graph.props(hid).get("ip_address") or "") in source_ips
    )


def _add_internal_source_hosts(sub: dict[str, Any], graph: ObservedGraph) -> None:
    actions = _unique_actions(sub.get("ir_artifacts") or [])
    for hid in _internal_login_source_hosts(graph):
        actions.append({"entity_id": hid, "kind": "host_to_isolate"})
    sub["ir_artifacts"] = _unique_actions(actions)


def _observed_inbound_source_ips(graph: ObservedGraph) -> tuple[set[str], set[str]]:
    """Source IPs grounded in a remote login or causal inbound connection.

    Returns (external, internal_confirmed_logon). A mere inbound TCP
    connection does NOT justify isolating its internal source.
    """
    procs = malicious_process_set(graph, graph.trigger_ids)
    sessions = {str(graph.props(pid).get("logon_id") or "").casefold()
                for pid in procs} - {"", "0x3e7", "0x0"}
    actor_sids = {str(graph.props(pid).get("user_sid") or "").casefold()
                  for pid in procs} - {""}
    actor_ids = {nid for nid, ent in graph.entities.items()
                 if ent.get("type") in USER_TYPES and
                 str(graph.props(nid).get("sid") or graph.props(nid).get("user_sid") or "").casefold() in actor_sids}
    host_ids = {graph.entities[pid].get("host_id") for pid in procs if pid in graph.entities}
    external: set[str] = set()
    internal: set[str] = set()
    for rel in graph.relations.values():
        typ = rel.get("type")
        data = logon_details(rel)
        if typ in {"logged_on_to", "authenticated_to", "successful_logon"}:
            session = str(data.get("logon_id") or data.get("session_id") or "").casefold()
            linked = (session in sessions if session else
                      rel.get("source_id") in actor_ids or rel.get("target_id") in host_ids)
            if not linked:
                continue
            if not confirmed_remote_login(rel):
                continue
            ip = str(data.get("source_ip") or data.get("src_ip") or "")
            if _private(ip) is False:
                external.add(ip)
            elif _private(ip) is True:
                internal.add(ip)
        elif typ in {"accepted_connection_from", "received_data_from"} and rel.get("source_id") in procs:
            dest = rel.get("target_id")
            if dest not in graph.entities or graph.etype(dest) != "network_connection":
                continue
            conn = graph.props(dest)
            ip = str(conn.get("src_ip") or conn.get("source_ip") or "")
            if _private(ip) is False:
                external.add(ip)
    return external, internal


def _add_inbound_sources(sub: dict[str, Any], graph: ObservedGraph) -> None:
    external, internal = _observed_inbound_source_ips(graph)
    hosts = graph.hosts_by_ip()
    hosts.update({str(graph.props(hid).get("ip_address")): hid
                  for hid, node in graph.entities.items()
                  if node.get("type") == "host" and graph.props(hid).get("ip_address")})
    actions = _unique_actions(sub.get("ir_artifacts") or [])
    def blocked_ip(action: dict[str, str]) -> str:
        nid = action["entity_id"]
        kind = graph.etype(nid)
        props = graph.props(nid)
        if kind == "host":
            return str(props.get("ip") or props.get("ip_address") or "")
        if kind == "network_connection":
            incoming = any(rel.get("type") in {"accepted_connection_from", "received_data_from"}
                           for rel in graph.inc(nid))
            keys = ("src_ip", "source_ip") if incoming else ("dst_ip", "destination_ip", "remote_ip")
            return next((str(props[key]) for key in keys if props.get(key)), "")
        return ""

    for ip in sorted(external):
        hid = hosts.get(ip)
        if not hid:
            continue
        blocks = [a for a in actions if a["kind"] == "network_block"]
        duplicate = next((a for a in blocks if blocked_ip(a) == ip), None)
        if duplicate:
            # Prefer a host entity over a network_connection for the same IP,
            # not two actions on the same address.
            if duplicate["entity_id"] != hid:
                actions.remove(duplicate)
                actions.append({"entity_id": hid, "kind": "network_block"})
        elif len(blocks) < 2:
            actions.append({"entity_id": hid, "kind": "network_block"})
    local_hosts = {graph.entities[pid].get("host_id") for pid in malicious_process_set(graph, graph.trigger_ids)
                   if pid in graph.entities}
    for ip in sorted(internal):
        hid = hosts.get(ip)
        if hid and hid not in local_hosts:
            actions.append({"entity_id": hid, "kind": "host_to_isolate"})
    sub["ir_artifacts"] = _unique_actions(actions)


def _combine_validated_changes(sub: dict[str, Any], graph: ObservedGraph) -> None:
    if sub.get("verdict") == "malicious":
        # Phase H proved host-targeted blocks valuable. If no matching opened
        # host is available, preserve the original mapper's connection block
        # rather than silently discarding an already-justified DNS action.
        if _external_connected_hosts(graph):
            _block_external_hosts(sub, graph)
        _add_written_files(sub, graph, EXECUTABLE_EXT)
    elif sub.get("verdict") == "benign":
        _omit_benign_scripts(sub, graph)


def report_probe_diagnostics(graph: ObservedGraph) -> dict[str, Any]:
    """Offline-only, public evidence counters; never used as decision feedback."""
    external, internal = _observed_inbound_source_ips(graph)
    return {
        "observed_service_ids": sorted(nid for nid, item in graph.entities.items()
                                       if item.get("type") == "windows_service"),
        "matched_service_ids": _opened_service_matches_process(graph),
        "external_inbound_source_ips": sorted(external),
        "confirmed_internal_source_ips": sorted(internal),
    }


def phaseL_probe_diagnostics(graph: ObservedGraph, mode: str) -> dict[str, Any]:
    """Offline inspection of whether the selected experiment actually fired."""
    if mode not in PHASE_L_MODES:
        return {}
    triggers = [t for t in graph.trigger_ids if graph.etype(t) == 'windows_process']
    observed = set()
    matched = set()
    for trigger in triggers:
        if mode == 'scheduled_task':
            observed.update(scheduled_task_sources(graph, trigger))
            matched.update(t for t in observed if graph.etype(t) == 'scheduled_task'
                           and graph.props(t).get('task_name'))
        elif mode == 'script_file':
            name = script_name_from_command(graph.props(trigger).get('cmdline') or
                                            graph.props(trigger).get('command_line'))
            if name:
                observed.add(name)
                matched.update(fid for fid, e in graph.entities.items()
                               if e.get('type') == 'windows_file' and
                               ntpath.basename(str(graph.props(fid).get('path') or
                                                  graph.props(fid).get('file_path') or '')).casefold() == name.casefold())
        elif mode == 'interactive_logon' and interactive_trigger(graph, trigger):
            ips = interactive_source_ips(graph, trigger)
            observed.update(ips)
            matched.update(hid for hid, e in graph.entities.items()
                           if e.get('type') == 'host' and
                           str(graph.props(hid).get('ip') or graph.props(hid).get('ip_address') or '') in ips)
        elif mode in {'agent_handles', 'agent_handles_nocite'} and is_protection_process(graph, trigger):
            targets = {r.get('target_id') for r in graph.out(trigger, {'opened_handle'})}
            observed.update(t for t in targets if isinstance(t, str))
            matched.update(t for t in targets if t in graph.entities)
    return {'mode': mode, 'candidate_ids_or_names': sorted(observed),
            'opened_matched_entity_ids': sorted(matched)}


def _fact_text(sub: dict[str, Any], graph: ObservedGraph) -> str:
    """Short, grounded description; no inferred intent, approvals, or reward."""
    facts = []
    trigger_procs = [pid for pid in graph.trigger_ids if graph.etype(pid) in PROCESS_TYPES]
    for pid in trigger_procs[:1]:
        p = graph.props(pid)
        image = str(p.get("image_path") or p.get("name") or "")
        if image:
            facts.append("Trigger image: " + image[:130])
        if p.get("user"):
            facts.append("Account: " + str(p["user"])[:90])
        if p.get("cmdline"):
            facts.append("Command: " + str(p["cmdline"])[:160])
    procs = malicious_process_set(graph, graph.trigger_ids)
    children = sorted({ntpath.basename(str(graph.props(pid).get("image_path") or ""))
                       for pid in procs if pid not in trigger_procs and graph.props(pid).get("image_path")})
    if children:
        facts.append("Observed children: " + ", ".join(children[:3]))
    write_paths = sorted({str(graph.props(rel["target_id"]).get("path") or "")
                          for pid in procs for rel in graph.out(pid, {"wrote_file"})
                          if graph.etype(rel["target_id"]) in FILE_TYPES and
                             graph.props(rel["target_id"]).get("path")})
    if write_paths:
        facts.append("Written files: " + ", ".join(write_paths[:2]))
    services = sorted({str(graph.props(rel["target_id"]).get("service_name") or
                           graph.props(rel["target_id"]).get("binary_path") or "")
                       for pid in procs for rel in graph.out(pid, {"created_service", "started_service"})
                       if graph.etype(rel["target_id"]) == "windows_service"})
    if services:
        facts.append("Service objects: " + ", ".join(x for x in services[:2] if x))
    peers = _external_connected_hosts(graph)
    if peers:
        facts.append("Resolved external peers: " + ", ".join(ip for ip, _id in peers[:2]))
    if sub.get("verdict") == "benign":
        cited = [graph.etype(a.get("entity_id", "")) for a in sub.get("legitimacy_evidence") or []
                 if a.get("anchor") == "entity"]
        if cited:
            facts.append("Cited entity types: " + ", ".join(str(t) for t in cited[:3]))
    if not facts:
        facts.append(f"Observed graph contains {len(graph.entities)} entities and {len(graph.relations)} relations")
    return "; ".join(facts)[:700] + "."



def _prepend_benign_citations(sub: dict[str, Any], citations: list[dict[str, Any]],
                              limit: int = 3) -> None:
    """Cite only opened public entities, preserving normal ranked anchors."""
    current = [item for item in sub.get('legitimacy_evidence') or []
               if isinstance(item, dict) and item.get('anchor') == 'entity']
    selected = []
    seen = set()
    for item in citations + current:
        eid = item.get('entity_id')
        if not eid or eid in seen or not item.get('property_fields'):
            continue
        selected.append(item)
        seen.add(eid)
        if len(selected) == limit:
            break
    sub['legitimacy_evidence'] = selected


def _phaseL_benign(sub: dict[str, Any], graph: ObservedGraph, mode: str,
                   *, limit: int) -> None:
    """Exactly one Phase L citation arm, no invented IDs or field names."""
    if sub.get('verdict') != 'benign':
        return
    targets = []
    trigger_ids = [t for t in graph.trigger_ids if graph.etype(t) == 'windows_process']
    if mode == 'scheduled_task':
        for trigger in trigger_ids:
            for tid in scheduled_task_sources(graph, trigger):
                if graph.etype(tid) != 'scheduled_task':
                    continue
                p = graph.props(tid)
                fields = [f for f in ('task_name', 'action_target') if p.get(f) is not None]
                if fields:
                    targets.append({'anchor': 'entity', 'entity_id': tid,
                                    'property_fields': fields})
    elif mode == 'script_file':
        for trigger in trigger_ids:
            name = script_name_from_command(graph.props(trigger).get('cmdline') or
                                            graph.props(trigger).get('command_line'))
            if not name:
                continue
            host_id = (graph.entities.get(trigger) or {}).get('host_id')
            for fid, entity in graph.entities.items():
                if entity.get('type') != 'windows_file':
                    continue
                path = str(graph.props(fid).get('path') or graph.props(fid).get('file_path') or '')
                if (ntpath.basename(path).casefold() == name.casefold() and
                        (not entity.get('host_id') or entity.get('host_id') == host_id) and
                        path):
                    field = 'path' if graph.props(fid).get('path') else 'file_path'
                    targets.append({'anchor': 'entity', 'entity_id': fid,
                                    'property_fields': [field]})
    elif mode == 'interactive_logon':
        for trigger in trigger_ids:
            if not interactive_trigger(graph, trigger):
                continue
            host_id = (graph.entities.get(trigger) or {}).get('host_id')
            for ip in interactive_source_ips(graph, trigger):
                for hid, ent in graph.entities.items():
                    if ent.get('type') != 'host' or hid == host_id:
                        continue
                    props = graph.props(hid)
                    if str(props.get('ip') or props.get('ip_address') or '') != ip:
                        continue
                    fields = [f for f in ('hostname', 'role') if props.get(f) is not None]
                    if fields:
                        targets.append({'anchor': 'entity', 'entity_id': hid,
                                        'property_fields': fields})
    elif mode in {'agent_handles', 'agent_handles_nocite'}:
        # The zero-citation variant opens exactly the same targets as cited arm.
        protection = [pid for pid in trigger_ids if is_protection_process(graph, pid)]
        if mode == 'agent_handles_nocite':
            if protection:
                sub['legitimacy_evidence'] = []
            return
        for pid in protection:
            for rel in graph.out(pid, {'opened_handle'}):
                target = rel.get('target_id')
                if target not in graph.entities or target in graph.trigger_ids:
                    continue
                typ = graph.etype(target)
                if typ not in {'windows_process', 'windows_file'}:
                    continue
                p = graph.props(target)
                preferred = (('image_path', 'name') if typ == 'windows_process'
                             else ('path', 'file_path', 'name'))
                fields = [key for key in preferred if p.get(key) is not None]
                if fields:
                    targets.append({'anchor': 'entity', 'entity_id': target,
                                    'property_fields': fields[:2]})
    if targets:
        _prepend_benign_citations(sub, targets[:2], limit=max(1, min(limit, 3)))


def apply_report_experiment(
    submission: dict[str, Any], graph: ObservedGraph, mode: str = "control",
    *, benign_limit: int = 3,
) -> dict[str, Any]:
    """Apply exactly one report variation after all normal mapping/reconciliation."""
    if mode not in MODES:
        raise ValueError(f"Invalid report experiment {mode!r}; valid: {sorted(MODES)}")
    result = deepcopy(submission)
    if mode in PHASE_I_MODES:
        _combine_validated_changes(result, graph)
        if result.get("verdict") == "malicious":
            if mode in {"baseline_archives", "inbound_sources", "service_persistence_v2", "inbound_guard"} | PHASE_L_MODES:
                _add_written_files(result, graph, ARCHIVE_EXT)
            if mode in {"inbound_sources", "inbound_guard"} | PHASE_L_MODES:
                _add_inbound_sources(result, graph)
            elif mode == "service_persistence_v2":
                _add_service_persistence(result, graph)
            elif mode == "internal_source":
                _add_internal_source_hosts(result, graph)
            elif mode == "service_persistence":
                _add_service_persistence(result, graph)
            elif mode == "archive_files":
                _add_written_files(result, graph, ARCHIVE_EXT)
    if mode in PHASE_L_MODES and result.get('verdict') == 'benign':
        _phaseL_benign(result, graph, mode, limit=benign_limit)
    elif mode == "malicious_files" and result.get("verdict") == "malicious":
        _add_files_and_service(result, graph)
    elif mode == "malicious_block" and result.get("verdict") == "malicious":
        _block_external_hosts(result, graph)
    elif mode == "benign_entities" and result.get("verdict") == "benign":
        _benign_entities(result, graph, max(1, min(benign_limit, 3)))
    elif mode == "fact_reasoning":
        result["reasoning"] = _fact_text(result, graph)
    return result


DELETED_FILE_KINDS = frozenset({"file_to_delete", "cleanup_to_verify", "file_observed",
                                "artifact_observed"})


def drop_deleted_file_artifacts(
    submission: dict[str, Any], graph: ObservedGraph,
) -> tuple[dict[str, Any], list[str]]:
    """Remove file actions on files the attacker already deleted.

    Phase M (179 tasks): every artifact on a deleted file lowered Q
    (cleanup_to_verify -0.07..-0.18, file_observed -0.08..-0.12); history shows
    file_to_delete on such files costs -2 final reward.  There is nothing left to
    delete, so the action is a false positive.  Applies to every report mode.
    """
    if submission.get("verdict") != "malicious":
        return submission, []
    deleted = {rel.get("target_id") for rel in graph.relations.values()
               if rel.get("type") == "deleted_file"}
    kept, dropped = [], []
    for item in submission.get("ir_artifacts") or []:
        if item.get("kind") in DELETED_FILE_KINDS and item.get("entity_id") in deleted:
            dropped.append(str(item.get("entity_id")))
        else:
            kept.append(item)
    if not dropped:
        return submission, []
    return {**submission, "ir_artifacts": kept}, dropped


# ---------------------------------------------------------------------------
# role_policy: explicit role-based report rules learned in Phase M (179 tasks,
# weights consistent in sign across three fixed-effect specifications).
# Roles are graph positions (child process, deleted file, external peer, ...),
# never scenario names, so the rules transfer to unseen scenarios.
# ---------------------------------------------------------------------------

_BENIGN_DROP_RELATIONS = frozenset({"win_process_create", "parent_of", "logged_on_to",
                                    "accepted_connection_from"})


def _chain_peer_ips(graph: ObservedGraph) -> set[str]:
    """IPs that causally touch the trigger chain: logon sources and connection peers."""
    from bluesec1_agent.probe_design import _ip_of
    procs = malicious_process_set(graph, graph.trigger_ids) or set(graph.trigger_ids)
    ips: set[str] = set()
    for rel in graph.relations.values():
        if rel.get("type") == "logged_on_to":
            props = {**(rel.get("properties") or {}), **(rel.get("logon_properties") or {})}
            ip = _ip_of(props, ("source_ip", "ip_address", "src_ip"))
            if ip:
                ips.add(ip)
        if rel.get("source_id") in procs and rel.get("type") in {
                "connected_to", "accepted_connection_from", "sent_data_to", "received_data_from"}:
            ip = _ip_of(graph.props(str(rel.get("target_id"))),
                        ("dst_ip", "destination_ip", "remote_ip", "src_ip", "source_ip"))
            if ip:
                ips.add(ip)
    return ips


GENERIC_GROUPS = frozenset({"administrators", "users", "domain users", "everyone",
                            "authenticated users", "builtin\\administrators", "builtin\\users",
                            "remote desktop users"})


def legitimising_groups(props: dict[str, Any]) -> list[str]:
    """Group memberships that describe an authorised role (not generic built-ins)."""
    raw = props.get("group_memberships")
    if isinstance(raw, str):
        raw = [g.strip(" '\"") for g in raw.strip("[]").split(",")]
    groups = [str(g) for g in raw or [] if str(g).strip()]
    meaningful = [g for g in groups if g.casefold() not in GENERIC_GROUPS]
    return meaningful


def apply_role_policy(submission: dict[str, Any], graph: ObservedGraph) -> dict[str, Any]:
    """Deterministic report rules by entity role; the verdict is never changed."""
    from bluesec1_agent.probe_design import _ip_of, candidate_roles
    roles = candidate_roles(graph)
    role_of: dict[str, str] = {}
    for role, ids in roles.items():
        for nid in ids:
            role_of.setdefault(nid, role)
    result = deepcopy(submission)
    if result.get("verdict") == "malicious":
        drop = {("script", "file_observed"), ("script", "artifact_observed"),
                ("written_file", "cleanup_to_verify"), ("external_conn", "network_block")}
        arts = [a for a in result.get("ir_artifacts") or []
                if (role_of.get(a.get("entity_id")), a.get("kind")) not in drop
                and role_of.get(a.get("entity_id")) != "deleted_file"]
        peer_ips = _chain_peer_ips(graph)
        for hid in roles.get("internal_peer_host", []):
            if _ip_of(graph.props(hid), ("ip", "ip_address")) in peer_ips:
                arts.append({"entity_id": hid, "kind": "host_to_isolate"})
        for hid in roles.get("external_host", [])[:2]:
            arts.append({"entity_id": hid, "kind": "network_block"})
        result["ir_artifacts"] = _unique_actions(arts)[:8]
    elif result.get("verdict") == "benign":
        kept = []
        for ev in result.get("legitimacy_evidence") or []:
            if ev.get("anchor") == "relation":
                rel = graph.relations.get(str(ev.get("relation_id"))) or {}
                if rel.get("type") in _BENIGN_DROP_RELATIONS:
                    continue
                kept.append(ev)
                continue
            nid = str(ev.get("entity_id"))
            role = role_of.get(nid)
            etype = graph.etype(nid)
            fields = [f for f in ev.get("property_fields") or [] if f != "script_text"]
            # Phase O: host citations (-0.02..-0.04 each) and written/read files never
            # legitimise an operation; the actor user is re-added below.
            if etype in {"host", "windows_file", "archive_file"} or not fields:
                continue
            if role in {"trigger_host", "trigger_process", "trigger_user"}:
                continue
            if role == "child_process" and "cmdline" in fields:
                continue
            if etype in USER_TYPES and not legitimising_groups(graph.props(nid)):
                continue
            kept.append({**ev, "property_fields": fields})
        cited = {ev.get("entity_id") for ev in kept}
        for uid in roles.get("trigger_user", [])[:1]:
            # Phase O: the actor's role (group membership) is the strongest single
            # citation (+0.12..+0.16).  Built-in/generic groups prove nothing
            # (local Administrator cited: -0.12), so such accounts are not cited.
            if legitimising_groups(graph.props(uid)):
                kept.insert(0, {"anchor": "entity", "entity_id": uid,
                                "property_fields": ["group_memberships"]})
        for uid in roles.get("group_changed_user", [])[:2]:
            if uid not in cited and graph.props(uid).get("username"):
                kept.append({"anchor": "entity", "entity_id": uid, "property_fields": ["username"]})
        result["legitimacy_evidence"] = kept[:4]
    return result
