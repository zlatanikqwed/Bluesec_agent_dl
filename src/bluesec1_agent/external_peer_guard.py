"""Causal external-host veto, opt-in for Phase K only.

Unlike a blanket `role=external` test, this requires an opened host with a
matching address AND a connection/logon causally attached to the alert chain.
Protective products and kernel pseudo-processes are excluded. The rule is
restricted to the high-precision PowerShell, svchost and Chrome process families.
"""
from __future__ import annotations

import ipaddress
import ntpath
import re
from typing import Any

from bluesec1_agent.decision_guard import AttackSignal
from bluesec1_agent.inbound_evidence import logon_details, confirmed_remote_login
from bluesec1_agent.response_mapper import ObservedGraph, malicious_process_set

_PROTECTED = re.compile(
    r"(?:^|[\\/])(ekrn|egui|avp|avpui|msmpeng|nissrv|senseir|"
    r"csfalconservice|sentinelagent|savservice|wrsa|mbamservice|"
    r"bdservicehost|carbonblack|cbdefense|eset)(?:\.exe)?$", re.I,
)
_ELIGIBLE = {"powershell.exe", "pwsh.exe", "svchost.exe", "chrome.exe"}
_PSEUDO = {"system", "registry", "memcompression"}


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _image(graph: ObservedGraph, pid: str) -> str:
    prop = graph.props(pid)
    return ntpath.basename(str(prop.get("image_path") or prop.get("image") or "").replace("/", "\\")).casefold()


def external_peer_signals(graph: ObservedGraph) -> list[AttackSignal]:
    """Return at most one strongly grounded signal for the trigger's process tree."""
    triggers = [pid for pid in graph.trigger_ids if graph.etype(pid) == "windows_process"]
    if not triggers:
        return []
    for trigger in triggers:
        image = _image(graph, trigger)
        if image in _PSEUDO or _PROTECTED.search(str(graph.props(trigger).get("image_path") or "")):
            continue
        chain = malicious_process_set(graph, [trigger])
        eligible: set[str] = set()
        for pid in chain:
            img = _image(graph, pid)
            if img in _ELIGIBLE and not _PROTECTED.search(str(graph.props(pid).get("image_path") or "")):
                eligible.add(pid)
        if not eligible:
            continue
        local_hosts = {graph.entities[pid].get("host_id") for pid in chain if pid in graph.entities}
        external: dict[str, str] = {}
        for hid, ent in graph.entities.items():
            if ent.get("type") != "host" or hid in local_hosts:
                continue
            props = graph.props(hid)
            if str(props.get("role") or "").casefold() != "external":
                continue
            addr = _ip(props.get("ip") or props.get("ip_address"))
            if addr:
                external[addr] = hid
        if not external:
            continue
        for pid in sorted(eligible):
            for rel in graph.out(pid, {"connected_to", "accepted_connection_from",
                                       "sent_data_to", "received_data_from"}):
                dest = str(rel.get("target_id") or "")
                if graph.etype(dest) == "host":
                    for ip, host_id in external.items():
                        if dest == host_id:
                            return [AttackSignal("causal contact with confirmed external host", pid, 5,
                                                 f"process={pid}; host={host_id}; ip={ip}")]
                if graph.etype(dest) != "network_connection" or dest not in graph.entities:
                    continue
                p = graph.props(dest)
                fields = (("src_ip", "source_ip") if rel["type"] in
                          {"accepted_connection_from", "received_data_from"} else
                          ("dst_ip", "destination_ip", "remote_ip"))
                addr = next((_ip(p.get(key)) for key in fields if _ip(p.get(key))), "")
                if addr in external:
                    return [AttackSignal("causal contact with confirmed external host", pid, 5,
                                         f"process={pid}; connection={dest}; host={external[addr]}; ip={addr}")]
        # An established remote login in the trigger's session can itself
        # provide the source IP; do not treat unrelated host search results as
        # causal evidence.
        sessions = {str(graph.props(pid).get("logon_id") or "").casefold() for pid in eligible}
        sessions -= {"", "0x3e7", "0x0"}
        local_targets = {graph.entities[pid].get("host_id") for pid in eligible if pid in graph.entities}
        actors = {str(graph.props(pid).get("user_sid") or "").casefold() for pid in eligible}
        actor_ids = {uid for uid, ent in graph.entities.items()
                     if ent.get("type") == "windows_user" and
                     str(graph.props(uid).get("sid") or "").casefold() in actors}
        for rel in graph.relations.values():
            if rel.get("type") != "logged_on_to" or not confirmed_remote_login(rel):
                continue
            data = logon_details(rel)
            sess = str(data.get("logon_id") or data.get("session_id") or "").casefold()
            linked = ((sess in sessions) if sess else
                      (rel.get("source_id") in actor_ids and rel.get("target_id") in local_targets))
            addr = _ip(data.get("source_ip") or data.get("src_ip"))
            if linked and addr in external:
                return [AttackSignal("confirmed external host initiated process logon", trigger, 5,
                                     f"logon={rel.get('id')}; host={external[addr]}; ip={addr}")]
    return []
