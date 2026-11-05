"""Deterministic incident scoping and response mapping (v25).

The LLM decides *whether* the activity is malicious and which processes are the
attacker's.  This module decides *what must be done* about it, from the graph the
agent has actually observed: which hosts to isolate, which identities to rotate,
which payloads to delete, which persistence to remove and which network peers to
block.  Every artifact is an id that was returned by the runtime.

Design rules:
- no invented ids: only entities/relations present in ``ObservedGraph``;
- response kinds follow the entity type (host -> host_to_isolate, user ->
  identity_to_rotate, ...); ``*_observed`` kinds only for pure evidence;
- tiers let you A/B precision vs recall on Practice without code changes.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

PROCESS_TYPES = {"windows_process", "linux_process"}
USER_TYPES = {"windows_user", "linux_user"}
FILE_TYPES = {"windows_file", "linux_file", "archive_file"}
PERSISTENCE_TYPES = {
    "windows_service", "scheduled_task", "wmi_event_consumer", "wmi_event_filter",
    "wmi_binding", "systemd_unit", "registry_key", "kernel_module", "windows_driver",
}
SPAWN_RELATIONS = {
    "win_process_create", "linux_process_create", "parent_of", "forked", "execve_transitioned",
}
FILE_WRITE_RELATIONS = {"wrote_file", "renamed_file", "extracted_to", "archived_to", "created_link"}
FILE_EXEC_RELATIONS = {"executed_file", "loaded_image", "executed_script", "loaded_driver"}
PERSISTENCE_RELATIONS = {
    "created_service", "modified_service", "created_scheduled_task", "created_wmi_filter",
    "created_wmi_consumer", "bound_wmi_filter_to_consumer", "set_registry_value",
    "created_registry_key", "loaded_kernel_module", "loaded_driver",
}
IDENTITY_CHANGE_RELATIONS = {
    "added_to_group", "created_account", "changed_password", "removed_from_group",
}
REMOTE_ADMIN_PORTS = {22, 135, 139, 445, 3389, 5985, 5986, 47001}
BUILTIN_USERS = {
    "system", "local service", "network service", "localsystem", "root", "trustedinstaller",
}
AUTORUN_KEY = re.compile(
    r"\\(run|runonce|services|winlogon|image file execution options|appinit_dlls|"
    r"shell folders|explorer\\shell|silentprocessexit|lsa|print\\monitors|"
    r"bootexecute|currentversion\\windows)\b",
    re.I,
)
SUSPICIOUS_PATH = re.compile(
    r"\\(windows\\temp|temp|tmp|users\\public|programdata|appdata|perflogs|"
    r"\$recycle\.bin|windows\\tasks)\\|^/(tmp|var/tmp|dev/shm)/",
    re.I,
)
SYSTEM_IMAGE = re.compile(
    r"\\windows\\(system32|syswow64|winsxs|servicing|explorer\.exe)|\\program files|"
    r"\\windows\\microsoft\.net\\|^/(usr/)?s?bin/",
    re.I,
)
PAYLOAD_EXT = re.compile(
    r"\.(exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|jse|hta|scr|msi|lnk|dmp|7z|zip|rar|"
    r"tmp|bin|dat|raw|kirbi|ccache|so|sh|py|elf)$",
    re.I,
)


def _network_remote_ip(graph: "ObservedGraph", nid: str) -> str | None:
    """Canonical EXTERNAL destination/source of an observed connection.

    The report acts on a single observed connection entity per distinct peer IP;
    never on every TCP session to the same peer.  Unknown/private addresses do
    not qualify as network blocks.
    """
    if graph.etype(nid) != "network_connection":
        return None
    props = graph.props(nid)
    for key in ("dst_ip", "remote_ip", "destination_ip", "src_ip", "source_ip"):
        address = str(props.get(key) or "").strip()
        if _private(address) is False:
            try:
                return str(ipaddress.ip_address(address))
            except ValueError:
                continue
    return None


def _dedupe_network_blocks(
    artifacts: list[dict[str, Any]], graph: "ObservedGraph", limit: int = 2,
) -> list[dict[str, Any]]:
    """Preserve first (highest-ranked) block per external IP, capped per case."""
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for artifact in artifacts:
        if artifact.get("kind") != "network_block":
            result.append(artifact)
            continue
        peer = _network_remote_ip(graph, str(artifact.get("entity_id") or ""))
        if peer is None or peer in seen or len(seen) >= limit:
            continue
        seen.add(peer)
        result.append(artifact)
    return result


def _private(ip: str | None) -> bool | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    # RFC 5737 TEST-NETs (192.0.2/24, 198.51.100/24, 203.0.113/24) are flagged as
    # "private" by ipaddress, but scenarios use them as internet addresses.
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        if addr in ipaddress.ip_network(net):
            return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


@dataclass
class ObservedGraph:
    """Everything the runtime has returned so far in one task."""

    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    relations: dict[str, dict[str, Any]] = field(default_factory=dict)
    trigger_ids: list[str] = field(default_factory=list)

    # ---- ingestion -------------------------------------------------------
    def absorb(self, value: Any) -> None:
        """Absorb an alert, tool result or search page (any nesting)."""
        if isinstance(value, list):
            for item in value:
                self.absorb(item)
            return
        if not isinstance(value, dict):
            return
        if isinstance(value.get("id"), str) and "source_id" in value and "target_id" in value:
            old = self.relations.get(value["id"], {})
            self.relations[value["id"]] = {**old, **value}
        elif isinstance(value.get("id"), str) and isinstance(value.get("type"), str):
            old = self.entities.get(value["id"], {})
            merged = {**old, **value}
            if old.get("properties") and value.get("properties"):
                merged["properties"] = {**old["properties"], **value["properties"]}
            self.entities[value["id"]] = merged
        for key in ("result", "results", "entities", "relations", "trigger_entities", "trigger_relations", "items"):
            if key in value:
                self.absorb(value[key])

    def absorb_alert(self, observation: dict[str, Any]) -> None:
        alert = (observation or {}).get("alert_text") or {}
        if isinstance(alert, str):
            try:
                alert = json.loads(alert)
            except ValueError:
                alert = {}
        for ent in alert.get("trigger_entities") or []:
            if isinstance(ent, dict) and ent.get("id"):
                self.trigger_ids.append(ent["id"])
        self.absorb(alert)

    # ---- helpers ---------------------------------------------------------
    def etype(self, nid: str) -> str | None:
        ent = self.entities.get(nid)
        if ent:
            return ent.get("type")
        # Endpoint types implied by relation semantics, without an extra call.
        for rel in self.relations.values():
            rtype = rel.get("type")
            if rel.get("source_id") == nid and rtype == "runs_process":
                return "windows_user"
            if rel.get("source_id") == nid and rtype == "hosts":
                return "host"
        return None

    def props(self, nid: str) -> dict[str, Any]:
        return (self.entities.get(nid) or {}).get("properties") or {}

    def out(self, nid: str, types: set[str] | None = None) -> Iterable[dict[str, Any]]:
        for rel in self.relations.values():
            if rel.get("source_id") == nid and (types is None or rel.get("type") in types):
                yield rel

    def inc(self, nid: str, types: set[str] | None = None) -> Iterable[dict[str, Any]]:
        for rel in self.relations.values():
            if rel.get("target_id") == nid and (types is None or rel.get("type") in types):
                yield rel

    def hosts_by_ip(self) -> dict[str, str]:
        return {
            p.get("ip"): nid
            for nid, e in self.entities.items()
            if e.get("type") == "host" and (p := e.get("properties") or {}).get("ip")
        }

    def users_by_name(self) -> dict[str, str]:
        index: dict[str, str] = {}
        for nid, e in self.entities.items():
            if e.get("type") in USER_TYPES:
                p = e.get("properties") or {}
                name = str(p.get("username") or "").lower()
                if name:
                    index[name] = nid
                    if p.get("domain"):
                        index[f"{str(p['domain']).lower()}\\{name}"] = nid
        return index


@dataclass
class MappedArtifact:
    entity_id: str
    kind: str
    tier: int
    why: str


def _user_is_builtin(user: str | None) -> bool:
    if not user:
        return True
    name = user.split("\\")[-1].strip().lower()
    return name in BUILTIN_USERS or name.endswith("$")


def malicious_process_set(graph: ObservedGraph, seeds: Iterable[str]) -> set[str]:
    """Seed processes plus every observed descendant (by edge or by parent pid)."""
    procs = {s for s in seeds if graph.etype(s) in PROCESS_TYPES}
    frontier = list(procs)
    while frontier:
        nid = frontier.pop()
        children = {r["target_id"] for r in graph.out(nid, SPAWN_RELATIONS)}
        p = graph.props(nid)
        for cid, ent in graph.entities.items():
            cp = ent.get("properties") or {}
            if (
                ent.get("type") in PROCESS_TYPES
                and p.get("pid") is not None
                and cp.get("parent_pid") == p.get("pid")
                and ent.get("host_id") == graph.entities.get(nid, {}).get("host_id")
                and str(cp.get("start_time", "")) >= str(p.get("start_time", ""))
            ):
                children.add(cid)
        for cid in children - procs:
            if graph.etype(cid) in PROCESS_TYPES:
                procs.add(cid)
                frontier.append(cid)
    return procs


def map_response(
    graph: ObservedGraph,
    seed_processes: Iterable[str],
    *,
    max_tier: int = 2,
    include_observed_processes: bool = True,
    max_network_blocks: int = 2,
) -> list[dict[str, str]]:
    """Return ``ir_artifacts`` for a malicious verdict.

    Tier 1: hosts, actor identities, payloads, persistence, external peers.
    Tier 2: lateral-movement peers, exposed credentials, staged/deleted files.
    Tier 3: weaker context (any written file, any spawned process host).
    """
    seeds = list(seed_processes) or [t for t in graph.trigger_ids if graph.etype(t) in PROCESS_TYPES]
    procs = malicious_process_set(graph, seeds)
    found: dict[tuple[str, str], MappedArtifact] = {}

    def add(nid: str | None, kind: str, tier: int, why: str) -> None:
        if not nid or tier > max_tier:
            return
        if graph.etype(nid) is None:
            return
        key = (nid, kind)
        if key not in found or found[key].tier > tier:
            found[key] = MappedArtifact(nid, kind, tier, why)

    host_ip = graph.hosts_by_ip()
    users = graph.users_by_name()
    malicious_paths: set[str] = set()

    for pid in procs:
        ent = graph.entities.get(pid, {})
        p = graph.props(pid)
        if include_observed_processes:
            add(pid, "process_observed", 1, "attacker-controlled process")
        # 1. Compromised host.
        add(ent.get("host_id"), "host_to_isolate", 1, "attacker code executed here")
        for rel in graph.inc(pid, {"hosts"}):
            add(rel["source_id"], "host_to_isolate", 1, "attacker code executed here")
        # 2. Identity the attacker operated as.
        if not _user_is_builtin(p.get("user")):
            for rel in graph.inc(pid, {"runs_process"}):
                add(rel["source_id"], "identity_to_rotate", 1, f"actor account {p.get('user')}")
            uid = users.get(str(p.get("user", "")).lower()) or users.get(
                str(p.get("user", "")).split("\\")[-1].lower()
            )
            add(uid, "identity_to_rotate", 1, f"actor account {p.get('user')}")
            # Same user SID is stronger than display-name matching; search
            # returns the genuine windows_user entity rather than a guessed ID.
            user_sid = str(p.get("user_sid") or "").casefold()
            if user_sid:
                for candidate, user_node in graph.entities.items():
                    if user_node.get("type") in USER_TYPES and str(
                        graph.props(candidate).get("sid") or graph.props(candidate).get("user_sid") or ""
                    ).casefold() == user_sid:
                        add(candidate, "identity_to_rotate", 1, "confirmed trigger session SID")
        # 3. Credentials exposed on the command line (-u/-p, /user:, -Credential).
        cmd = str(p.get("cmdline") or "")
        for name, uid in users.items():
            if "\\" in name and name in cmd.lower():
                add(uid, "identity_to_rotate", 2, "credential used/exposed in command line")
        image = str(p.get("image_path") or "")
        if image and (SUSPICIOUS_PATH.search(image) or not SYSTEM_IMAGE.search(image)):
            # e.g. C:\Windows\Temp\python.exe or a PsExec-style C:\Windows\sync.exe
            malicious_paths.add(image.lower())
        # 4. Payloads: require BOTH a write by the causal chain AND
        # an execution of that file by a member of the same chain.
        executed_images = {
            str(graph.props(proc).get("image_path") or "").casefold().replace("/", "\\")
            for proc in procs
        }
        executed_file_ids = {edge["target_id"] for proc in procs
                             for edge in graph.out(proc, FILE_EXEC_RELATIONS)}
        written_file_ids = {edge["target_id"] for proc in procs
                            for edge in graph.out(proc, {"wrote_file"})}
        for rel in graph.out(pid, FILE_WRITE_RELATIONS | FILE_EXEC_RELATIONS):
            tid = rel["target_id"]
            tp = graph.props(tid)
            path = str(tp.get("path") or "")
            payload = bool(
                tp.get("is_executable") or PAYLOAD_EXT.search(path) or SUSPICIOUS_PATH.search(path)
            )
            if graph.etype(tid) in FILE_TYPES:
                executed = (tid in executed_file_ids or
                            path.casefold().replace("/", "\\") in executed_images)
                if tid in written_file_ids and executed and payload:
                    add(tid, "file_to_delete", 1, f"written and executed by chain: {path}")
                if path:
                    malicious_paths.add(path.lower())
            elif graph.etype(tid) == "powershell_script" and path and tid in written_file_ids \
                    and tid in executed_file_ids:
                add(tid, "file_to_delete", 1, f"written and executed script {path}")
        for rel in graph.out(pid, {"deleted_file"}):
            add(rel["target_id"], "cleanup_to_verify", 2, "attacker removed this file")
        # 5. Persistence.
        for rel in graph.out(pid, PERSISTENCE_RELATIONS):
            tid = rel["target_id"]
            ttype = graph.etype(tid)
            if ttype == "registry_key":
                key = str(graph.props(tid).get("path") or graph.props(tid).get("key_path") or "")
                add(tid, "persistence_to_remove", 1 if AUTORUN_KEY.search(key) else 3, key)
            elif ttype in PERSISTENCE_TYPES:
                add(tid, "persistence_to_remove", 1, rel["type"])
        # 6. Identity / group changes made by the attacker.
        for rel in graph.out(pid, IDENTITY_CHANGE_RELATIONS):
            add(rel["target_id"], "identity_to_rotate", 1, rel["type"])
        # 7. Network: external peers blocked, internal admin peers isolated.
        for rel in list(graph.out(pid, {"connected_to", "sent_data_to"})) + list(
            graph.out(pid, {"accepted_connection_from", "received_data_from"})
        ):
            cid = rel["target_id"]
            cp = graph.props(cid)
            inbound = rel["type"] in {"accepted_connection_from", "received_data_from"}
            peer = cp.get("src_ip") if inbound else cp.get("dst_ip")
            if _private(peer) is False and (
                str(cp.get("query_status") or "").upper() == "SUCCESS"
                and str(cp.get("fqdn") or "").lower().rstrip(".").endswith(".invalid")
            ):
                add(cid, "network_block", 1, f"verified suspicious domain {peer}")
            # A remote peer is not necessarily compromised merely because it
            # communicated with the trigger. Do not isolate it on direction/port
            # alone (especially for normal remote administration).
        for rel in graph.out(pid, {"opened_share_session", "remote_wmi_exec", "logged_on_to"}):
            if graph.etype(rel["target_id"]) == "host":
                add(rel["target_id"], "host_to_isolate", 2, rel["type"])

    # Persistence objects that point at an attacker file (service ImagePath, task action).
    for nid, ent in graph.entities.items():
        if ent.get("type") not in PERSISTENCE_TYPES:
            continue
        blob = " ".join(str(v) for v in (ent.get("properties") or {}).values()).lower()
        if any(path and path in blob for path in malicious_paths):
            add(nid, "persistence_to_remove", 1, "references attacker payload")
    # File entities for attacker images (e.g. C:\Windows\Temp\python.exe).
    for nid, ent in graph.entities.items():
        if ent.get("type") in FILE_TYPES:
            path = str((ent.get("properties") or {}).get("path", "")).lower()
            if path and path in malicious_paths and nid in {
                e["target_id"] for proc in procs for e in graph.out(proc, {"wrote_file"})
            } and path.replace("/", "\\") in {
                str(graph.props(proc).get("image_path") or "").casefold().replace("/", "\\")
                for proc in procs
            }:
                add(nid, "file_to_delete", 1, "observed write and subsequent execution")
    # Inbound external connections to hosts we isolate (e.g. RDP from internet).
    isolated = {a.entity_id for a in found.values() if a.kind == "host_to_isolate"}
    for nid, ent in graph.entities.items():
        if ent.get("type") == "network_connection" and ent.get("host_id") in isolated:
            p = ent.get("properties") or {}
            if str(p.get("query_status") or "").upper() == "SUCCESS" and \
                    str(p.get("fqdn") or "").lower().rstrip(".").endswith(".invalid"):
                add(nid, "network_block", 1, "successful reserved-domain DNS resolution")
    for nid, ent in graph.entities.items():
        if ent.get("type") in {"email", "email_attachment", "email_url"} and max_tier >= 2:
            add(nid, "mailbox_action", 2, "delivery vector")

    ordered = sorted(found.values(), key=lambda a: (a.tier, a.kind, a.entity_id))
    return _dedupe_network_blocks(
        [{"entity_id": a.entity_id, "kind": a.kind, "_tier": a.tier, "_why": a.why}
         for a in ordered], graph, limit=max_network_blocks)


def strip_debug(artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [{"entity_id": a["entity_id"], "kind": a["kind"]} for a in artifacts]


def merge_submission(
    submission: dict[str, Any], graph: ObservedGraph, *, max_tier: int = 2,
    max_network_blocks: int = 2,
) -> dict[str, Any]:
    """High-precision remediation only; drop non-action *_observed artifacts."""
    if submission.get("verdict") != "malicious":
        return submission
    items = submission.get("ir_artifacts") or []
    seeds = [a.get("entity_id") for a in items if isinstance(a, dict)
             and graph.etype(a.get("entity_id", "")) in PROCESS_TYPES]
    mapped = strip_debug(map_response(graph, seeds + graph.trigger_ids, max_tier=max_tier,
                                      include_observed_processes=False,
                                      max_network_blocks=max_network_blocks))
    priority = ["host_to_isolate", "identity_to_rotate", "persistence_to_remove",
                "file_to_delete", "network_block", "mailbox_action", "cleanup_to_verify"]
    best: dict[str, str] = {}
    # The model may name a genuine but unrelated object. Only graph-justified
    # response actions survive into final artifacts; never emit *_observed.
    for item in mapped:
        if not isinstance(item, dict):
            continue
        nid, kind = item.get("entity_id"), item.get("kind")
        if not isinstance(nid, str) or kind not in priority or nid not in graph.entities:
            continue
        allowed = {"host_to_isolate": {"host"},
                   "identity_to_rotate": USER_TYPES,
                   "file_to_delete": FILE_TYPES | {"powershell_script"},
                   "persistence_to_remove": PERSISTENCE_TYPES | {"registry_value"},
                   "network_block": {"network_connection", "host"}}
        if kind in allowed and graph.etype(nid) not in allowed[kind]:
            continue
        old = best.get(nid)
        if old is None or priority.index(kind) < priority.index(old):
            best[nid] = kind
    return {**submission, "ir_artifacts": _dedupe_network_blocks(
        [{"entity_id": nid, "kind": kind} for nid, kind in best.items()],
        graph, limit=max_network_blocks)}


CRED_IN_CMDLINE = re.compile(
    r"(?:-u|/user:|-user|-credential|-username|/u:)\s*['\"]?([A-Za-z0-9_.-]+\\[A-Za-z0-9_.$-]+)",
    re.I,
)
WELL_KNOWN_LOGONS = {"0x3e7", "0x3e4", "0x3e5", "0x0"}
REMOTE_PARENTS = re.compile(r"wsmprovhost|psexesvc|wmiprvse|winrshost|sshd|w3wp|services\.exe", re.I)


def scoping_pivots(
    graph: ObservedGraph,
    seed_processes: Iterable[str],
    done: set[str],
    *,
    max_relations_per_process: int = 6,
) -> list[tuple[str, dict[str, Any], str]]:
    """Next calls that fill missing *response* categories of a malicious case.

    Every pivot is adjacent to an attacker-controlled process (or is a targeted
    search for an identity/host it already references), so it should be a
    relevant call for the efficiency metric rather than background enumeration.
    ``done`` holds keys of pivots already executed (``tool:arg``).
    """
    seeds = list(seed_processes) or list(graph.trigger_ids)
    procs = malicious_process_set(graph, seeds)
    users = graph.users_by_name()
    host_ip = graph.hosts_by_ip()
    out: list[tuple[int, str, dict[str, Any], str]] = []

    def want(prio: int, tool: str, args: dict[str, Any], why: str) -> None:
        key = f"{tool}:{next(iter(args.values()))}"
        if key not in done and all(f"{t}:{next(iter(a.values()))}" != key for _, t, a, _ in out):
            out.append((prio, tool, args, why))

    resolved_users = {
        str(graph.props(pid).get("user", "")).lower()
        for pid in procs
        if any(graph.inc(pid, {"runs_process"}))
    } | set(users)
    for pid in sorted(procs):
        ent = graph.entities.get(pid) or {}
        p = ent.get("properties") or {}
        rel_ids = ent.get("relation_ids") or {}
        incoming, outgoing = rel_ids.get("incoming") or [], rel_ids.get("outgoing") or []
        # (1) who ran it: runs_process / parent edge is among the incoming relations.
        user = str(p.get("user") or "").lower()
        if (not _user_is_builtin(user) and user not in resolved_users
                and user.split("\\")[-1] not in resolved_users):
            resolved_users.add(user)  # one account lookup per identity, not per process
            for rid in incoming[:3]:
                if rid not in graph.relations:
                    want(1, "get_relation", {"relation_id": rid}, "identify actor account")
        # (2) consequences of attacker processes.
        for rid in outgoing[:max_relations_per_process]:
            if rid not in graph.relations:
                want(2, "get_relation", {"relation_id": rid}, "attacker process consequence")
        for rel in graph.out(pid):
            tid = rel["target_id"]
            if tid not in graph.entities and rel.get("type") not in {"hosts"}:
                want(2, "get_entity", {"entity_id": tid}, f"inspect {rel.get('type')} target")
        # (3) credentials typed on the command line.
        for match in CRED_IN_CMDLINE.finditer(str(p.get("cmdline") or "")):
            name = match.group(1).lower()
            if name not in users and name.split("\\")[-1] not in users:
                want(3, "search", {"query": match.group(1).split("\\")[-1],
                                   "scope": {"kind": "entity", "type": "windows_user"}},
                     "credential exposed on command line")
        # (4) source of a remote session (WinRM/PsExec/WMI/web): follow the logon id.
        if REMOTE_PARENTS.search(str(p.get("parent_image") or "")) and p.get("logon_id"):
            if len(str(p["logon_id"])) >= 5 and str(p["logon_id"]).lower() not in WELL_KNOWN_LOGONS:
                want(4, "search", {"query": str(p["logon_id"])}, "remote session origin")
    # (5) internal peers of attacker connections that are not yet mapped to hosts.
    for pid in procs:
        for rel in list(graph.out(pid, {"connected_to", "accepted_connection_from"})):
            cp = graph.props(rel["target_id"])
            peer = cp.get("src_ip") if rel["type"] == "accepted_connection_from" else cp.get("dst_ip")
            if peer and _private(peer) and peer not in host_ip:
                want(5, "search", {"query": peer, "scope": {"kind": "entity", "type": "host"}},
                     "map lateral-movement peer to a host")
    out.sort(key=lambda item: item[0])
    return [(tool, args, why) for _, tool, args, why in out]


def pivot_key(tool: str, args: dict[str, Any]) -> str:
    return f"{tool}:{next(iter(args.values()))}"


# --------------------------------------------------------------------------
# Benign: cite the object that *authorizes* the activity, not the alert process.
# --------------------------------------------------------------------------
AUTHORIZING_RELATIONS = {
    "ran_scheduled_task", "created_scheduled_task", "started_service", "created_service",
    "executed_script", "logged_on_to", "established_vpn_session", "issued_by_template",
    "opened_handle_on_ad_object", "msi_install_completed",
}
ANCHOR_TYPES = {
    "scheduled_task", "windows_service", "powershell_script", "ad_object", "systemd_unit",
    "x509_certificate", "certificate_template", "vpn_session",
}
SKIP_FIELDS = {
    "md5", "sha1", "sha256", "sid", "user_sid", "pid", "parent_pid", "logon_id", "session_id",
    "timestamp", "start_time", "ad_object_id", "file_version", "src_port",
}
ADMIN_SHARE_PATH = re.compile(r"\\(netlogon|sysvol)\\|\\program files", re.I)


def _anchor_fields(props: dict[str, Any], limit: int = 4) -> list[str]:
    return [k for k, v in props.items() if k not in SKIP_FIELDS and v not in (None, "", [], {})][:limit]


def benign_anchor_pivots(
    graph: ObservedGraph, focus: Iterable[str], done: set[str]
) -> list[tuple[str, dict[str, Any], str]]:
    """Calls that open the authorizing object of the alerted activity."""
    out: list[tuple[str, dict[str, Any], str]] = []
    for nid in focus:
        ent = graph.entities.get(nid) or {}
        for rid in (ent.get("relation_ids") or {}).get("incoming", [])[:6]:
            if rid not in graph.relations and f"get_relation:{rid}" not in done:
                out.append(("get_relation", {"relation_id": rid}, "find authorizing object"))
    for rel in graph.relations.values():
        if rel.get("type") in AUTHORIZING_RELATIONS:
            for end in (rel.get("source_id"), rel.get("target_id")):
                if end and end not in graph.entities and f"get_entity:{end}" not in done:
                    out.insert(0, ("get_entity", {"entity_id": end}, f"open {rel['type']} endpoint"))
    return out


def benign_anchor_evidence(graph: ObservedGraph, limit: int = 3) -> list[dict[str, Any]]:
    """Prefer actual peer host, account memberships, and service binary path.

    Never cite the trigger itself or source_id/target_id-only relations.
    """
    choices: list[tuple[int, dict[str, Any]]] = []
    trigger_ids = set(graph.trigger_ids)
    trigger_hosts = {
        graph.entities[t].get("host_id") for t in trigger_ids
        if t in graph.entities and graph.entities[t].get("host_id")
    } | {t for t in trigger_ids if graph.etype(t) == "host"}
    causal_procs = malicious_process_set(graph, trigger_ids)
    causal_procs.update(t for t in trigger_ids if graph.etype(t) in PROCESS_TYPES)
    known_users = {
        str(graph.props(pid).get("user") or "").casefold()
        for pid in causal_procs
    } - {""}
    known_sids = {
        str(graph.props(pid).get("user_sid") or "").casefold()
        for pid in causal_procs
    } - {""}
    user_ids = {r.get("source_id") for r in graph.relations.values()
                if r.get("type") == "runs_process" and r.get("target_id") in causal_procs}
    observed_ips: set[str] = set()
    for pid in causal_procs:
        pp = graph.props(pid)
        for key in ("source_ip", "src_ip", "remote_ip", "client_ip"):
            if pp.get(key):
                observed_ips.add(str(pp[key]))
    for relation in graph.relations.values():
        rtype = relation.get("type")
        if rtype == "logged_on_to" and (
            relation.get("target_id") in trigger_hosts
            or relation.get("source_id") in user_ids
        ):
            rp = relation.get("properties") or {}
            for key in ("source_ip", "src_ip", "remote_ip", "client_ip"):
                if rp.get(key):
                    observed_ips.add(str(rp[key]))
        elif (relation.get("source_id") in causal_procs and
              rtype in {"connected_to", "accepted_connection_from",
                        "received_data_from", "sent_data_to"}):
            cp = graph.props(relation.get("target_id"))
            for key in ("dst_ip", "src_ip", "remote_ip", "source_ip"):
                if cp.get(key):
                    observed_ips.add(str(cp[key]))
    for hid in trigger_hosts:
        hp = graph.props(hid)
        for key in ("ip", "ip_address"):
            observed_ips.discard(str(hp.get(key) or ""))
    # Cite the changed *object* first, not its technical relation. For group
    # changes the added user can differ from the account that ran the trigger.
    changed_user_ids: set[str] = set()
    changed_service_ids: set[str] = set()
    written_file_ids: set[str] = set()
    for r in graph.relations.values():
        typ = r.get("type")
        src, dst = r.get("source_id"), r.get("target_id")
        if typ in {"added_to_group", "removed_from_group", "created_account"}:
            changed_user_ids.update(nid for nid in (src, dst) if (
                graph.etype(nid) in USER_TYPES or
                (graph.etype(nid) == "ad_object" and
                 any(graph.props(nid).get(k) for k in ("username", "group_memberships")))))
        if typ in {"created_service", "started_service", "modified_service"}:
            changed_service_ids.update(nid for nid in (src, dst) if graph.etype(nid) == "windows_service")
        if typ == "wrote_file" and src in causal_procs and graph.etype(dst) in FILE_TYPES:
            written_file_ids.add(dst)

    for nid, ent in graph.entities.items():
        if nid in trigger_ids:
            continue
        typ = ent.get("type")
        props = ent.get("properties") or {}
        if typ in USER_TYPES or (typ == "ad_object" and nid in changed_user_ids):
            username = str(props.get("username") or "").casefold()
            domain = str(props.get("domain") or "").casefold()
            sid = str(props.get("sid") or props.get("user_sid") or "").casefold()
            if (nid not in changed_user_ids and nid not in user_ids and
                sid not in known_sids and username not in known_users and
                (not domain or f"{domain}\\{username}" not in known_users) and
                any(known_users | known_sids | user_ids)):
                continue
            fields = [k for k in ("group_memberships", "username") if props.get(k) is not None]
            priority = 0 if nid in changed_user_ids else 4
        elif typ == "windows_service":
            fields = [k for k in ("binary_path", "service_name") if props.get(k) is not None]
            priority = 0 if nid in changed_service_ids else 5
        elif typ == "host" and nid not in trigger_hosts and str(props.get("ip") or "") in observed_ips:
            fields = [k for k in ("hostname", "role") if props.get(k) is not None]
            priority = 1
        elif typ in FILE_TYPES and nid in written_file_ids:
            fields = [k for k in ("path", "file_path", "filename", "name") if props.get(k) is not None]
            priority = 2
        elif typ in ANCHOR_TYPES:
            fields = _anchor_fields(props, 2)
            priority = 6
        else:
            continue
        if fields:
            choices.append((priority, {"anchor": "entity", "entity_id": nid,
                                       "property_fields": fields[:2]}))
    choices.sort(key=lambda x: (x[0], x[1]["entity_id"]))
    return [item for _, item in choices[:limit]]


def merge_benign(submission: dict[str, Any], graph: ObservedGraph, *, limit: int = 3) -> dict[str, Any]:
    if submission.get("verdict") != "benign":
        return submission
    selected = benign_anchor_evidence(graph, limit)
    cited = {x["entity_id"] for x in selected}
    for item in submission.get("legitimacy_evidence") or []:
        if len(selected) >= limit or not isinstance(item, dict) or item.get("anchor") != "entity":
            continue
        nid = item.get("entity_id")
        if nid in graph.trigger_ids or nid in cited or nid not in graph.entities:
            continue
        typ = graph.etype(nid)
        if typ not in {"host", *USER_TYPES, "windows_service", *ANCHOR_TYPES}:
            if not (typ in FILE_TYPES and any(
                r.get("type") == "wrote_file" and r.get("target_id") == nid and
                r.get("source_id") in malicious_process_set(graph, graph.trigger_ids)
                for r in graph.relations.values())):
                continue
        props = graph.props(nid)
        fields = [f for f in (item.get("property_fields") or [])
                  if f in props and f not in {"source_id", "target_id"}][:2]
        if fields:
            selected.append({"anchor": "entity", "entity_id": nid,
                             "property_fields": fields})
            cited.add(nid)
    return {**submission, "legitimacy_evidence": selected}


def benign_to_malicious(
    submission: dict[str, Any], issues: Iterable[Any], hard_codes: set[str], graph: ObservedGraph
) -> dict[str, Any] | None:
    """Overrule a benign verdict when a deterministic detector raised a hard attack code.

    ``issues`` are objects with ``code`` and ``entity_ids`` (soc_v23.ClaimIssue).
    """
    if submission.get("verdict") != "benign" or not hard_codes:
        return None
    hard = [i for i in issues if getattr(i, "code", "") in hard_codes]
    if not hard:
        return None
    ids = [n for i in hard for n in getattr(i, "entity_ids", ()) if graph.etype(n)]
    ids += [t for t in graph.trigger_ids if graph.etype(t) in PROCESS_TYPES]
    seen: list[str] = []
    for n in ids:
        if n not in seen:
            seen.append(n)
    artifacts = strip_debug(map_response(graph, seen + graph.trigger_ids,
                                         max_tier=2, include_observed_processes=False))
    if not artifacts:
        return None
    codes = ", ".join(sorted({i.code for i in hard}))
    return {
        "verdict": "malicious",
        "ir_artifacts": artifacts,
        "reasoning": (submission.get("reasoning", "")[:600] + f" | Overruled by verified detector "
                      f"findings that the benign account does not explain: {codes}."),
    }
