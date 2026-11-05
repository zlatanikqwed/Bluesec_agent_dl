"""SOC knowledge engine: causal technique hypotheses backed by observed graph facts.

No labels or host/IP allow-lists and no inferred ground truth. Findings are
investigation leads, never forced attack verdicts. Works with the runtime's
entity/relation dictionary types; all referenced IDs originated in observations.
"""
from __future__ import annotations

import ntpath
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

# Not a blacklist of products: operation patterns derived from Windows/PowerShell
# semantics. They are combined with graph provenance before making a finding.
TECHNIQUES = (
    ("credential_access", "Credential material requested", 8,
     r"sekurlsa::(?:logonpasswords|ekeys|tickets)|lsadump::|\bcomsvcs\.dll\b.{0,70}\bminidump\b|\bprocdump\S*\b.{0,130}\blsass\b|\bntdsutil\b.{0,130}\bifm\b"),
    ("recovery_inhibition", "Recovery or logging protection altered", 8,
     r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwbadmin\s+delete\s+catalog\b|\bwevtutil(?:\.exe)?\s+cl\s+security\b"),
    ("network_redirection", "Network proxy or forwarding configuration", 7,
     r"\bnetsh\s+interface\s+portproxy\s+(?:add|set|delete)\b|\bnew-netnat\b|\bset-netipinterface\b"),
    ("encoded_execution", "Encoded or obfuscated execution", 3,
     r"(?:^|\s)-(?:enc|encodedcommand)\b|\bfrombase64string\s*\(|\b-invoke-expression\b"),
    ("remote_code_execution", "Download and immediate execution", 7,
     r"\biex\s*\(?\s*\(?\s*(?:new-object|iwr|invoke-webrequest)|\biex\b.{0,110}\bdownloadstring\b|\bdownloadstring\b.{0,110}\biex\b"),
    ("persistence_command", "Autorun or recurring execution configured", 5,
     r"\breg(?:\.exe)?\s+add\s+[^\n]{0,180}\\(?:currentversion\\run|winlogon)\b|\bschtasks(?:\.exe)?\s+/create\b|\bnew-scheduledtask\b"),
    ("ad_sensitive_change", "Directory permissions or privileged membership modified", 6,
     r"\badd-adgroupmember\b|\bset-acl\b|\bset-adobject\b|\bset-adaccountcontrol\b|\bdsacls\b"),
)
_EXEC_FIELDS = ("cmdline", "command_line", "command", "command_text", "script_text",
                "script_block_text", "cmdline_decoded", "script_text_decoded", "arguments",
                "value_data", "parameter_binding")
_INV_EDGES = {"hosts", "runs_process", "member_of", "belongs_to", "logged_on_to"}
_STATE_EDGES = {"wrote_file", "deleted_file", "renamed_file", "modified_file", "created_file",
                "created_service", "installed_service", "created_scheduled_task", "scheduled_task_created",
                "modified_registry_value", "created_registry_value", "wrote_registry_value",
                "changed_ad_object", "modified_ad_object", "added_member", "added_to_group"}
_REMOTE_EDGES = {"connected_to", "accepted_connection_from", "established_connection"}
_SCRIPT_EDGES = {"executed_script", "invoked_cmdlet", "win_process_create", "created_process"}
_RELEVANT_TYPES = {"windows_process", "linux_process", "powershell_script", "powershell_cmdlet_invocation",
                   "windows_file", "registry_value", "scheduled_task", "windows_service", "ad_object"}
_IGNORED_OBJECTS = {"host", "windows_user", "linux_user"}

@dataclass(frozen=True)
class SOCHypothesis:
    technique: str
    title: str
    weight: int
    entity_ids: tuple[str, ...]
    relation_ids: tuple[str, ...]
    observations: tuple[str, ...]
    test: str
    # signal = possible risk, impact = actual observed operation, context = relevant context
    level: str = "signal"

    def explain(self) -> str:
        return (f"{self.technique} [{self.level}, priority {self.weight}]: "
                f"{self.title}; facts: {'; '.join(self.observations)[:410]}; "
                f"entities={','.join(self.entity_ids[:4])}; "
                f"relations={','.join(self.relation_ids[:4])}; "
                f"NEXT CHECK: {self.test}")


class SecurityEngine:
    """Deterministic event interpreter + evidence-grounded next-action planning."""

    def __init__(self, director: Any):
        self.director = director

    def _connected(self, memory: Any) -> set[str]:
        dist = self.director.causal_distance(memory)
        return {ident for ident, d in dist.items() if d <= 4}

    @staticmethod
    def _cmd(props: dict[str, Any]) -> str:
        return "\n".join(str(props.get(k) or "")[:1400] for k in _EXEC_FIELDS)

    def hypotheses(self, memory: Any) -> list[SOCHypothesis]:
        near = self._connected(memory)
        findings: list[SOCHypothesis] = []
        nodes = memory.observed_nodes
        outgoing = defaultdict(list)
        incoming = defaultdict(list)
        for rid, (kind, src, dst) in memory.graph_edges.items():
            if src not in near and dst not in near:
                continue
            outgoing[src].append((rid, kind.lower(), dst))
            incoming[dst].append((rid, kind.lower(), src))
        for identifier, node in nodes.items():
            if identifier not in near or node.get("type") not in _RELEVANT_TYPES:
                continue
            p = node.get("properties") or {}
            if not isinstance(p, dict):
                continue
            cmd = self._cmd(p)
            for technique, title, severity, pattern in TECHNIQUES:
                if re.search(pattern, cmd, re.I | re.S):
                    corroborating = tuple(r for r, typ, _ in outgoing[identifier]
                                          if typ in (_STATE_EDGES | _REMOTE_EDGES | _SCRIPT_EDGES))
                    findings.append(SOCHypothesis(
                        technique, title, severity, (identifier,), corroborating[:4],
                        (f"observed {node.get('type')} command: {cmd[:230]}",),
                        "Verify executed operation, its affected object, originating identity, and independent legitimate scope.",
                        "impact" if corroborating and severity >= 7 else "signal"))
            if node.get("type") == "windows_process":
                image = str(p.get("image_path") or p.get("cmdline") or "").lower()
                if "wsmprovhost.exe" in image:
                    children = [(r,t,d) for r,t,d in outgoing[identifier]
                                if t in {"win_process_create", "created_process"}
                                and "powershell" in str((nodes.get(d,{}).get("properties") or {}).get("image_path") or
                                                       (nodes.get(d,{}).get("properties") or {}).get("cmdline") or "").lower()]
                    if children:
                        findings.append(SOCHypothesis(
                            "winrm_remote_shell", "Remote Windows management session started PowerShell", 5,
                            (identifier, children[0][2]), (children[0][0],),
                            ("Confirmed parent-child chain wsmprovhost -> PowerShell",),
                            "Inspect source identity and remote WinRM connection, then actual remote script or downstream changes."))
            # Command-line location is a lead, not proof of maliciousness.
            img = str(p.get("image_path") or "")
            if (node.get("type") == "windows_process" and
                    re.search(r"\\(?:temp|users\\public|appdata\\local\\temp)\\[^\\]+\.(?:exe|dll)$", img, re.I)):
                findings.append(SOCHypothesis(
                    "staged_binary", "Executable launched from a staging directory", 4,
                    (identifier,), tuple(r for r, t, _ in incoming[identifier] if t in _SCRIPT_EDGES)[:2],
                    (f"image_path={img[:180]}",),
                    "Determine file origin, signature/owner, child activity, and target changes."))
        # Link real event types with their affected objects. An isolated process
        # command and an unrelated file modification must NOT be joined.
        for rid, (kind, src, dst) in memory.graph_edges.items():
            typ = kind.lower()
            if src not in near and dst not in near or typ in _INV_EDGES:
                continue
            if typ in _STATE_EDGES:
                target = nodes.get(dst, {})
                p = target.get("properties") or {}
                detail = next((f"{k}={str(p[k])[:190]}" for k in
                               ("path", "name", "value_data", "service_name", "task_name", "object_type")
                               if p.get(k) not in (None, "")), "target properties not opened")
                weight = 7 if ("ad_" in typ or "group" in typ or "registry" in typ) else 5
                findings.append(SOCHypothesis(
                    "state_change", f"Observed {typ} effect", weight, (src, dst), (rid,),
                    (f"{src} --{typ}--> {dst}", detail),
                    "Inspect modified object and before/after state; verify purpose and identity scope.",
                    "impact" if dst in memory.fetched_ids else "signal"))
            elif typ in _REMOTE_EDGES:
                net = nodes.get(dst, {})
                p = net.get("properties") or {}
                port = str(p.get("dst_port") or "")
                if port in {"445", "5985", "5986", "3389", "5986"}:
                    findings.append(SOCHypothesis(
                        "remote_access", "Remote administrative protocol observed", 4,
                        (src, dst), (rid,),
                        (f"{src} --{typ}--> {dst}", f"src_ip={p.get('src_ip', '?')}; dst={p.get('dst_ip', '?')}:{port}"),
                        "Trace SOURCE process/identity and the command or file operations on the TARGET host."))
        # Multi-step techniques require that EACH supporting relation has been opened.
        for pid, relations in outgoing.items():
            kinds = {typ for _, typ, _ in relations}
            state = [(rid, typ, dst) for rid, typ, dst in relations if typ in _STATE_EDGES]
            comms = [(rid, typ, dst) for rid, typ, dst in relations if typ in _REMOTE_EDGES]
            if state and comms:
                findings.append(SOCHypothesis(
                    "change_and_network", "Same process modified data and communicated over network", 7,
                    (pid, *tuple(dst for _, _, dst in state[:2]), *tuple(dst for _, _, dst in comms[:1])),
                    tuple(rid for rid, _, _ in (state[:2] + comms[:1])),
                    (f"{len(state)} state-changing and {len(comms)} network edges share the same process",),
                    "Check exact content/target and transmission direction; benign synchronization and exfiltration are competing hypotheses."))
        # Chain-level correlations: these require the same VERIFIED process ids
        # (and matching paths/ports), not a bundle of suspicious terms from
        # arbitrary nearby search results.
        for pid, node in nodes.items():
            if pid not in near or node.get("type") != "windows_process":
                continue
            props = node.get("properties") or {}
            if not isinstance(props, dict):
                continue
            cmd = str(props.get("cmdline") or "")
            # A different domain identity used for SMB from a process owned by
            # another user needs provenance checking. It is NOT automatically evil.
            user_match = re.search(r"/user:([^\s]+)", cmd, re.I)
            if re.search(r"\bnet(?:1)?\s+use\b", cmd, re.I) and user_match:
                arg_user = user_match.group(1).replace("/", "\\").lower()
                proc_user = str(props.get("user") or "").lower()
                if proc_user and proc_user != arg_user:
                    related = tuple(r for r,t,_ in outgoing[pid] if t in _REMOTE_EDGES)
                    findings.append(SOCHypothesis(
                        "cross_identity_smb", "Network share connected using another identity", 6,
                        (pid,), related,
                        (f"process_owner={proc_user}", f"explicit_share_identity={arg_user}"),
                        "Verify actual credential scope, the remote share, and subsequent operations.",
                        "impact" if related else "signal"))
            # A staged process that actually performs destructive or write operations
            # is stronger than its path or the word 'delete' alone.
            path = str(props.get("image_path") or cmd.split(" ")[0]).replace("/", "\\")
            if re.search(r"\\(?:temp|public)\\[^\\]+\.exe$", path, re.I):
                changes = [(r,t,d) for r,t,d in outgoing[pid] if t in _STATE_EDGES]
                if changes:
                    findings.append(SOCHypothesis(
                        "staged_process_changed_data", "Temp/Public executable modified real objects", 7,
                        (pid,) + tuple(d for _,_,d in changes[:2]), tuple(r for r,_,_ in changes[:2]),
                        (f"binary={path[:165]}", f"confirmed_actions={[t for _,t,_ in changes[:3]]}"),
                        "Inspect source of executable, content of changed files, and legitimate job context.",
                        "impact"))
            # Executable written by a PowerShell process and subsequently executed
            # as its child; do not infer this chain from filename similarity alone.
            for r_write, typ, file_id in outgoing[pid]:
                if typ not in {"wrote_file", "created_file"}:
                    continue
                file_node = nodes.get(file_id, {})
                file_path = str((file_node.get("properties") or {}).get("path") or "")
                if not re.search(r"\.(?:exe|dll)$", file_path, re.I):
                    continue
                for r_create, edge_type, child_id in outgoing[pid]:
                    if edge_type not in {"win_process_create", "created_process"}:
                        continue
                    child = nodes.get(child_id, {})
                    child_path = str((child.get("properties") or {}).get("image_path") or
                                     (child.get("properties") or {}).get("cmdline") or "")
                    if not child_path.lower().replace("/", "\\").startswith(
                            file_path.lower().replace("/", "\\")):
                        continue
                    descendants = [(r,t,d) for r,t,d in outgoing[child_id] if t in _STATE_EDGES]
                    findings.append(SOCHypothesis(
                        "write_execute_chain", "Written executable subsequently launched by the same actor", 8,
                        (pid, file_id, child_id) + tuple(d for _,_,d in descendants[:1]),
                        (r_write, r_create) + tuple(r for r,_,_ in descendants[:2]),
                        (f"file={file_path[:180]}",
                         f"child_produced_changes={len(descendants)}"),
                        "Check what the generated executable did, its source, and whether that exact task is authorized.",
                        "impact"))
            # A service binary executing a staged interpreter under a different
            # principal is a cross-identity execution lead, NOT automatic compromise.
            if "-service" in cmd.lower() or "service" in ntpath.basename(path).lower():
                for rid, typ, child_id in outgoing[pid]:
                    if typ not in {"win_process_create", "created_process"}:
                        continue
                    child = nodes.get(child_id, {})
                    cp = child.get("properties") or {}
                    cimage = str(cp.get("image_path") or "")
                    if (re.search(r"\\temp\\(?:python|powershell|cmd|wscript)(?:\.exe)?$", cimage, re.I)
                            and cp.get("user") != props.get("user")):
                        findings.append(SOCHypothesis(
                            "service_cross_identity_execution",
                            "Service spawned a staged interpreter under another principal", 7,
                            (pid, child_id), (rid,),
                            (f"service={path[:160]}", f"child_image={cimage[:170]}",
                             f"parent_user={props.get('user')}; child_user={cp.get('user')}"),
                            "Inspect service configuration, child script/commands, and security context switch.", "impact"))
            # Nondefault WinRM port, combined with observed forwarding/service
            # connections, may indicate a tunnel or approved management gateway.
            m = re.search(r"\bNew-PSSession\b[^\n]{0,280}\s-Port\s+(\d{2,5})\b", cmd, re.I)
            if m and m.group(1) not in {"5985", "5986"}:
                port = m.group(1)
                matching = []
                for rid,(typ,src,dst) in memory.graph_edges.items():
                    if typ.lower() not in _REMOTE_EDGES or src not in near and dst not in near:
                        continue
                    for netid in (src,dst):
                        np = (nodes.get(netid,{}) or {}).get("properties") or {}
                        if str(np.get("dst_port") or "") == port:
                            matching.append((rid,netid))
                if matching:
                    findings.append(SOCHypothesis(
                        "nonstandard_remote_session", "Nonstandard remote session port with confirmed network flow", 7,
                        (pid, matching[0][1]), tuple(r for r,_ in matching[:2]),
                        (f"remote_command={cmd[:205]}", f"network_port={port}"),
                        "Trace source host, forwarded destination and the commands run after authentication.",
                        "impact"))
        # Repeated server SMB sessions are a source-host investigation priority.
        smb = defaultdict(list)
        for nid,node in nodes.items():
            if node.get("type") != "network_connection" or nid not in near:
                continue
            props = node.get("properties") or {}
            if str(props.get("dst_port") or "") == "445":
                key = (str(props.get("src_ip") or ""), str(props.get("dst_ip") or ""))
                if all(key):
                    smb[key].append(nid)
        for (src,dst), connections in smb.items():
            if len(connections) >= 3:
                findings.append(SOCHypothesis(
                    "smb_burst", "Repeated inbound SMB sessions from one source", 4,
                    tuple(connections[:3]), (),
                    (f"source={src}; destination={dst}; distinct_connection_records={len(connections)}",),
                    "Investigate SOURCE endpoint and authentication/file operations; repeated SMB alone is not an attack."))
        # Deduplicate identical findings and prioritize observation -> endpoint.
        unique: dict[tuple[str, tuple[str, ...], tuple[str, ...]], SOCHypothesis] = {}
        for item in findings:
            unique.setdefault((item.technique, item.entity_ids, item.relation_ids), item)
        return sorted(unique.values(), key=lambda f: (-f.weight, f.technique, f.entity_ids))[:22]

    def next_lead(self, memory: Any, tools: set[str]) -> tuple[str, dict[str, str], str] | None:
        """Get a concrete causal object before a blind relation enumeration.

        Emits only tool IDs that appear in the user's alert or tool results.
        """
        ids = memory.known_ids
        for finding in self.hypotheses(memory):
            # First inspect an actual affected object of a state change / network.
            for ident in reversed(finding.entity_ids):
                if (ident in ids and ident not in memory.fetched_ids and
                    ident not in memory.rejected_ids and ident not in memory.relation_ids and
                    memory.entity_types.get(ident) not in _IGNORED_OBJECTS):
                    if ident in memory.ad_object_ids and "get_ad_object_info" in tools:
                        return "get_ad_object_info", {"ad_object_id": ident, "reasoning": finding.test}, finding.technique
                    if "get_entity" in tools:
                        return "get_entity", {"entity_id": ident, "reasoning": finding.test}, finding.technique
            # Open a confirmed event relation only if not yet fetched.
            for rid in finding.relation_ids:
                if rid in ids and rid not in memory.fetched_ids and "get_relation" in tools:
                    return "get_relation", {"relation_id": rid, "reasoning": finding.test}, finding.technique
        return None

    def grounded_search(self, memory: Any, tools: set[str]) -> tuple[str, dict[str, str], str] | None:
        """One bounded pivot by a real observed IP/path when relation graph is exhausted."""
        if "search" not in tools:
            return None
        queries = []
        for f in self.hypotheses(memory):
            if f.technique in {"smb_burst", "remote_access", "nonstandard_remote_session"}:
                for ident in f.entity_ids:
                    p = (memory.observed_nodes.get(ident, {}) or {}).get("properties") or {}
                    ip = p.get("src_ip")
                    if ip and len(str(ip)) >= 7:
                        queries.append((str(ip), "Trace the originating host or process of observed remote traffic."))
            if f.technique in {"write_execute_chain", "state_change", "staged_process_changed_data"}:
                for ident in f.entity_ids:
                    p = (memory.observed_nodes.get(ident,{}) or {}).get("properties") or {}
                    path = str(p.get("path") or "")
                    name = ntpath.basename(path.replace("/", "\\"))
                    if len(name) >= 5 and not name.lower() in {"powershell.exe", "svchost.exe"}:
                        queries.append((name, "Trace content and follow-up effects of the observed changed file."))
        searched = {call.lower() for call in memory.calls_made if call.startswith("search(")}
        for query, why in queries:
            if not any(query.lower() in call for call in searched):
                if sum(call.startswith("search(") for call in memory.calls_made) >= 3:
                    break
                return "search", {"query": query, "reasoning": why}, "grounded_soc_search"
        return None

    def benign_correlations(self, memory: Any) -> list[str]:
        """Grounded support for H_normal, not a blanket safe-list or verdict.

        We only recognize a positive *sequence* involving the same object. An
        absence of other actions, signature or generic admin role is not enough.
        """
        near = self._connected(memory)
        by_target: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for rid,(rel, src, dst) in memory.graph_edges.items():
            if src in near or dst in near:
                by_target[dst][rel.lower()].append(rid)
        observations=[]
        for obj, rels in by_target.items():
            stopped = rels.get("stopped_service", []) + rels.get("service_stopped", [])
            started = rels.get("started_service", []) + rels.get("service_started", [])
            if stopped and started:
                observations.append(
                    f"Possible maintenance: same service object {obj} has observed stop "
                    f"{stopped[0]} and start {started[0]}; verify operator authority and timing")
        return observations[:4]

    def dossier(self, memory: Any, *, limit: int = 10) -> str:
        findings = self.hypotheses(memory)[:limit]
        if not findings:
            return "SOC CORRELATION: No verified technique findings yet. UNKNOWN is not benign."
        normal = self.benign_correlations(memory)
        extra = ("\nH_NORMAL corroboration (not automatically authorized):\n" +
                 "\n".join("- " + row for row in normal)) if normal else ""
        return ("SOC CORRELATION — hypotheses, NOT automatic attack verdicts:\n" +
                "\n".join("- " + f.explain() for f in findings) + extra)

    def review_questions(self, memory: Any, submission: dict[str, Any]) -> list[str]:
        if submission.get("verdict") != "benign":
            return []
        lines: list[str] = []
        cited = {item.get("entity_id") or item.get("relation_id")
                 for item in submission.get("legitimacy_evidence") or []
                 if isinstance(item, dict)}
        reason = str(submission.get("reasoning") or "").lower()
        # A citation to the trigger executable is not an explanation of an effect.
        for finding in self.hypotheses(memory):
            if finding.weight < 5:
                continue
            if finding.level != "impact" and finding.weight < 7:
                continue
            if not (set(finding.relation_ids) & cited or
                    set(finding.entity_ids[1:]) & cited):
                lines.append("UNCITED " + finding.explain())
            elif finding.technique in {"credential_access", "network_redirection",
                                         "recovery_inhibition", "change_and_network", "ad_sensitive_change",
                                         "write_execute_chain", "nonstandard_remote_session",
                                         "service_cross_identity_execution", "staged_process_changed_data",
                                         "cross_identity_smb"}:
                # Even correctly citing the action does NOT establish normal intent.
                lines.append("EXPLAIN AUTHORIZED SCOPE OF " + finding.explain())
            if len(lines) >= 3:
                break
        return lines
