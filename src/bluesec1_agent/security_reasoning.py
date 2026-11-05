"""Evidence-grounded SOC semantics shared by investigator and independent reviewers.

This is not a signature-based verdict engine. It extracts *different sorts of facts*
from disparate telemetry and states the limitations of each inference. In
particular, search hits may corroborate a graph object by content hash even
when their IDs have not been joined by the remote investigation service.
"""

from __future__ import annotations

import ipaddress
import ntpath
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SecurityFinding:
    priority: int
    kind: str
    observation: str
    limitation: str
    references: tuple[str, ...]

    def render(self) -> str:
        refs = ",".join(str(x) for x in self.references[:2]) if self.priority >= 90 else ",".join(str(x)[:8] for x in self.references[:3])
        return (f"[{self.kind}; observed/correlated; refs={refs}] {self.observation} "
                f"LIMIT: {self.limitation}")


def _props(node: dict[str, Any]) -> dict[str, Any]:
    values = node.get("properties")
    return values if isinstance(values, dict) else node


def _normalize_path(path: Any) -> str:
    return ntpath.normcase(ntpath.normpath(str(path).strip('"\''))) if path else ""


def _service_image_path(raw: Any) -> str:
    """Extract a literal .exe/.com image path, excluding service arguments.

    Do not resolve environment variables or infer paths not present in telemetry.
    """
    text = str(raw or "").strip()
    match = re.match(r'^(?:"([^"\r\n]+?\.(?:exe|com))"|(.+?\.(?:exe|com)))(?=\s|$)',
                     text, re.I)
    return (match.group(1) or match.group(2)) if match else ""


def _digest(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s if re.fullmatch(r"[0-9a-f]{64}", s) else ""


def _safe(value: Any, length: int = 120) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")[:length]


def _ip_in(text: str) -> set[str]:
    result = set()
    for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            result.add(str(ipaddress.ip_address(token)))
        except ValueError:
            pass
    return result


# Command capabilities are not verdicts. Each capability has a legitimate and
# an abusive application; the graph must decide which actually occurred.
COMMAND_CAPABILITIES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("network-redirect", re.compile(r"\b(?:netsh\s+interface\s+portproxy|socat\s+|ssh\s+-[LRD]\b|New-NetNat\b|Set-NetIPInterface\b)", re.I),
     "the effective listener/destination, requester, and observed traffic"),
    ("network-policy-change", re.compile(r"\b(?:netsh\s+advfirewall|(?:New|Set|Remove)-NetFirewallRule\b|ufw\s+|iptables\s+)", re.I),
     "the effective rule, exposed service and initiating identity"),
    ("scheduled-execution", re.compile(r"\b(?:schtasks(?:\.exe)?\s+/create\b|Register-ScheduledTask\b|New-ScheduledTask\b|crontab\s+)", re.I),
     "the scheduled payload, trigger, run-as identity and follow-on effect"),
    ("service-installation", re.compile(r"\b(?:sc(?:\.exe)?\s+create\b|New-Service\b|systemctl\s+enable\b)", re.I),
     "service executable, its signer/provenance and observed service startup"),
    ("directory-privilege-change", re.compile(r"\b(?:Add-ADGroupMember|Set-ADAccountControl|Add-LocalGroupMember|net\s+(?:localgroup|group)\b|dsmod\s+group\b)", re.I),
     "the changed principal/group, actual membership result and operator context"),
    ("directory-object-operation", re.compile(r"\b(?:\[ADSI\]|\.Put\s*\(|(?:Set|Add|Remove|New)-AD(?:User|Object|Group|Computer)|DirectoryEntry\b)", re.I),
     "the distinguished name/target and whether directory state was actually changed; account role is not authorization"),
    ("credential-specified", re.compile(r"\b(?:net\s+use\b[^\r\n]{0,400}/user:|(?:-Credential|/user:|runas\s+/user:))", re.I),
     "the target identity, credential source and the subsequent access outcome"),
    ("sensitive-process-memory", re.compile(r"\b(?:MiniDumpWriteDump|sekurlsa::|procdump\b|comsvcs\.dll\b|Invoke-Mimikatz\b)", re.I),
     "whether memory/credentials were actually read or a dump created, and who initiated it"),
    ("recovery-impact", re.compile(r"\b(?:vssadmin(?:\.exe)?\s+delete\b|wbadmin(?:\.exe)?\s+delete\b|bcdedit\s+/set\b|rm\s+-rf\b)", re.I),
     "the actual recovery/security state changed and any independent maintenance context"),
    ("web-request", re.compile(r"\b(?:Invoke-WebRequest|Invoke-RestMethod|curl(?:\.exe)?\s+|wget\s+|bitsadmin\s+/transfer\b|Start-BitsTransfer\b)", re.I),
     "the HTTP method and payload, endpoint, returned data and any follow-on execution"),
    ("dynamic-code-loading", re.compile(r"\b(?:DownloadString\s*\(|IEX\s*\(|Invoke-Expression\b|Assembly\]::Load\s*\(|Invoke-ReflectivePEInjection\b)", re.I),
     "whether the fetched or in-memory content was actually executed and its effects"),
    ("data-movement", re.compile(r"\b(?:robocopy\b|xcopy\b|Compress-Archive\b|7z(?:\.exe)?\s+a\b|tar\s+-c|rclone\s+copy\b)", re.I),
     "data source/sensitivity, actual destination and the actor's task"),
)


def _event_props(node: dict[str, Any]) -> dict[str, Any]:
    """Flatten scalar edge fields without interpreting missing fields as failure."""
    out: dict[str, Any] = {}
    for k, v in node.items():
        if isinstance(v, dict):
            for ik, iv in v.items():
                if isinstance(iv, (str, int, float, bool)):
                    out[ik.lower()] = iv
        elif isinstance(v, (str, int, float, bool)):
            out[k.lower()] = v
    return out


def _auth_outcome(fields: dict[str, Any]) -> str:
    for name in ("auth_failed", "login_failed"):
        v = fields.get(name)
        if v is True or str(v).lower() == "true":
            return "failed"
        if v is False or str(v).lower() == "false":
            return "success"
    for name in ("auth_success", "login_success", "success"):
        v = fields.get(name)
        if v is True or str(v).lower() == "true":
            return "success"
        if v is False or str(v).lower() == "false":
            return "failed"
    raw = str(fields.get("status", fields.get("result", ""))).lower()
    if raw in {"success", "successful", "ok", "0x0", "0"}:
        return "success"
    if raw in {"failed", "failure", "denied", "error", "0xc000006d", "0xc000006a", "0xc0000064"}:
        return "failed"
    return "unknown"


def collect_security_findings(memory: Any) -> list[SecurityFinding]:
    nodes: dict[str, dict[str, Any]] = memory.observed_nodes
    edges: dict[str, tuple[str, str, str]] = memory.graph_edges
    findings: list[SecurityFinding] = []
    add = findings.append
    # 1. Join separate telemetry records only by *exact* content hash, path,
    # host and role. Search results are not automatically assumed connected.
    files: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    processes: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for nid, node in nodes.items():
        typ = str(node.get("type", "")).lower()
        if nid in memory.relation_ids:
            continue
        digest = _digest(_props(node).get("sha256"))
        if digest:
            if typ.endswith("file") or typ in {"file", "windows_file", "linux_file"}:
                files[digest].append((nid, node))
            elif "process" in typ:
                processes[digest].append((nid, node))

    confirmed_writes: set[str] = {
        dst for kind, _, dst in edges.values()
        if re.search(r"writ|wrot|creat|download", kind, re.I)
    }
    # A process that is independently observed at the same binary path and hash
    # is a stronger, testable counterfact than a speculation about execution.
    seen_hashes: set[str] = set()
    for digest in files.keys() & processes.keys():
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        for fid, fnode in files[digest][:2]:
            fp = _props(fnode)
            for pid, pnode in processes[digest][:2]:
                pp = _props(pnode)
                fhost, phost = fnode.get("host_id"), pnode.get("host_id")
                if fhost and phost and fhost != phost:
                    continue
                file_path = _normalize_path(fp.get("path"))
                proc_path = _normalize_path(pp.get("image_path"))
                if file_path and proc_path and file_path != proc_path:
                    continue
                writers = [(rid, actor) for rid, (kind, actor, target) in edges.items()
                           if target == fid and re.search(r"writ|wrot|creat|download", kind, re.I)]
                certainty = "written in observed graph" if fid in confirmed_writes else "observed file"
                write_context = (f"; writer={writers[0][1]}; write-event={writers[0][0]}"
                                 if writers else "")
                add(SecurityFinding(
                    105 if fid in confirmed_writes else 85,
                    "file-process-provenance",
                    f"{certainty} ({fid[:8]}) matches a separate observed PROCESS ({pid[:8]}) "
                    f"by exact SHA-256; path={_safe(fp.get('path') or pp.get('image_path'), 95)}; "
                    f"process user={_safe(pp.get('user'), 50)}{write_context}",
                    "A same-host, same-path, same-SHA256 process record IS observed, so 'no process observed' "
                    "would contradict evidence. hash equality alone does NOT establish that the writer launched "
                    "the process, that it ran AFTER the write, or that it is malware.",
                    (fid, pid, *(writers[0][:1] if writers else ())),
                ))
                break

    # 1b. Windows service execution chains are not legitimized by services.exe.
    # Corroborate the ACTUAL registered image, spawned process and follow-on child.
    # This uses graph edges and observed registry value fields; a service label
    # alone is never proof of authorized deployment or remote-execution misuse.
    service_names: dict[str, tuple[str, str]] = {}
    for sid, node in nodes.items():
        if sid in memory.relation_ids or "service" not in str(node.get("type", "")).lower():
            continue
        name = str(_props(node).get("service_name") or _props(node).get("name") or "")
        if name:
            service_names[name.casefold()] = (sid, name)
    for rid, (kind, actor, registry) in edges.items():
        if not re.search(r"(?:set|wrot|writ|modif).*registr", kind, re.I):
            continue
        reg_node = nodes.get(registry, {})
        regp = _props(reg_node)
        regpath = str(regp.get("path") or regp.get("key_path") or "")
        regimage_raw = regp.get("value_data") or regp.get("data")
        regimage = _service_image_path(regimage_raw)
        match = re.search(r"\\services\\([^\\]+)(?:\\|$)", regpath, re.I)
        if not match or not regimage:
            continue
        service = service_names.get(match.group(1).casefold())
        if not service:
            continue
        normalized_image = _normalize_path(regimage)
        candidates = [(pid, node) for pid, node in nodes.items()
                      if pid not in memory.relation_ids
                      and "process" in str(node.get("type", "")).lower()
                      and _normalize_path(_props(node).get("image_path")) == normalized_image]
        for procid, procnode in candidates[:1]:
            if (reg_node.get("host_id") and procnode.get("host_id")
                    and reg_node["host_id"] != procnode["host_id"]):
                continue
            parent_edges = [(eid, src) for eid, (ek, src, dst) in edges.items()
                            if dst == procid and "process_create" in ek.lower()]
            child_edges = [(eid, dst) for eid, (ek, src, dst) in edges.items()
                           if src == procid and "process_create" in ek.lower()]
            if not parent_edges:
                # A registry pointing to a binary is not itself execution.
                continue
            child_description = "; ".join(
                f"spawned={child_id}({ _safe(_props(nodes.get(child_id, {})).get('image_path'), 90) })"
                for _, child_id in child_edges[:2])
            add(SecurityFinding(
                110, "service-binary-lineage",
                f"service={service[1]} ({service[0]}) registry={registry} image={_safe(regimage,110)} "
                f"registry-change={rid}; observed service binary PROCESS={procid} "
                f"created-by={parent_edges[0][1]} event={parent_edges[0][0]}"
                + (f"; {child_description}" if child_description else ""),
                "A signed Windows service manager proves only which Windows component launched "
                "the binary, NOT whether its registered image was trustworthy or approved. "
                "This chain does not by itself establish who registered the service or malicious intent.",
                (service[0], procid, registry),
            ))

    # 2. Distinguish attempts, successful access, and an actual compromise.
    groups: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    group_refs: dict[tuple[str, str], list[str]] = defaultdict(list)
    for rid, (kind, src, dst) in edges.items():
        if not re.search(r"log|auth|sign.in|credential", kind, re.I):
            continue
        f = _event_props(nodes.get(rid, {}))
        if not ({"auth_failed", "auth_success", "logon_type", "status", "result"} & f.keys()):
            continue
        src_ip = str(f.get("source_ip", f.get("src_ip", "")))
        if not src_ip:
            sp = _props(nodes.get(src, {}))
            src_ip = str(sp.get("src_ip", sp.get("source_ip", sp.get("ip", ""))))
        group = (src_ip or "source-not-recorded", dst)
        groups[group][_auth_outcome(f)] += 1
        group_refs[group].append(rid)
    for (source, dest), counts in sorted(groups.items(), key=lambda kv: -sum(kv[1].values()))[:4]:
        total = sum(counts.values())
        if total < 2 and not counts["failed"]:
            continue
        add(SecurityFinding(
            95 if counts["failed"] >= 2 else 70,
            "authentication-outcomes",
            f"source={_safe(source, 65)} target={dest[:8]}; observed authentication events: "
            f"failed={counts['failed']}, successful={counts['success']}, "
            f"unknown={counts['unknown']} (total={total})",
            "Failures are observable access attempts, NOT successful intrusion; "
            "absence of success does NOT establish benign intent. Check origin and target role.",
            tuple(group_refs[(source, dest)][:4]),
        ))

    # 3. Interpret the *capability* expressed by commands, not whether using
    # the capability was permitted. Distinguish command intention from effect.
    cap_seen: set[tuple[str, str]] = set()
    cap_content_seen: set[tuple[str, str, str]] = set()
    for nid, node in nodes.items():
        if nid in memory.relation_ids:
            continue
        p = _props(node)
        commands = [str(p.get(field, "")) for field in (
            "cmdline_decoded", "script_text_decoded", "command_line_decoded",
            "script_block_text", "script_text", "command", "cmdline", "value_data")]
        text = "\n".join(s[:1800] for s in commands if s)
        if not text:
            continue
        for cap, pattern, question in COMMAND_CAPABILITIES:
            if not pattern.search(text):
                continue
            host = str(node.get("host_id", ""))
            semantic_key = (host, cap, re.sub(r"\s+", " ", text).strip().lower()[:360])
            if (nid, cap) in cap_seen or semantic_key in cap_content_seen:
                continue
            cap_seen.add((nid, cap))
            cap_content_seen.add(semantic_key)
            add(SecurityFinding(
                82 if cap in {"credential-specified", "sensitive-process-memory", "recovery-impact",
                               "directory-privilege-change", "network-redirect"} else 58,
                "command-capability:" + cap,
                f"observed command/script in {nid[:8]} requests capability={cap}; "
                f"excerpt={_safe(text, 180)}",
                f"A command expresses intent/capability, not necessarily success or abuse; verify {question}.",
                (nid,),
            ))
            if len(cap_seen) >= 16:
                break
        if len(cap_seen) >= 16:
            break

    # 4. Handle access is a capability: querying is not dumping, and read
    # rights are not evidence that memory *was* actually read.
    for rid, (kind, src, dst) in edges.items():
        if not re.search(r"handle|process_access|opened_process", kind, re.I):
            continue
        fields = _event_props(nodes.get(rid, {}))
        raw = fields.get("granted_access")
        if raw is None:
            continue
        try:
            mask = int(str(raw), 0) if str(raw).lower().startswith("0x") else int(str(raw))
        except (TypeError, ValueError):
            continue
        read = bool(mask & 0x10)
        query = bool(mask & 0x1000)
        add(SecurityFinding(
            80 if read else 55,
            "process-handle-capability",
            f"handle event {rid[:8]} grants mask={hex(mask)}: "
            + ("memory-reading right granted; " if read else "no documented memory-read right; ")
            + f"PROCESS_QUERY_LIMITED_INFORMATION={'YES' if query else 'NO'}",
            "Process handle creation alone does not demonstrate memory dumping. "
            "Query-only access does not grant permission to read process memory.",
            (rid, src, dst),
        ))

    # Deduplicate without collapsing facts about different objects. Multiple
    # match families can be useful, but keep output bounded for Qwen3-14B.
    uniq: dict[tuple[str, tuple[str, ...]], SecurityFinding] = {}
    for f in findings:
        k = (f.kind, f.references[:2])
        if k not in uniq:
            uniq[k] = f
    # Evidence linked to the trigger matters more than an unrelated search hit.
    # Keep graph distances independent of the model's provisional verdict.
    focus = set(getattr(memory, "focus_ids", ()) or ())
    if focus:
        adjacency: dict[str, set[str]] = defaultdict(set)
        for _, src, dst in edges.values():
            adjacency[src].add(dst)
            adjacency[dst].add(src)
        linked = set(focus)
        frontier = set(focus)
        for _ in range(4):
            frontier = set().union(*(adjacency.get(n, set()) for n in frontier)) - linked
            linked |= frontier
            if not frontier:
                break
        return sorted(uniq.values(), key=lambda f: (
            -(f.priority + (20 if set(f.references) & linked else 0)),
            f.kind, f.references))
    return sorted(uniq.values(), key=lambda f: (-f.priority, f.kind, f.references))


def security_case_summary(memory: Any, *, limit: int = 5, max_chars: int = 2100) -> str:
    """Small evidence-type matrix; completely independent of expected verdict."""
    found = collect_security_findings(memory)
    if not found:
        return "No additional cross-source semantic corroboration yet."
    result: list[str] = []
    for fact in found:
        line = fact.render()
        if len("\n".join([*result, line])) > max_chars:
            break
        result.append(line)
        if len(result) == limit:
            break
    return "\n".join(result)
