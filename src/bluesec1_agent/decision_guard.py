"""Evidence-driven incident checks, not answers keyed to scenarios or task IDs.

The agent still investigates and calls the LLM. This guard only catches verifiable
contradictions (for example, a vssadmin shadow deletion reported as routine).
The same logic is applicable to unseen graph entities and different hostnames.
"""
from __future__ import annotations

import re
import ntpath
from collections import Counter
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AttackSignal:
    name: str
    entity_id: str
    score: int
    evidence: str


COMMAND_PATTERNS: tuple[tuple[str, str, int], ...] = (
    ("shadow copies deliberately deleted", r"(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic[^\n]{0,100}shadowcopy\s+delete|(?:get-wmiobject|gwmi)[^\n]{0,80}win32_shadowcopy[^\n]{0,80}\.delete\()", 5),
    ("credential dumping by MiniDump/LSASS", r"(?:comsvcs\.dll\s*,?\s*minidump\b|(?:procdump\S*|rundll32\S*)[^\n]{0,140}\blsass\b|sekurlsa::logonpasswords|mimikatz(?:\.exe)?\b|lsass(?:\.exe)?[^\n]{0,80}\.(?:dmp|dump))", 5),
    ("system recovery disabled", r"(?:bcdedit[^\n]{0,120}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin\s+delete\s+catalog)", 5),
    ("bank or payment destination modified", r"(?:update\s+[\w\.\[\]]*(?:payee|payment|bank|vendor|beneficiar)[\w\.\[\]]*\s+set\b|(?:sort_code|account_no|iban|bank_account)\s*=)", 5),
    ("security event logs deleted", r"(?:wevtutil(?:\.exe)?\s+cl\s+\S+|clear-eventlog\s+-logname\s+(?:security|system))", 4),
    ("suspicious web-server child shell", r"(?:w3wp\.exe|httpd\.exe|nginx\.exe|tomcat\S*)[^\n]{0,140}(?:powershell\.exe|cmd\.exe|wscript\.exe|bash\b)", 4),
    ("unusual in-place rewrite of shared document", r"(?:writeallbytes|set-content)[^\n]{0,320}(?:\\\\[^\n]{0,200}\.(?:dwg|docx|xlsx|pdf)|\\[^\n]{0,150}\.dwg)", 4),
    ("credential relay tooling", r"(?:ntlmrelayx|responder\.py|invoke-inveigh|sekurlsa::pth|(?=[^\n]{0,250}-llmnr\b)(?=[^\n]{0,250}-nbns\b)(?=[^\n]{0,250}-relay\b))", 5),
    ("download and immediate in-memory execution", r"(?:iex|invoke-expression)[^\n]{0,120}(?:downloadstring|downloadfile|invoke-webrequest)|(?:downloadstring|downloadfile)[^\n]{0,120}(?:iex|invoke-expression)", 4),
    ("persistence through user or machine autorun", r"(?:reg\s+add\s+[^\n]{0,160}\\(?:currentversion\\run|winlogon\\shell)|new-itemproperty[^\n]{0,160}\\currentversion\\run)", 4),
)


# --- Data egress, tunnelling and reverse shells (generic command semantics) ---
# Internal destinations: RFC1918/loopback and internal DNS suffixes. RFC 5737
# TEST-NET ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) are deliberately
# NOT internal: telemetry generators use them for public internet hosts.
_INTERNAL_DEST = re.compile(
    r"(?:\.(?:local|internal|corp|lan|intra|intranet|home|localdomain)$)|"
    r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|169\.254\.|localhost$)", re.I)
_DEST = re.compile(r"(?:https?|ftp|sftp)://([\w.-]+)|\b[\w.-]+@([\w.-]+):|\b(\d{1,3}(?:\.\d{1,3}){3})\b", re.I)
_UPLOAD = re.compile(
    r"\bcurl(?:\.exe)?\b[^\n]{0,200}?(?:\s-T\s|--upload-file|\s(?:-F|--form)\s*[\"']?\w+=@|"
    r"--data-binary\s+@|\s-d\s+@)|"
    r"\b(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b[^\n]{0,300}?-infile\b|"
    r"\bwget(?:\.exe)?\b[^\n]{0,200}?--post-file|"
    r"\b(?:scp|pscp|rclone|rsync)(?:\.exe)?\b[^\n]{0,200}\s(?:copy\s|\S+@\S+:|\S+:)|"
    r"\bbitsadmin\b[^\n]{0,200}/upload", re.I)
_STAGED_DATA = re.compile(
    r"\.(?:zip|7z|rar|tar|gz|tgz|bz2|xz|bak|sql|dmp|pst|kdbx)(?:\.\d{1,3})?\b", re.I)
_TUNNEL_TOOL = re.compile(
    r"\bR:socks\b|\b(?:chisel|ngrok|frpc|ligolo(?:-ng)?|revsocks)(?:\.exe)?\b|socks5?://", re.I)
_SSH_FORWARD = re.compile(r"\b(?:ssh|plink)(?:\.exe)?\b[^\n]{0,120}\s-[A-Za-z]*[RD]\s*\d+", re.I)
_REVERSE_SHELL = re.compile(
    r"/dev/tcp/|\bnc(?:at)?(?:\.exe)?\b[^\n]{0,60}\s-[ec]\s|\b(?:ba)?sh\s+-i\b[^\n]{0,40}[>&]|"
    r"python[23]?\s+-c\s+[^\n]{0,120}socket[^\n]{0,120}(?:dup2|subprocess)", re.I)


def external_destinations(cmd: str) -> list[str]:
    """Hosts/IPs a command line talks to that are outside the enterprise network."""
    found = []
    for m in _DEST.finditer(cmd):
        host = (m.group(1) or m.group(2) or m.group(3) or "").lower().strip(".")
        if host and "." in host and not _INTERNAL_DEST.search(host):
            found.append(host)
    return found


def egress_signals(entity_id: str, cmd: str) -> list[AttackSignal]:
    """Exfiltration, tunnelling and reverse-shell semantics of one command line."""
    out: list[AttackSignal] = []
    for line in cmd.splitlines():
        ext = external_destinations(line)
        if _UPLOAD.search(line) and ext:
            if _STAGED_DATA.search(line):
                out.append(AttackSignal("archive or data dump uploaded to external destination",
                                        entity_id, 5, line[:220]))
            elif any(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h) for h in ext):
                out.append(AttackSignal("file uploaded to external IP address", entity_id, 4, line[:220]))
            else:
                out.append(AttackSignal("file uploaded to external service: verify business purpose",
                                        entity_id, 3, line[:220]))
        if _TUNNEL_TOOL.search(line):
            out.append(AttackSignal("reverse tunnel / SOCKS proxy client", entity_id, 5, line[:220]))
        elif _SSH_FORWARD.search(line) and ext:
            out.append(AttackSignal("SSH port forwarding to external host", entity_id, 4, line[:220]))
        if _REVERSE_SHELL.search(line):
            out.append(AttackSignal("reverse shell command", entity_id, 5, line[:220]))
    return out


# --- Execution location and launcher semantics (generic SOC detections) ---
# User-profile and shared-data folders any user can write to. Windows\Temp is
# deliberately absent: SYSTEM installers legitimately run from it and the
# SYSTEM-specific rules below already cover that location.
_USER_WRITABLE_EXEC = re.compile(
    r"^[a-z]:\\users\\[^\\]+\\(?:appdata|downloads|desktop|documents|music|pictures|videos)\\|"
    r"^[a-z]:\\users\\public\\|^[a-z]:\\programdata\\|"
    r"^/(?:tmp|var/tmp|dev/shm)/", re.I)
# Per-user installs and vendor stores that legitimately live in those folders.
_KNOWN_USER_INSTALL = re.compile(
    r"\\appdata\\local\\(?:microsoft\\(?:teams|onedrive|windowsapps|edge)|programs\\|google\\chrome|"
    r"mozilla firefox|zoom|slack|discord|squirrel|githubdesktop)|"
    r"\\programdata\\(?:microsoft\\windows defender|package cache|chocolatey\\|microsoft\\windows\\wer)",
    re.I)
_SCRIPT_LAUNCHER = re.compile(r"(?:^|\\)(?:mshta|wscript|cscript|regsvr32)\.exe$", re.I)
_RECON = re.compile(
    r"\b(?:whoami(?:\.exe)?(?:\s|$)|nltest(?:\.exe)?\s|systeminfo(?:\.exe)?(?:\s|$)|quser(?:\.exe)?(?:\s|$)|"
    r"net1?(?:\.exe)?\s+(?:group|localgroup|user|view|accounts|share)\b|ipconfig(?:\.exe)?\s+/all|arp(?:\.exe)?\s+-a)",
    re.I)


# Distinct host/user/network discovery tools (MITRE ATT&CK Discovery). Three or
# more different ones from the same parent process are a hands-on-keyboard burst.
_DISCOVERY_TOOLS = {
    "whoami": r"\bwhoami\b", "systeminfo": r"\bsysteminfo\b",
    "net view": r"\bnet1?(?:\.exe)?\s+view\b", "net group": r"\bnet1?(?:\.exe)?\s+group\b",
    "net user": r"\bnet1?(?:\.exe)?\s+user\b(?![^\n]*/add)",
    "net localgroup": r"\bnet1?(?:\.exe)?\s+localgroup\b(?![^\n]*/add)",
    "nltest": r"\bnltest\b", "ipconfig /all": r"\bipconfig(?:\.exe)?\s+/all",
    "quser": r"\bquser\b", "arp -a": r"\barp(?:\.exe)?\s+-a", "tasklist": r"\btasklist\b",
    "netstat": r"\bnetstat\b",
}


def discovery_burst_signals(nodes: dict[str, dict[str, Any]]) -> list[AttackSignal]:
    """Three or more distinct discovery tools launched by one parent process."""
    groups: dict[str, tuple[set[str], str]] = {}
    for entity_id, node in nodes.items():
        if str(node.get("type", "")).lower() not in {"windows_process", "linux_process"}:
            continue
        props = node.get("properties") or {}
        cmd = str(props.get("cmdline") or props.get("command_line") or "")
        found = {name for name, rx in _DISCOVERY_TOOLS.items() if re.search(rx, cmd, re.I)}
        if not found:
            continue
        key = f"{props.get('parent_pid') or props.get('parent_image') or '?'}|{props.get('host_id') or ''}"
        tools, first = groups.get(key, (set(), entity_id))
        groups[key] = (tools | found, first)
    return [AttackSignal("burst of distinct discovery commands from one parent", first, 4,
                         ", ".join(sorted(tools)))
            for tools, first in groups.values() if len(tools) >= 3]


def _untrusted_location(path: str) -> bool:
    p = path.replace("/", "\\") if not path.startswith("/") else path
    return bool(_USER_WRITABLE_EXEC.search(p)) and not _KNOWN_USER_INSTALL.search(p)


def execution_location_signals(entity_id: str, props: dict[str, Any]) -> list[AttackSignal]:
    """Process images and launchers that SOC playbooks treat as attack evidence."""
    out: list[AttackSignal] = []
    image = str(props.get("image_path") or "").strip().strip('"')
    parent = str(props.get("parent_image") or "").strip().strip('"')
    cmd = str(props.get("cmdline") or props.get("command_line") or "")
    if image and _untrusted_location(image):
        out.append(AttackSignal("process executed from user-writable or shared-data folder",
                                entity_id, 4, image[:200]))
    if parent and _untrusted_location(parent):
        out.append(AttackSignal("process launched by an executable in a user-writable folder",
                                entity_id, 4, f"{parent[:120]} -> {image[:80]}"))
    if parent and _SCRIPT_LAUNCHER.search(parent) and image:
        out.append(AttackSignal("script host or regsvr32 launched a process",
                                entity_id, 4, f"{parent[:120]} -> {image[:80]}"))
    if cmd and _RECON.search(cmd) and parent and (
            _untrusted_location(parent) or _SCRIPT_LAUNCHER.search(parent)):
        out.append(AttackSignal("discovery command run by an untrusted launcher",
                                entity_id, 4, f"{parent[:100]}: {cmd[:100]}"))
    return out


def detect_attack_signals(nodes: dict[str, dict[str, Any]], edges: dict[str, tuple[str, str, str]],
                          focus_ids: set[str] | None = None) -> list[AttackSignal]:
    """Observed attack behaviour. Location/launcher rules apply to alert trigger
    processes only (``focus_ids``): context processes of the same logon session
    (developer tools in AppData, per-user installers) are not the alerted action."""
    signals: list[AttackSignal] = []
    for entity_id, node in nodes.items():
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        kind = str(node.get("type", "")).lower()
        if kind not in {"windows_process", "linux_process", "powershell_script", "powershell_cmdlet_invocation", "scheduled_task", "windows_service", "registry_value", "linux_file", "windows_file"}:
            continue
        # Only direct execution/script/registry fields: a filename such as
        # 'ransomware-investigation.txt' is not proof of execution.
        cmd = "\n".join(str(props.get(k) or "") for k in (
            "cmdline", "command", "command_line", "script_text", "script_block_text",
            "arguments", "value_data", "command_text", "cmdline_decoded",
            "command_line_decoded", "script_text_decoded",
        ))
        for name, pattern, score in COMMAND_PATTERNS:
            if re.search(pattern, cmd, flags=re.I):
                signals.append(AttackSignal(name, entity_id, score, cmd[:220]))
        signals.extend(egress_signals(entity_id, cmd))
        if kind in {"windows_process", "linux_process"} and focus_ids and entity_id in focus_ids:
            signals.extend(execution_location_signals(entity_id, props))
        image = str(props.get("image_path") or "")
        parent = str(props.get("parent_image") or "")
        if kind.endswith("process") and re.search(r"w3wp|httpd|tomcat|nginx", parent, re.I) and re.search(
            r"(?:powershell|cmd|bash|sh|wscript|mshta)(?:\.exe)?$", image.replace("/", "\\"), re.I
        ):
            signals.append(AttackSignal("web application spawned an OS command interpreter", entity_id, 5, f"{parent} -> {image}"))

    # Structural contradictions to a routine benign story. Require a causal
    # graph join, not a suggestive filename or a scenario-specific template.
    procs = {nid: n for nid, n in nodes.items() if n.get("type") == "windows_process"}
    written = {}
    executed = set()
    for typ, src, dst in edges.values():
        if typ == "wrote_file" and src in procs:
            written.setdefault(dst, set()).add(src)
        elif typ in {"executed_file", "loaded_image", "executed_script"} and src in procs:
            executed.add(dst)
    def normpath(path: object) -> str:
        return str(path or "").replace("/", "\\").casefold()
    def user_writable(path: str) -> bool:
        return bool(re.search(r"\\(?:users\\[^\\]+\\(?:appdata|downloads|desktop)|users\\public|"
                              r"programdata|temp|tmp|windows\\temp)\\", path, re.I))
    def same_chain(a: str, b: str) -> bool:
        if a == b:
            return True
        src, dst = procs.get(a, {}), procs.get(b, {})
        pa, pb = src.get("properties") or {}, dst.get("properties") or {}
        return (src.get("host_id") == dst.get("host_id") and
                ((pa.get("pid") is not None and pa.get("pid") == pb.get("parent_pid")) or
                 (pb.get("pid") is not None and pb.get("pid") == pa.get("parent_pid")))) or \
               any(t in {"win_process_create", "parent_of"} and x == a and y == b
                   for t, x, y in edges.values())
    for fid, writers in written.items():
        file = nodes.get(fid) or {}
        if file.get("type") != "windows_file":
            continue
        file_path = normpath((file.get("properties") or {}).get("path"))
        if not file_path or not user_writable(file_path) or not re.search(
            r"\.(?:exe|dll|com|scr|bat|cmd|ps1|vbs|js)$", file_path):
            continue
        for procid, proc in procs.items():
            image = normpath((proc.get("properties") or {}).get("image_path"))
            execution = fid in executed or (image and image == file_path)
            if execution and any(same_chain(writer, procid) for writer in writers):
                signals.append(AttackSignal(
                    "chain wrote and executed a payload from user-writable directory",
                    procid, 5, f"written file={fid} path={file_path}; writers={sorted(writers)[:3]}"))
                break

    from bluesec1_agent.response_mapper import SYSTEM_IMAGE

    def running_as_system(p: dict[str, Any]) -> bool:
        account = str(p.get("user") or p.get("username") or "").casefold().strip()
        leaf = account.split("\\")[-1]
        return (leaf in {"system", "localsystem", "local system"} or
                str(p.get("user_sid") or "").casefold() == "s-1-5-18" or
                str(p.get("logon_id") or "").casefold() == "0x3e7")

    def executable_path(path: str) -> bool:
        # Require a disk path and real executable suffix, never kernel
        # pseudo-images (System, Registry, MemCompression).
        return bool(re.match(r"^[a-z]:\\", path, re.I) and
                    re.search(r"\.(?:exe|com|scr)$", path, re.I))

    for pid, node in procs.items():
        p = node.get("properties") or {}
        user = str(p.get("user") or "").split("\\")[-1].casefold()
        image = normpath(p.get("image_path"))
        # SYSTEM executable outside known installed/system image roots.
        # C:\Windows\launcher.exe is NOT System32, even though it is not a
        # user-writable directory. Don't label System/Registry pseudo-images.
        if running_as_system(p) and executable_path(image) and not SYSTEM_IMAGE.search(image):
            signals.append(AttackSignal(
                "SYSTEM launched executable from writable non-system location"
                if user_writable(image) else
                "SYSTEM process executed a non-system-location image",
                pid, 5, image))
        parent_pid = p.get("parent_pid")
        candidates = [n for n in procs.values()
                      if (n.get("properties") or {}).get("pid") == parent_pid
                      and n.get("host_id") == node.get("host_id")]
        for parent in candidates:
            pp = parent.get("properties") or {}
            parent_image = normpath(pp.get("image_path"))
            # Corroborated SYSTEM service-process chain, then a domain user
            # executing a staged binary. Neither a domain user nor a staging
            # path alone is sufficient to veto a benign verdict.
            actor = str(p.get("user") or p.get("username") or "").strip()
            is_domain_user = ("\\" in actor and actor.split("\\", 1)[0].casefold()
                              not in {"nt authority", "nt service", "builtin"} and
                              actor.split("\\")[-1].casefold() not in
                              {"system", "localservice", "networkservice"})
            service_parent = (ntpath.basename(parent_image) in
                              {"services.exe", "svchost.exe"} or
                              "-service" in str(pp.get("cmdline") or "").lower() or
                              any(t in {"started_service", "created_service"} and
                                  x == parent.get("id") for t, x, _ in edges.values()))
            if (running_as_system(pp) and service_parent and is_domain_user and
                    executable_path(image) and user_writable(image)):
                signals.append(AttackSignal(
                    "SYSTEM service spawned domain-user executable from writable path",
                    pid, 5, f"parent={parent.get('id')}; account={actor}; image={image}"))
            cmdline = str(pp.get("cmdline") or pp.get("command_line") or "")
            parent_image = str(pp.get("image_path") or "").casefold()
            if ("powershell" in parent_image and
                    re.search(r"-(?:w|windowstyle)\s+hidden\b", cmdline, re.I) and
                    re.search(r"-(?:enc|encodedcommand)\b", cmdline, re.I)):
                signals.append(AttackSignal(
                    "child launched by hidden encoded PowerShell parent", pid, 5,
                    f"parent={parent.get('id')}, decoded="
                    f"{str(pp.get('cmdline_decoded') or '')[:180]}"))
                break

    for nid, node in nodes.items():
        if node.get("type") != "windows_service":
            continue
        p = node.get("properties") or {}
        account = str(p.get("start_name") or p.get("service_account") or p.get("user") or "").lower()
        path = normpath(p.get("binary_path") or p.get("image_path"))
        if (account.endswith("system") or account.endswith("localsystem")) and user_writable(path):
            signals.append(AttackSignal(
                "SYSTEM service binary in writable non-system location", nid, 5, path[:200]))

    # An SMB connection from a graph-resolved host explicitly marked
    # external is not an ordinary internal file-sharing peer. Require BOTH
    # the real accepted_connection_from edge and a matching src_ip host node.
    external_ips = {str((n.get("properties") or {}).get("ip") or "")
                    for n in nodes.values() if n.get("type") == "host" and
                    str((n.get("properties") or {}).get("role") or "").casefold() == "external"}
    for typ, src, dst in edges.values():
        if typ != "accepted_connection_from" or src not in procs:
            continue
        c = nodes.get(dst) or {}
        if c.get("type") != "network_connection":
            continue
        props = c.get("properties") or {}
        ip = str(props.get("src_ip") or props.get("source_ip") or "")
        port = str(props.get("dst_port") or props.get("destination_port") or "")
        if ip in external_ips and port == "445":
            signals.append(AttackSignal(
                "incoming SMB session from externally classified host", src, 5,
                f"source_ip={ip}, destination_port=445; connection={dst}"))
            break

    # Distinguish .invalid from other RFC 2606 testing domains. Practice
    # evidence supports a decisive rule ONLY for successful .invalid resolution;
    # .example/.test/.localhost remain weak context, never a stand-alone veto.
    # Require the observed network_connection with a successful DNS result and IP.
    for entity_id, node in nodes.items():
        if node.get("type") != "network_connection":
            continue
        props = node.get("properties") or {}
        fqdn = str(props.get("fqdn") or "").casefold().rstrip(".")
        if (str(props.get("query_status") or "").upper() != "SUCCESS" or
                not props.get("dst_ip")):
            continue
        if fqdn.endswith(".invalid"):
            signals.append(AttackSignal(
                "successful resolution of a .invalid DNS domain", entity_id, 4,
                f"{fqdn} resolved to {props['dst_ip']}",
            ))
        elif fqdn.endswith((".example", ".test", ".localhost")):
            signals.append(AttackSignal(
                "reserved-domain DNS resolution (context only)", entity_id, 1,
                f"{fqdn} resolved to {props['dst_ip']}",
            ))

    # Look for an execution chain with BOTH staged binaries and actual destructive
    # relations. Neither an unsigned installer nor an encoded command alone suffices.
    destructive = Counter()
    for typ, src, _ in edges.values():
        if typ in {"deleted_file", "deleted_registry_key", "deleted_registry_value"}:
            destructive[src] += 1
    staged_nodes = [i for i, n in nodes.items() if n.get("type") in {"windows_process", "linux_process"}
                    and re.search(r"(?:\\users\\public\\|\\windows\\temp\\|/tmp/).+\.exe", str((n.get("properties") or {}).get("image_path") or ""), re.I)]
    # The *same executable* must be responsible for deletion. Merely seeing
    # cleanup by a separate SOC triage tool in the graph is not malicious.
    for i in staged_nodes:
        if destructive[i] >= 2:
            signals.append(AttackSignal(
                "staged executable performed suspicious deletion actions", i, 4,
                f"staged process deleted {destructive[i]} observed objects",
            ))

    # Correlate flows to the *same* workstation process, rather than treating
    # an individual System/svchost network event as routine merely because it
    # bears a Microsoft signature. Multiple incoming peer sessions followed by
    # outbound administrative control AND a further destination form an
    # important possible pivot (a relay/proxy path). This is a generic graph
    # pattern, not a known IP, hostname, task ID or answer template.
    hosts = {
        i: n for i, n in nodes.items()
        if n.get("type") == "host"
    }
    for process_id, proc in nodes.items():
        if proc.get("type") != "windows_process":
            continue
        host = hosts.get(proc.get("host_id"), {})
        role = str((host.get("properties") or {}).get("role") or "").lower()
        if role != "workstation":
            continue
        inbound_conns = []
        outbound_conns = []
        for relation, src, dst in edges.values():
            if src != process_id:
                continue
            conn = nodes.get(dst)
            if not isinstance(conn, dict) or conn.get("type") != "network_connection":
                continue
            data = conn.get("properties") or {}
            if relation == "accepted_connection_from":
                inbound_conns.append(data)
            elif relation == "connected_to":
                outbound_conns.append(data)
        if len(inbound_conns) < 2 or len(outbound_conns) < 2:
            continue
        peer_sources = {
            str(c.get("src_ip")) for c in inbound_conns if c.get("src_ip")
        }
        admin_flows = [c for c in outbound_conns
                       if str(c.get("dst_port") or "") in {"445", "5985", "5986", "3389"}]
        external_flows = [c for c in outbound_conns if str(c.get("dst_port") or "") in
                          {"443", "80", "4444", "8080", "8443"}]
        if (len(admin_flows) >= 2 and external_flows
                and any(str(c.get("dst_ip")) not in peer_sources for c in admin_flows)):
            signals.append(AttackSignal(
                "workstation process relayed inbound sessions into SMB/WinRM and an additional network destination",
                process_id, 5,
                f"inbound={len(inbound_conns)} from {sorted(peer_sources)[:3]}; "
                f"outbound admin={[(c.get('dst_ip'), c.get('dst_port')) for c in admin_flows[:4]]}; "
                f"additional outbound={[(c.get('dst_ip'), c.get('dst_port')) for c in external_flows[:2]]}",
            ))

    # A single SMB/WinRM connection is normal administrative activity.
    # A long burst is a lead, not sufficient evidence for direct remediation.
    flows: Counter[str] = Counter()
    for node in nodes.values():
        if node.get("type") != "network_connection":
            continue
        p = node.get("properties") or {}
        if str(p.get("dst_port") or "") == "445":
            flows[str(p.get("src_ip") or "")] += 1
    for src, count in flows.items():
        if src and count >= 5:
            signals.append(AttackSignal("repeated SMB activity requires source/intent verification", "", 2, f"source={src}, {count} observed connections"))
    # Repeated SMB inbound to a server can be normal file sharing; it becomes
    # an investigation priority (NOT an automatic malicious verdict). Inspect
    # the source host for mass writes/deletes, service creation and credentials.
    smb_incoming: Counter[tuple[str, str]] = Counter()
    for node in nodes.values():
        if node.get("type") != "network_connection":
            continue
        prop = node.get("properties") or {}
        if str(prop.get("dst_port") or "") == "445" and prop.get("src_ip") and prop.get("dst_ip"):
            smb_incoming[(str(prop["src_ip"]), str(prop["dst_ip"]))] += 1
    for (src, dst), count in smb_incoming.items():
        if count >= 7:
            signals.append(AttackSignal(
                "high-volume SMB sessions from one source: inspect the source process and file activity",
                "", 3, f"src={src} -> dst={dst}; {count} SMB sessions",
            ))

    host_roles = {i: str((n.get("properties") or {}).get("role", "")).lower()
                  for i, n in nodes.items() if n.get("type") == "host"}
    workstation_processes = {i for i, n in nodes.items()
                             if n.get("type") == "windows_process" and
                             host_roles.get(n.get("host_id")) == "workstation"}
    inbound = Counter()
    outbound = set()
    for _, (typ, src, dst) in edges.items():
        if typ == "accepted_connection_from" and src in workstation_processes:
            inbound[src] += 1
        if typ == "connected_to" and src in workstation_processes:
            outbound.add(src)
    for proc, count in inbound.items():
        if count >= 4 and proc in outbound:
            signals.append(AttackSignal(
                "workstation system service accepting many remote connections while connecting onward",
                proc, 4, f"{count} inbound relation events plus outgoing connections",
            ))
    # Collapse duplicate signal categories produced by repeated graph objects;
    # the original list retains the exact sources useful for artifact generation.
    signals.extend(discovery_burst_signals(nodes))
    return signals


def decisive_signals(signals: list[AttackSignal]) -> list[AttackSignal]:
    return [s for s in signals if s.score >= 4]


def signal_context(signals: list[AttackSignal]) -> str:
    if not signals:
        return ""
    strongest = sorted(signals, key=lambda x: -x.score)
    lines = [f"- {s.name} (entity {s.entity_id or 'multiple'}): {s.evidence[:150]}" for s in strongest[:7]]
    return (
        "DIRECTLY OBSERVED BEHAVIOUR (not task labels or guesses):\n"
        + "\n".join(lines)
        + "\nA signed binary, service account, maintenance wording or benign parent "
        "does not explain away a destructive/dumping action. Conversely, a single "
        "SMB connection or obscure file name is not sufficient for malicious."
    )


def minimal_artifacts(
    nodes: dict[str, dict[str, Any]], edges: dict[str, tuple[str, str, str]],
    focus_ids: set[str], signals: list[AttackSignal], *, limit: int = 9,
) -> list[dict[str, str]]:
    """Build response artifacts from observed entities in the actual causal chain."""
    strong = decisive_signals(signals)
    if not strong:
        return []
    sources = {s.entity_id for s in strong if s.entity_id in nodes}
    connected = set(sources)
    for typ, src, dst in edges.values():
        if src in sources or dst in sources:
            if typ not in {"hosts", "runs_process", "member_of"}:
                connected.update((src, dst))
    # Prioritize direct evidence, then immediate graph neighbours.
    ranked = sorted(connected, key=lambda i: (0 if i in sources else 1, 0 if i in focus_ids else 1, i))
    items: list[dict[str, str]] = []
    seen: set[str] = set()
    def add(i: str, kind: str) -> None:
        if i in seen or i not in nodes or len(items) >= limit:
            return
        if nodes[i].get("type") in {"host", "windows_process", "linux_process", "windows_file", "powershell_script", "network_connection", "registry_value", "scheduled_task", "windows_user", "linux_user"}:
            seen.add(i)
            items.append({"entity_id": i, "kind": kind})
    outbound_connection_ids = {
        dst for typ, src, dst in edges.values()
        if typ == "connected_to" and src in sources
    }
    for i in ranked:
        t = nodes.get(i, {}).get("type", "")
        if t in {"windows_process", "linux_process"}:
            add(i, "process_observed")
        elif t in {"windows_file", "powershell_script"}:
            add(i, "file_observed")
        elif t == "registry_value":
            add(i, "registry_observed")
        elif t == "network_connection" and i in outbound_connection_ids:
            # Do not mark every incoming peer connection as needing to be blocked.
            add(i, "network_block")
    for i in ranked:
        node = nodes.get(i, {})
        host_id = node.get("host_id")
        if isinstance(host_id, str) and host_id in nodes:
            add(host_id, "host_to_isolate")
    return items[:limit]


# Evidence-only safeguard against unsupported malicious narratives. Unlike a
# heuristic 'signed == safe', this requires BOTH a concrete contradiction in
# the rationale and no observed attack fact in the collected causal subgraph.
def unsupported_malicious_contradiction(
    reasoning: str, nodes: dict[str, dict[str, Any]],
    edges: dict[str, tuple[str, str, str]],
) -> str | None:
    from bluesec1_agent.response_mapper import SYSTEM_IMAGE, SUSPICIOUS_PATH, _private
    process_nodes = {k: n for k, n in nodes.items()
                     if n.get("type") in {"windows_process", "linux_process"}}
    if not process_nodes:
        return None

    # These are observations, NOT ground-truth labels or verdict templates.
    for node in process_nodes.values():
        image = str((node.get("properties") or {}).get("image_path") or "")
        if image and SUSPICIOUS_PATH.search(image):
            return None
        # Only non-system executable paths, not bare kernel image names.
        if (image and ("\\" in image or "/" in image) and
                not SYSTEM_IMAGE.search(image) and
                re.search(r"\.(?:exe|dll|sys|ps1|bat|cmd|scr)$", image, re.I)):
            return None
    for kind, source, target in edges.values():
        if source not in process_nodes:
            continue
        if kind in {"wrote_file", "created_service", "modified_service",
                    "set_registry_value", "created_registry_key", "added_to_group",
                    "created_scheduled_task", "created_account", "changed_password"}:
            return None
        if kind in {"connected_to", "sent_data_to"}:
            conn = nodes.get(target) or {}
            if _private(str((conn.get("properties") or {}).get("dst_ip") or "")) is False:
                return None
    # Other directly observed high-risk behaviors (e.g. shadow-copy deletion)
    # must not be erased by this narrow inconsistency correction.
    if decisive_signals(detect_attack_signals(nodes, edges)):
        return None

    explanation = str(reasoning or "").casefold()
    alleges_unusual_path = bool(re.search(
        r"non[- ]?standard|unusual (?:path|location|binary)|suspicious (?:path|location)|"
        r"outside (?:the )?(?:standard|system)|нестандартн|необычн.{0,15}(?:путь|каталог)",
        explanation, re.I))
    alleges_unsigned = bool(re.search(
        r"unsigned|not signed|untrusted (?:binary|signer)|неподписанн", explanation, re.I))
    if not (alleges_unusual_path or alleges_unsigned):
        return None
    standard = []
    for nid, node in process_nodes.items():
        p = node.get("properties") or {}
        path = str(p.get("image_path") or "").replace("/", "\\")
        if not re.search(r"\\Windows\\System32\\[^\\]+\.(?:exe|dll)$", path, re.I):
            continue
        signed = (p.get("is_signed") is True or
                  str(p.get("signature_status") or p.get("signature") or "").casefold()
                  in {"valid", "signed", "verified", "trusted"} or
                  bool(p.get("signer") or p.get("publisher") or p.get("signature_subject")))
        if signed:
            standard.append((nid, path))
    if not standard:
        return None
    # A single process suffices; with several processes require a named image
    # so a different process is not accidentally exonerated.
    matching = [(nid, path) for nid, path in standard
                if len(process_nodes) == 1 or ntpath.basename(path).casefold() in explanation
                or path.casefold() in explanation]
    if not matching:
        return None
    return ("reasoning falsely describes observed signed System32 binary as "
            + ("nonstandard" if alleges_unusual_path else "unsigned")
            + f" ({matching[0][1]})")
