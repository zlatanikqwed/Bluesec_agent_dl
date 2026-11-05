import base64
import copy
import contextlib
import json
import ntpath
import re
from collections import Counter
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field

from bluesec1_agent.response_mapper import (
    ObservedGraph,
    benign_anchor_pivots,
    benign_to_malicious,
    merge_benign,
    merge_submission,
    pivot_key,
    scoping_pivots,
)
from bluesec1_agent.llm import NextStepRequestError, StructuredStepClient, render_json
from bluesec1_agent.models import FinishInvestigationRequest, SearchRequest
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.evidence_workbench import EvidenceWorkbench
from bluesec1_agent.security_engine import SecurityEngine
from bluesec1_agent.soc_v18 import SOCV18
from bluesec1_agent.soc_v19 import SOCV19
from bluesec1_agent.soc_v20 import ForensicCaseState
from bluesec1_agent.soc_v21 import RiskAdaptiveCaseState, corroborated_submission
from bluesec1_agent.soc_v22 import EvidenceFocusedCaseState, SOCV22
from bluesec1_agent.soc_v23 import ReasonedEvidenceCaseState, SemanticEvidenceValidator, SOCV23
from bluesec1_agent.soc_v24 import ThreatCasebook, ThreatHuntingCaseState, SOCV24
from bluesec1_agent.decision_guard import detect_attack_signals, decisive_signals, minimal_artifacts, signal_context, unsupported_malicious_contradiction
from bluesec1_agent.external_peer_guard import external_peer_signals
from bluesec1_agent.harvest_v31 import EvidenceHarvester, _public as public_evidence
from bluesec1_agent.benign_probe import (
    apply_benign_probe, apply_benign_probe_extra, context_calls,
)
from bluesec1_agent.probe_design import apply_random_probe, expand_design, explore_design
from bluesec1_agent.report_experiments import (
    apply_report_experiment, MODES as REPORT_EXPERIMENT_MODES, PHASE_I_MODES, PHASE_L_MODES,
    PROBE_MODES, apply_role_policy, drop_deleted_file_artifacts,
    report_probe_diagnostics, phaseL_probe_diagnostics,
)
from bluesec1_client import (
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)

SYSTEM_PROMPT = """
You are a SOC incident investigator. Investigate a graph of observable processes,
identities, files, networks and their typed relations. Each tool call costs time.
You MUST investigate the behavior causing THIS alert, not follow a fixed playbook.

Your task has two parts: (1) decide malicious vs benign, (2) report precise evidence.
Maintain two competing causal explanations throughout the investigation:
H_attack: unauthorized activity explains the observations.
H_normal: an authorized workflow explains the SAME observations and effects.
Test both against the actual graph. Do not mistake a signed binary, internal IP,
admin user, well-known process or familiar port for proof of authorization.
Likewise, anomalous tooling alone does not prove malicious intent.
A process or account name never grants blanket authorization: compare the actual
operation and target with the observed task, service and identity scope.
However, a missing approval ticket or the lack of an explicit authorization
log is not, by itself, evidence of compromise; evaluate the coherent causal
workflow and observed consequences rather than requiring unseen approvals.

For EVERY next tool call, decide what uncertainty will be reduced and what outcomes
would support or weaken each explanation. Put your active question and factual
observations in current_state; keep inference explicitly separate from observations.
Prefer calls that expose parent/initiator, executed command, downstream changes,
communications and relevant identity. For changes to identity, permissions or
configuration, open the changed OBJECT and determine the before/after effect;
opening the administrative executable is not enough. Compare evidence temporally and causally.
Do not enumerate edges of hub hosts/accounts or repeat uninformative relations.
Missing evidence is unknown, NOT a negative observation.

get_entity(entity_id) returns properties and relation_ids. Those are relation IDs:
open with get_relation(relation_id) for source, target and type. For a remote
account use get_ad_object_info(ad_object_id). search is substring-based (>=5 chars).
Decoded command/script fields are directly relevant observations.

Finish when your two explanations have been compared against behavioral evidence,
not when a fixed number of tools was consumed. For malicious outcomes report only
observed, causally connected entities and justified response actions; avoid
inventing isolated hosts or identities to rotate. For benign outcomes cite actual
observed operation and effects, not merely signed/name/system metadata.
Only cite ids and fields actually returned by the task or investigation tools.
Return a single valid NextStep JSON object per turn.
""".strip()

GPT_OSS_GUIDANCE = """
SPECIAL INSTRUCTIONS FOR TOOL-USE AGENTS:
- A finish_investigation call is NOT a substitute for investigating. In particular,
  the alert's command line, a signed executable, SYSTEM, internal address or a
  service account cannot establish benign intent without checking actions.
- Inspect the initiating operation, its observed consequences, and the entity at
  a high-consequence relation endpoint before a benign verdict. Explicitly
  contrast observed impact with a plausible legitimate workflow.
- If you only inspected the alert process itself, you are NOT ready to finish.
  Open a returned relation ID, then its actual endpoint; use search if the
  connected graph offers no useful lead. A missing edge means unknown, not benign.
- For malicious decisions, distinguish code execution, file write, credentials,
  exfiltration and persistence from mere suspicious tool names. Cite observed
  effects rather than unsupported assumptions.
- Do not invent IDs, field names, permissions, absent operations or approvals.
""".strip()


# --- Legacy diagnostic incident labels (NOT the planning policy) -----------------
# Kept for API compatibility and historical tests; v5 runtime uses the evidence-
# driven InvestigationDirector instead of injecting these static playbooks.

PLAYBOOKS: dict[str, str] = {
    "ransomware": (
        "LIKELY RANSOMWARE / DESTRUCTION. Decisive checks:\n"
        "- shadow-copy/backup deletion (vssadmin, wmic shadowcopy, wbadmin, bcdedit);\n"
        "- mass file writes/renames, ransom extensions or notes;\n"
        "- the process tree: what spawned this and what it spawned.\n"
        "If deletion or mass encryption is present -> malicious; isolate the host, "
        "list the payload files and the connections."
    ),
    "credential_theft": (
        "LIKELY CREDENTIAL ACCESS. Decisive checks:\n"
        "- access to lsass (dump via procdump/comsvcs/taskmgr), ntds.dit, SAM/SYSTEM;\n"
        "- mimikatz/sekurlsa strings, *.kirbi, hashes files, asrep/kerberoast;\n"
        "- which account ran it and what it did next (lateral movement?).\n"
        "If credentials were dumped -> malicious; rotate the accounts, isolate hosts."
    ),
    "lateral_movement": (
        "LIKELY LATERAL MOVEMENT. Decisive checks:\n"
        "- remote-exec: PsExec/PSEXESVC, WMI, WinRM (5985), scheduled task on a peer;\n"
        "- SMB (445)/WinRM fan-out to many hosts in a short window;\n"
        "- the credential used and where it came from.\n"
        "Map hosts and accounts in the causal chain. Isolate only genuinely compromised "
        "hosts; mere remote access is not proof of compromise. An authorized administrator "
        "connecting by WinRM can be benign; inspect the remote command and follow-on effects."
    ),
    "encoded_exec": (
        "LIKELY FILELESS / ENCODED EXECUTION. Decisive checks:\n"
        "- the FULL command line, decoded (`_decoded` field): IEX, DownloadString,"
        " FromBase64String, -enc, -w hidden, -ep bypass;\n"
        "- download source (odd domain, internal share) and what was fetched/run;\n"
        "- child processes and network connections it opened.\n"
        "Download-and-run or obfuscated payload -> malicious."
    ),
    "suspicious_binary": (
        "UNTRUSTED BINARY (runs from Temp/Public/ProgramData, odd name, unsigned).\n"
        "Decisive checks:\n"
        "- signature, original_filename vs image name, how it arrived (parent, "
        "download);\n"
        "- what it did: children, files, network, persistence it created.\n"
        "Treat as malicious unless clearly a legitimate installer/updater you can "
        "prove."
    ),
    "web_shell": (
        "WEB-SERVER PROCESS (w3wp/httpd) SPAWNED SOMETHING. Decisive checks:\n"
        "- child processes of the web worker (cmd/powershell = web shell);\n"
        "- files written under webroot; the request/source IP;\n"
        "A web worker spawning a shell or writing scripts -> malicious."
    ),
    "vendor_agent": (
        "TRIGGER IS A KNOWN SECURITY/VENDOR AGENT (EDR, AV, backup). Usually benign,\n"
        "but confirm, do not assume:\n"
        "- signer and path match the real vendor; parent is services.exe/SYSTEM;\n"
        "- it is NOT a renamed binary abusing the name; no odd children or C2.\n"
        "If it genuinely is the vendor agent doing its job -> benign with evidence."
    ),
    "admin_activity": (
        "TRIGGER IS AN ADMIN/SYSTEM TOOL (powershell, net, mmc, svchost, GPO/SYSVOL\n"
        "script, service account). This is the HARDEST case: attackers use exactly\n"
        "these tools, so a trusted name proves nothing. Do NOT assume routine.\n"
        "Mandatory before any verdict:\n"
        "- read what the command/script ACTUALLY does — decode every `_decoded`"
        " field, open the script file, follow what it writes/runs;\n"
        "- open the PARENT, the CHILD processes, and the NETWORK connections;\n"
        "- check whether THIS action fits the account's normal job.\n"
        "Call benign ONLY after you have seen the actual behaviour and it is plainly\n"
        "routine (e.g. a documented GPO script doing config). Any download-and-run,\n"
        "encoded payload, credential access, odd child process, or external/lateral\n"
        "connection requires correlation; remote management alone does not imply an\n"
        "attack. If you could not read what it does, seek corroboration rather than\n"
        "inventing a verdict."
    ),
    "ad_admin": (
        "AD ADMINISTRATION. Read the actual AD group membership or object mutation and\n"
        "investigate the operator identity, origin host, and preceding access.\n"
        "MMC/dsa.msc and LDAP are normal domain administration. Group modification\n"
        "is malicious only with unauthorized identity, suspicious sequence or\n"
        "other compromise; do not assume every Domain Admins change is an attack."
    ),
    "generic": (
        "No specific pattern matched the trigger. Investigate the chain: parent and\n"
        "command line, child processes, files written, network connections, the\n"
        "account, persistence. Decide by behaviour."
    ),
}

# Ordered (first match wins). Each: playbook key, regex over the trigger blob.
CLASSIFIER: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ransomware",
        re.compile(
            r"vssadmin|shadowcopy|wbadmin|bcdedit|\.lockbit|"
            r"\.loginblob|ransom|\.encrypted\b",
            re.I,
        ),
    ),
    (
        "credential_theft",
        re.compile(
            r"lsass|mimikatz|sekurlsa|ntds\.dit|\bSAM\b|"
            r"procdump|comsvcs|\.kirbi|kerberoast|asrep",
            re.I,
        ),
    ),
    (
        "encoded_exec",
        re.compile(
            r"frombase64|-enc\b|-encodedcommand|downloadstring|"
            r"iex\b|invoke-expression|-ep\s*bypass|-w\s*hidden",
            re.I,
        ),
    ),
    (
        "web_shell",
        re.compile(
            r"w3wp\.exe|httpd|inetsrv|tomcat|nginx\.exe|"
            r"\\inetpub\\",
            re.I,
        ),
    ),
    (
        "lateral_movement",
        re.compile(
            r"psexec|psexesvc|wsmprovhost|winrm|wmic\b|"
            r"\\445\b|port.{0,3}445|port.{0,3}5985",
            re.I,
        ),
    ),
    (
        "suspicious_binary",
        re.compile(
            r"/users/public/|/temp/[^/]+\.exe|"
            r"/programdata/[^/]+\.exe|"
            r"/windows/[a-z]+-\d+\.exe",
            re.I,
        ),
    ),
    (
        "vendor_agent",
        re.compile(
            r"palo alto|cisco\\amp|cyvera|crowdstrike|sentinel|"
            r"defender|symantec|mcafee|\\traps\\|backup|veeam",
            re.I,
        ),
    ),
    ("web_shell", re.compile(r"w3wp", re.I)),
    (
        "ad_admin",
        re.compile(r"dsa\.msc|domain admins|add-adgroupmember|added_to_group", re.I),
    ),
    (
        "admin_activity",
        re.compile(
            r"powershell|\\net1?\.exe|mmc\.exe|svchost|"
            r"system32|netlogon|sysvol|\bgpo\b|svc[_-]|"
            r"\\system\b|userinit|explorer",
            re.I,
        ),
    ),
)


def _is_external_ip(ip: str) -> bool:
    """True if ip is a routable (non-private, non-local) IPv4 address."""
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    if a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    if a == 169 and b == 254:  # link-local
        return False
    return 1 <= a <= 223


def classify_incident(blob: str) -> str:
    """Pick the playbook whose pattern first matches the trigger text.

    Backslashes are normalised to forward slashes first so Windows paths match
    regardless of how they were escaped in the source JSON.
    """
    text = blob.replace("\\\\", "/").replace("\\", "/")
    for key, pattern in CLASSIFIER:
        if pattern.search(text):
            return key
    return "generic"


LABEL_FIELDS = (
    "hostname",
    "image_path",
    "cmdline",
    "user",
    "name",
    "path",
    "file_path",
    "ip",
    "remote_ip",
    "dest_ip",
    "domain",
    "key_path",
    "value_name",
    "subject",
    "sender",
    "url",
    "task_name",
    "service_name",
    "sam_account_name",
    "role",
)
ID_KEYS = {"id", "entity_id", "relation_id", "source_id", "target_id", "host_id", "ad_object_id"}
# Entities that link to almost everything: their relations are not suggested.
HUB_TYPES = {"host", "windows_user", "linux_user", "ad_object"}

# (label, regex) pairs. A hit while the model wants a benign verdict is challenged.
RED_FLAGS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ransomware: shadow-copy deletion",
        re.compile(
            r"vssadmin.{0,20}delete\s+shadows|wmic.{0,20}shadowcopy\s+delete"
            r"|bcdedit.{0,40}(recoveryenabled\s+no|bootstatuspolicy)",
            re.I,
        ),
    ),
    (
        "ransom/staging file extension",
        re.compile(r"\.(lockbit|loginblob\d*|locked|encrypted|crypt|kirbi)\b", re.I),
    ),
    (
        "credential theft",
        re.compile(
            r"mimikatz|sekurlsa|logonpasswords|lsass.{0,10}\.dmp|ntds\.dit"
            r"|\bSAM\b.{0,20}SYSTEM|hashes?\.txt|asrep|kerberoast",
            re.I,
        ),
    ),
    ("NTLM relay / responder", re.compile(r"-relay\b|-llmnr\b|-nbns\b|spooferip|responder", re.I)),
    (
        "encoded / download-and-run payload",
        re.compile(
            r"frombase64string|downloadstring|iex\s*\(|-enc(odedcommand)?\s"
            r"|-ep\s+bypass|-w\s+hidden|invoke-expression",
            re.I,
        ),
    ),
    (
        "anti-sandbox check",
        re.compile(r"vmware\|virtualbox|virtualbox\|vmware|-notmatch.{0,20}vmware", re.I),
    ),
    (
        "exec from user-writable path",
        re.compile(
            r"\\(temp|public|programdata)\\[^\\\"]+\.exe"
            r"|\\appdata\\[^\\\"]+\.exe",
            re.I,
        ),
    ),
    ("remote-exec service (PsExec-like)", re.compile(r"psexesvc|pipe\\PSEXESVC", re.I)),
    (
        "payment / bank-detail tampering",
        re.compile(r"update\s+\S*payee\S*\s+set|sort_code\s*=|account_no\s*=", re.I),
    ),
)

LOOKUP_ID_ARGS = {
    "get_entity": "entity_id",
    "get_relation": "relation_id",
    "get_ad_object_info": "ad_object_id",
}
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)


# A long base64 run anywhere in a command line (-enc, FromBase64String, raw blob).
B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _try_b64(blob: str) -> str | None:
    blob += "=" * (-len(blob) % 4)
    for encoding in ("utf-16-le", "utf-8"):
        with contextlib.suppress(Exception):
            text = base64.b64decode(blob).decode(encoding)
            ascii_ratio = sum(c.isascii() and (c.isprintable() or c.isspace()) for c in text) / len(
                text
            )
            # Require mostly-ASCII and at least one letter: filters hashes/keys
            if ascii_ratio > 0.95 and any(c.isalpha() and c.isascii() for c in text):
                return text
    return None


def decode_encoded_commands(value: Any) -> Any:
    """Add `<field>_decoded` beside any command-line field carrying a base64 payload."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            out[key] = decode_encoded_commands(item)
            if isinstance(item, str) and len(item) > 24 and ("_decoded" not in key):
                best = max((m.group(0) for m in B64_RE.finditer(item)), key=len, default="")
                if len(best) >= 24 and (decoded := _try_b64(best)) is not None:
                    out[f"{key}_decoded"] = decoded
        return out
    if isinstance(value, list):
        return [decode_encoded_commands(item) for item in value]
    return value


def parse_json_strings(value: Any) -> Any:
    """Turn JSON-encoded string fields (like alert_text) into objects."""
    if isinstance(value, dict):
        return {k: parse_json_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [parse_json_strings(v) for v in value]
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        with contextlib.suppress(json.JSONDecodeError):
            return parse_json_strings(json.loads(value))
    return value


def shrink(value: Any, max_list: int = 25, max_str: int = 2000) -> Any:
    """Cap long lists and strings so one result cannot flood the context."""
    if isinstance(value, dict):
        return {k: shrink(v, max_list, max_str) for k, v in value.items()}
    if isinstance(value, list):
        head = [shrink(v, max_list, max_str) for v in value[:max_list]]
        if len(value) > max_list:
            head.append(
                f"... {len(value) - max_list} more items omitted; their ids are in "
                "'Not yet explored ids'. Use search with scope/time_window to filter."
            )
        return head
    if isinstance(value, str) and len(value) > max_str:
        return value[:max_str] + f"... [{len(value) - max_str} chars cut]"
    return value


def compact(value: Any) -> Any:
    """Drop null and empty fields recursively to save context tokens."""
    if isinstance(value, dict):
        out = {k: compact(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v not in (None, "", [], {})}
    if isinstance(value, list):
        return [compact(v) for v in value if v not in (None, "", [], {})]
    return value


class InvestigationMemory:
    """Ids seen so far, a compact entity index and a cache of tool calls."""

    def __init__(self) -> None:
        self.known_ids: set[str] = set()
        self.index: dict[str, str] = {}
        self.cache: dict[str, dict[str, Any]] = {}
        self.rejected_ids: set[str] = set()
        self.fetched_ids: set[str] = set()
        self.trigger_ids: set[str] = set()
        self.calls_made: list[str] = []
        self.ad_object_ids: set[str] = set()
        self.relation_ids: set[str] = set()
        self.relation_types: dict[str, str] = {}
        self.opened_rel_types: Counter[str] = Counter()
        self.red_flags: dict[str, str] = {}  # label -> id (or "" ) where first seen
        self.incident_type: str = "generic"
        self.alert_description: str = ""
        self.playbook: str = ""
        self.entity_types: dict[str, str] = {}
        self.relation_owner: dict[str, tuple[str, str, str]] = {}
        self._admin_conn_targets: set[str] = set()
        self.observed_nodes: dict[str, dict[str, Any]] = {}
        self.graph_edges: dict[str, tuple[str, str, str]] = {}
        self.focus_ids: set[str] = set()
        self.discovery_order: dict[str, int] = {}
        self.targeted_content_searches: int = 0

    # Strong *observations* must be tested against context; weak ones require
    # corroboration and must never veto a benign verdict by themselves.
    STRONG_INDICATORS = frozenset({
        "ransomware: shadow-copy deletion",
        "credential theft",
        "NTLM relay / responder",
        "remote-exec service (PsExec-like)",
        "payment / bank-detail tampering",
    })

    def scan_flags(self, text: str, node_id: str) -> None:
        for label, pattern in RED_FLAGS:
            if label not in self.red_flags and pattern.search(text):
                self.red_flags[label] = node_id

    def strongly_suspicious(self) -> dict[str, str]:
        return {k: v for k, v in self.red_flags.items() if k in self.STRONG_INDICATORS
                or "web shell / RCE" in k or "winlogon spawned" in k}

    def analyze_entity(self, node: dict[str, Any]) -> None:
        """Derive behavioural red flags that a small model misreads.

        The model sees a connection or a child process but cannot judge whether it
        is anomalous. Here the CODE judges and files a plain-language conclusion,
        which is then injected into the context like any other red flag.
        """
        props = node.get("properties") if isinstance(node.get("properties"), dict) else node
        node_type = str(node.get("type", ""))
        node_id = str(node.get("id") or node.get("entity_id") or node.get("relation_id") or "")

        # 1. Network connections: external destination, C2 ports, admin-protocol fan-out.
        dst = str(props.get("dst_ip") or props.get("remote_ip") or props.get("dest_ip") or "")
        dport = str(
            props.get("dst_port") or props.get("remote_port") or props.get("dest_port") or ""
        )
        direction = str(props.get("direction") or "")
        if dst and _is_external_ip(dst):
            self.red_flags.setdefault(
                f"external connection to {dst}:{dport or '?'}",
                node_id,
            )
        if dport in {"4444", "8443", "1337", "9001"}:
            self.red_flags.setdefault(f"connection on known-C2 port {dport}", node_id)
        if dport in {"445", "5985", "5986", "3389"} and direction == "outbound":
            self._admin_conn_targets.add(dst or node_id)
            if len(self._admin_conn_targets) >= 3:
                self.red_flags.setdefault(
                    "outbound admin-protocol (SMB/WinRM/RDP) fan-out to 3+ hosts "
                    "— lateral movement",
                    node_id,
                )

        # 2. Core OS processes (not just binaries under C:\Windows\System32).
        image = str(props.get("image_path") or props.get("process_name") or "").lower()
        quiet = {
            "system", "userinit.exe", "winlogon.exe", "lsass.exe",
            "services.exe", "smss.exe", "csrss.exe",
        }
        # Compare the executable basename, not substring 'system' in System32.
        executable = ntpath.basename(image.replace("/", "\\"))
        if dst and _is_external_ip(dst) and executable in quiet:
            self.red_flags.setdefault(
                f"process {image or node_type} should never reach external hosts, "
                f"but connects to {dst} — injection or masquerade",
                node_id,
            )

        # A renamed Office document with a second unexplained extension is a
        # significant lead, although there are legitimate encryption/backup tools.
        path = str(props.get("path") or props.get("file_path") or "")
        if re.search(r"\.(?:docx?|xlsx?|pptx?|pdf|txt|csv)\.[a-z0-9_-]{3,18}$", path, re.I):
            self.red_flags.setdefault(
                f"document with appended extension (verify write/rename): {path[-110:]}",
                node_id,
            )

        # 3. Process parentage: a trusted parent spawning an unexpected child.
        parent = str(props.get("parent_image") or "").lower()
        child_shells = (
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
        )
        web_parents = ("w3wp.exe", "httpd.exe", "tomcat", "nginx.exe", "sqlservr.exe")
        if any(w in parent for w in web_parents) and any(c in image for c in child_shells):
            self.red_flags.setdefault(
                f"web/db server process ({parent}) spawned a shell ({image}) — web shell / RCE",
                node_id,
            )
        if "winlogon.exe" in parent and "userinit.exe" not in image and image:
            self.red_flags.setdefault(
                f"winlogon spawned {image} instead of userinit — persistence/injection",
                node_id,
            )

    def absorb(self, value: Any) -> None:
        """Collect ids and one-line summaries from any tool payload."""
        if isinstance(value, dict):
            nid = value.get("id") or value.get("entity_id") or value.get("relation_id") or ""
            # Never scan meta-data, tool descriptions or free-form LLM reasoning
            # as evidence. Only graph objects with a concrete type and id count.
            if isinstance(nid, str) and isinstance(value.get("type"), str):
                props = value.get("properties") or {}
                if not isinstance(props, dict):
                    props = {}
                self.scan_flags(json.dumps(props, ensure_ascii=False), str(nid))
                self.analyze_entity(value)
            node_id = value.get("id") or value.get("entity_id") or value.get("relation_id")
            node_type = value.get("type")
            if isinstance(node_id, str) and isinstance(node_type, str):
                self.index.setdefault(node_id, self._summary(value, node_type))
                self.observed_nodes[node_id] = value
                self.discovery_order.setdefault(node_id, len(self.discovery_order))
                if (isinstance(value.get("source_id"), str)
                        and isinstance(value.get("target_id"), str)):
                    self.graph_edges[node_id] = (
                        node_type, value["source_id"], value["target_id"]
                    )
                if "source_id" in value or "target_id" in value:
                    self.relation_ids.add(node_id)
                    self.relation_types[node_id] = str(node_type)
                else:
                    self.entity_types[node_id] = node_type
            relation_ids = value.get("relation_ids")
            if isinstance(relation_ids, dict) and isinstance(node_id, str):
                owner_type = str(node_type)
                for direction, ids in relation_ids.items():
                    for rid in ids if isinstance(ids, list) else []:
                        if not isinstance(rid, str):
                            continue
                        self.relation_ids.add(rid)
                        self.known_ids.add(rid)
                        self.discovery_order.setdefault(rid, len(self.discovery_order))
                        current = self.relation_owner.get(rid)
                        if current is None or current[1] in HUB_TYPES:
                            self.relation_owner[rid] = (node_id, owner_type, str(direction))
            for key, item in value.items():
                if key in ID_KEYS and isinstance(item, str):
                    self.known_ids.add(item)
                    self.discovery_order.setdefault(item, len(self.discovery_order))
                    if key == "ad_object_id":
                        self.ad_object_ids.add(item)
                self.absorb(item)
        elif isinstance(value, list):
            for item in value:
                self.absorb(item)
        elif isinstance(value, str):
            self.known_ids.update(UUID_RE.findall(value))
            if value.startswith(("{", "[")):
                with contextlib.suppress(json.JSONDecodeError):
                    self.absorb(json.loads(value))

    @staticmethod
    def _summary(node: dict[str, Any], node_type: str) -> str:
        if "source_id" in node or "target_id" in node:
            ts = node.get("timestamp") or ""
            return f"rel {node_type}: {node.get('source_id')} -> {node.get('target_id')} {ts}"
        props = node.get("properties") if isinstance(node.get("properties"), dict) else node
        labels = [f"{f}={str(props[f])[:80]}" for f in LABEL_FIELDS if props.get(f)]
        return f"{node_type}: " + ", ".join(labels[:4])

    def index_text(self, limit: int = 65) -> str:
        # Unrelated entities flood the context in large search results.
        selected = list(self.index.items())[-limit:]
        focused = [(i, self.index[i]) for i in self.focus_ids if i in self.index]
        merged = dict(selected)
        merged.update(focused)
        return "\n".join(f"{node_id} | {summary}" for node_id, summary in merged.items())

    def evidence_text(self, limit: int = 22) -> str:
        """Compact causal edge summary; use ids and types from actual results."""
        edges = list(self.graph_edges.items())
        prioritized = sorted(edges, key=lambda e: (
            0 if (e[1][1] in self.focus_ids or e[1][2] in self.focus_ids) else 1,
            1 if e[1][0] in {"hosts", "runs_process"} else 0,
        ))
        return "\n".join(
            f"{rid} | {rel}: {self.index.get(src, src)[:90]} -> "
            f"{self.index.get(dst, dst)[:90]}"
            for rid, (rel, src, dst) in prioritized[:limit]
        )

    def frontier(self, limit: int = 22) -> list[str]:
        """Prioritize the trigger neighborhood rather than alphabetical UUID order."""
        candidates: list[tuple[tuple[int, int, int, int, str], str]] = []
        for identifier in self.known_ids:
            if identifier in self.fetched_ids or identifier in self.ad_object_ids:
                continue
            owner = self.relation_owner.get(identifier)
            if owner is not None and owner[1] in HUB_TYPES:
                continue
            # Prefer relations around the trigger and discovered process/file nodes.
            # Avoid opening common `hosts` edges a second time.
            if identifier in self.relation_types and self.relation_types[identifier] == "hosts":
                continue
            focus = 0 if owner and owner[0] in self.focus_ids else 1
            related = 0 if owner and owner[1] in {
                "windows_process", "linux_process", "powershell_script",
                "windows_file", "network_connection", "scheduled_task",
            } else 1
            kind = 0 if owner is not None else (1 if identifier in self.entity_types else 2)
            # Preserve graph encounter order, not arbitrary UUID ordering.
            order = self.discovery_order.get(identifier, 1_000_000)
            candidates.append(((focus, related, kind, order, identifier), identifier))
        candidates.sort()
        return [identifier for _, identifier in candidates[:limit]]

    def describe(self, node_id: str) -> str:
        owner = self.relation_owner.get(node_id)
        if owner is not None:
            owner_id, owner_type, direction = owner
            label = self.index.get(owner_id, owner_type)
            return f"RELATION ({direction}) of {label} -> open with get_relation"
        if node_id in self.relation_ids:
            return self.index.get(node_id, "RELATION -> open with get_relation")
        return self.index.get(node_id, "entity, not opened yet -> get_entity")

    def hidden_host_relations(self) -> int:
        return sum(
            1
            for rid, owner in self.relation_owner.items()
            if owner[1] in HUB_TYPES and rid not in self.fetched_ids
        )

    def flag_text(self) -> str:
        if not self.red_flags:
            return ""
        lines = [f"- {label} (near {nid or 'see data'})" for label, nid in self.red_flags.items()]
        return (
            "Potential indicators (NOT verdicts; assess in causal context and check "
            "benign explanations):\n" + "\n".join(lines[:18])
        )

    def context_text(self) -> str:
        parts = []
        if self.playbook:
            parts.append(f"PLAYBOOK — {self.incident_type}:\n{self.playbook}")
        direct_signals = signal_context(detect_attack_signals(
            self.observed_nodes, self.graph_edges, getattr(self, "trigger_ids", None)))
        if direct_signals:
            parts.append(direct_signals)
        flags = self.flag_text()
        if flags:
            parts.append(flags)
        if self.index:
            parts.append("Verified graph objects (ids you may cite):\n" + self.index_text())
        edges = self.evidence_text()
        if edges:
            parts.append("Observed causal edges (do not infer unseen edges):\n" + edges)
        if self.calls_made:
            parts.append(
                "Calls already made (never repeat them):\n"
                + "\n".join(f"- {c}" for c in self.calls_made[-22:])
            )
        frontier = self.frontier()
        if frontier:
            lines = [f"- {i} | {self.describe(i)}" for i in frontier]
            parts.append(
                "Not yet explored ids (candidates for the next call):\n" + "\n".join(lines)
            )
        hidden = self.hidden_host_relations()
        if hidden:
            parts.append(
                f"({hidden} relations of hosts and users are hidden: they link to almost "
                "everything. Do not walk them one by one; use search instead.)"
            )
        return "\n\n".join(parts)

    @staticmethod
    def cache_key(tool_name: str, arguments: dict[str, Any]) -> str:
        args = {k: v for k, v in arguments.items() if k != "reasoning"}
        return f"{tool_name}:{json.dumps(args, sort_keys=True, default=str)}"


def concise_tool_catalog(tool_specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Show only actionable runtime contracts to the model, not 45KB of duplicated JSON schema.

    Full validation continues to use the locally typed NextStep schema and the
    remote runtime contract; this changes *only* prompt representation.
    """
    known = {
        "get_entity": ["entity_id", "reasoning"],
        "get_relation": ["relation_id", "reasoning"],
        "get_ad_object_info": ["ad_object_id", "reasoning"],
        "search": ["query", "reasoning", "page_id?", "scope?", "time_window?", "sort_order?"],
        "finish_investigation": ["submission"],
    }
    compact_specs = []
    for spec in tool_specs:
        name = spec.get("name")
        if not isinstance(name, str):
            continue
        fields = known.get(name)
        if fields is None:
            schema = spec.get("parameters") or {}
            fields = list((schema.get("properties") or {}).keys())
        compact_specs.append({"name": name, "arguments": fields})
    return compact_specs


def submission_ids(arguments: dict[str, Any]) -> list[str]:
    """Entity and relation ids cited by a finish_investigation call."""
    submission = arguments.get("submission") or {}
    ids = [a.get("entity_id") for a in submission.get("ir_artifacts") or []]
    for evidence in submission.get("legitimacy_evidence") or []:
        ids.append(evidence.get("entity_id") or evidence.get("relation_id"))
    return [i for i in ids if isinstance(i, str)]


ARTIFACT_ALLOWED_TYPES: dict[str, set[str]] = {
    "host_to_isolate": {"host"},
    "identity_to_rotate": {"windows_user", "linux_user", "ad_object"},
    "network_block": {"network_connection"},
    "file_to_delete": {"windows_file", "linux_file", "archive_file"},
    "persistence_to_remove": {"registry_key", "registry_value", "scheduled_task", "windows_service", "systemd_unit", "wmi_event_consumer", "wmi_binding"},
    "process_observed": {"windows_process", "linux_process", "powershell_cmdlet_invocation"},
    "file_observed": {"windows_file", "linux_file", "archive_file", "powershell_script"},
    "registry_observed": {"registry_key", "registry_value"},
    "identity_observed": {"windows_user", "linux_user", "ad_object"},
    "mount_observed": {"mounted_volume"},
    "lnk_observed": {"lnk_shortcut"},
    "ticket_observed": {"kerberos_ticket"},
}


def validate_artifact_types(sub: dict[str, Any], memory: InvestigationMemory) -> tuple[dict[str, Any], int]:
    """Remove mis-typed IR artifacts without inventing new remediation actions."""
    items = sub.get("ir_artifacts") or []
    corrected: list[dict[str, Any]] = []
    changed = 0
    seen: set[tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            changed += 1
            continue
        nid, kind = item.get("entity_id"), item.get("kind")
        if not isinstance(nid, str) or not isinstance(kind, str):
            changed += 1
            continue
        node_type = memory.entity_types.get(nid)
        allowed = ARTIFACT_ALLOWED_TYPES.get(kind)
        if node_type is not None and allowed is not None and node_type not in allowed:
            # Stay forensic rather than inventing an IR action against an unrelated type.
            replacement = {
                "host": "artifact_observed",
                "windows_process": "process_observed", "linux_process": "process_observed",
                "windows_file": "file_observed", "linux_file": "file_observed",
                "archive_file": "file_observed", "powershell_script": "file_observed",
                "registry_key": "registry_observed", "registry_value": "registry_observed",
                "windows_user": "identity_observed", "linux_user": "identity_observed",
                "ad_object": "identity_observed",
            }.get(node_type, "artifact_observed")
            kind = replacement
            changed += 1
        key = nid, kind
        if key in seen:
            changed += 1
            continue
        seen.add(key)
        corrected.append({"entity_id": nid, "kind": kind})
    return ({**sub, "ir_artifacts": corrected}, changed)


class AgentRunResult(BaseModel):
    """Aggregate results returned by one remote benchmark run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    successful_tasks: int
    failed_tasks: int
    task_results: list[TaskResult] = Field(default_factory=list)


class SimpleSGRAgent:
    """One-action-per-turn LLM loop with context control and local guards."""

    def __init__(
        self,
        llm: StructuredStepClient,
        *,
        max_steps: int = 22,
        context_chars: int = 40_000,
        keep_recent_results: int = 6,
        trajectory_dir: str | None = "runs",
        max_finish_rejections: int = 1,
        min_entities_before_benign: int = 2,
        enough_to_decide: int = 14,
        max_stale_steps: int = 4,
        max_same_relation: int = 4,
        review_enabled: bool = True,
        gpt_oss_mode: bool = False,
        v16_mode: bool = False,
        security_mode: bool = False,
        soc_v18_mode: bool = False,
        soc_v19_mode: bool = False,
        soc_v20_mode: bool = False,
        soc_v21_mode: bool = False,
        soc_v22_mode: bool = False,
        soc_v23_mode: bool = False,
        soc_v24_mode: bool = False,
        v25_response_mode: bool = False,
        v25_response_tier: int = 2,
        v25_scope_calls: int = 6,
        v25_hard_codes: str = "",
        v25_benign_anchors: bool = False,
        v25_benign_calls: int = 3,
        v25_benign_max_evidence: int = 3,
        harvest_mode: bool = True,
        harvest_budget: int = 8,
        report_experiment: str = "control",
        drop_deleted_file_artifacts: bool = True,
        arbiter_llm: StructuredStepClient | None = None,
        arbiter_shadow: bool = False,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.llm = llm
        # Optional stronger model used ONLY to settle analyst/reviewer disagreements.
        self.arbiter_llm = arbiter_llm
        self.arbiter_shadow = arbiter_shadow
        self.director = InvestigationDirector()
        self.workbench = EvidenceWorkbench(self.director)
        self.security = SecurityEngine(self.director)
        self.soc_v18 = (SOCV24(self.director) if soc_v24_mode else
                        SOCV23(self.director) if soc_v23_mode else
                        SOCV22(self.director) if soc_v22_mode else
                        SOCV19(self.director) if (soc_v19_mode or soc_v20_mode or soc_v21_mode)
                        else SOCV18(self.director))
        self.soc_v24_mode = soc_v24_mode
        self.v25_response_mode = v25_response_mode
        self.v25_response_tier = v25_response_tier
        self.v25_scope_calls = v25_scope_calls
        self.v25_hard_codes = {c.strip() for c in v25_hard_codes.split(",") if c.strip()}
        self.v25_benign_anchors = v25_benign_anchors
        self.v25_benign_calls = v25_benign_calls
        self.v25_benign_max_evidence = max(1, min(3, v25_benign_max_evidence))
        self.threat_casebook = ThreatCasebook() if soc_v24_mode else None
        self.soc_v23_mode = soc_v23_mode or soc_v24_mode
        self.semantic_validator = SemanticEvidenceValidator() if self.soc_v23_mode else None
        self.soc_v22_mode = soc_v22_mode or self.soc_v23_mode
        self.soc_v21_mode = soc_v21_mode or self.soc_v22_mode
        self.soc_v20_mode = soc_v20_mode or self.soc_v21_mode
        self.soc_v19_mode = soc_v19_mode or self.soc_v20_mode
        self.soc_v18_mode = soc_v18_mode or self.soc_v19_mode
        self.security_mode = security_mode
        self.v16_mode = v16_mode
        self.review_enabled = review_enabled
        self.gpt_oss_mode = gpt_oss_mode
        self.max_steps = min(max_steps, 28)  # avoid 50-100-call traps
        if report_experiment not in REPORT_EXPERIMENT_MODES:
            raise ValueError(f"Invalid report experiment: {report_experiment}")
        self.report_experiment = report_experiment
        self.drop_deleted_file_artifacts = drop_deleted_file_artifacts
        # Phase M probe keeps the proven Phase K investigation; only the report is randomized.
        self.harvest_profile = ("inbound_guard" if report_experiment in PROBE_MODES
                                else report_experiment)
        self.harvest_mode = harvest_mode
        self.harvest_budget = max(1, min(harvest_budget, self.max_steps - 1, 10))
        self.context_chars = context_chars
        self.keep_recent_results = keep_recent_results
        self.trajectory_dir = Path(trajectory_dir) if trajectory_dir else None
        self.max_finish_rejections = (max(max_finish_rejections, 4) if gpt_oss_mode
                                      else max_finish_rejections)
        self.min_entities_before_benign = min_entities_before_benign
        self.enough_to_decide = enough_to_decide
        self.max_stale_steps = max_stale_steps
        self.max_same_relation = max_same_relation

    async def run(self, client: RemoteBenchmarkClient) -> AgentRunResult:
        """Consume the remote queue and aggregate authoritative task results."""
        remote_run = client.run
        if remote_run is None:
            raise RuntimeError("RemoteBenchmarkClient must be open before running the agent.")

        task_results: list[TaskResult] = []
        while (session := await client.start_task()) is not None:
            logger.info("Starting investigation for task {}.", session.task_id)
            transcript: list[dict[str, Any]] = []
            try:
                task_result = await self._investigate(session, transcript)
            except Exception as exc:
                logger.error("Task {} failed in the agent: {}", session.task_id, exc)
                error_message = f"{type(exc).__name__}: {exc}"[:2_000]
                aborted_result = await session.abort_task(error_message=error_message)
                task_result = TaskResult.model_validate(aborted_result)
            logger.info("Task {} result: {}", session.task_id, task_result.model_dump())
            self._save(remote_run.run_id, session, transcript, task_result)
            task_results.append(task_result)

        successful_tasks = sum(
            result.completion_reason in {"terminated", "truncated"} for result in task_results
        )
        return AgentRunResult(
            run_id=remote_run.run_id,
            successful_tasks=successful_tasks,
            failed_tasks=len(task_results) - successful_tasks,
            task_results=task_results,
        )

    async def _investigate(
        self, session: RemoteBenchmarkSession, transcript: list[dict[str, Any]]
    ) -> TaskResult:
        """Drive one leased task until its terminal investigation tool succeeds."""
        observation = session.task.observation
        tool_specs = self._tool_specs(observation)
        available_tools = {spec["name"] for spec in tool_specs if isinstance(spec.get("name"), str)}
        if "finish_investigation" not in available_tools:
            raise ValueError("The runtime did not advertise finish_investigation.")

        memory = InvestigationMemory()
        # v25: lossless record of everything the runtime returned (ids, edges, props).
        observed_graph = ObservedGraph()
        # v28: hard detector findings raised against any benign proposal in this task.
        seen_benign_issues: list[Any] = []
        public_observation = public_evidence(compact(
            decode_encoded_commands(
                parse_json_strings({k: v for k, v in observation.items() if k != "available_tools"})
            )
        ))
        # The graph must have the same decoded evidence as the investigator and
        # final decision guard, not the pre-decoding initial alert.
        observed_graph.absorb_alert(public_observation)
        memory.absorb(public_observation)
        memory.trigger_ids = set(memory.known_ids)
        alert = public_observation.get("alert_text", {})
        if isinstance(alert, dict):
            memory.alert_description = str(alert.get("alert_description", ""))[:500]
            # Hosts and identities are high-degree hubs: using them as graph
            # centres promotes unrelated enterprise background activity.
            anchors = [e for e in alert.get("trigger_entities", [])
                       if isinstance(e, dict) and isinstance(e.get("id"), str)]
            specific = {e["id"] for e in anchors if e.get("type") not in HUB_TYPES}
            memory.focus_ids = specific or {e["id"] for e in anchors}
            # Trigger relations already have their full type and endpoints in the alert.
            memory.fetched_ids.update(
                e["id"] for e in alert.get("trigger_relations", [])
                if isinstance(e, dict) and isinstance(e.get("id"), str)
            )
        trigger_blob = render_json(public_observation)
        memory.incident_type = classify_incident(trigger_blob)
        # Classifier is diagnostic only. The active evidence determines the next
        # question; no scenario-specific answer template is injected into Qwen.
        memory.playbook = ""
        logger.info("Classified incident as '{}'.", memory.incident_type)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT + ("\n\n" + GPT_OSS_GUIDANCE if self.gpt_oss_mode else "")
             + ("\n\nV16: Keep separate OBSERVATIONS, ATTACK EXPLANATION, NORMAL EXPLANATION, "
                "and UNKNOWN FACTS. Before benign, explain the actual observed operation "
                "and its affected object, not merely actor identity/signature. "
                "Do not treat suspicious tooling alone as unauthorized intent. "
                "Use relation IDs and affected objects as evidence. A conclusion can be "
                "revisited in the independent fact audit." if self.v16_mode else "")},
            {
                "role": "user",
                "content": render_json(
                    {
                        "instruction": "Investigate this alert and submit the correct response.",
                        "initial_observation": public_observation,
                        "available_tools": concise_tool_catalog(tool_specs),
                        "step_budget": self.max_steps,
                    }
                ),
            },
        ]
        transcript.extend(messages)
        harvested = False
        if self.harvest_mode and "search" in available_tools and self.max_steps >= 3:
            # Keep v31's verdict, reviewers and response logic. Only the evidence
            # acquisition phase changes: public typed search instead of broad
            # get_relation enumeration. Each prefetch counts toward the same
            # platform tool-call budget as original acquisition.
            harvest_call_count = 0
            def on_harvest_evidence(tool: str, args: dict[str, Any], response: Any) -> None:
                nonlocal harvest_call_count
                harvest_call_count += 1
                feedback = self._tool_feedback(response)
                public_result = public_evidence(decode_encoded_commands(feedback.get("result")))
                observed_graph.absorb(public_result)
                memory.absorb(public_result)
                if tool == "search":
                    # search already exposes FULL properties; do not re-open
                    # its hits individually just to register discovery.
                    memory.fetched_ids.update(observed_graph.entities)
                    memory.fetched_ids.update(observed_graph.relations)
                target = args.get(LOOKUP_ID_ARGS.get(tool, ""))
                if isinstance(target, str):
                    memory.fetched_ids.add(target)
                if tool == "get_relation" and isinstance(target, str):
                    memory.opened_rel_types[memory.relation_types.get(target, "")] += 1
                memory.calls_made.append(self._call_label(tool, args))
                memory.cache[InvestigationMemory.cache_key(tool, args)] = {
                    **feedback, "result": public_result,
                }
                # OFFLINE DIAGNOSTICS ONLY. Reward is written into the trajectory
                # but is never put into messages, graph, memory, or the LLM digest.
                # Store one entry per harvest call even when no entities are returned.
                scope = (args.get("scope") or {}).get("type") if tool == "search" else None
                reason = str(args.get("reasoning") or "").casefold()
                category = ("child_process" if reason.startswith("child:") else
                            "effect_" + reason.split(":", 2)[1] if reason.startswith("effect:") else
                            "id" if tool == "search" and not scope and
                            "id" in reason else
                            "session" if scope in {"windows_process", "logged_on_to"} else
                            "identity" if scope == "windows_user" else
                            "files" if scope in {"windows_file", "linux_file"} or
                            "file" in reason or "payload" in reason else
                            "peers" if scope == "host" else
                            "connections" if scope == "network_connection" or
                            "connection" in reason else
                            "service" if scope == "windows_service" else
                            "id" if tool == "search" and not scope else
                            "endpoint" if tool == "get_entity" else "other")
                event = {"phase": "evidence_harvest", "tool": tool,
                         "harvest_call_index": harvest_call_count,
                         "harvest_category": category,
                         "arguments": args, "result": public_result,
                         "runtime_reward": response.reward}
                transcript.append({"role": "audit", "content": render_json(event)})
                logger.info("OFFLINE harvest reward: call={} category={} tool={} reward={}",
                            event["harvest_call_index"], category, tool, response.reward)
                self._save_partial(session, transcript)

            profile = self.harvest_profile
            harvested_result = await EvidenceHarvester(budget=self.harvest_budget,
                                                service_probe=profile in PHASE_I_MODES,
                                                inbound_probe=profile in ({"inbound_sources", "inbound_guard"} | PHASE_L_MODES),
                                                evidence_probe=(profile if profile in PHASE_L_MODES
                                                                else "")).collect(
                session, public_observation, available_tools, on_harvest_evidence)
            if harvested_result.terminal is not None:
                return TaskResult.model_validate(harvested_result.terminal)
            harvested = harvested_result.completed and harvested_result.calls > 0
            if harvested:
                messages.append({"role": "user", "content": (
                    "Evidence harvest completed with " + str(harvested_result.calls) +
                    " public tool calls. Verified findings below are the starting "
                    "point for the ORIGINAL v31 decision/review pipeline. "
                    "Compare H_attack against H_normal and return finish_investigation "
                    "using actual observed entity IDs and fields. Do not run more "
                    "generic relation enumeration. Unknown remains unknown.\n" +
                    harvested_result.digest)})
                transcript.append(messages[-1])
                logger.info("V31 Harvest complete: {} calls, {} entities, {} relations",
                            harvested_result.calls, harvested_result.discovered_entities,
                            harvested_result.discovered_relations)
        finish_rejections = 0
        duplicate_streak = 0
        last_notes = "(no notes yet)"
        stale_steps = 0
        known_before = len(memory.known_ids)
        reviewed_finish = False
        v16_final_checked = False
        v18_checked = False
        v23_challenge_revision: str | None = None
        v24_challenge_revision: str | None = None
        v23_recent_rejection: str = ""
        case_state = ((ThreatHuntingCaseState(self.soc_v18) if self.soc_v24_mode else
                       ReasonedEvidenceCaseState(self.soc_v18) if self.soc_v23_mode else
                       EvidenceFocusedCaseState(self.soc_v18) if self.soc_v22_mode else
                       RiskAdaptiveCaseState(self.soc_v18) if self.soc_v21_mode else
                       ForensicCaseState(self.soc_v18)) if self.soc_v20_mode else None)
        low_information_steps = 0

        for step_index in range(len(memory.calls_made) + 1, self.max_steps + 1):
            ready_to_conclude, readiness_reason = self.director.readiness(
                memory, steps_used=len(memory.calls_made)
            )
            # A decision review at the first *evidence-complete* checkpoint
            # stops an otherwise endless 24-step enumeration. It requires a
            # connected, examined causal graph, never a scenario name/ID.
            evidence_finish = ready_to_conclude and step_index >= 16
            force_finish = harvested or evidence_finish or (
                duplicate_streak >= 3
                or stale_steps >= self.max_stale_steps
                or low_information_steps >= 4
                or step_index >= max(2, int(0.88 * self.max_steps))
            )
            request = self._request_messages(messages, memory, remaining_steps=self.max_steps - step_index + 1)
            if (step_index in {12, 17, 21} and not force_finish
                    and len(memory.graph_edges) >= 3):
                request.append({"role": "user", "content": self.director.decision_checkpoint(
                    memory, steps_used=step_index - 1,
                    remaining_steps=self.max_steps - step_index + 1,
                )})
            # V19 collects primary forensic facts WITHOUT requesting a new LLM
            # decision at every graph traversal. Known graph IDs only; the SOC
            # planner gives control back to the analyst when information gain
            # drops or the investigation budget is spent.
            if case_state is not None:
                # V20 observations may change after an audit or a refused final.
                # Revalidate the audit only against the *current* evidence snapshot.
                case_state.update(memory)
                if not case_state.review_current(memory):
                    reviewed_finish = False
                if not case_state.challenge_current(memory):
                    v18_checked = False
                preplanned = case_state.select_acquisition(
                    memory, available_tools, step_index=step_index,
                    max_steps=self.max_steps, force_finish=force_finish)
                if self.soc_v21_mode and preplanned is not None:
                    transcript.append({"role": "audit", "content": render_json({
                        "v21_risk_tier": case_state.risk_profile(memory).tier,
                        **({"v22_consequence_first": preplanned.phase == "consequence-first"}
                           if self.soc_v22_mode else {}),
                        **({"v23_semantic_pivot": preplanned.phase == "semantic-attribution"}
                           if self.soc_v23_mode else {}),
                        "v21_budget": case_state.minimum_acquisitions,
                        "v21_observed_findings": [f.name for f in self.soc_v18.findings(memory)[:5]],
                    })})
            else:
                preplanned = (self.soc_v18.next_inspection(memory, available_tools)
                              if self.soc_v19_mode and not force_finish else None)
            if preplanned is not None:
                from bluesec1_agent.models import NextStep
                lead = preplanned.lead
                step = NextStep.model_validate({
                    "current_state": ("V19 forensic acquisition: " + preplanned.question)[:1100],
                    "plan_remaining_steps_brief": [
                        "Inspect the grounded evidence, then evaluate H_attack versus H_normal."],
                    "task_completed": False,
                    "function": {"tool": lead.tool, **lead.arguments},
                })
                transcript.append({"role": "audit", "content": render_json({
                    **({"v20_phase": case_state.stage, "v20_revision": case_state.revision(memory)} if case_state else {}),
                    "v19_acquisition": preplanned.question,
                    "phase": preplanned.phase,
                    "next_tool": lead.tool,
                    "next_arguments": lead.arguments,
                })})
                logger.info("V19 forensic acquisition: {} -> {}", lead.reason, lead.tool)
            elif case_state is not None:
                # No LLM votes while there is a valuable verified graph lead.
                # When such leads are exhausted, use a dedicated decision call
                # rather than an open-ended step that keeps attempting finish.
                case_state.move("DECIDE")
                decision_request = [*request, {"role": "user", "content":
                    case_state.decision_instructions(memory) + "\n" +
                    self.soc_v18.dossier(memory, limit=12)}]
                if self.soc_v23_mode and v23_recent_rejection:
                    feedback_question = (
                        "VALIDATION FEEDBACK ON PREVIOUS FINISH (NOT a ground-truth label): "
                        + v23_recent_rejection[:950]
                        + "\nDo not repeat the same unsupported conclusion. Compare both "
                          "hypotheses with the exact observed event and its effects. "
                          "If a normal explanation is independently supported, cite it; "
                          "otherwise do not invent approval, purpose or absence of activity.")
                    if finish_rejections >= 2:
                        # A repeatedly rejected answer often results from the
                        # model anchoring on its earlier benign narrative. A
                        # NEW compact case review is safer than repeatedly
                        # replaying that incorrect transcript. Never force a
                        # verdict; both explanations remain available.
                        decision_request = [
                            {"role": "system", "content": (
                                "Independent DFIR adjudicator. Review the verified graph "
                                "and explicit validation objection afresh, without previous "
                                "model opinions. Return a schema-valid finish_investigation. "
                                "Direct attack evidence may justify malicious; proven "
                                "normal cause may justify benign. Signed actors alone are "
                                "NOT proof of authorization. Cite ONLY observed IDs.")},
                            {"role": "user", "content": (
                                self.director.review_dossier(memory, ledger_limit=13)[:9000]
                                + "\n" + self.soc_v18.dossier(memory, limit=9)[:4000]
                                + "\n" + feedback_question)},
                        ]
                        transcript.append({"role": "audit", "content": render_json({
                            "v23_fresh_review_after_rejections": finish_rejections,
                            "revision": case_state.revision(memory),
                        })})
                    else:
                        decision_request.append({"role": "user", "content": feedback_question})
                    v23_recent_rejection = ""
                try:
                    step = await self.llm.next_step(decision_request, finish_only=True)
                except NextStepRequestError as exc:
                    step = await self._recover_structured_step(memory, transcript, error=exc)
                case_state.decision_attempts += 1
                transcript.append({"role": "audit", "content": render_json({
                    "v20_phase": "DECIDE", "revision": case_state.revision(memory),
                    "decision_attempts": case_state.decision_attempts})})
            elif force_finish:
                logger.info("Final evidence review at step {}: {}", step_index,
                            readiness_reason if evidence_finish else "budget/stagnation limit")
                request = [
                    *request,
                    {
                        "role": "user",
                        "content": (
                            "Evidence review: distinguish checked facts from missing causal "
                            "links; do not claim unexamined actions have been explained. Compare a concrete attack explanation "
                            "with a corroborated normal/response explanation, then submit "
                            "finish_investigation. For benign: cite the actual operations and "
                            "legitimacy evidence, not just system ownership or signing. "
                            "For malicious: cite the unauthorized actions and resulting effects. "
                            "Do not infer facts from missing edges."
                        ),
                    },
                ]
                try:
                    step = await self.llm.next_step(request, finish_only=True)
                except NextStepRequestError as exc:
                    step = await self._recover_structured_step(memory, transcript, error=exc)
            else:
                try:
                    step = await self.llm.next_step(request)
                except NextStepRequestError as exc:
                    # A long or non-ASCII evidence history can push a small model
                    # into malformed JSON. A new, bounded decision-only context
                    # is preferable to aborting an already investigated task.
                    step = await self._recover_structured_step(memory, transcript, error=exc)
            # V18 ACTIVE POLICY: unlike the legacy post-finish guard, evaluate the
            # verified frontier after EVERY LLM proposal (including lookup proposals).
            # Override only premature finish or demonstrably lower-value browsing;
            # never fabricate a tool target or override a budget-mandated finish.
            if self.soc_v18_mode and not self.soc_v19_mode and not force_finish and step_index <= min(self.max_steps - 5, 14):
                lead = self.soc_v18.plan(memory, available_tools)
                proposed_tool = step.function.tool
                proposed_sub = (step.function.model_dump(mode="json", by_alias=True,
                                  exclude={"tool"}, exclude_none=True).get("submission", {})
                                if proposed_tool == "finish_investigation" else {})
                missing = self.soc_v18.unmet(memory, proposed_sub) if proposed_sub else []
                current_rid = getattr(step.function, "relation_id", "")
                relation_type = memory.relation_types.get(current_rid, "").lower()
                premature = (proposed_tool == "finish_investigation" and
                             (len(memory.calls_made) < 5 or bool(missing) or
                              bool(lead and lead.priority >= 7 and step_index <= 11)))
                browsing = (proposed_tool == "get_relation" and
                            relation_type in {"hosts", "runs_process", "member_of", "logged_on_to"}
                            and bool(lead and lead.priority >= 7))
                unnecessary_search = (proposed_tool == "search" and
                                      bool(lead and lead.priority >= 9) and
                                      len(memory.calls_made) >= 2)
                if lead and (premature or browsing or unnecessary_search):
                    reason = (f"v18 active policy: {lead.reason}; priority={lead.priority}; "
                              f"unresolved_techniques={len(missing)}; calls={len(memory.calls_made)}")
                    transcript.append({"role": "audit", "content": render_json({
                        "v18_active_plan": reason, "proposed_tool": proposed_tool,
                        "next_tool": lead.tool, "next_arguments": lead.arguments,
                    })})
                    logger.info("V18 planner: {} -> {} ({})", proposed_tool, lead.tool, reason)
                    step = self._replace_finish_with_lookup(
                        step, lead.tool, lead.arguments, reason)
            # When an effect's content is unknown, another get_entity is not a
            # content read. One targeted SEARCH can sometimes reveal script/content
            # or related activity; never repeat that same query.
            if (step.function.tool == "finish_investigation" and
                    step_index <= self.max_steps - 6 and "search" in available_tools):
                lead = self.director.targeted_content_search(memory)
                if lead is not None:
                    query, rationale = lead
                    memory.targeted_content_searches += 1
                    step.function = SearchRequest(tool="search", query=query,
                                                   reasoning=rationale)
                    step.task_completed = False
                    logger.info("Investigating unresolved effect via targeted search: {}", query)
            # v16 uses the actual discovered effect ledger to choose grounded next
            # investigations. The guard has a strict budget cap: after verifying
            # causal consequences, further generic hub traversals waste steps.
            if ((self.v16_mode or self.security_mode) and not self.soc_v18_mode
                    and step.function.tool == "finish_investigation"
                    and not force_finish and step_index < min(self.max_steps - 4, 16)):
                proposed_sub = step.function.model_dump(
                    mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                ).get("submission", {})
                effect_rows = self.workbench.effects(memory, limit=12)
                gaps = self.workbench.uncovered(memory, proposed_sub)
                unchecked = any(e.weight >= 4 and not e.target_opened for e in effect_rows)
                count = len(memory.calls_made)
                soc_gap = (self.security.review_questions(memory, proposed_sub)
                           if self.security_mode else [])
                soc_lead = (self.security.next_lead(memory, available_tools)
                            if self.security_mode else None)
                should_investigate = (count < 5 or unchecked or
                                      (proposed_sub.get("verdict") == "benign" and
                                       (not effect_rows or (count < 10 and bool(gaps))
                                        or (count < 12 and bool(soc_gap) and bool(soc_lead)))))
                needs_source = bool(self.security_mode and proposed_sub.get("verdict") == "benign" and
                                    count < 11 and any(f.technique in {
                                        "smb_burst", "nonstandard_remote_session", "cross_identity_smb"}
                                        for f in self.security.hypotheses(memory)))
                should_investigate = should_investigate or needs_source
                if should_investigate:
                    targeted_source = (self.security.grounded_search(memory, available_tools)
                                       if needs_source else None)
                    lead = (soc_lead or targeted_source or self.workbench.next_lead(memory, available_tools)
                            or (self.security.grounded_search(memory, available_tools)
                                if self.security_mode and bool(soc_gap) else None))
                    if lead is not None:
                        tool, arguments, reason = lead
                        why = (f"v17_soc: {len(self.security.hypotheses(memory))} technique hypotheses; "
                               if self.security_mode else "v16: ") + (
                                   f"{count} calls; {len(effect_rows)} observed effects; {reason}")
                        transcript.append({"role": "audit", "content": render_json({
                            "v16_evidence_gate": why,
                            **({"v17_security_gate": why} if self.security_mode else {}),
                            "rejected_early_verdict": proposed_sub.get("verdict"),
                            "next_tool": tool,
                            "next_arguments": arguments,
                        })})
                        logger.info("{} evidence plan: {} -> {}: {}",
                                    "V17 SOC" if self.security_mode else "V16",
                                    step.function.tool, tool, why)
                        step = self._replace_finish_with_lookup(step, tool, arguments, why)
            # Legacy GPT-OSS guard is retained for non-v16 runs only.
            elif (self.gpt_oss_mode and not self.v16_mode and not self.security_mode
                    and not self.soc_v18_mode
                    and step.function.tool == "finish_investigation"
                    and not force_finish and step_index < self.max_steps - 4):
                replacement = self._redirect_premature_finish(
                    step.function.submission.verdict, memory, available_tools
                )
                if replacement is not None:
                    tool, arguments, why = replacement
                    logger.info("GPT-OSS evidence gate: {} -> {}: {}",
                                step.function.tool, tool, why)
                    transcript.append({"role": "audit", "content": render_json({
                        "evidence_gate": why,
                        "rejected_early_verdict": step.function.submission.verdict,
                        "next_tool": tool,
                        "next_arguments": arguments,
                    })})
                    step = self._replace_finish_with_lookup(step, tool, arguments, why)
            # Separation of duties: the investigator proposes a conclusion, then
            # an independent adversarial evidence audit tries to falsify it.
            # This is an additional LLM reasoning pass, not a platform tool call.
            if (self.review_enabled and not reviewed_finish
                    and step.function.tool == "finish_investigation"
                    and (len(memory.calls_made) >= 5 or self.gpt_oss_mode)
                    and (step_index < self.max_steps - 1 or self.gpt_oss_mode)):
                reviewed_finish = True
                if case_state is not None:
                    case_state.mark_reviewed(memory)
                    transcript.append({"role": "audit", "content": render_json({
                        "v20_phase": "VERIFY", "revision": case_state.revision(memory)})})
                proposed = step.function.model_dump(
                    mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                ).get("submission", {})
                audit_request = self.director.independent_review_messages(
                    memory, remaining_steps=self.max_steps - step_index)
                if self.soc_v18_mode:
                    audit_request.append({"role": "user", "content": self.soc_v18.dossier(memory, limit=9)})
                if self.v16_mode or self.security_mode:
                    # Blind audit: only observed facts, NOT analyst's preferred verdict.
                    audit_request.append({"role": "user", "content":
                        "V16 VERIFIED EFFECT LEDGER:\n" + self.workbench.digest(memory, limit=12)
                        + "\nTest H_attack and H_normal separately using those effects."
                        + ("\n" + self.security.dossier(memory) if self.security_mode else "")})
                try:
                    # Blind reviewer does not see the proposal. Only real graph facts.
                    revised = await self.llm.next_step(audit_request, finish_only=True)
                    review_sub = revised.function.model_dump(
                        mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                    ).get("submission", {})
                    logger.info("Blind independent audit: {} vs {}.",
                                proposed.get("verdict"), review_sub.get("verdict"))
                    transcript.append({"role": "audit", "content": render_json({
                        "proposed_submission": proposed,
                        "blind_review": review_sub,
                    })})
                    if proposed.get("verdict") == review_sub.get("verdict"):
                        # Agreement is not sufficient if both analysts cite only
                        # trusted parents/accounts while leaving an observed
                        # modification or cross-identity action unexplained.
                        # Reopen with a FRESH consequence-focused question; the
                        # challenger may still conclude benign on positive facts.
                        if self.v16_mode or self.security_mode:
                            gaps = [e.statement() for e in self.workbench.uncovered(memory, proposed)]
                            gaps += [e.statement() for e in self.workbench.uncovered(memory, review_sub)]
                        else:
                            gaps = self.director.benign_evidence_gaps(memory, proposed) if (
                                proposed.get("verdict") == "benign") else []
                            gaps += self.director.benign_evidence_gaps(memory, review_sub) if (
                                review_sub.get("verdict") == "benign") else []
                        if self.security_mode and proposed.get("verdict") == "benign":
                            gaps += self.security.review_questions(memory, proposed)
                            gaps += self.security.review_questions(memory, review_sub)
                        gaps = list(dict.fromkeys(gaps))[:4]
                        if gaps:
                            logger.info("Agreed benign review omitted {} causal considerations; checking.", len(gaps))
                            try:
                                challenger = await self.llm.next_step(
                                    self.director.agreed_benign_challenge_messages(memory, gaps),
                                    finish_only=True)
                                challenge_sub = challenger.function.model_dump(
                                    mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                                ).get("submission", {})
                                transcript.append({"role": "audit", "content": render_json({
                                    "unexplained_consequences": gaps,
                                    "challenge": challenge_sub,
                                })})
                                if challenge_sub.get("verdict") != proposed.get("verdict"):
                                    arbitration = (self.workbench.dossier_messages(memory, proposed, challenge_sub)
                                                   if (self.v16_mode or self.security_mode) else
                                                   self.director.arbitration_messages(memory, proposed, challenge_sub))
                                    if self.security_mode:
                                        arbitration.append({"role": "user", "content": self.security.dossier(memory)})
                                    step = await self._arbitrate(arbitration, transcript, "consequence")
                                    transcript.append({"role": "audit", "content": render_json({
                                        "consequence_arbitration": step.function.model_dump(mode="json")
                                    })})
                                    logger.info("Consequence-focused arbitration resolved a benign disagreement.")
                                else:
                                    merged = self._merge_agreed_evidence(
                                        proposed, challenge_sub, memory)
                                    step.function = FinishInvestigationRequest.model_validate({
                                        "tool": "finish_investigation", "submission": merged
                                    })
                            except Exception as exc:
                                logger.warning("Consequence check unavailable: {}", exc)
                        # An agreeing independent reviewer corroborates the
                        # classification; it must not silently DISCARD the
                        # investigator's more complete citations or artifacts.
                        if not gaps:
                            merged = self._merge_agreed_evidence(proposed, review_sub, memory)
                            step.function = FinishInvestigationRequest.model_validate({
                                "tool": "finish_investigation", "submission": merged
                            })
                    elif self.gpt_oss_mode or len(memory.calls_made) >= 10:
                        # Tiebreaker is used ONLY on a disagreement. It receives
                        # both arguments and the same observed facts, never a vote.
                        try:
                            arbitration = (self.workbench.dossier_messages(memory, proposed, review_sub)
                                           if (self.v16_mode or self.security_mode) else
                                           self.director.arbitration_messages(memory, proposed, review_sub))
                            if self.security_mode:
                                arbitration.append({"role": "user", "content": self.security.dossier(memory)})
                            revised = await self._arbitrate(arbitration, transcript, "disagreement")
                            transcript.append({"role": "audit", "content": render_json({
                                "arbitration": revised.function.model_dump(mode="json")
                            })})
                            logger.info("Independent arbitration resolved disagreement.")
                            step = revised
                        except Exception as exc:
                            # Neither analyst's answer has priority in a tie.
                            # Do not switch to the blind review by accident if
                            # the arbitration transport or schema fails.
                            logger.warning("Disagreement arbitration unavailable: {}", exc)
                    else:
                        # Preserve the v9/v10 shallow-review behavior when a
                        # third pass cannot be justified by available evidence.
                        step = revised
                        logger.info("Shallow independent audit preferred on disagreement.")
                except Exception as exc:
                    logger.warning("Independent verdict audit unavailable: {}", exc)
            # v16 final fact reconciliation: neither consensus nor a single
            # arbitrator may silently make a known effect disappear. This is a
            # bounded decision-only check; it never forces a malicious outcome.
            if ((self.v16_mode or self.security_mode) and not self.soc_v18_mode
                    and step.function.tool == "finish_investigation"
                    and reviewed_finish and not v16_final_checked):
                current = step.function.model_dump(
                    mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                ).get("submission", {})
                serious_gaps = [e for e in self.workbench.uncovered(memory, current)
                                if e.weight >= 5]
                soc_checks = (self.security.review_questions(memory, current)
                              if self.security_mode else [])
                if serious_gaps or soc_checks:
                    v16_final_checked = True
                    try:
                        # Challenger is asked to falsify final NORMAL hypothesis
                        # against facts, not endorse a predetermined MALICIOUS label.
                        check_messages = self.director.agreed_benign_challenge_messages(
                            memory, [e.statement() for e in serious_gaps] + soc_checks)
                        check_messages.append({"role": "user", "content":
                            "V16 decision check (observations, not labels):\n"
                            + self.workbench.final_claim_check(memory, current)
                            + ("\n" + self.security.dossier(memory) if self.security_mode else "")})
                        challenge = await self.llm.next_step(check_messages, finish_only=True)
                        check_sub = challenge.function.model_dump(
                            mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                        ).get("submission", {})
                        transcript.append({"role": "audit", "content": render_json({
                            "v16_fact_check": {"observed_effects":
                                [e.relation_id for e in serious_gaps],
                                "challenger": check_sub},
                        })})
                        if check_sub.get("verdict") != current.get("verdict"):
                            decision_request = self.workbench.dossier_messages(
                                memory, current, check_sub)
                            if self.security_mode:
                                decision_request.append({"role": "user", "content": self.security.dossier(memory)})
                            step = await self.llm.next_step(decision_request, finish_only=True)
                            transcript.append({"role": "audit", "content": render_json({
                                "v16_fact_tiebreak": step.function.model_dump(mode="json")
                            })})
                        else:
                            combined = self._merge_agreed_evidence(current, check_sub, memory)
                            step.function = FinishInvestigationRequest.model_validate({
                                "tool": "finish_investigation", "submission": combined
                            })
                    except Exception as exc:
                        logger.warning("V16 factual review unavailable: {}", exc)
            # V18 pre-submission falsification: challenge unsupported benign
            # reasoning using concrete observed techniques, never a fixed label.
            if (self.soc_v18_mode and not v18_checked and
                    step.function.tool == "finish_investigation"):
                v18_checked = True
                if case_state is not None:
                    case_state.mark_challenged(memory)
                proposed = step.function.model_dump(mode="json", by_alias=True,
                                exclude={"tool"}, exclude_none=True).get("submission", {})
                missing = self.soc_v18.unmet(memory, proposed)
                forensic_gaps = (self.soc_v18.benign_gaps(memory, proposed)
                                 if self.soc_v19_mode else [])
                if missing or forensic_gaps:
                    transcript.append({"role": "audit", "content": render_json({
                        "v18_fact_challenge": [finding.text() for finding in missing],
                        **({"v19_benign_gaps": forensic_gaps} if self.soc_v19_mode else {})})})
                    try:
                        challenge = [
                            {"role": "system", "content": (
                                "Independent SOC evidence judge. Return a single schema-valid "
                                "finish_investigation. Compare BOTH hypotheses. Do not treat "
                                "an unexplained effect as authorized, or an anomalous technique "
                                "alone as confirmed malicious. Cite real graph IDs only.")},
                            {"role": "user", "content": (
                                self.director.review_dossier(memory, ledger_limit=12)
                                + "\n" + self.soc_v18.dossier(memory, limit=12)
                                + "\nORIGINAL PROPOSAL (untrusted interpretation):\n"
                                + render_json(proposed)[:2400]
                                + "\nUNRESOLVED CLAIMS:\n" +
                                "\n".join(f.text() for f in missing) +
                                "\n" + "\n".join(forensic_gaps) +
                                "\nEvaluate these facts against possible normal and attack causes. "
                                "Submit final verdict and observed evidence.")},
                        ]
                        reviewed = await self.llm.next_step(challenge, finish_only=True)
                        if reviewed.function.tool == "finish_investigation":
                            candidate = reviewed.function.model_dump(mode="json", by_alias=True,
                                        exclude={"tool"}, exclude_none=True).get("submission", {})
                            sanitized, _ = self.soc_v18.sanitize(candidate, memory)
                            required = ("ir_artifacts" if candidate.get("verdict") == "malicious"
                                        else "legitimacy_evidence")
                            # Reject an alternative verdict founded on invented evidence;
                            # no majority voting or automatic malicious fallback.
                            if sanitized.get(required):
                                step = reviewed
                            else:
                                logger.warning("V18 fact challenge supplied no grounded evidence; "
                                               "retaining original proposal.")
                        logger.info("V18 independent fact challenge completed ({} gaps).", len(missing))
                    except Exception as exc:
                        logger.warning("V18 independent fact challenge unavailable: {}", exc)
            # V23: one SOURCE-GROUNDED semantic critique after the entire
            # investigator/reviewer/arbitrator path. An agreeing blind reviewer
            # cannot transform inferred approval into an observed fact.
            if (self.soc_v23_mode and self.semantic_validator is not None and
                    step.function.tool == "finish_investigation"):
                revision = case_state.revision(memory) if case_state else ""
                proposed = step.function.model_dump(
                    mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                ).get("submission", {})
                issues = self.semantic_validator.issues(memory, proposed)
                if proposed.get("verdict") == "benign":
                    seen_benign_issues.extend(issues)
                critical = [i for i in issues if i.weight >= 5]
                if critical and v23_challenge_revision != revision:
                    v23_challenge_revision = revision
                    transcript.append({"role": "audit", "content": render_json({
                        "v23_semantic_issues": [x.text() for x in critical[:5]],
                        "evidence_revision": revision,
                    })})
                    try:
                        prompt = [
                            {"role": "system", "content": (
                                "You are a skeptical DFIR fact validator. Return exactly one "
                                "schema-valid finish_investigation. Graph facts override both "
                                "earlier model opinions. No automatic malicious bias: lack of "
                                "approval proof alone does NOT prove unauthorized action. "
                                "Do not claim absent effects, tickets, task triggers or "
                                "authentication outcomes unless graph evidence establishes them. "
                                "Either support a normal workflow with real facts, or state "
                                "the evidenced attack behavior and provide valid artifacts.")},
                            {"role": "user", "content": (
                                self.director.review_dossier(memory, ledger_limit=13)[:8500]
                                + "\nCONFIRMED SOC FINDINGS:\n"
                                + self.soc_v18.dossier(memory, limit=9)[:3800]
                                + "\nUNVERIFIED ORIGINAL CLAIMS:\n"
                                + self.semantic_validator.check_text(memory, proposed)
                                + "\nORIGINAL CONCLUSION (untrusted):\n"
                                + render_json(proposed)[:2100]
                                + "\nGive a grounded revised submission, without made-up IDs.")},
                        ]
                        revised = await self.llm.next_step(prompt, finish_only=True)
                        candidate = revised.function.model_dump(
                            mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
                        ).get("submission", {})
                        sanitized, _ = self.soc_v18.sanitize(candidate, memory)
                        required = ("ir_artifacts" if sanitized.get("verdict") == "malicious"
                                    else "legitimacy_evidence")
                        remaining = self.semantic_validator.issues(memory, sanitized)
                        # Never accept an alternative verdict based on nonexistent
                        # evidence. Accept either an actually repaired claim or
                        # a grounded alternative hypothesis.
                        if (sanitized.get(required) and
                                (len([i for i in remaining if i.weight >= 5]) < len(critical))):
                            step = revised
                            transcript.append({"role": "audit", "content": render_json({
                                "v23_revised_verdict": sanitized.get("verdict"),
                                "v23_remaining_claim_issues": [i.code for i in remaining],
                            })})
                    except Exception as exc:
                        logger.warning("V23 semantic validation unavailable: {}", exc)
            # v24 independent behavioral review: checks the retrieved action
            # graph regardless of what the model chose to mention. This review
            # runs after the ordinary analyst, blind audit and arbitration.
            if (self.soc_v24_mode and self.threat_casebook is not None and
                    step.function.tool == 'finish_investigation'):
                revision = case_state.revision(memory) if case_state else ''
                proposal = step.function.model_dump(
                    mode='json', by_alias=True, exclude={'tool'}, exclude_none=True
                ).get('submission', {})
                missing = self.threat_casebook.challenge(memory, proposal)
                if proposal.get('verdict') == 'benign':
                    seen_benign_issues.extend(missing)
                if missing and v24_challenge_revision != revision:
                    v24_challenge_revision = revision
                    transcript.append({'role':'audit','content':render_json({
                        'v24_action_audit': [i.text() for i in missing[:5]],
                        'v24_verified_actions':len(self.threat_casebook.observed_actions(memory)),
                        'v24_revision':revision,
                    })})
                    try:
                        examination=[
                          {'role':'system','content':(
                            'You are an independent DFIR behavior examiner, not a vote-counter. '
                            'Return one schema-valid finish_investigation. Verified events in the '
                            'mandatory ledger must be explained individually. Evidence of attack '
                            'requires actual causal behavior; absence of approval alone is NOT proof '
                            'of wrongdoing. Do not invent negative facts, benign change tickets, '
                            'authorization, missing execution or absent logons. Cite only verified IDs. '
                            'A previous verdict is not ground truth.')},
                          {'role':'user','content':(
                            self.threat_casebook.dossier(memory,limit=12)[:6800]
                            +'\nVERIFIED INCIDENT HYPOTHESES:\n'
                            +self.soc_v18.dossier(memory,limit=8)[:4300]
                            +'\nUNACCOUNTED ACTIONS:\n'
                            +'\n'.join(i.text() for i in missing[:5])
                            +'\nPRIOR CANDIDATE (NOT AUTHORITATIVE):\n'
                            +render_json(proposal)[:1600]
                            +'\nCompare H_attack and H_normal independently. '
                            'An actual PsExec-family control pipe, explicit alternate '
                            'SMB credential use or unexplained cross-protocol administration '
                            'cannot be dismissed by a Microsoft signature.')},
                        ]
                        correction=await self.llm.next_step(examination,finish_only=True)
                        proposed=correction.function.model_dump(
                            mode='json',by_alias=True,exclude={'tool'},exclude_none=True
                        ).get('submission',{})
                        fixed,_=self.soc_v18.sanitize(proposed,memory)
                        still=self.threat_casebook.challenge(memory,fixed)
                        if fixed.get('verdict') == 'malicious':
                            artifacts=fixed.get('ir_artifacts') or []
                            anchors={a.actor for a in self.threat_casebook.observed_actions(memory)}
                            anchors.update(a.target for a in self.threat_casebook.observed_actions(memory))
                            # Do not accept a new malicious theory citing only
                            # an unrelated host or arbitrary search result.
                            grounded=any(isinstance(a,dict) and a.get('entity_id') in anchors
                                         for a in artifacts)
                            critical_attack_claims = (
                                self.semantic_validator.issues(memory, fixed)
                                if self.semantic_validator is not None else []
                            )
                            accept=bool(artifacts and grounded and
                                        not any(i.weight >= 5 for i in critical_attack_claims))
                        else:
                            accept=bool(fixed.get('legitimacy_evidence')) and len(still)<len(missing)
                        if accept:
                            step=correction
                            transcript.append({'role':'audit','content':render_json({
                                'v24_behavioral_revision':fixed.get('verdict'),
                                'v24_remaining_gaps':[i.code for i in still],
                            })})
                    except Exception as exc:
                        logger.warning('V24 behavioral review unavailable: {}',exc)
            tool_name = step.function.tool
            arguments = step.function.model_dump(
                mode="json", by_alias=True, exclude={"tool"}, exclude_none=True
            )
            tool_name, arguments, route_note = self._route(
                tool_name, arguments, memory, available_tools
            )
            if tool_name == "finish_investigation" and self.soc_v18_mode:
                sub, removed = self.soc_v18.sanitize(arguments.get("submission", {}), memory)
                arguments = {"submission": sub}
                if removed:
                    logger.warning("V18: removed {} unsupported final evidence references.", removed)
                    transcript.append({"role": "audit", "content": render_json({
                        "v18_evidence_sanitized": removed})})
            if tool_name == "finish_investigation":
                arguments, assessment = self._reconcile_final(
                    arguments, memory, external_graph=(observed_graph if
                    self.harvest_profile in ({"inbound_guard"} | PHASE_L_MODES) else None))
                if assessment:
                    logger.warning("Incident guard: {}", assessment)
                if self.soc_v18_mode:
                    vetted, removed = self.soc_v18.sanitize(arguments.get("submission", {}), memory)
                    if removed:
                        arguments = {"submission": vetted}
                        logger.warning("V18 final post-guard validation removed {} unsupported "
                                       "references.", removed)
            if tool_name == "finish_investigation" and self.soc_v21_mode:
                replacement = corroborated_submission(
                    memory, self.soc_v18, arguments.get("submission", {}))
                if replacement is not None:
                    vetted, removed = self.soc_v18.sanitize(replacement, memory)
                    if vetted.get("ir_artifacts"):
                        arguments = {"submission": vetted}
                        transcript.append({"role": "audit", "content": render_json({
                            "v21_corroborated_execution": vetted.get("reasoning", ""),
                            "artifact_count": len(vetted["ir_artifacts"]),
                            "invalid_references": removed,
                        })})
                        logger.warning("V21: independently corroborated executed memory payload; "
                                       "rejecting unsupported benign narrative")
            if route_note:
                logger.info(route_note)
            # Follow a CONFIRMED effect endpoint when the model is merely
            # enumerating more relations of a process it has already sampled.
            tool_name, arguments, effect_note = self._prefer_effect_endpoint(
                tool_name, arguments, memory, available_tools
            )
            if effect_note:
                route_note = f"{route_note or ''} {effect_note}".strip()
                logger.info(effect_note)
            # Small models can get stuck re-opening the same entity; recover
            # deterministically using an unvisited, relevant neighboring edge.
            tool_name, arguments, recovery_note = self._recover_duplicate(
                tool_name, arguments, memory, available_tools
            )
            if recovery_note:
                route_note = f"{route_note or ''} {recovery_note}".strip()
                logger.info(recovery_note)
            notes = step.current_state.strip()
            notes_changed = bool(notes) and notes != "(no notes)" and notes != last_notes
            if notes_changed:
                last_notes = notes
            if notes_changed or len(memory.known_ids) > known_before:
                stale_steps = 0
            else:
                stale_steps += 1
            known_before = len(memory.known_ids)
            tool_call_id = f"step_{step_index}"
            assistant = {
                "role": "assistant",
                "content": f"{last_notes}\nNext: {step.plan_remaining_steps_brief[0]}",
                "tool_calls": [
                    {
                        "type": "function",
                        "id": tool_call_id,
                        "function": {"name": tool_name, "arguments": render_json(arguments)},
                    }
                ],
            }
            messages.append(assistant)
            transcript.append(assistant)

            feedback = self._local_check(
                tool_name, arguments, available_tools, memory, finish_rejections
            )
            if feedback is not None:
                if tool_name == "finish_investigation":
                    finish_rejections += 1
                    if self.soc_v23_mode and "strong observed attack indicators" in str(feedback.get("message", "")):
                        v23_recent_rejection = str(feedback.get("message", ""))
                        transcript.append({"role": "audit", "content": render_json({
                            "v23_finish_rejected": v23_recent_rejection[:950],
                            "v23_rejection_count": finish_rejections,
                        })})
            else:
                key = InvestigationMemory.cache_key(tool_name, arguments)
                if key in memory.cache:
                    duplicate_streak += 1
                    feedback = dict(memory.cache[key])
                    feedback["note"] = (
                        f"DUPLICATE #{duplicate_streak}: you already made this exact call, "
                        "the result is repeated above. Do NOT call it again. Open an id "
                        "from 'Not yet explored ids' or call finish_investigation."
                    )
                    if duplicate_streak >= 3:
                        feedback["note"] += (
                            " You are looping. Call finish_investigation NOW with the "
                            "evidence you already have."
                        )
                    logger.info("Served duplicate {} from cache.", tool_name)
                else:
                    if tool_name == "finish_investigation":
                        if case_state is not None:
                            case_state.move("SUBMIT")
                            transcript.append({"role": "audit", "content": render_json({
                                "v20_phase": "SUBMIT", "revision": case_state.revision(memory),
                                "review_current": case_state.review_current(memory),
                                "state_history": case_state.phase_history})})
                        if self.v25_response_mode and self.v25_hard_codes:
                            # v27 arbiter: a weak LLM must not wave away a verified
                            # high-risk action that its benign story leaves unexplained.
                            sub0 = arguments.get("submission", {})
                            issues: list[Any] = []
                            try:
                                if self.threat_casebook is not None:
                                    issues += list(self.threat_casebook.challenge(memory, sub0))
                                if self.semantic_validator is not None:
                                    issues += list(self.semantic_validator.issues(memory, sub0))
                            except Exception as exc:
                                logger.warning("v27 arbiter unavailable: {}", exc)
                            # v28: a finding raised earlier still counts even if the final
                            # benign wording no longer triggers the detector.
                            issues = issues + seen_benign_issues
                            flipped = benign_to_malicious(
                                sub0, issues, self.v25_hard_codes, observed_graph)
                            if flipped is not None:
                                logger.warning("v27 arbiter: benign -> malicious ({})",
                                               [i.code for i in issues])
                                transcript.append({"role": "audit", "content": render_json({
                                    "v27_arbiter_flip": [getattr(i, "code", "") for i in issues]})})
                                arguments = {"submission": flipped}
                        if (self.v25_response_mode and self.v25_benign_anchors
                                and arguments.get("submission", {}).get("verdict") == "benign"):
                            # v27: open the object that authorizes the activity and cite it.
                            done_b: set[str] = set()
                            focus = list(observed_graph.trigger_ids) + [
                                e.get("entity_id") for e in
                                arguments["submission"].get("legitimacy_evidence") or []
                                if e.get("entity_id")]
                            budget_b = (0 if harvested else
                                        min(self.v25_benign_calls, self.max_steps - step_index - 1))
                            for _ in range(max(0, budget_b)):
                                pivots = benign_anchor_pivots(observed_graph, focus, done_b)
                                if not pivots:
                                    break
                                pv_tool, pv_args, pv_why = pivots[0]
                                done_b.add(pivot_key(pv_tool, pv_args))
                                if pv_tool not in available_tools:
                                    continue
                                pv_args = {**pv_args, "reasoning": f"v27 legitimacy anchor: {pv_why}"}
                                pv_resp = await session.call_tool(pv_tool, pv_args)
                                transcript.append({"role": "audit", "content": render_json({
                                    "v27_anchor_call": {"tool": pv_tool, "arguments": pv_args},
                                    "runtime_reward": pv_resp.reward})})
                                if pv_resp.task_result is not None:
                                    return TaskResult.model_validate(pv_resp.task_result)
                                pv_feedback = self._tool_feedback(pv_resp)
                                observed_graph.absorb(pv_feedback.get("result"))
                                memory.absorb(pv_feedback.get("result"))
                                memory.calls_made.append(self._call_label(pv_tool, pv_args))
                                target = pv_args.get(LOOKUP_ID_ARGS.get(pv_tool, ""))
                                if isinstance(target, str):
                                    memory.fetched_ids.add(target)
                                transcript.append({"role": "tool",
                                                   "content": render_json(shrink(pv_feedback))})
                            anchored = merge_benign(arguments["submission"], observed_graph,
                                                  limit=self.v25_benign_max_evidence)
                            if anchored is not arguments["submission"]:
                                transcript.append({"role": "audit", "content": render_json({
                                    "v27_anchor_evidence": anchored.get("legitimacy_evidence")})})
                                arguments = {"submission": anchored}
                        # No early positional truncation: it used to retain
                        # LLM-selected relation citations and discard better
                        # host/user anchors. Final merge_benign ranks observed
                        # entity evidence first, THEN applies the 2/3 cap.
                        if (self.v25_response_mode
                                and arguments.get("submission", {}).get("verdict") == "malicious"):
                            # v25 scoping burst: a few deterministic calls adjacent to the
                            # attacker's processes, so the response covers the blast radius.
                            seeds = [a.get("entity_id") for a in
                                     arguments["submission"].get("ir_artifacts") or []]
                            seeds = [s for s in seeds if isinstance(s, str)]
                            done: set[str] = set()
                            budget = min(self.v25_scope_calls, self.max_steps - step_index - 1,
                                         max(0, 10 - len(memory.calls_made) - 1)
                                         if harvested else self.v25_scope_calls)
                            for _ in range(max(0, budget)):
                                pivots = scoping_pivots(
                                    observed_graph, seeds + list(observed_graph.trigger_ids), done)
                                if not pivots:
                                    break
                                pv_tool, pv_args, pv_why = pivots[0]
                                done.add(pivot_key(pv_tool, pv_args))
                                if pv_tool not in available_tools:
                                    continue
                                pv_args = {**pv_args, "reasoning": f"v25 scoping: {pv_why}"}
                                pv_resp = await session.call_tool(pv_tool, pv_args)
                                transcript.append({"role": "audit", "content": render_json({
                                    "v25_scope_call": {"tool": pv_tool, "arguments": pv_args},
                                    "runtime_reward": pv_resp.reward})})
                                if pv_resp.task_result is not None:
                                    return TaskResult.model_validate(pv_resp.task_result)
                                pv_feedback = self._tool_feedback(pv_resp)
                                observed_graph.absorb(pv_feedback.get("result"))
                                memory.absorb(pv_feedback.get("result"))
                                memory.calls_made.append(self._call_label(pv_tool, pv_args))
                                target = pv_args.get(LOOKUP_ID_ARGS.get(pv_tool, ""))
                                if isinstance(target, str):
                                    memory.fetched_ids.add(target)
                                transcript.append({"role": "tool",
                                                   "content": render_json(shrink(pv_feedback))})
                        if self.v25_response_mode:
                            original = arguments.get("submission", {})
                            merged = merge_submission(
                                original, observed_graph, max_tier=self.v25_response_tier
                            )
                            if merged is not original:
                                transcript.append({"role": "audit", "content": render_json({
                                    "v25_llm_artifacts": original.get("ir_artifacts"),
                                    "v25_final_artifacts": merged.get("ir_artifacts"),
                                })})
                                arguments = {"submission": merged}
                        # Final deterministic policy applies even when the old
                        # v25 response flags are disabled. No additional tool
                        # calls: only entities and edges already observed.
                        final_submission = arguments.get("submission") or {}
                        if final_submission.get("verdict") == "malicious":
                            arguments = {"submission": merge_submission(
                                final_submission, observed_graph,
                                max_tier=self.v25_response_tier)}
                        elif final_submission.get("verdict") == "benign":
                            ranked = merge_benign(
                                final_submission, observed_graph,
                                limit=self.v25_benign_max_evidence)
                            transcript.append({"role": "audit", "content": render_json({
                                "benign_evidence_ranked": ranked.get("legitimacy_evidence"),
                                "benign_evidence_prior_count": len(
                                    final_submission.get("legitimacy_evidence") or []),
                            })})
                            arguments = {"submission": ranked}
                        # Pure report A/B switch: the same investigation, verdict,
                        # reconciliation and mapper run for every arm. Only the
                        # completed submission is varied, and no tool is called.
                        baseline_report = arguments.get("submission") or {}
                        ablated_report = apply_report_experiment(
                            baseline_report, observed_graph, self.harvest_profile,
                            benign_limit=self.v25_benign_max_evidence,
                        )
                        if self.drop_deleted_file_artifacts:
                            ablated_report, dropped_deleted = drop_deleted_file_artifacts(
                                ablated_report, observed_graph)
                            if dropped_deleted:
                                logger.info("Dropped actions on already deleted files: {}",
                                            dropped_deleted)
                        transcript.append({"role": "audit", "content": render_json({
                            "report_experiment": self.report_experiment,
                            "report_probe_diagnostics": report_probe_diagnostics(observed_graph)
                                if self.report_experiment in PHASE_I_MODES else {},
                            "phaseL_probe_diagnostics": phaseL_probe_diagnostics(
                                observed_graph, self.report_experiment),
                            "report_before": baseline_report,
                            "report_after": ablated_report,
                            "report_changed_fields": sorted(
                                k for k in set(baseline_report) | set(ablated_report)
                                if baseline_report.get(k) != ablated_report.get(k)
                            ),
                        })})
                        if self.report_experiment in {"benign_probe", "benign_probe2"} and \
                                ablated_report.get("verdict") == "benign":
                            seed = str(session.task_id)
                            for probe_tool, probe_args, label in context_calls(observed_graph):
                                probe_response = await session.call_tool(probe_tool, probe_args)
                                probe_result = public_evidence(
                                    self._tool_feedback(probe_response).get("result"))
                                observed_graph.absorb(probe_result)
                                transcript.append({"role": "audit", "content": render_json({
                                    "phase": "benign_context", "tool": probe_tool,
                                    "explore_category": label, "arguments": probe_args,
                                    "result": probe_result,
                                    "runtime_reward": probe_response.reward})})
                                if probe_response.task_result is not None:
                                    transcript.append({"role": "tool", "content": "terminal"})
                                    return TaskResult.model_validate(probe_response.task_result)
                            if self.report_experiment == "benign_probe2":
                                probed_report, probe = apply_benign_probe_extra(
                                    apply_role_policy(ablated_report, observed_graph),
                                    observed_graph, seed)
                            else:
                                probed_report, probe = apply_benign_probe(
                                    ablated_report, observed_graph, seed)
                            transcript.append({"role": "audit", "content": render_json({
                                "benign_probe_design": probe,
                                "benign_probe_before": ablated_report,
                                "report_after": probed_report,
                            })})
                            ablated_report = probed_report
                        # benign_probe keeps the role_policy report for malicious tasks.
                        if self.report_experiment == "role_policy" or (
                                self.report_experiment in {"benign_probe", "benign_probe2"}
                                and ablated_report.get("verdict") == "malicious"):
                            policy_report = apply_role_policy(ablated_report, observed_graph)
                            transcript.append({"role": "audit", "content": render_json({
                                "role_policy_before": ablated_report,
                                "report_after": policy_report,
                            })})
                            ablated_report = policy_report
                        if self.report_experiment == "random_probe":
                            probed_report, probe = apply_random_probe(
                                ablated_report, observed_graph, str(session.task_id))
                            transcript.append({"role": "audit", "content": render_json({
                                "probe_design": probe,
                                "probe_report_before": ablated_report,
                                "report_after": probed_report,
                            })})
                            ablated_report = probed_report
                        if self.report_experiment == "explore_probe":
                            # Report is already fixed above; extra opens cannot change it.
                            seed = str(session.task_id)
                            probe_graph = copy.deepcopy(observed_graph)
                            expand = expand_design(probe_graph, seed)
                            for item in expand:
                                if not item["enabled"]:
                                    continue
                                probe_args = {"query": item["entity_id"],
                                              "reasoning": "explore:expand_child effects"}
                                probe_response = await session.call_tool("search", probe_args)
                                probe_result = public_evidence(
                                    self._tool_feedback(probe_response).get("result"))
                                probe_graph.absorb(probe_result)
                                transcript.append({"role": "audit", "content": render_json({
                                    "phase": "explore_probe", "tool": "search",
                                    "explore_category": "expand_child",
                                    "arguments": probe_args, "result": probe_result,
                                    "runtime_reward": probe_response.reward})})
                                if probe_response.task_result is not None:
                                    transcript.append({"role": "tool", "content": "terminal"})
                                    return TaskResult.model_validate(probe_response.task_result)
                            plan = explore_design(probe_graph, seed)
                            plan["expand"] = expand
                            transcript.append({"role": "audit", "content": render_json({
                                "explore_design": plan})})
                            for category, entity_id in plan["calls"]:
                                probe_args = {"entity_id": entity_id,
                                              "reasoning": f"explore:{category}"}
                                probe_response = await session.call_tool("get_entity", probe_args)
                                probe_feedback = self._tool_feedback(probe_response)
                                transcript.append({"role": "audit", "content": render_json({
                                    "phase": "explore_probe", "tool": "get_entity",
                                    "explore_category": category, "arguments": probe_args,
                                    "result": public_evidence(probe_feedback.get("result")),
                                    "runtime_reward": probe_response.reward})})
                                if probe_response.task_result is not None:
                                    transcript.append({"role": "tool", "content": "terminal"})
                                    return TaskResult.model_validate(probe_response.task_result)
                        arguments = {"submission": ablated_report}
                        logger.info("Submitting: {}", render_json(arguments))
                    response = await session.call_tool(tool_name, arguments)
                    # Practice diagnostics only: keep the runtime's per-call signal for
                    # offline analysis. The agent's decisions must not depend on it.
                    transcript.append({"role": "audit", "content": render_json({
                        "runtime_reward": response.reward,
                        "runtime_info_keys": sorted((response.info or {}).keys()),
                        # Offline diagnostics: the full terminal response, in case the
                        # runtime explains the score. Written after the last call, so
                        # it can never influence this episode.
                        **({"finish_observation": response.observation,
                            "finish_info": response.info,
                            "finish_task_result": response.task_result.model_dump()
                            if response.task_result is not None else None}
                           if tool_name == "finish_investigation" else {}),
                    })})
                    if response.task_result is not None:
                        transcript.append({"role": "tool", "content": "terminal"})
                        return TaskResult.model_validate(response.task_result)
                    duplicate_streak = 0
                    feedback = self._tool_feedback(response)
                    observed_graph.absorb(feedback.get("result"))
                    before_evidence = (len(memory.observed_nodes), len(memory.graph_edges))
                    memory.absorb(feedback.get("result"))
                    after_evidence = (len(memory.observed_nodes), len(memory.graph_edges))
                    if after_evidence == before_evidence:
                        low_information_steps += 1
                    else:
                        low_information_steps = 0
                    feedback = shrink(feedback)
                    memory.cache[key] = feedback
                    target = arguments.get(LOOKUP_ID_ARGS.get(tool_name, ""))
                    if isinstance(target, str):
                        memory.fetched_ids.add(target)
                    if tool_name == "get_relation":
                        memory.opened_rel_types[memory.relation_types.get(target, "")] += 1
                    memory.calls_made.append(self._call_label(tool_name, arguments))
                    logger.info("Tool {} returned {}.", tool_name, feedback.get("status"))

            feedback = dict(feedback)
            if route_note:
                feedback["note"] = f"{route_note} {feedback.get('note', '')}".strip()
            feedback["budget"] = f"{step_index}/{self.max_steps} steps used"
            if low_information_steps >= 2:
                feedback["information_gain_warning"] = (
                    "Repeated observations added no new graph objects or relations. "
                    "Change the causal question or finish; do not enumerate a hub."
                )
            explored = len(memory.fetched_ids - memory.trigger_ids)
            if step_index >= 0.75 * self.max_steps:
                feedback["warning"] = "Budget almost spent: finish NOW with what you have."
            elif explored >= self.enough_to_decide:
                feedback["warning"] = (
                    f"You have opened {explored} graph objects around the trigger — that is "
                    "enough to decide. Review your playbook checklist and call "
                    "finish_investigation unless a specific lead is still open."
                )
            elif stale_steps >= self.max_stale_steps // 2:
                feedback["warning"] = (
                    f"Your notes have not changed for {stale_steps} steps: these calls add "
                    "nothing. Change direction or finish."
                )
            tool_message = {
                "role": "tool",
                "content": render_json(feedback),
                "tool_call_id": tool_call_id,
            }
            messages.append(tool_message)
            transcript.append(tool_message)
            self._elide(messages)
            self._save_partial(session, transcript)

        raise RuntimeError(
            f"Agent hit the {self.max_steps}-step limit without finish_investigation."
        )

    async def _arbitrate(self, messages: list[dict[str, Any]], transcript: list[dict[str, Any]],
                         label: str) -> Any:
        """Settle a verdict disagreement, with the optional arbiter model.

        Falls back to the main model if the arbiter fails, so a flaky remote API
        never changes the behaviour of the calibrated pipeline. When shadowing is
        on, the main model answers the same prompt too; its verdict is only logged
        for offline comparison and never used.
        """
        if self.arbiter_llm is None:
            return await self.llm.next_step(list(messages), finish_only=True)
        record: dict[str, Any] = {"arbiter_call": label,
                                  "arbiter_model": getattr(self.arbiter_llm, "model", None)}
        try:
            step = await self.arbiter_llm.next_step(list(messages), finish_only=True)
            record["source"] = "arbiter"
        except Exception as exc:
            logger.warning("Arbiter model unavailable ({}); main model arbitrates.", exc)
            record["source"] = "fallback_main"
            record["error"] = str(exc)[:300]
            step = await self.llm.next_step(list(messages), finish_only=True)
        record["verdict"] = getattr(getattr(step.function, "submission", None), "verdict", None)
        if self.arbiter_shadow and record["source"] == "arbiter":
            try:
                shadow = await self.llm.next_step(list(messages), finish_only=True)
                record["shadow_main_verdict"] = getattr(
                    getattr(shadow.function, "submission", None), "verdict", None)
            except Exception as exc:
                record["shadow_error"] = str(exc)[:300]
        logger.info("Arbitration ({}): {} via {}.", label, record.get("verdict"), record["source"])
        transcript.append({"role": "audit", "content": render_json(record)})
        return step

    async def _recover_structured_step(
        self,
        memory: InvestigationMemory,
        transcript: list[dict[str, Any]],
        *,
        error: NextStepRequestError,
    ) -> Any:
        """Recover a truncated/invalid Qwen reply with a fresh bounded verdict.

        Original alert and verified graph remain; the corrupted model response,
        earlier opinions, and repeated tool-output bodies are deliberately absent.
        The model must still select the verdict and cite facts. A failed recovery
        raises normally rather than fabricating a result or a case-specific label.
        """
        logger.warning("Structured model step failed; retrying with compact verified evidence: {}", error)
        transcript.append({"role": "audit", "content": render_json({
            "recovery": "structured_output_error",
            "cause": str(error)[:300],
        })})
        compact_review = self.director.review_dossier(memory, ledger_limit=10)
        # Two bounded attempts: the second is even smaller, never a replay of
        # the malformed answer. Both use the public finish-only JSON contract.
        for max_chars in (8500, 4800):
            messages = [
                {"role": "system", "content": (
                    "You are a SOC analyst. Produce a valid structured "
                    "finish_investigation submission using ONLY the verified evidence "
                    "below. Choose malicious or benign based on what actually occurred "
                    "and its causal context. No further investigation tools. "
                    "Avoid quoting long scripts or repeating paths unnecessarily; "
                    "a concise reasoning string and grounded IDs are sufficient. "
                    "Do not assume a signed/system process is authorized, or that a "
                    "suspicious filename alone proves compromise."
                )},
                {"role": "user", "content": (
                    "The previous generation could not be parsed. This is a NEW "
                    "independent short final assessment, not a request to repair or "
                    "repeat its malformed output. Use only confirmed IDs and fields.\n\n"
                    + compact_review[:max_chars]
                    + "\n\nReturn one finish_investigation now."
                )},
            ]
            try:
                result = await self.llm.next_step(messages, finish_only=True)
                if result.function.tool == "finish_investigation":
                    logger.info("Recovered malformed LLM step with compact final review.")
                    return result
            except NextStepRequestError:
                logger.warning("Bounded structured recovery attempt failed (limit {}).", max_chars)
        raise error

    def _merge_agreed_evidence(
        self,
        investigator: dict[str, Any],
        reviewer: dict[str, Any],
        memory: InvestigationMemory,
    ) -> dict[str, Any]:
        """Preserve grounded primary citations when two independent verdicts agree.

        Prior versions sent only the reviewer's often shorter artifact/evidence
        list, discarding work collected by the investigator. Merge corroborated
        *observed* references without changing verdict or inventing entities.
        """
        result = dict(investigator)
        verdict = result.get("verdict")
        if verdict not in {"malicious", "benign"} or reviewer.get("verdict") != verdict:
            return result
        field = "ir_artifacts" if verdict == "malicious" else "legitimacy_evidence"
        originals = result.get(field) or []
        additions = reviewer.get(field) or []
        combined: list[dict[str, Any]] = []
        seen: set[str] = set()
        distances = self.director.causal_distance(memory)
        for item in [*originals, *additions]:
            if not isinstance(item, dict):
                continue
            anchor = item.get("anchor", "entity")
            entity_id = item.get("entity_id") if anchor == "entity" else item.get("relation_id")
            if not isinstance(entity_id, str) or entity_id not in memory.observed_nodes:
                continue
            if verdict == "malicious" and entity_id in memory.relation_ids:
                continue
            if verdict == "benign":
                if anchor not in {"entity", "relation"}:
                    continue
                if (anchor == "entity") == (entity_id in memory.relation_ids):
                    continue
                node = memory.observed_nodes[entity_id]
                props = node.get("properties") or {}
                fields = item.get("property_fields") or []
                available = set(node) | (set(props) if isinstance(props, dict) else set())
                if not fields or any(f not in available for f in fields):
                    continue
            # A newly suggested artifact must be a real observed participant in
            # the alert subgraph; identity/host hubs do not establish causality.
            corroborated = entity_id in distances
            if not corroborated and anchor == "relation" and entity_id in memory.graph_edges:
                _, source, target = memory.graph_edges[entity_id]
                corroborated = source in distances or target in distances
            if item in additions and item not in originals and not corroborated:
                continue
            key = f"{anchor}:{entity_id}"
            if key not in seen:
                seen.add(key)
                combined.append(item)
            if len(combined) == 10:
                break
        if combined:
            result[field] = combined
        return result

    @staticmethod
    def _reconcile_final(
        arguments: dict[str, Any], memory: InvestigationMemory,
        external_graph: ObservedGraph | None = None,
    ) -> tuple[dict[str, Any], str | None]:
        """Correct only decisive contradictions, never infer intent from a name.

        Verify the model's cited benign fields exist. Directly observed destructive
        actions cannot be described as routine solely because a binary is signed.
        """
        sub = arguments.get("submission") or {}
        if not isinstance(sub, dict):
            return arguments, None
        signals = detect_attack_signals(memory.observed_nodes, memory.graph_edges, memory.trigger_ids)
        strong = decisive_signals(signals)
        if external_graph is not None:
            strong.extend(external_peer_signals(external_graph))
        verdict = sub.get("verdict")
        if verdict == "malicious":
            contradiction = unsupported_malicious_contradiction(
                str(sub.get("reasoning") or ""), memory.observed_nodes, memory.graph_edges)
            if contradiction:
                return {"submission": {
                    "verdict": "benign", "legitimacy_evidence": [],
                    "reasoning": ("No observed causal attack effects support the claimed "
                                  "malicious explanation; " + contradiction + "."),
                }}, "rejected unsupported malicious: " + contradiction
            sub, adjusted = validate_artifact_types(sub, memory)
            if adjusted:
                arguments = {"submission": sub}
        if verdict == "benign" and strong:
            kinds = ", ".join(dict.fromkeys(s.name for s in strong))
            evidence_graph = ObservedGraph()
            evidence_graph.absorb(list(memory.observed_nodes.values()))
            evidence_graph.trigger_ids = [nid for nid in memory.focus_ids
                                          if evidence_graph.etype(nid) in {"windows_process", "linux_process"}]
            artifacts = merge_submission({"verdict": "malicious", "ir_artifacts": [],
                                          "reasoning": "structural attack signals"},
                                         evidence_graph).get("ir_artifacts", [])
            if artifacts:
                return {"submission": {
                    "verdict": "malicious", "ir_artifacts": artifacts,
                    "reasoning": (
                        f"Observed high-risk activity contradicts a routine benign verdict: {kinds}. "
                        "These actions are not made safe by a valid signer or administrative account."
                    ),
                }}, f"corrected unsupported benign verdict: {kinds}"
        if verdict == "benign":
            original = sub.get("legitimacy_evidence") or []
            repaired = []
            for item in original:
                if not isinstance(item, dict):
                    continue
                key = "entity_id" if item.get("anchor") == "entity" else "relation_id"
                nid = item.get(key)
                node = memory.observed_nodes.get(nid)
                if node is None:
                    continue
                props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
                available = set(node) | set(props)
                fields = [f for f in item.get("property_fields", []) if f in available]
                if not fields:
                    semantic = (
                        ("script_text", "cmdline", "command", "task_name", "path", "image_path")
                        if item.get("anchor") == "entity" else
                        ("operation", "action", "command", "source_id", "target_id", "type")
                    )
                    fields = [f for f in semantic if f in available][:3]
                if not fields:
                    continue
                repaired.append({"anchor": item["anchor"], key: nid, "property_fields": fields})
            # Recover DIRECTLY DESCRIBED operational citations. The model may
            # describe an observed effect in its rationale but cite only the
            # signed process. Add a real relation ONLY when the written rationale
            # identifies its affected object and a participant was already cited.
            # No verdict adjustment and no inferred authorization are allowed.
            references = repaired or original
            additions = []
            cited = {
                item.get("entity_id") or item.get("relation_id")
                for item in references if isinstance(item, dict)
            }
            explanation = str(sub.get("reasoning") or "").casefold()
            distances = InvestigationDirector.causal_distance(memory)
            import ntpath
            for rid, (kind, actor, target) in memory.graph_edges.items():
                if len(additions) >= 2 or len(references) + len(additions) >= 10:
                    break
                if (rid in cited or
                        not ({actor, target} & cited) or
                        min(distances.get(actor, 9), distances.get(target, 9)) > 2 or
                        InvestigationDirector.consequence_weight(kind) < 4):
                    continue
                node = memory.observed_nodes.get(target) or {}
                props = node.get("properties") or {}
                if not isinstance(props, dict):
                    continue
                name = str(props.get("path") or props.get("task_name") or
                           props.get("name") or props.get("share_name") or "")
                label = ntpath.basename(name.replace("/", "\\")).casefold()
                if len(label) < 5 or label not in explanation:
                    continue
                event = memory.observed_nodes.get(rid) or {}
                fields = [f for f in ("type", "source_id", "target_id") if f in event]
                if not fields:
                    continue
                additions.append({"anchor": "relation", "relation_id": rid,
                                  "property_fields": fields})
                cited.add(rid)
            if additions:
                return {"submission": {**sub, "legitimacy_evidence": [*references, *additions]}}, (
                    "added already-explained causal relation citations"
                    + (" and repaired field names" if repaired != original else ""))
            if repaired and repaired != original:
                return {"submission": {**sub, "legitimacy_evidence": repaired}}, "repaired cited field names against actual tool results"
        if verdict == "malicious" and adjusted:
            return arguments, f"corrected {adjusted} mis-typed or duplicate IR artifacts"
        return arguments, None

    def _prefer_effect_endpoint(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        memory: "InvestigationMemory",
        available_tools: set[str],
    ) -> tuple[str, dict[str, Any], str | None]:
        """Redirect low-information relation enumeration toward a REAL effect.

        Only intervenes when four relations of the same owner have already been
        opened and a stronger, observed action supplies a specific unexplored
        participant. Never invent a tool target, and never discard a relation
        already known to describe a high-consequence action.
        """
        if tool_name != "get_relation":
            return tool_name, arguments, None
        rid = arguments.get("relation_id")
        owner = memory.relation_owner.get(rid)
        if owner is None or self.director.consequence_weight(
            memory.relation_types.get(rid, "")
        ) >= 5:
            return tool_name, arguments, None
        opened = sum(1 for candidate, own in memory.relation_owner.items()
                     if own[0] == owner[0] and candidate in memory.fetched_ids)
        if opened < 4:
            return tool_name, arguments, None
        for candidate in self.director.rank_frontier(memory):
            if candidate.identifier == owner[0]:
                continue  # re-opening the already sampled owner adds little
            if candidate.tool not in {"get_entity", "get_ad_object_info"}:
                continue
            if candidate.tool not in available_tools:
                continue
            # Endpoint must be part of a directly observed consequence, not
            # any random entity that happens to be visible in the graph.
            related = [kind for kind, src, dst in memory.graph_edges.values()
                       if candidate.identifier in {src, dst}]
            is_directory = candidate.tool == "get_ad_object_info"
            if not is_directory and not any(self.director.consequence_weight(k) >= 5
                                            for k in related):
                continue
            arg_name = "ad_object_id" if is_directory else "entity_id"
            new_args = {arg_name: candidate.identifier, "reasoning": candidate.question}
            return candidate.tool, new_args, (
                "Prioritized an unexamined endpoint of a confirmed consequence "
                "over further relation enumeration."
            )
        return tool_name, arguments, None

    @staticmethod
    def _recover_duplicate(
        tool_name: str,
        arguments: dict[str, Any],
        memory: "InvestigationMemory",
        available_tools: set[str],
    ) -> tuple[str, dict[str, Any], str | None]:
        if tool_name not in LOOKUP_ID_ARGS and tool_name != "search":
            return tool_name, arguments, None
        key = InvestigationMemory.cache_key(tool_name, arguments)
        if key not in memory.cache:
            return tool_name, arguments, None
        for lead in InvestigationDirector(frontier_limit=25).rank_frontier(memory):
            candidate = lead.identifier
            owner = memory.relation_owner.get(candidate)
            if owner is not None and owner[1] in HUB_TYPES:
                continue
            if memory.relation_types.get(candidate) in {"hosts", "runs_process", "member_of"}:
                continue
            if lead.tool == "get_relation" and "get_relation" in available_tools:
                new_name, arg_name = "get_relation", "relation_id"
            elif lead.tool == "get_entity" and "get_entity" in available_tools:
                new_name, arg_name = "get_entity", "entity_id"
            elif lead.tool == "get_ad_object_info" and "get_ad_object_info" in available_tools:
                new_name, arg_name = "get_ad_object_info", "ad_object_id"
            else:
                continue
            new_args = {arg_name: candidate, "reasoning":
                        "Highest-value unexplored evidence: " + lead.question}
            if InvestigationMemory.cache_key(new_name, new_args) not in memory.cache:
                return new_name, new_args, f"Avoided repeated {tool_name}, exploring {candidate}."
        return tool_name, arguments, None

    @staticmethod
    def _route(
        tool_name: str,
        arguments: dict[str, Any],
        memory: "InvestigationMemory",
        available_tools: set[str],
    ) -> tuple[str, dict[str, Any], str | None]:
        """Send a lookup to the tool that matches the id kind, for free."""
        reasoning = arguments.get("reasoning", "lookup")
        target = arguments.get(LOOKUP_ID_ARGS.get(tool_name, ""))
        if not isinstance(target, str):
            return tool_name, arguments, None
        if (
            tool_name != "get_relation"
            and target in memory.relation_ids
            and "get_relation" in available_tools
        ):
            new = ("get_relation", {"relation_id": target, "reasoning": reasoning})
        elif (
            tool_name != "get_ad_object_info"
            and target in memory.ad_object_ids
            and target not in memory.entity_types
            and "get_ad_object_info" in available_tools
        ):
            new = ("get_ad_object_info", {"ad_object_id": target, "reasoning": reasoning})
        elif tool_name != "get_entity" and tool_name != "get_ad_object_info" and target in memory.entity_types:
            new = ("get_entity", {"entity_id": target, "reasoning": reasoning})
        else:
            return tool_name, arguments, None
        note = f"Routed {tool_name} -> {new[0]}: {target} is that kind of id."
        return new[0], new[1], note

    @staticmethod
    def _replace_finish_with_lookup(
        step: Any, tool: str, arguments: dict[str, Any], why: str
    ) -> Any:
        """A valid typed, visible action replaces an evidence-free final answer."""
        from bluesec1_agent.models import NextStep

        return NextStep.model_validate({
            "current_state": (step.current_state[:850] +
                " | Local evidence gate: " + why[:440]),
            "plan_remaining_steps_brief": ["Check a grounded causal lead, then reassess."],
            "task_completed": False,
            "function": {"tool": tool, **arguments},
        })

    def _redirect_premature_finish(
        self,
        verdict: str,
        memory: InvestigationMemory,
        available_tools: set[str],
    ) -> tuple[str, dict[str, Any], str] | None:
        """Require an actual causal chain for GPT-OSS, not just a trigger name.

        Uses only discovered graph IDs; never fabricates a lead or forces a
        verdict. If no meaningful known lead exists, the model may finish.
        """
        minimum = 8 if verdict == "benign" else 6
        count = len(memory.calls_made)
        distances = self.director.causal_distance(memory)
        important = [
            (kind, src, dst) for kind, src, dst in memory.graph_edges.values()
            if self.director.consequence_weight(kind) >= 4
            and min(distances.get(src, 5), distances.get(dst, 5)) <= 2
        ]
        unresolved = {
            endpoint for kind, src, dst in important
            if self.director.consequence_weight(kind) >= 5
            for endpoint in (src, dst)
            if (endpoint not in memory.fetched_ids
                and endpoint not in memory.relation_ids
                and memory.entity_types.get(endpoint) not in
                {"host", "windows_user", "linux_user"})
        }
        insufficient = count < minimum or not important or bool(unresolved)
        if not insufficient:
            return None
        candidates = self.director.rank_frontier(memory)
        for lead in candidates:
            if lead.tool not in available_tools:
                continue
            if lead.identifier in memory.fetched_ids or lead.identifier in memory.rejected_ids:
                continue
            # Prefer opening the actual affected entity if it remains unknown.
            # A hub host/user is not a causally discriminating investigation.
            if lead.tool == "get_entity" and memory.entity_types.get(lead.identifier) in {
                    "host", "windows_user", "linux_user"}:
                continue
            arg = LOOKUP_ID_ARGS.get(lead.tool)
            if arg is None:
                continue
            query = (f"Confirm the factual consequence and authorized scope: {lead.question}"
                     if lead.identifier in unresolved else lead.question)
            reason = f"only {count} calls; {len(important)} action edges; {len(unresolved)} unopened effect endpoints"
            return lead.tool, {arg: lead.identifier, "reasoning": query[:1300]}, reason
        # No known link left — don't fabricate an ID or exhaust the budget.
        return None

    @staticmethod
    def _repair_finish(arguments: dict[str, Any], memory: InvestigationMemory) -> list[str]:
        """Fix mechanical report errors in place instead of asking the LLM again.

        With temperature 0 the finish-only LLM repeats the same submission, so a
        rejection for a relation id / unknown id / missing field looped until the
        26-step limit and the task was aborted (Q=0).  Repairs are deterministic:
        a relation id becomes its observed target entity, otherwise it is dropped;
        unknown ids are dropped; non-existent citation fields are removed.
        """
        submission = arguments.get("submission")
        if not isinstance(submission, dict):
            return []
        notes: list[str] = []
        artifacts = submission.get("ir_artifacts")
        if isinstance(artifacts, list):
            fixed, seen = [], set()
            for item in artifacts:
                nid = item.get("entity_id") if isinstance(item, dict) else None
                if nid in memory.relation_ids:
                    rel = memory.observed_nodes.get(nid) or {}
                    target = rel.get("target_id")
                    if isinstance(target, str) and target in memory.known_ids \
                            and target not in memory.relation_ids:
                        notes.append(f"artifact relation {nid} -> target {target}")
                        nid = target
                    else:
                        notes.append(f"artifact relation {nid} dropped")
                        continue
                if not isinstance(nid, str) or nid not in memory.known_ids:
                    notes.append(f"artifact unknown id {nid} dropped")
                    continue
                key = (nid, item.get("kind"))
                if key not in seen:
                    seen.add(key)
                    fixed.append({**item, "entity_id": nid})
            submission["ir_artifacts"] = fixed
        evidence = submission.get("legitimacy_evidence")
        if isinstance(evidence, list):
            kept = []
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                ident = item.get("entity_id") or item.get("relation_id")
                if ident not in memory.known_ids:
                    notes.append(f"citation unknown id {ident} dropped")
                    continue
                observed = memory.observed_nodes.get(ident)
                fields = list(item.get("property_fields") or [])
                if observed is not None:
                    props = observed.get("properties")
                    available = set(observed) | (set(props) if isinstance(props, dict) else set())
                    good = [f for f in fields if f in available]
                    if good != fields:
                        dropped = sorted(set(fields) - set(good))
                        notes.append(f"citation {ident} fields {dropped} removed")
                    fields = good
                if item.get("anchor") == "entity" and not fields:
                    notes.append(f"citation {ident} has no valid fields, dropped")
                    continue
                kept.append({**item, "property_fields": fields})
            submission["legitimacy_evidence"] = kept
        return notes

    def _local_check(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        available_tools: set[str],
        memory: InvestigationMemory,
        finish_rejections: int,
    ) -> dict[str, Any] | None:
        """Reject bad calls locally so they never cost a server tool call."""
        if tool_name not in available_tools:
            return {
                "status": "error",
                "message": f"Tool {tool_name!r} is not advertised. "
                f"Available tools: {sorted(available_tools)}",
            }
        if tool_name == "get_relation":
            rid = arguments.get("relation_id")
            rtype = memory.relation_types.get(rid, "")
            informative = {"wrote_file", "deleted_file", "read_file", "executes",
                           "spawned", "created_process", "made_connection",
                           "network_connection", "created_service", "writes_registry"}
            if (rtype and rtype not in informative
                    and memory.opened_rel_types[rtype] >= self.max_same_relation):
                return {
                    "status": "error",
                    "message": f"You already opened {self.max_same_relation} "
                    f"'{rtype}' relations; they repeat. Stop enumerating this type — "
                    "reason about the pattern you already saw, follow a different "
                    "relation kind, or finish.",
                }
        id_arg = LOOKUP_ID_ARGS.get(tool_name)
        if id_arg is not None:
            target = arguments.get(id_arg)
            if (
                isinstance(target, str)
                and target not in memory.known_ids
                and target not in memory.rejected_ids
            ):
                memory.rejected_ids.add(target)
                return {
                    "status": "error",
                    "message": f"{id_arg} {target!r} was never returned by the alert or a "
                    "tool, so it probably does not exist. Use an id from the entity index "
                    "or your notes, or find it with search first.",
                }
        if tool_name == "finish_investigation":
            repaired = self._repair_finish(arguments, memory)
            if repaired:
                logger.warning("Finish repaired locally (no LLM retry): {}", repaired)
            guarded = finish_rejections < self.max_finish_rejections
            verdict = (arguments.get("submission") or {}).get("verdict")
            # Only strong observed activity triggers a challenge. Weak suspicious
            # strings (encoded command, Temp binary, public IP, archive, etc.) may
            # be genuine forensic or administrative activity.
            if guarded and verdict == "benign" and memory.strongly_suspicious():
                labels = "; ".join(memory.strongly_suspicious())
                return {
                    "status": "error",
                    "message": "The case includes strong observed attack indicators: "
                    f"{labels}. Before a benign verdict, inspect the causal behavior "
                    "and explain specific benign context for these facts. If this is "
                    "an attack, submit malicious with precise IR artifacts.",
                }
            explored = len(memory.fetched_ids - memory.trigger_ids)
            if (guarded and verdict == "benign"
                    and explored < self.min_entities_before_benign
                    and bool(self.director.rank_frontier(memory))):
                return {
                    "status": "error",
                    "message": f"Only {explored} nodes or edges beyond the trigger inspected. "
                    "Verify child activity and changes to files/network, then cite "
                    "their concrete benign behavior instead of names/signatures.",
                }
            unknown = [i for i in submission_ids(arguments) if i not in memory.known_ids]
            if unknown:
                return {
                    "status": "error",
                    "message": "Submission cites ids never returned by the alert or a tool: "
                    f"{unknown}. Use only ids you have seen, or investigate them first.",
                }
            if verdict == "benign":
                evidence = arguments["submission"].get("legitimacy_evidence", [])
                invalid = []
                for item in evidence:
                    identifier = item.get("entity_id") or item.get("relation_id")
                    observed = memory.observed_nodes.get(identifier, {})
                    props = observed.get("properties")
                    available = set(observed) | (set(props) if isinstance(props, dict) else set())
                    missing = set(item.get("property_fields", [])) - available
                    if identifier in memory.observed_nodes and missing:
                        invalid.append((identifier, sorted(missing)))
                if invalid:
                    return {
                        "status": "error",
                        "message": (f"Benign citation fields do not exist: {invalid}. "
                        "Use the ACTUAL observed field names; cite causal evidence."),
                    }
                meaningful = {
                    "cmdline", "path", "file_path", "name", "image_path", "target_id",
                    "source_id", "dst_ip", "remote_ip", "domain", "write_mode",
                    "operation", "query", "script", "script_block_text", "command",
                    "arguments", "user", "remote_port", "dst_port", "description",
                }
                cited = {f for item in evidence for f in item.get("property_fields", [])}
                if guarded and evidence and not (cited & meaningful):
                    return {
                        "status": "error",
                        "message": "Benign citations are only signatures/metadata/log sources. "
                        "Provide observed behavior (e.g. commands, file/network operations "
                        "and their relation endpoints), or investigate further.",
                    }
            if verdict == "malicious":
                invalid_artifacts = [a for a in arguments["submission"].get("ir_artifacts", [])
                                     if a.get("entity_id") in memory.relation_ids]
                if invalid_artifacts:
                    return {"status": "error", "message":
                            "IR artifacts require ENTITY IDs, not relation IDs. "
                            f"Replace: {invalid_artifacts}"}
        return None

    def _request_messages(
        self, messages: list[dict[str, Any]], memory: InvestigationMemory,
        *, remaining_steps: int = 12,
    ) -> list[dict[str, Any]]:
        """Provide verified behavioral evidence and adaptive discriminating questions.

        Avoid a long UUID inventory / fixed playbook. The graph is the case file,
        the director tracks what it does and does not establish.
        """
        signals = signal_context(detect_attack_signals(
            memory.observed_nodes, memory.graph_edges, memory.trigger_ids))
        context = [self.director.situation(memory, remaining_steps=remaining_steps)]
        if signals:
            context.append("Observed candidate signals (verify intent/causality):\n" + signals)
        if self.v16_mode or self.security_mode:
            context.append(self.workbench.digest(memory, limit=7))
        if self.security_mode:
            context.append(self.security.dossier(memory, limit=7))
        if self.soc_v18_mode:
            context.append(self.soc_v18.dossier(memory, limit=7))
        if memory.graph_edges and len(memory.calls_made) < 10:
            context.append("Confirmed graph relations:\n" + memory.evidence_text(limit=17))
        if memory.calls_made:
            context.append("Recent executed calls (do not repeat):\n" +
                           "\n".join(memory.calls_made[-12:]))
        # A compact current case file beats 20k tokens of the investigator's
        # own prior assertions. Keep the real initial alert, last few complete
        # assistant/tool pairs and a freshly rebuilt verified evidence ledger.
        selected = messages
        if len(memory.calls_made) >= 10:
            if len(messages) > 2 + 2 * self.keep_recent_results:
                selected = messages[:2] + messages[-2 * self.keep_recent_results:]
            context.append("Verified compact case file: keep ACTUAL scripts, task "
                           "payloads and AD account scope, not just process names. "
                           "Unlinked search hits are not causal proof:\n" +
                           self.director.review_dossier(memory, ledger_limit=11))
        return [*selected, {"role": "user", "content": "\n\n".join(context)}]

    def _elide(self, messages: list[dict[str, Any]]) -> None:
        """Replace the oldest tool results with stubs when context grows too large."""
        total = sum(len(str(m.get("content", ""))) for m in messages[2:])
        tool_positions = [i for i, m in enumerate(messages) if m["role"] == "tool"]
        for i in tool_positions[: -self.keep_recent_results or None]:
            if total <= self.context_chars:
                break
            old = str(messages[i]["content"])
            if old.startswith('{"elided"'):
                continue
            stub = '{"elided": true, "note": "Old result removed; rely on your notes."}'
            messages[i] = {**messages[i], "content": stub}
            total -= len(old) - len(stub)

    @staticmethod
    def _call_label(tool_name: str, arguments: dict[str, Any]) -> str:
        args = {k: v for k, v in arguments.items() if k != "reasoning"}
        return f"{tool_name}({json.dumps(args, ensure_ascii=False, default=str)[:160]})"

    def _save_partial(
        self, session: RemoteBenchmarkSession, transcript: list[dict[str, Any]]
    ) -> None:
        """Keep the trajectory on disk even if the run is interrupted."""
        if self.trajectory_dir is None:
            return
        try:
            path = self.trajectory_dir / "in_progress" / f"{session.task_id}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render_json({"messages": transcript}), encoding="utf-8")
        except Exception as exc:
            logger.warning("Could not save partial trajectory: {}", exc)

    def _save(
        self,
        run_id: str,
        session: RemoteBenchmarkSession,
        transcript: list[dict[str, Any]],
        task_result: TaskResult,
    ) -> None:
        """Write the full trajectory for error analysis and later fine-tuning."""
        if self.trajectory_dir is None:
            return
        try:
            path = self.trajectory_dir / run_id / f"{session.task_id}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                render_json(
                    {"task_result": task_result.model_dump(mode="json"), "messages": transcript}
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("Could not save trajectory: {}", exc)

    @staticmethod
    def _tool_specs(observation: dict[str, Any]) -> list[dict[str, Any]]:
        """Decode the runtime tool catalog from the current observation."""
        raw_tool_specs = observation.get("available_tools")
        if not isinstance(raw_tool_specs, str):
            raise ValueError("Observation has no JSON-encoded available_tools field.")
        try:
            tool_specs = json.loads(raw_tool_specs)
        except json.JSONDecodeError as exc:
            raise ValueError("available_tools is not valid JSON.") from exc
        if not isinstance(tool_specs, list) or not all(
            isinstance(specification, dict) for specification in tool_specs
        ):
            raise ValueError("available_tools must encode a list of tool specifications.")
        return [dict(specification) for specification in tool_specs]

    @staticmethod
    def _tool_feedback(response: ToolCallResult) -> dict[str, Any]:
        """Reduce a remote tool response to the actual result for the LLM.

        The runtime returns the whole observation (alert, tool catalog, ...) and puts
        the result of this call into `last_tool_result` as a JSON string.
        """
        raw = response.info.get("tool_result")
        if raw is None:
            observation = response.observation or {}
            raw = observation.get("last_tool_result", observation)
            if isinstance(raw, dict):
                raw = {k: v for k, v in raw.items() if k not in {"alert_text", "available_tools"}}
        raw = decode_encoded_commands(parse_json_strings(raw))
        return compact(
            {
                "tool_name": response.tool_name,
                "status": response.info.get("tool_status", "unknown"),
                "result": raw,
                "error": response.info.get("error"),
                "terminated": response.terminated,
                "truncated": response.truncated,
            }
        )
