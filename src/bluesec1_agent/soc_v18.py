"""v18: deterministic SOC reasoning primitives, never a synthetic ground truth label.

The engine can recognize the *meaning* of script execution and graph effects,
choose real tool targets, and reject unsupported final citations. Its signals
are explicitly hypotheses: neither a trusted signer nor a suspicious technique
alone decides an incident. No external requests, binary execution or eval.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

from bluesec1_agent.security_engine import SecurityEngine

_COMMAND_FIELDS = (
    "script_text_decoded", "cmdline_decoded", "script_block_text",
    "script_text", "cmdline", "command", "command_line", "command_text",
    "arguments", "value_data", "parameter_binding",
)
_HIGH_IMPACT = {
    "wrote_file", "created_file", "deleted_file", "renamed_file", "modified_file",
    "created_service", "installed_service", "created_scheduled_task",
    "modified_registry_value", "created_registry_value", "changed_ad_object",
    "modified_ad_object", "added_member", "added_to_group",
    "win_process_create", "created_process", "executed_script",
}
_BACKGROUND = {"hosts", "runs_process", "logged_on_to", "member_of", "belongs_to"}
_HUBS = {"host", "windows_user", "linux_user"}
# Distinguish interpretation of the ACTUAL code from assertions about outcome.
_DOTNET_LOAD = re.compile(r"(?:reflection\s*\.\s*assembly|reflection\.assembly|\bassembly)\s*\]\s*::\s*load\s*\(|\b(?:reflection\.)?assembly\s*::\s*load\s*\(", re.I)
_ENTRY_INVOKE = re.compile(r"\bentrypoint\s*\.\s*invoke\s*\(|\bgetmethod\s*\([^)]*\)\s*\.\s*invoke\s*\(", re.I)
_REMOTE_BYTES = re.compile(r"\bdownloaddata\s*\(|\bdownloadstring\s*\(|\binvoke-webrequest\b|\b(?:curl|wget)(?:\.exe)?\b", re.I)
_IMAGE_DATA = re.compile(r"(?:\.(?:png|bmp|jpe?g)\b|\bsystem\.drawing\.bitmap\b|\bgetpixel\s*\(|\bimage\.fromfile\b)", re.I)
_PSEXEC = re.compile(r"\bpsexesvc\b|\\admin\$\\|\bpsexec(?:64)?\.exe\b", re.I)
_SENSITIVE = re.compile(r"\bsekurlsa::|\blsadump::|\bminidump\b.{0,100}\blsass\b|\bcomsvcs\.dll\b.{0,140}\bminidump\b", re.I | re.S)
_ENCODED = re.compile(r"(?:^|\s)-(?:enc|encodedcommand)\b|\bfrombase64string\s*\(", re.I)


@dataclass(frozen=True)
class Finding:
    name: str
    severity: int
    entity_ids: tuple[str, ...]
    relation_ids: tuple[str, ...]
    observed: str
    question: str
    category: str = "signal"  # observed technique is not equivalent to compromise

    def text(self) -> str:
        return (f"{self.name} [{self.category}; priority={self.severity}]: "
                f"{self.observed[:290]}; IDs={','.join(self.entity_ids[:4])}; "
                f"relations={','.join(self.relation_ids[:3])}; CHECK {self.question}")


@dataclass(frozen=True)
class Lead:
    tool: str
    arguments: dict[str, str]
    reason: str
    priority: int


class SOCV18:
    def __init__(self, director: Any):
        self.director = director
        self.legacy = SecurityEngine(director)

    @staticmethod
    def _code(props: dict[str, Any]) -> str:
        text = '\n'.join(str(props.get(k) or '')[:10_000] for k in _COMMAND_FIELDS)
        # Optional safe decoding for literal -EncodedCommand; no code evaluation.
        # The graph's own decoded fields take precedence when present.
        if not props.get('cmdline_decoded'):
            match = re.search(r'(?:^|\s)-(?:enc|encodedcommand)\s+["\']?([A-Za-z0-9+/=]{24,})', text, re.I)
            if match:
                try:
                    blob = base64.b64decode(match.group(1), validate=True)
                    if len(blob) <= 12_000:
                        text += '\nDECODED_POWERSHELL: ' + blob.decode('utf-16-le')[:6_000]
                except (ValueError, UnicodeError):
                    pass
        return text[:40_000]

    def findings(self, memory: Any) -> list[Finding]:
        near = self.director.causal_distance(memory)
        nodes = memory.observed_nodes
        graph = memory.graph_edges
        output: list[Finding] = []
        for nid, node in nodes.items():
            if near.get(nid, 99) > 4:
                continue
            props = node.get('properties') or {}
            if not isinstance(props, dict):
                continue
            command = self._code(props)
            if not command.strip():
                continue
            related = [(rid, kind.lower(), dst) for rid, (kind, src, dst) in graph.items()
                       if src == nid and near.get(dst, 99) <= 5]
            relevant = tuple(rid for rid, kind, _ in related if kind in _HIGH_IMPACT or kind in
                             {'connected_to', 'established_connection', 'accepted_connection_from'})
            has_reflection = bool(_DOTNET_LOAD.search(command))
            invoker = bool(_ENTRY_INVOKE.search(command))
            if has_reflection:
                method = 'EntryPoint.Invoke observed' if invoker else 'assembly load observed'
                output.append(Finding('dotnet_memory_assembly', 9 if invoker else 8,
                    (nid,), relevant[:4], f'PowerShell/.NET {method}; in-memory loading (not merely base64 text)',
                    'Inspect assembly origin, invoked target and child/file/network effects.',
                    'execution' if invoker else 'signal'))
                if _REMOTE_BYTES.search(command):
                    output.append(Finding('remote_reflection_loader', 10,
                        (nid,), relevant[:4], 'Byte retrieval and .NET Assembly.Load occur in the same observed command/script',
                        'Check destination and whether the loaded code actually invoked an entry point.',
                        'execution' if invoker else 'signal'))
                if _IMAGE_DATA.search(command):
                    output.append(Finding('image_payload_loader', 10,
                        (nid,), relevant[:4], 'Image processing and .NET in-memory assembly loading in one observed script',
                        'Trace decoded bytes and immediate execution; image file name alone is not proof of staging.',
                        'execution' if invoker else 'signal'))
            if _SENSITIVE.search(command):
                output.append(Finding('credential_material_command', 9, (nid,), relevant[:4],
                    'Observed credential-sensitive command or script',
                    'Check actual execution, accessed target, owner identity and forensic/defensive context.'))
            if _PSEXEC.search(command):
                output.append(Finding('remote_service_execution', 6, (nid,), relevant[:4],
                    'Observed PsExec/PSEXESVC-related invocation',
                    'Inspect installed service binary, remote principal, child process and affected files.'))
            if _ENCODED.search(command) and (has_reflection or related):
                output.append(Finding('encoded_and_effectful', 5, (nid,), relevant[:3],
                    'Encoded execution syntax and an observed operation are connected to one actor',
                    'Check decoded script content and effect; encoding alone is not malicious.'))
        # Depend on existing causal edge provenance; never connect processes by matching names alone.
        for h in self.legacy.hypotheses(memory):
            if h.technique in {'state_change', 'remote_access', 'staged_binary', 'encoded_execution'}:
                continue  # retain these as planner context without multiplying low-specificity findings
            output.append(Finding(h.technique, h.weight, h.entity_ids, h.relation_ids,
                                  '; '.join(h.observations)[:310], h.test, h.level))
        unique: dict[tuple[str, tuple[str, ...], tuple[str, ...]], Finding] = {}
        for f in output:
            unique.setdefault((f.name, f.entity_ids, f.relation_ids), f)
        return sorted(unique.values(), key=lambda f: (-f.severity, f.name, f.entity_ids))[:28]

    def plan(self, memory: Any, tools: set[str], *, max_candidates: int = 30) -> Lead | None:
        """Select real, not-yet-fetched graph targets. Never fabricate UUID/search term."""
        known = memory.known_ids
        distances = self.director.causal_distance(memory)
        incident = {x for f in self.findings(memory) for x in (*f.entity_ids, *f.relation_ids)}
        leads: list[Lead] = []
        for rid, (kind, source, target) in memory.graph_edges.items():
            k = kind.lower()
            if distances.get(source, 99) > 4 and distances.get(target, 99) > 4:
                continue
            if (target in known and target not in memory.fetched_ids and
                target not in memory.rejected_ids and target not in memory.relation_ids and
                memory.entity_types.get(target) not in _HUBS and 'get_entity' in tools):
                rank = 9 if k in _HIGH_IMPACT else 4 if k not in _BACKGROUND else 0
                if rank:
                    rank += 3 if rid in incident or source in incident else 0
                    rank += 1 if target in memory.focus_ids else 0
                    if target in memory.ad_object_ids and 'get_ad_object_info' in tools:
                        leads.append(Lead('get_ad_object_info', {'ad_object_id': target,
                            'reasoning': f'Inspect outcome of verified {k}; establish scope and before/after.'},
                            f'actual {k} target', rank))
                    else:
                        leads.append(Lead('get_entity', {'entity_id': target,
                            'reasoning': f'Inspect target of verified {k} and test normal vs attack.'},
                            f'actual {k} target', rank))
            if (source in known and source not in memory.fetched_ids and
                source not in memory.rejected_ids and source not in memory.relation_ids and
                memory.entity_types.get(source) not in _HUBS and
                k in _HIGH_IMPACT and 'get_entity' in tools):
                leads.append(Lead('get_entity', {'entity_id': source,
                    'reasoning': f'Identify actor of observed {k}, inspect its command and identity.'},
                    f'actual {k} actor', 8))
        for candidate in self.director.rank_frontier(memory)[:max_candidates]:
            ident = candidate.identifier
            if ident not in known or ident in memory.fetched_ids or ident in memory.rejected_ids:
                continue
            typ = memory.relation_types.get(ident, '').lower()
            if candidate.tool == 'get_relation':
                if 'get_relation' not in tools or typ in _BACKGROUND:
                    continue
                rank = (8 if typ in _HIGH_IMPACT else 4) + (2 if ident in incident else 0)
                leads.append(Lead('get_relation', {'relation_id': ident,
                    'reasoning': 'Inspect verified graph relation: ' + candidate.question[:190]},
                    'unopened ' + typ, rank))
            elif candidate.tool == 'get_entity':
                if 'get_entity' not in tools or memory.entity_types.get(ident) in _HUBS:
                    continue
                leads.append(Lead('get_entity', {'entity_id': ident,
                    'reasoning': candidate.question}, 'nearby verified actor', 3))
            elif candidate.tool == 'get_ad_object_info' and 'get_ad_object_info' in tools:
                leads.append(Lead('get_ad_object_info', {'ad_object_id': ident,
                    'reasoning': candidate.question}, 'verify actual identity scope', 6))
        if not leads:
            return None
        # Stable ordering: high-impact before generic browsing; deterministic UUID tie break.
        return sorted(leads, key=lambda l: (-l.priority, l.tool, str(l.arguments)))[0]

    def unmet(self, memory: Any, submission: dict[str, Any]) -> list[Finding]:
        if submission.get('verdict') != 'benign':
            return []
        cited = {x.get('relation_id') or x.get('entity_id') for x in
                 submission.get('legitimacy_evidence') or [] if isinstance(x, dict)}
        # A cited actor process is not a citation of the effect. Unopened operations
        # remain unknown, not evidence that the action was authorized.
        return [f for f in self.findings(memory) if f.severity >= 7
                and (f.category == 'execution' or f.category == 'impact' or f.severity >= 9)
                and not (set(f.relation_ids) & cited and set(f.entity_ids) & cited)][:4]

    @staticmethod
    def sanitize(submission: dict[str, Any], memory: Any) -> tuple[dict[str, Any], int]:
        """Remove unsupported citations, preserving the model's verdict and rationale."""
        result = dict(submission)
        removed = 0
        if result.get('verdict') == 'benign':
            good = []
            for entry in result.get('legitimacy_evidence') or []:
                if not isinstance(entry, dict):
                    removed += 1
                    continue
                key = 'relation_id' if entry.get('anchor') == 'relation' else 'entity_id'
                nid = entry.get(key)
                node = memory.observed_nodes.get(nid)
                if not node or (key == 'relation_id' and nid not in memory.graph_edges) or (
                    key == 'entity_id' and nid in memory.graph_edges):
                    removed += 1
                    continue
                available = set(node) | set(node.get('properties') or {})
                fields = [f for f in entry.get('property_fields') or [] if f in available]
                if not fields:
                    removed += 1
                    continue
                good.append({'anchor': entry.get('anchor'), key: nid, 'property_fields': fields})
            result['legitimacy_evidence'] = good
        else:
            good = []
            for entry in result.get('ir_artifacts') or []:
                if not isinstance(entry, dict) or entry.get('entity_id') not in memory.observed_nodes:
                    removed += 1
                    continue
                good.append(entry)
            result['ir_artifacts'] = good
        return result, removed

    def dossier(self, memory: Any, *, limit: int = 6) -> str:
        rows = self.findings(memory)[:limit]
        lines = ['SOC V18 • VERIFIED TELEMETRY AND TESTABLE ATTACK TECHNIQUES (NOT VERDICTS):']
        if not rows:
            lines.append('No matched behavioral technique yet. UNKNOWN IS NOT BENIGN.')
        lines.extend('- ' + f.text() for f in rows)
        lines.append('Check actor → behavior → target/effect → possible authorized workflow. '
                     'Do not assume all signed programs are benign, or that suspicious techniques guarantee compromise.')
        return '\n'.join(lines)
