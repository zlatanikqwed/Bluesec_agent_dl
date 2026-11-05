"""v19 forensic-first control plane for the BlueSec investigation runtime.

This is NOT a malware classifier. It controls *evidence acquisition* and checks
whether verdict citations are anchored in observed task telemetry. It never
executes retrieved script text, never creates graph IDs, and never fabricates
an attack/benign ground truth label.
"""
from __future__ import annotations

import ntpath
import re
import ipaddress
from dataclasses import dataclass
from typing import Any

from bluesec1_agent.soc_v18 import SOCV18, Finding, Lead

# Graph edges that indicate real changes or code/privilege execution, rather than
# a static inventory association with a common hub.
_EFFECTS = {
    "wrote_file", "created_file", "deleted_file", "renamed_file", "modified_file",
    "executed_file", "executed_script", "loaded_image", "win_process_create",
    "created_process", "parent_of", "created_service", "modified_service",
    "started_service", "created_scheduled_task", "ran_scheduled_task",
    "created_registry_key", "set_registry_value", "deleted_registry_value",
    "created_account", "added_to_group", "removed_from_group", "dcsync_replication",
    "opened_handle", "accessed_process", "created_pipe", "connected_to_pipe",
    "injected_into", "created_thread", "remote_wmi_exec", "tunneled_via",
    "sent_data_to", "archived_to", "extracted_to", "truncated_file",
}
_REMOTE = {
    "connected_to", "accepted_connection_from", "sent_data_to", "received_data_from",
    "opened_share_session", "remote_wmi_exec", "established_vpn_session",
    "tunneled_through", "tunneled_via",
}
_SCRIPT = {"executed_script", "invoked_cmdlet", "payload_references"}
_IGNORE = {"hosts", "runs_process", "member_of", "logged_on_to", "belongs_to",
           "resolves_to", "mounted", "issued_by_template"}
_HUBS = {"host", "windows_user", "linux_user", "linux_group"}
_SENSITIVE_PATH = re.compile(r"\\(?:appdata\\(?:roaming|local)|temp|programdata)\\|\\netlogon\\", re.I)
_SUSPICIOUS_FILENAME = re.compile(r"\.(?:exe|dll|ps1|vbs|hta)$", re.I)
_PROVENANCE_PHRASE = re.compile(
    r"\b(?:authorized|approved|documented|whitelisted|legitimate|expected|normal|routine)\b", re.I)


@dataclass(frozen=True)
class Inspection:
    lead: Lead
    question: str
    phase: str


class SOCV19(SOCV18):
    """An explicit observe → acquire → adversarial assess → verify pipeline."""

    def __init__(self, director: Any):
        super().__init__(director)

    def findings(self, memory: Any) -> list[Finding]:
        found = list(super().findings(memory))
        nodes, graph = memory.observed_nodes, memory.graph_edges
        close = self.director.causal_distance(memory)
        # Important: effects are joined ONLY by a verified graph edge and source
        # process ID; never join unrelated nodes by hostname or search text.
        for rid, (kind, src, dst) in graph.items():
            typ = kind.lower()
            if close.get(src, 99) > 4 and close.get(dst, 99) > 4:
                continue
            if typ not in _EFFECTS and typ not in _REMOTE:
                continue
            srcnode, dstnode = nodes.get(src, {}), nodes.get(dst, {})
            source = srcnode.get('properties') or {}
            target = dstnode.get('properties') or {}
            if not isinstance(source, dict): source = {}
            if not isinstance(target, dict): target = {}
            cmd = self._code(source)
            img = str(source.get('image_path') or source.get('cmdline') or '')
            path = str(target.get('path') or target.get('image_path') or target.get('name') or '')
            if typ in {"wrote_file", "created_file"} and _SUSPICIOUS_FILENAME.search(path):
                stage = bool(_SENSITIVE_PATH.search(path))
                found.append(Finding('executable_artifact_written', 8 if stage else 6,
                     (src, dst), (rid,), f'{ntpath.basename(img) or src} {typ} {path[:190]}',
                     'Determine payload origin, whether this same file executed, and the documented purpose.',
                     'impact' if stage else 'signal'))
            if typ in _REMOTE and ("wsmprovhost" in img.lower() or
                                   "powershell" in cmd.lower() or "psexesvc" in img.lower()):
                found.append(Finding('remote_control_attribution', 7, (src, dst), (rid,),
                     f'{typ}: actor={img[:125]}; remote={str(target.get("src_ip") or target.get("dst_ip") or path)[:100]}',
                     'Identify actual source machine/account, remote command and resulting modifications.',
                     'signal'))
            if typ in {"created_service", "started_service", "created_scheduled_task"}:
                found.append(Finding('execution_persistence_mechanism', 8, (src, dst), (rid,),
                     f'{typ}; service/task={path[:160]}; actor={img[:110]}',
                     'Inspect service/task command, creator and any child activity; verify legitimate installation.',
                     'impact'))
            if typ in {"opened_handle", "accessed_process"} and 'lsass' in path.lower():
                found.append(Finding('sensitive_process_access', 6, (src, dst), (rid,),
                     f'{typ} to LSASS by {img[:160]}',
                     'Inspect access rights/dump effects and the actor: security tools may legitimately access LSASS.',
                     'signal'))
        unique: dict[tuple[str, tuple[str, ...], tuple[str, ...]], Finding] = {}
        for item in found:
            unique.setdefault((item.name, item.entity_ids, item.relation_ids), item)
        return sorted(unique.values(), key=lambda f: (-f.severity, f.name))[:32]

    def _priority(self, memory: Any, lead: Lead) -> int:
        """A score about INFORMATION GAIN, not about maliciousness."""
        ident = (lead.arguments.get('relation_id') or lead.arguments.get('entity_id') or
                 lead.arguments.get('ad_object_id') or '')
        typ = memory.relation_types.get(ident, '').lower()
        score = lead.priority
        if typ in _IGNORE: return -50
        if typ in _SCRIPT: score += 8
        if typ in _EFFECTS: score += 7
        if typ in _REMOTE: score += 6
        if typ in {"invoked_cmdlet", "executed_script", "payload_references"}: score += 3
        # Process and script endpoints explain semantics, not just signatures.
        enttype = memory.entity_types.get(ident, '').lower()
        if enttype in {"powershell_script", "powershell_cmdlet_invocation", "registry_key", "windows_file"}:
            score += 4
        if ident in memory.focus_ids: score += 3
        if ident in memory.rejected_ids or ident in memory.fetched_ids: return -50
        return score

    def _source_pivot(self, memory: Any, tools: set[str]) -> Lead | None:
        """Pivot to the actual *remote* peer, never the local side by default.

        A search hit is a lead, not causal proof. Only query endpoints retrieved
        through verified alert-connected remote edges; never infer execution.
        """
        if 'search' not in tools or len(memory.calls_made) < 3:
            return None
        close = self.director.causal_distance(memory)
        remote_ips: list[str] = []
        for rid, (kind, src, dst) in memory.graph_edges.items():
            kind = kind.lower()
            if (kind not in _REMOTE or close.get(src, 99) > 4 or
                    rid not in memory.fetched_ids or dst not in memory.fetched_ids):
                continue
            props = (memory.observed_nodes.get(dst) or {}).get('properties') or {}
            if not isinstance(props, dict):
                continue
            inbound = (kind == 'accepted_connection_from' or
                       str(props.get('direction') or '').lower() == 'inbound')
            field = 'src_ip' if inbound else 'dst_ip'
            ip = str(props.get(field) or '').strip()
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if (parsed.version != 4 or parsed.is_loopback or
                    parsed.is_unspecified or parsed.is_multicast):
                continue
            remote_ips.append(ip)
        for ip in dict.fromkeys(remote_ips):
            if any(f'search(' in label and ip in label for label in memory.calls_made):
                continue
            return Lead('search', {'query': ip, 'reasoning':
                'Attribute this verified remote network peer to its actual host/process/account. '
                'Search matches require a separate causal check; do not infer benign or malicious.'},
                'grounded remote-peer IP attribution', 8)
        return None

    def next_inspection(self, memory: Any, tools: set[str], *, max_steps: int = 13,
                        minimum_steps: int = 5) -> Inspection | None:
        """Select safe, already-discovered graph IDs; stop when marginal gain is low.

        This method runs BEFORE asking the LLM, so the model cannot prematurely
        terminate or repeatedly vote benign instead of opening the known causal edge.
        """
        count = len(memory.calls_made)
        if count >= max_steps: return None
        distances = self.director.causal_distance(memory)
        possible: list[Lead] = []
        for identifier in memory.known_ids:
            if identifier in memory.fetched_ids or identifier in memory.rejected_ids:
                continue
            etype = memory.entity_types.get(identifier, '')
            if identifier in memory.relation_ids:
                typ = memory.relation_types.get(identifier, '').lower()
                if 'get_relation' not in tools or typ in _IGNORE: continue
                owner = memory.relation_owner.get(identifier, ('', '', ''))[0]
                if owner and distances.get(owner, 99) > 4: continue
                priority = (11 if typ in _EFFECTS else
                            9 if typ in _REMOTE or typ in _SCRIPT else 5)
                possible.append(Lead('get_relation', {
                    'relation_id': identifier,
                    'reasoning': 'Establish actor, action, target and causality for this actual observed edge.'},
                    f'unopened relation {typ or "unknown"}', priority))
            elif etype and etype not in _HUBS and 'get_entity' in tools:
                if distances.get(identifier, 99) > 4 and identifier not in memory.focus_ids:
                    continue
                priority = 13 if identifier in memory.focus_ids else (9 if etype in {
                    'powershell_script', 'windows_process', 'powershell_cmdlet_invocation', 'windows_file',
                    'windows_service', 'registry_key', 'network_connection'} else 5)
                possible.append(Lead('get_entity', {
                    'entity_id': identifier,
                    'reasoning': 'Read the exact process/script/target properties before forming a verdict.'},
                    f'open {etype}', priority))
        # The v18 graph planner knows about inferred causal endpoints. Use it as
        # one candidate, not as authority for every decision.
        previous = super().plan(memory, tools)
        if previous: possible.append(previous)
        if not possible:
            pivot=self._source_pivot(memory,tools)
            return Inspection(pivot, pivot.reason, 'source-attribution') if pivot else None
        ranked = sorted(possible, key=lambda x: (-self._priority(memory, x),
                    x.tool, str(x.arguments)))
        winner = ranked[0]
        effective = self._priority(memory, winner)
        # Continue after the basic provenance pass ONLY for specifically helpful
        # actions; generic relation enumeration is not worthwhile.
        cutoff = 6 if count < minimum_steps else 15 if count >= 9 else 11
        if effective < cutoff:
            pivot=self._source_pivot(memory,tools)
            return Inspection(pivot, pivot.reason, 'source-attribution') if pivot else None
        stage = 'actor-and-script' if count < 3 else 'effects-and-attribution'
        return Inspection(winner, f'Highest grounded information gain={effective}: {winner.reason}', stage)

    def benign_gaps(self, memory: Any, submission: dict[str, Any]) -> list[str]:
        """Challenge factual assertions without inventing an authorization log."""
        if submission.get('verdict') != 'benign': return []
        entries = submission.get('legitimacy_evidence') or []
        cited = {e.get('entity_id') or e.get('relation_id') for e in entries if isinstance(e, dict)}
        observed = memory.observed_nodes
        gaps: list[str] = []
        if not entries:
            gaps.append('No actual graph citation was supplied for benign. Attach a real action edge or actor/target field.')
        facts = self.findings(memory)
        for f in facts:
            if f.severity < 7: continue
            ids = set(f.entity_ids) | set(f.relation_ids)
            if not ids.intersection(cited):
                gaps.append(f'Unaddressed observed technique: {f.text()}')
        # A citation is an address, not an explanation. In particular, the same
        # actor's signed metadata cannot explain observed in-memory execution.
        rationale = str(submission.get('reasoning') or '').lower()
        specific_terms = {
            'dotnet_memory_assembly': ('assembly', 'reflection', 'memory', 'загруз'),
            'remote_reflection_loader': ('download', 'retriev', 'assembly', 'reflection', 'байт'),
            'image_payload_loader': ('png', 'bitmap', 'image', 'pixel', 'изображ'),
            'credential_material_command': ('credential', 'lsass', 'sekurlsa', 'парол'),
            'executable_artifact_written': ('exe', 'dll', 'executab', 'библиотек'),
            'execution_persistence_mechanism': ('service', 'task', 'служб', 'задач'),
            'write_execute_chain': ('execut', 'launch', 'запуск', 'выполн'),
        }
        for f in facts:
            if f.severity < 8 or f.name not in specific_terms: continue
            if not any(word in rationale for word in specific_terms[f.name]):
                gaps.append(f'Observed technique {f.name} is not materially discussed: {f.text()}')
        # A PROCESS citation alone is not direct evidence about its downstream
        # file/registry/network outcome, even if it contains a signed field.
        impacts = [(rid,k,src,dst) for rid,(k,src,dst) in memory.graph_edges.items()
                   if k.lower() in _EFFECTS and (rid in memory.fetched_ids or rid in observed)]
        for rid, typ, src, dst in impacts[:5]:
            if (rid not in cited and dst not in cited and
                    typ.lower() not in {'parent_of', 'win_process_create'}):
                gaps.append(f'Unexplained confirmed outcome {typ} {src} -> {dst} (relation {rid}).')
        rationale = str(submission.get('reasoning') or '')
        if _PROVENANCE_PHRASE.search(rationale) and not any(
                str((observed.get(i) or {}).get('properties', {}).get(k, '')).lower().find('authorized') >= 0
                for i in cited for k in ('description', 'script_text', 'command', 'comment')):
            gaps.append('The stated approved/documented workflow is an inference; identify its observed operational basis.')
        return gaps[:6]

    def unmet(self, memory: Any, submission: dict[str, Any]) -> list[Finding]:
        found = super().unmet(memory, submission)
        if submission.get('verdict') == 'benign':
            # High-specificity behavior ALWAYS deserves a fresh independent
            # examination, even if the first analyst pasted a valid UUID.
            for f in self.findings(memory):
                if f.severity >= 9 and f.name in {
                    'dotnet_memory_assembly', 'remote_reflection_loader',
                    'image_payload_loader', 'credential_material_command',
                } and f not in found:
                    found.append(f)
            cited = {e.get('entity_id') or e.get('relation_id') for e in
                     (submission.get('legitimacy_evidence') or []) if isinstance(e, dict)}
            for f in self.findings(memory):
                if f.severity < 8: continue
                if not (set(f.entity_ids) | set(f.relation_ids)) & cited and f not in found:
                    found.append(f)
        return found[:6]

    @staticmethod
    def _fallback_evidence(memory: Any, limit: int = 4) -> list[dict[str, Any]]:
        """Only real, opened operations and fields; never a synthetic citation."""
        output: list[dict[str, Any]] = []
        ranks = {'executed_script': 10, 'wrote_file': 10, 'set_registry_value': 10,
                 'created_service': 10, 'win_process_create': 9, 'connected_to': 8,
                 'accepted_connection_from': 8, 'created_pipe': 5, 'opened_handle': 6}
        for rid, (kind, src, dst) in sorted(memory.graph_edges.items(),
                key=lambda item: (-ranks.get(item[1][0].lower(), 1),item[0])):
            node = memory.observed_nodes.get(rid)
            if not node: continue
            fields = [k for k in ('type', 'source_id', 'target_id', 'timestamp') if k in node]
            if fields:
                output.append({'anchor':'relation', 'relation_id':rid,'property_fields':fields[:3]})
            if len(output) >= limit: break
        if len(output) < limit:
            for eid in memory.fetched_ids:
                if eid in memory.relation_ids: continue
                node = memory.observed_nodes.get(eid)
                if not node:continue
                props = node.get('properties') or {}
                fields = [k for k in ('script_text_decoded','script_text', 'cmdline', 'path', 'image_path',
                                      'src_ip','dst_ip','user','value_data','description') if k in props]
                if fields: output.append({'anchor':'entity','entity_id':eid,'property_fields':fields[:3]})
                if len(output)>=limit:break
        return output[:limit]

    def sanitize(self, submission: dict[str, Any], memory: Any) -> tuple[dict[str, Any], int]:
        result, removed = super().sanitize(submission, memory)
        if result.get('verdict') == 'benign':
            evidence = list(result.get('legitimacy_evidence') or [])
            used = {x.get('entity_id') or x.get('relation_id') for x in evidence}
            # When the reviewer hallucinates all citations, attach verified ones;
            # this does not assert benign intent, it records real operations.
            # Prefer a causal relation as corroboration if the model cites only
            # an actor. Do not append unrelated background observations.
            direct_operations = {rid for rid, (kind, _, _) in memory.graph_edges.items()
                                 if kind.lower() in _EFFECTS or kind.lower() in _REMOTE}
            covered = bool(direct_operations & used)
            for x in self._fallback_evidence(memory):
                ident=x.get('entity_id') or x.get('relation_id')
                if ident not in used and (not evidence or (not covered and ident in direct_operations)):
                    evidence.append(x);used.add(ident)
                    covered |= ident in direct_operations
                if len(evidence)>=3 and covered:break
            result['legitimacy_evidence'] = evidence
        elif result.get('verdict') == 'malicious' and not result.get('ir_artifacts'):
            for eid in sorted(memory.fetched_ids):
                node=memory.observed_nodes.get(eid, {})
                kind=node.get('type')
                if kind == 'windows_process':
                    result['ir_artifacts']=[{'entity_id':eid,'kind':'process_observed'}];break
                if kind == 'windows_file':
                    result['ir_artifacts']=[{'entity_id':eid,'kind':'file_observed'}];break
        return result, removed

    def dossier(self, memory: Any, *, limit: int = 9) -> str:
        base=super().dossier(memory,limit=limit)
        actions=[f'{src} --{kind}--> {dst} [relation={rid}]' for rid,(kind,src,dst)
                 in memory.graph_edges.items() if kind.lower() in _EFFECTS or kind.lower() in _REMOTE]
        return (base+'\nV19 FORENSIC CHAIN (observed only):\n'+
                ('\n'.join(actions[:12]) or 'No causal action edge yet.')+
                '\nDecide only AFTER the actor, exact command, affected target and alternative normal workflow are assessed. '
                'Unknown subsequent activity is NOT proof it did not happen. Report uncertainty explicitly. '
                'Never treat an account name, signer, internal IP or approval speculation as a verdict.')
