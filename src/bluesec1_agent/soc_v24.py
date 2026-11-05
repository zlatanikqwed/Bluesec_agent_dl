"""v24: evidence-native SOC casebook, hypothesis testing and final consistency check.

No task/hostname identifiers or answer-key labels.  All behavioral observations
are rooted in fetched entities and verified causal relations.  A suspicion is
an investigation obligation, NEVER an automatic malicious classification.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import re
import ipaddress
from collections import defaultdict

from bluesec1_agent.soc_v18 import Lead
from bluesec1_agent.soc_v19 import Inspection
from bluesec1_agent.soc_v23 import SOCV23, ReasonedEvidenceCaseState, SemanticEvidenceValidator, ClaimIssue


@dataclass(frozen=True)
class SecurityAction:
    category: str
    severity: int
    actor: str
    target: str
    relation_id: str
    observation: str
    question: str

    def describe(self) -> str:
        return (f'[{self.category}; priority={self.severity}] '
                f'actor={self.actor} target={self.target} relation={self.relation_id}; '
                f'{self.observation}; VERIFY: {self.question}')


_CATEGORY_TERMS = {
    'remote_shell': ('remote', 'pssession', 'winrm', 'credential', 'port', 'session'),
    'credentialed_share': ('share', 'smb', 'credential', 'account', 'net use', 'user'),
    'cross_identity_share': ('share', 'smb', 'credential', 'alternate', 'account', 'user', 'identity'),
    'remote_control_pipe': ('pipe', 'psexec', 'service', 'remote', 'ipc'),
    'smb_source': ('smb', 'share', 'authentication', 'source', 'incoming', 'connection'),
    'relay_surface': ('incoming', 'outbound', 'smb', 'remote', 'forward', 'source', 'port', 'session'),
    'network_bridge': ('inbound', 'outbound', 'external', 'proxy', 'portproxy', 'forward', 'tunnel', 'connection', 'https'),
    'staged_execution': ('created', 'launched', 'executed', 'service', 'payload', 'script', 'binary'),
    'file_change': ('write', 'file', 'created', 'deleted', 'modified', 'document', 'artifact'),
    'identity_change': ('group', 'account', 'user', 'privilege', 'membership', 'ad'),
    'persistence_change': ('service', 'registry', 'scheduled', 'task', 'persistence'),
    'code_execution': ('script', 'cmdlet', 'powershell', 'execution', 'code'),
}


class ThreatCasebook:
    """A mandatory observable action ledger, independent of model narratives."""

    @staticmethod
    def _remote_non_lan(ip: str) -> bool:
        """External peer by enterprise-network boundary, not ip.is_global.

        Documentation/test addresses such as 192.0.2.0/24 are external to
        the corporate RFC1918 address space and occur in provided scenarios.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.version != 4 or addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            return False
        return not (addr in ipaddress.ip_network('10.0.0.0/8')
                    or addr in ipaddress.ip_network('172.16.0.0/12')
                    or addr in ipaddress.ip_network('192.168.0.0/16')
                    or addr in ipaddress.ip_network('169.254.0.0/16'))

    def observed_actions(self, memory: Any) -> list[SecurityAction]:
        nodes = memory.observed_nodes
        fetched = memory.fetched_ids
        edges = memory.graph_edges
        actions: list[SecurityAction] = []
        # Never trust search-only nodes, relation-owner hints or untyped edges.
        related: dict[str, list[tuple[str,str,str]]] = defaultdict(list)
        for rid, (typ, actor, target) in edges.items():
            if rid not in fetched or actor not in nodes:
                continue
            if actor not in fetched and actor not in memory.focus_ids:
                continue
            related[actor].append((rid, typ.lower(), target))
        for actor, verified in related.items():
            src = nodes.get(actor) or {}
            props = src.get('properties') or {}
            if not isinstance(props, dict): props = {}
            cmd = ' '.join(str(props.get(k) or '') for k in (
                'cmdline','cmdline_decoded','script_text','script_text_decoded'))
            lower = cmd.lower()
            for rid, kind, target in verified:
                targetnode = nodes.get(target) or {}
                tp = (targetnode.get('properties') or {}) if target in fetched else {}
                if not isinstance(tp, dict): tp = {}
                if kind in {'executed_script', 'invoked_cmdlet'}:
                    text = ' '.join(str(tp.get(k) or '') for k in ('script_text','script_text_decoded','command_name'))
                    if re.search(r'new-pssession|invoke-command|enter-pssession|winrs\b', text + ' ' + cmd, re.I):
                        actions.append(SecurityAction('remote_shell', 8, actor, target, rid,
                            'Verified PowerShell remote-session operation',
                            'Attribute actual endpoint, supplied identity and remotely executed command'))
                    elif text:
                        actions.append(SecurityAction('code_execution', 4, actor, target, rid,
                            f'Executed script/cmdlet: {text[:120]}',
                            'Verify full script semantics and downstream effects'))
                if kind in {'connected_to', 'accepted_connection_from'} and target in fetched:
                    port = str(tp.get('dst_port') or '')
                    proto = str(tp.get('protocol') or '').lower()
                    if port in {'445','139'} or proto == 'smb':
                        if re.search(r'\bnet\s+(?:use|view)\b[^\n]{0,170}/user:', lower):
                            actions.append(SecurityAction('credentialed_share', 8, actor, target, rid,
                                f'Explicit credential use during SMB operation to {tp.get("dst_ip", "?")}',
                                'Verify identity ownership, source host and actual accessed share'))
                            # The executing Windows token and explicitly
                            # supplied SMB principal are distinct identities.
                            # The mismatch is verifiable, but its authorization
                            # remains an open question, not an attack label.
                            supplied = re.search(r'/user:(\S+)', cmd, re.I)
                            principal = supplied.group(1).lower() if supplied else ''
                            executor = str(props.get('user') or '').lower()
                            if (principal and executor and
                                    principal.split('\\')[-1] != executor.split('\\')[-1]):
                                actions.append(SecurityAction('cross_identity_share', 9,
                                    actor, target, rid,
                                    f'Executing principal {executor} supplied SMB identity {principal}',
                                    'Correlate the credential owner and authenticated session; '
                                    'the account name alone does not prove permission'))
                if kind in {'created_pipe', 'opened_pipe', 'connected_to_pipe'} and target in fetched:
                    pipe = str(tp.get('pipe_name') or tp.get('name') or '')
                    if 'psexesvc' in pipe.lower():
                        actions.append(SecurityAction('remote_control_pipe', 9, actor, target, rid,
                            f'Observed PsExec-family named pipe: {pipe[:120]}',
                            'Attribute creator, remote initiator and command; a pipe alone is not proof of compromise'))
                if kind in {'wrote_file','created_file','modified_file','deleted_file','renamed_file','truncated_file'}:
                    targetpath = str(tp.get('path') or tp.get('name') or '')
                    actions.append(SecurityAction('file_change', 5, actor, target, rid,
                        f'{kind} {targetpath[:120] or "(target details unknown)"}',
                        'Determine which concrete object changed and whether the actor was authorized'))
                if kind in {'added_to_group','removed_from_group','created_account','reset_password'}:
                    actions.append(SecurityAction('identity_change', 9, actor, target, rid,
                        f'{kind} user/group', 'Verify requested authorization and exact group/account changed'))
                if kind in {'created_service','modified_service','created_registry_key','set_registry_value',
                              'created_scheduled_task','ran_scheduled_task'}:
                    actions.append(SecurityAction('persistence_change', 7, actor, target, rid,
                        kind, 'Verify exact target, provenance and execution context'))
                if kind in {'win_process_create','created_process','parent_of'} and target in fetched:
                    child = ' '.join(str(tp.get(k) or '') for k in ('image_path','cmdline')).lower()
                    if (re.search(r'\\(?:temp|appdata|programdata)\\[^\s]{0,90}\.exe', child)
                        or ('python' in child and 'temp' in child)):
                        actions.append(SecurityAction('staged_execution', 7, actor, target, rid,
                            f'Executed nonstandard image: {child[:125]}',
                            'Establish executable origin, signer, identity and actual side effects'))
            # A multi-event *correlation* must share the same fetched actor.
            inbound = []
            outgoing = []
            for rid, kind, target in verified:
                if kind not in {'accepted_connection_from','connected_to'} or target not in fetched: continue
                p = (nodes.get(target) or {}).get('properties') or {}
                if not isinstance(p, dict): continue
                if kind == 'accepted_connection_from': inbound.append((rid,target,p))
                else: outgoing.append((rid,target,p))
            smb = [(rid,tid,p) for rid,tid,p in inbound if str(p.get('dst_port')) in ('445','139')]
            if len(smb)>=3:
                sources={str(p.get('src_ip')) for _,_,p in smb if p.get('src_ip')}
                if len(sources)==1:
                    rid,tid,_=smb[0]
                    actions.append(SecurityAction('smb_source', 7, actor, tid, rid,
                        f'{len(smb)} inbound SMB sessions from one peer {next(iter(sources))}',
                        'Check authenticated source process and file/service consequences; inbound packets do not establish harmlessness'))
            # v26: Receiving on one side and reaching an external destination
            # on the other side is a MATERIAL bridge. An iphlpsvc/system signer
            # does not establish why the forwarding occurred. The relation and
            # BOTH endpoints must already have been fetched; search hits never
            # establish this action on their own. TEST-NET destinations appear
            # in the practice scenarios and are considered remote (not RFC1918).
            if inbound and outgoing:
                from_external = [(rid,tid,p) for rid,tid,p in outgoing
                                 if self._remote_non_lan(str(p.get('dst_ip') or ''))]
                if from_external:
                    rid,tid,p = from_external[0]
                    ing = inbound[0][2]
                    actions.append(SecurityAction('network_bridge', 9, actor, tid, rid,
                        f'Actor received {ing.get("src_ip", "?")} -> '
                        f'{ing.get("dst_ip", "?")} and contacted non-LAN '
                        f'{p.get("dst_ip", "?")}:{p.get("dst_port", "?")}',
                        'Check forwarding configuration, causal sequence, '
                        'remote recipient and authorization; do not treat '
                        'external communication as automatically exfiltration'))
            if len(inbound)>=1 and len(outgoing)>=1:
                administrative=[(rid,tid,p) for rid,tid,p in outgoing if str(p.get('dst_port')) in ('445','139','5985','5986')]
                if administrative:
                    r,t,_ = administrative[0]
                    actions.append(SecurityAction('relay_surface', 8, actor, t, r,
                        'Same observed process accepts inbound traffic and connects to administrative endpoint',
                        'Attribute remote caller, connecting process and intended command; do not infer authorization from signer'))
        dedup = {}
        for a in actions:
            dedup.setdefault((a.category,a.actor,a.target,a.relation_id),a)
        return sorted(dedup.values(), key=lambda a: (-a.severity,a.category,a.relation_id))[:22]

    def unmet(self, memory: Any, submission: dict[str, Any], minimum: int = 6) -> list[SecurityAction]:
        if submission.get('verdict') != 'benign': return []
        reasoning = str(submission.get('reasoning') or '').lower()
        cited = set()
        for obj in submission.get('legitimacy_evidence') or []:
            if isinstance(obj,dict):cited.add(obj.get('entity_id') or obj.get('relation_id'))
        outstanding=[]
        for action in self.observed_actions(memory):
            if action.severity < minimum:continue
            words = _CATEGORY_TERMS.get(action.category,())
            mentions = any(w in reasoning for w in words)
            # A citation to the ACTOR alone never covers the consequence.
            anchors = action.target in cited or action.relation_id in cited
            if not anchors or not mentions:
                outstanding.append(action)
        return outstanding[:5]

    def dossier(self, memory: Any, *, limit: int = 12) -> str:
        actions = self.observed_actions(memory)
        if not actions:
            return 'NO VERIFIED SECURITY-ACTION CHAIN in the opened graph; no claims of authorization or absence of unseen effects are justified.'
        return ('MANDATORY FORENSIC ACTION LEDGER — verified graph operations, NOT verdicts:\n'
                + '\n'.join('- '+a.describe() for a in actions[:limit])
                + '\nFor each material action compare H_attack/H_normal and identify what is UNKNOWN. '
                  'A signed parent, SYSTEM account or an internal address does not explain it. '
                  'Do NOT classify by technique names alone.')

    def challenge(self, memory: Any, submission: dict[str,Any]) -> list[ClaimIssue]:
        issues=[]
        if submission.get('verdict') != 'benign':return issues
        for act in self.unmet(memory, submission):
            issues.append(ClaimIssue('unaccounted_'+act.category, min(9,act.severity),
                'The final benign account fails to substantiate this verified causal action: '
                +act.observation+'. '+act.question,
                tuple(v for v in (act.target,act.actor) if v in memory.fetched_ids)))
        text=str(submission.get('reasoning') or '').lower()
        actual=self.observed_actions(memory)
        # A correct anchor to a remote-control or credentialed action is NOT
        # evidence that it was approved. Material positive-authorization facts
        # must be observed, rather than inferred from Microsoft signatures.
        high_remote=[a for a in actual if a.category in {
            'remote_control_pipe','relay_surface','credentialed_share','cross_identity_share','remote_shell','network_bridge'}
            and a.severity >= 7]
        if high_remote and re.search(r'\b(authorized|approved|routine|legitimate|maintenance|normal)\b',text):
            approval=False
            relevant={node for a in high_remote for node in (a.actor,a.target)}
            # A ticket on some *unrelated* node in the enterprise cannot
            # authorize this event. Follow fetched explicit authorization edges.
            for rid,(relation,src,dst) in memory.graph_edges.items():
                if (rid in memory.fetched_ids and
                    relation.lower() in ('authorized_by','approved_by','part_of_change',
                                          'has_approval','associated_with_ticket')):
                    if src in relevant:relevant.add(dst)
                    if dst in relevant:relevant.add(src)
            for nid in relevant & memory.fetched_ids:
                prop=(memory.observed_nodes.get(nid) or {}).get('properties') or {}
                if not isinstance(prop,dict):continue
                for key in ('approval_status','approved','authorized','change_ticket','change_id'):
                    value=str(prop.get(key) or '').lower().strip()
                    if value and value not in {'false','0','no','none','unknown'}:
                        approval=True
            if not approval:
                a=high_remote[0]
                issues.append(ClaimIssue('material_remote_action_not_authorized',8,
                    'The observed material remote/network action is real, but no checked '
                    'record establishes its authorization or purpose. An internal host or SYSTEM '
                    'account cannot establish this; compare concrete effects.',
                    tuple(v for v in (a.target,a.actor) if v in memory.fetched_ids)))
        smb=[a for a in actual if a.category=='smb_source']
        if smb and re.search(r'failed\s+(?:ntlm|logon|auth)|no successful logon|authentication (?:attempts )?failed|0xc000',text):
            auth=False
            auth_nodes={a.target for a in smb}
            for rid,(rel,src,dst) in memory.graph_edges.items():
                if rid in memory.fetched_ids and rel.lower() in ('authenticated_as',
                        'attempted_logon','logon_result','authenticated_by'):
                    if src in auth_nodes:auth_nodes.add(dst)
                    if dst in auth_nodes:auth_nodes.add(src)
            for nid in auth_nodes & memory.fetched_ids:
                p=(memory.observed_nodes.get(nid) or {}).get('properties') or {}
                if not isinstance(p,dict):continue
                if any(p.get(k) is not None for k in ('auth_result','auth_status','authentication_status','logon_status','ntstatus')):
                    auth=True
            if not auth:
                issues.append(ClaimIssue('smb_authentication_outcome_unverified',7,
                    'Observed SMB network endpoints and unrelated logon text do not prove '
                    'successful or failed authentication for THESE connections. '
                    'Confirm a joined authentication result before relying on it.',
                    tuple(a.target for a in smb[:3] if a.target in memory.fetched_ids)))
        if smb and re.search(r'\b(?:normal|routine|legitimate|authorized|expected|typical|benign)\b', text):
            # Three packets from the same address do not establish an
            # authenticated, authorized file-sharing workflow. Demand an
            # observed source identity + causal operation, not mere citations.
            source_ips = set()
            for a in smb:
                props = (memory.observed_nodes.get(a.target) or {}).get('properties') or {}
                if isinstance(props, dict) and props.get('src_ip'):
                    source_ips.add(str(props['src_ip']))
            source_correlated = False
            for nid in memory.fetched_ids:
                node = memory.observed_nodes.get(nid) or {}
                if node.get('type') not in ('windows_process','linux_process'):
                    continue
                prop = node.get('properties') or {}
                if not isinstance(prop, dict):continue
                if str(prop.get('ip') or prop.get('src_ip') or '') in source_ips:
                    # A source host/process needs a verified causal edge
                    # back to this event, not a same-name search hit.
                    source_correlated = any(r in memory.fetched_ids and
                        (x == nid or y == nid) and
                        (x in {a.actor for a in smb} or y in {a.actor for a in smb} or
                         x in {a.target for a in smb} or y in {a.target for a in smb})
                        for r,(_,x,y) in memory.graph_edges.items())
                    if source_correlated:break
            if not source_correlated:
                issues.append(ClaimIssue('smb_source_purpose_unverified',8,
                    'Repeated SMB inbound connections were retrieved, but neither '
                    'the authenticated remote initiator nor the purpose of the '
                    'sessions was causally verified. SYSTEM belongs to the '
                    'recipient kernel, not necessarily the remote caller.',
                    tuple(a.target for a in smb[:3] if a.target in memory.fetched_ids)))
        if re.search(r'\b(no\s+(?:downstream|anomalous|file|security|remote)|only\s+(?:normal|routine))\b',text):
            if any(a.severity >=7 for a in actual):
                issues.append(ClaimIssue('absence_claim_contradicted_by_actions',8,
                    'Blanket assertion of no important downstream effect conflicts with retrieved causal actions. '
                    'Discuss those actions and their implications.',
                    tuple(a.target for a in actual[:3] if a.target in memory.fetched_ids)))
        return sorted(issues,key=lambda x:(-x.weight,x.code))[:6]


class SOCV24(SOCV23):
    """Reuses v22 graph traversal, adds independent security action provenance."""

    def __init__(self, director: Any):
        super().__init__(director)
        self.casebook=ThreatCasebook()

    def dossier(self, memory: Any, limit: int = 9) -> str:
        return super().dossier(memory,limit=limit) + '\n' + self.casebook.dossier(memory,limit=limit)


@dataclass
class ThreatHuntingCaseState(ReasonedEvidenceCaseState):
    """One bounded, source-grounded pivot for peer attribution after traversal."""
    attribution_pivots: set[str] = field(default_factory=set)

    def _peer_pivot(self,memory:Any,tools:set[str])->Inspection|None:
        if 'search' not in tools or len(self.attribution_pivots)>=1:return None
        casebook=ThreatCasebook()
        urgent={'smb_source','relay_surface','credentialed_share','cross_identity_share','remote_control_pipe','network_bridge'}
        actions=[a for a in casebook.observed_actions(memory) if a.category in urgent]
        for a in actions:
            # Search only an EXACT IP present in the FETCHED target of an
            # alert-connected causal edge; never synthesize a host or account.
            for nodeid in (a.target,a.actor):
                if nodeid not in memory.fetched_ids:continue
                p=(memory.observed_nodes.get(nodeid) or {}).get('properties') or {}
                direction = str(p.get('direction') or '').lower()
                relation_kind = str(memory.graph_edges.get(a.relation_id, ('', '', ''))[0]).lower()
                # Direction can be absent in the network object; verify its edge.
                inbound = direction == 'inbound' or relation_kind == 'accepted_connection_from'
                keys = ('src_ip',) if inbound else ('dst_ip',)
                for key in keys:
                    ip=str(p.get(key) or '').strip()
                    try:
                        addr=ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if (addr.version != 4 or addr.is_loopback or
                            addr.is_multicast or addr.is_unspecified):continue
                    if ip in self.attribution_pivots:continue
                    args={'query':ip,'reasoning':
                        'Attribute the exact observed network peer to a process/account, '
                        'then verify linked actions. A search hit is NOT confirmed execution.'}
                    if memory.cache_key('search',args) in memory.cache:continue
                    self.attribution_pivots.add(ip)
                    return Inspection(Lead('search',args,'peer-source evidence pivot',13),
                                      'Attribute verified remote peer IP','threat-attribution')
        return None

    def _bridge_configuration_followup(self, memory: Any, tools: set[str]) -> Inspection | None:
        """Verify a discovered forwarding command on the actual affected host.

        A search hit is a lead, NOT evidence. This pivot opens at most one
        high-specificity process or registry artifact on an alert-connected
        host. The node must match a verified bridge, not a cached keyword in
        an unrelated enterprise machine.
        """
        if 'get_entity' not in tools:
            return None
        bridges = [a for a in ThreatCasebook().observed_actions(memory)
                   if a.category == 'network_bridge']
        if not bridges:
            return None
        host_ids = {((memory.observed_nodes.get(a.actor) or {}).get('host_id'))
                    for a in bridges}
        host_ids.discard(None)
        candidates=[]
        for nid, node in memory.observed_nodes.items():
            if nid in memory.fetched_ids or nid in memory.rejected_ids:
                continue
            if not isinstance(node,dict) or node.get('type') != 'windows_process':
                continue
            if node.get('host_id') not in host_ids:
                continue
            props = node.get('properties') or {}
            if not isinstance(props, dict):continue
            cmd = str(props.get('cmdline') or '')
            if re.search(r'\bnetsh\b.{0,100}\binterface\s+portproxy\s+(?:add|set)\b',cmd,re.I):
                candidates.append(nid)
        if not candidates:
            return None
        nid = sorted(candidates, key=lambda n:memory.discovery_order.get(n,999999))[0]
        return Inspection(Lead('get_entity', {'entity_id':nid, 'reasoning':
            'Verify on this incident host the exact discovered portproxy '
            'configuration and compare it with observed inbound and outbound '
            'connections. A search result alone does not prove modification.'},
            'verified forwarding configuration pivot', 24),
            'Resolve search-discovered forwarding configuration', 'bridge-configuration')

    def select_acquisition(self,memory:Any,tools:set[str],*,step_index:int,max_steps:int,
                           force_finish:bool=False)->Inspection|None:
        if not force_finish and step_index < max_steps-3:
            bridge = self._bridge_configuration_followup(memory, tools)
            if bridge is not None:
                self.move('ACQUIRE')
                return bridge
        original=super().select_acquisition(memory,tools,step_index=step_index,
                                        max_steps=max_steps,force_finish=force_finish)
        if original is not None or force_finish or step_index>=max_steps-5:return original
        pivot=self._peer_pivot(memory,tools)
        if pivot:self.move('ACQUIRE')
        return pivot

    def decision_instructions(self,memory:Any)->str:
        return super().decision_instructions(memory)+'\n'+ThreatCasebook().dossier(memory,limit=12)
