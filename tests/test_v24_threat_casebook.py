"""Behavior-first v24 regressions: grounded facts, harmless controls, and loop."""
import asyncio
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v24 import ThreatCasebook, SOCV24, ThreatHuntingCaseState
from test_v16_loop import FakeSession, finish


def mproc(pid='p', cmd='System', image='System'):
    m=InvestigationMemory()
    m.focus_ids={pid}
    m.absorb({'id':pid,'type':'windows_process','properties':{'cmdline':cmd,'image_path':image,'user':'SYSTEM'}})
    m.fetched_ids.add(pid)
    return m


def entity(m,ident,kind,properties):
    m.absorb({'id':ident,'type':kind,'properties':properties})
    m.fetched_ids.add(ident)


def edge(m,rid,kind,src,dst):
    m.absorb({'id':rid,'type':kind,'source_id':src,'target_id':dst})
    m.fetched_ids.add(rid)


def cats(m):
    return {a.category for a in ThreatCasebook().observed_actions(m)}


def test_pipe_is_independent_of_model_claims():
    m=mproc(cmd=r'C:\Windows\service.exe -service')
    entity(m,'pipe','windows_pipe',{'pipe_name':r'\\.\pipe\PSEXESVC-ADM-stdin'})
    edge(m,'r','created_pipe','p','pipe')
    assert 'remote_control_pipe' in cats(m)
    assert ThreatCasebook().challenge(m, {'verdict':'benign','reasoning':'Normal signed service',
                                            'legitimacy_evidence':[{'entity_id':'p'}]})


def test_pipe_lookalike_in_search_does_not_prove_execution():
    m=mproc()
    m.absorb({'id':'unopened','type':'windows_pipe','properties':{'pipe_name':'PSEXESVC-stdin'}})
    edge(m,'r','created_pipe','p','unopened')
    assert 'remote_control_pipe' not in cats(m)


def test_peer_with_netuse_explicit_creds_requires_explanation():
    m=mproc(cmd=r'net use \\srv\ADMIN$ /user:DOMAIN\admin [redacted]')
    entity(m,'net','network_connection',{'dst_ip':'172.16.0.12','dst_port':445,'src_ip':'172.16.0.5'})
    edge(m,'r','connected_to','p','net')
    assert 'credentialed_share' in cats(m)
    case=ThreatCasebook()
    assert case.unmet(m,{'verdict':'benign','reasoning':'Signed Microsoft binary.',
                           'legitimacy_evidence':[{'entity_id':'p'}]})
    assert not case.unmet(m,{'verdict':'benign','reasoning':'SMB share explicitly used an alternate account; authorization remains unknown.',
                         'legitimacy_evidence':[{'relation_id':'r'}]})


def test_inbound_smb_burst_rooted_in_same_actor():
    m=mproc()
    for i in range(3):
        nid=f'n{i}'
        entity(m,nid,'network_connection',{'src_ip':'10.0.0.8','dst_port':445})
        edge(m,f'e{i}','accepted_connection_from','p',nid)
    assert 'smb_source' in cats(m)
    assert any(x.code=='unaccounted_smb_source' for x in ThreatCasebook().challenge(m,
        {'verdict':'benign','reasoning':'Only the Windows kernel was observed.'}))


def test_single_inbound_smb_is_not_high_severity_event():
    m=mproc()
    entity(m,'n','network_connection',{'src_ip':'10.0.0.8','dst_port':445})
    edge(m,'r','accepted_connection_from','p','n')
    assert not [a for a in ThreatCasebook().observed_actions(m) if a.severity>=7]


def test_inbound_and_outbound_admin_same_actor():
    m=mproc(cmd=r'svchost.exe -k netsvcs -p -s iphlpsvc')
    for rid,kind,port in [('i','accepted_connection_from',61224),('o','connected_to',445)]:
        entity(m,rid+'n','network_connection',{'dst_port':port,'src_ip':'10.0.0.5','dst_ip':'10.0.0.6'})
        edge(m,rid,kind,'p',rid+'n')
    assert 'relay_surface' in cats(m)


def test_abusive_claim_of_absence_is_refuted():
    m=mproc()
    entity(m,'pipe','windows_pipe',{'pipe_name':'PSEXESVC-111-stdin'})
    edge(m,'r','created_pipe','p','pipe')
    claim=ThreatCasebook().challenge(m, {'verdict':'benign',
        'reasoning':'There are no downstream effects and only normal signed processes.'})
    assert any(a.code=='absence_claim_contradicted_by_actions' for a in claim)


def test_no_auto_malicious_label_on_legitimate_pipe():
    m=mproc()
    entity(m,'pipe','windows_pipe',{'pipe_name':'PSEXESVC-111-stdin'})
    edge(m,'r','created_pipe','p','pipe')
    assert ThreatCasebook().challenge(m,{'verdict':'malicious','reasoning':'Observed remote control pipe.'})==[]


def test_attribution_search_one_real_peer_only():
    m=mproc(cmd='net use \\server\admin$ /user:DOMAIN\admin')
    entity(m,'n','network_connection',{'dst_port':445,'src_ip':'10.0.0.7','dst_ip':'10.0.0.9'})
    edge(m,'r','connected_to','p','n')
    case=ThreatHuntingCaseState(SOCV24(InvestigationDirector()))
    first=case._peer_pivot(m,{'search'})
    assert first and first.lead.arguments['query'] == '10.0.0.9'
    assert case._peer_pivot(m,{'search'}) is None


def test_search_result_only_not_action_or_peer_query():
    m=mproc()
    m.absorb({'id':'net','type':'network_connection','properties':{'src_ip':'10.0.0.9','dst_port':445}})
    assert ThreatHuntingCaseState(SOCV24(InvestigationDirector()))._peer_pivot(m,{'search'}) is None


def test_old_modes_not_affected_by_v24_switch():
    old=SimpleSGRAgent(object(),soc_v23_mode=True)
    assert not old.soc_v24_mode and old.threat_casebook is None
    new=SimpleSGRAgent(object(),soc_v24_mode=True)
    assert new.soc_v24_mode and new.soc_v23_mode and new.soc_v22_mode
    assert isinstance(new.soc_v18,SOCV24)


def test_complete_loop_with_no_forced_malicious():
    class LLM:
        async def next_step(self,messages,*,finish_only=False):return finish()
    agent=SimpleSGRAgent(LLM(),soc_v24_mode=True,gpt_oss_mode=True,
                          max_steps=12,trajectory_dir=None)
    session=FakeSession()
    result=asyncio.run(agent._investigate(session,[]))
    assert result.completion_reason=='terminated'
    assert session.calls[-1][1]['submission']['verdict']=='benign'


def test_approval_words_without_positive_proof_are_challenged():
    m=mproc(cmd=r'svchost.exe -k netsvcs -p -s iphlpsvc')
    entity(m,'in','network_connection',{'src_ip':'10.0.0.3','dst_port':62224})
    entity(m,'out','network_connection',{'dst_ip':'10.0.0.4','dst_port':445})
    edge(m,'ri','accepted_connection_from','p','in')
    edge(m,'ro','connected_to','p','out')
    proposal={'verdict':'benign','reasoning':'Routine authorized remote SMB administration',
              'legitimacy_evidence':[{'relation_id':'ro'},{'entity_id':'out'}]}
    issues=ThreatCasebook().challenge(m,proposal)
    assert any(i.code=='material_remote_action_not_authorized' for i in issues)


def test_smb_auth_failure_requires_correlated_evidence():
    m=mproc()
    for i in range(3):
        entity(m,f'n{i}','network_connection',{'src_ip':'10.0.0.6','dst_port':445})
        edge(m,f'r{i}','accepted_connection_from','p',f'n{i}')
    proposal={'verdict':'benign',
              'reasoning':'All repeated SMB connections failed NTLM auth with 0xc0000022',
              'legitimacy_evidence':[{'relation_id':'r0'}]}
    issues=ThreatCasebook().challenge(m,proposal)
    assert any(x.code=='smb_authentication_outcome_unverified' for x in issues)


def test_positive_authorization_record_removes_authorization_question():
    m=mproc(cmd=r'net use \\server\admin$ /user:DOMAIN\admin')
    entity(m,'net','network_connection',{'dst_ip':'10.0.0.5','dst_port':445})
    edge(m,'r','connected_to','p','net')
    entity(m,'auth','change_record',{'approved':True,'change_ticket':'CHG-12784'})
    edge(m,'approval-edge','approved_by','p','auth')
    proposal={'verdict':'benign','reasoning':'Authorized credentialed SMB share mapping',
              'legitimacy_evidence':[{'relation_id':'r'}]}
    assert not any(i.code=='material_remote_action_not_authorized'
                   for i in ThreatCasebook().challenge(m,proposal))


def test_complete_v24_loop_behaviour_examiner_can_revise_benign():
    import json
    from bluesec1_agent.models import NextStep
    from bluesec1_client import PublicTask, ToolCallResult, TaskResult

    class PipeSession(FakeSession):
        def __init__(self):
            super().__init__()
            self.task = PublicTask(task_id=self.task_id, observation={
                'alert_text': {'alert_description':'Remote service pipe detected',
                    'trigger_entities':[{'id':'proc','type':'windows_process',
                        'properties':{'cmdline':r'C:\Windows\service-8.exe -service','user':'SYSTEM'}}]},
                'available_tools':json.dumps([{'name':name,'arguments':[arg]}
                      for name,arg in [('get_entity','entity_id'),('get_relation','relation_id'),
                                       ('finish_investigation','submission')]]),
            })
        async def call_tool(self,name,args):
            self.calls.append((name,args))
            if name=='get_entity' and args['entity_id']=='proc':
                obs={'id':'proc','type':'windows_process','properties':{
                    'cmdline':r'C:\Windows\service-8.exe -service','user':'SYSTEM'},
                    'relation_ids':{'outgoing':['r']}}
            elif name=='get_relation' and args['relation_id']=='r':
                obs={'id':'r','type':'created_pipe','source_id':'proc','target_id':'pipe'}
            elif name=='get_entity' and args['entity_id']=='pipe':
                obs={'id':'pipe','type':'windows_pipe',
                     'properties':{'pipe_name':r'\\.\pipe\PSEXESVC-OPS-stdin'}}
            elif name=='finish_investigation':
                return ToolCallResult(task_id=self.task_id,tool_name=name,terminated=True,
                    task_result=TaskResult(task_id=self.task_id,completion_reason='terminated'))
            else:raise AssertionError((name,args))
            return ToolCallResult(task_id=self.task_id,tool_name=name,
                observation={'last_tool_result':json.dumps(obs)},info={'tool_status':'ok'})

    def response(verdict):
        sub=({'verdict':'malicious','reasoning':
                'PsExec-family remote service pipe was created by the observed nonstandard process.',
              'ir_artifacts':[{'entity_id':'proc','kind':'process_observed'}]}
             if verdict=='malicious' else
             {'verdict':'benign','reasoning':'Normal Microsoft system service with no downstream effects.',
              'legitimacy_evidence':[{'anchor':'entity','entity_id':'proc',
                                      'property_fields':['cmdline','user']}]})
        return NextStep.model_validate({'current_state':'Review observed actions',
            'plan_remaining_steps_brief':['Submit'],'task_completed':True,
            'function':{'tool':'finish_investigation','submission':sub}})

    class LLM:
        def __init__(self):self.v24_reviews=0
        async def next_step(self,messages,*,finish_only=False):
            if any('DFIR behavior examiner' in x.get('content','') for x in messages):
                self.v24_reviews+=1
                return response('malicious')
            return response('benign')

    session=PipeSession(); llm=LLM(); trail=[]
    agent=SimpleSGRAgent(llm,soc_v24_mode=True,max_steps=15,
                           trajectory_dir=None,review_enabled=False,gpt_oss_mode=True)
    result=asyncio.run(agent._investigate(session,trail))
    assert result.completion_reason=='terminated'
    assert llm.v24_reviews==1
    assert session.calls[-1][1]['submission']['verdict']=='malicious'
    assert any('v24_behavioral_revision' in str(m) for m in trail)


def test_unrelated_approval_does_not_sanitize_remote_action():
    m=mproc(cmd=r'net use \\server\admin$ /user:DOMAIN\admin')
    entity(m,'net','network_connection',{'dst_ip':'10.0.0.5','dst_port':445})
    edge(m,'r','connected_to','p','net')
    entity(m,'unrelated','change_record',{'approved':True,'change_ticket':'CHG-98765'})
    proposal={'verdict':'benign','reasoning':'Authorized credentialed SMB mapping',
              'legitimacy_evidence':[{'relation_id':'r'}]}
    assert any(i.code=='material_remote_action_not_authorized'
               for i in ThreatCasebook().challenge(m,proposal))


def test_outbound_peer_pivot_queries_destination_not_local_src():
    m = mproc(cmd=r'net use \\server\share /user:DOMAIN\admin')
    entity(m, 'net', 'network_connection', {
        'src_ip': '10.15.0.7', 'dst_ip': '172.22.0.12',
        'dst_port': 445, 'direction': 'outbound'})
    edge(m, 'r', 'connected_to', 'p', 'net')
    case = ThreatHuntingCaseState(SOCV24(InvestigationDirector()))
    assert case._peer_pivot(m, {'search'}).lead.arguments['query'] == '172.22.0.12'


def test_identity_change_endpoint_is_priority_even_if_windows_user():
    m = mproc(cmd='mmc.exe dsa.msc')
    entity(m, 'target_user', 'windows_user', {'group_memberships': ['Domain Admins']})
    edge(m, 'r', 'added_to_group', 'p', 'target_user')
    # Simulate an entity known via graph but not yet fetched.
    m.fetched_ids.remove('target_user')
    engine = SOCV24(InvestigationDirector())
    proposal = engine._endpoint(m, {'get_entity'})
    assert proposal is not None
    assert proposal.lead.tool == 'get_entity'
    assert proposal.lead.arguments['entity_id'] == 'target_user'


def test_malicious_identity_change_is_challenged_when_unauthorized_unproven():
    from bluesec1_agent.soc_v23 import SemanticEvidenceValidator
    m = mproc(cmd='mmc.exe dsa.msc')
    entity(m, 'target_user', 'windows_user', {'group_memberships': ['Domain Admins']})
    edge(m, 'r', 'added_to_group', 'p', 'target_user')
    issues = SemanticEvidenceValidator().issues(m, {
        'verdict': 'malicious',
        'reasoning': 'Unauthorized elevation: user added to Domain Admins without any recorded approval.',
    })
    assert any(i.code == 'identity_change_authorization_unverified' for i in issues)


def test_identity_change_explicit_approval_contradicts_unauthorized_claim():
    from bluesec1_agent.soc_v23 import SemanticEvidenceValidator
    m = mproc(cmd='mmc.exe dsa.msc')
    entity(m, 'target_user', 'windows_user', {'group_memberships': ['Domain Admins']})
    entity(m, 'approval', 'change_record', {'approved': True})
    edge(m, 'r', 'added_to_group', 'p', 'target_user')
    edge(m, 'ra', 'approved_by', 'p', 'approval')
    result = SemanticEvidenceValidator().issues(m, {
        'verdict': 'malicious',
        'reasoning': 'Unauthorized elevation, without any recorded approval.'
    })
    assert any(i.code == 'identity_change_authorization_contradicted' for i in result)


def test_inbound_peer_pivot_uses_edge_when_direction_missing():
    m = mproc()
    for i in range(3):
        entity(m, f'net{i}', 'network_connection', {'src_ip': '10.10.1.8',
               'dst_ip': '172.22.1.5', 'dst_port': 445})
        edge(m, f'r{i}', 'accepted_connection_from', 'p', f'net{i}')
    pivot = ThreatHuntingCaseState(SOCV24(InvestigationDirector()))._peer_pivot(m, {'search'})
    assert pivot is not None
    assert pivot.lead.arguments['query'] == '10.10.1.8'

# V26 regressions: effects must be corroborated before benign closure.
def test_v26_portproxy_like_bridge_requires_effect_explanation():
    m=mproc(cmd=r'C:\Windows\System32\svchost.exe -k netsvcs -s iphlpsvc')
    m.observed_nodes['p']['host_id']='local-host'
    entity(m,'incoming','network_connection',{'direction':'outbound','src_ip':'10.0.0.18',
        'dst_ip':'10.0.0.8','dst_port':62816})
    edge(m,'ri','accepted_connection_from','p','incoming')
    entity(m,'outgoing','network_connection',{'direction':'outbound','src_ip':'10.0.0.8',
        'dst_ip':'192.0.2.30','dst_port':443})
    edge(m,'ro','connected_to','p','outgoing')
    assert 'network_bridge' in cats(m)
    s={'verdict':'benign','reasoning':'Normal signed internal remote management on HTTPS',
       'legitimacy_evidence':[{'relation_id':'ri'}]}
    assert any(i.code=='unaccounted_network_bridge' for i in ThreatCasebook().challenge(m,s))
    # Search-hit-only netsh process cannot be presented as confirmed execution.
    m.absorb({'id':'netsh','type':'windows_process','host_id':'local-host',
              'properties':{'cmdline':'netsh interface portproxy add v4tov4 listenport=62816'}})
    assert 'portproxy_rule' not in cats(m)
    st=ThreatHuntingCaseState(SOCV24(InvestigationDirector()))
    followup=st._bridge_configuration_followup(m, {'get_entity'})
    assert followup and followup.lead.arguments['entity_id']=='netsh'
    m.fetched_ids.add('netsh')
    assert st._bridge_configuration_followup(m,{'get_entity'}) is None


def test_v26_unrelated_search_hit_is_not_opened_by_bridge_pivot():
    m=mproc()
    m.observed_nodes['p']['host_id']='host-A'
    entity(m,'incoming','network_connection',{'src_ip':'10.0.0.5','dst_port':55000})
    edge(m,'r1','accepted_connection_from','p','incoming')
    entity(m,'outgoing','network_connection',{'dst_ip':'203.0.113.15','dst_port':443})
    edge(m,'r2','connected_to','p','outgoing')
    m.absorb({'id':'other','type':'windows_process','host_id':'host-B',
              'properties':{'cmdline':'netsh interface portproxy add v4tov4 listenport=80'}})
    st=ThreatHuntingCaseState(SOCV24(InvestigationDirector()))
    assert st._bridge_configuration_followup(m,{'get_entity'}) is None


def test_v26_inbound_smb_normality_requires_source_attribution():
    m=mproc(cmd='System')
    for i in range(3):
        entity(m,f'n{i}','network_connection', {'direction':'inbound',
            'src_ip':'192.168.216.235','dst_ip':'10.215.202.209','dst_port':445})
        edge(m,f'r{i}','accepted_connection_from','p',f'n{i}')
    proposal={'verdict':'benign', 'reasoning':'Typical normal SMB traffic on signed SYSTEM',
        'legitimacy_evidence':[{'relation_id':'r0'},{'relation_id':'r1'},{'relation_id':'r2'}]}
    assert any(i.code=='smb_source_purpose_unverified' for i in ThreatCasebook().challenge(m,proposal))


def test_v26_smb_single_session_does_not_trigger_burst_guard():
    m=mproc()
    entity(m,'n','network_connection',{'src_ip':'10.0.0.6','dst_port':445})
    edge(m,'r','accepted_connection_from','p','n')
    assert not any(i.code=='smb_source_purpose_unverified' for i in
        ThreatCasebook().challenge(m,{'verdict':'benign','reasoning':'normal',
          'legitimacy_evidence':[{'relation_id':'r'}]}))


def test_v26_different_supplied_smb_identity_is_flagged_as_question():
    m=mproc(cmd=r'net use \\server\Diagnostics$ /user:SUMMIT\adm_c.reed [redacted]')
    m.observed_nodes['p']['properties']['user']=r'LIBRARY81\svc_workplace'
    entity(m,'smb','network_connection',{'dst_ip':'172.22.108.87','dst_port':445})
    edge(m,'r','connected_to','p','smb')
    assert 'cross_identity_share' in cats(m)
    issues=ThreatCasebook().challenge(m,{
       'verdict':'benign','reasoning':'Normal signed maintenance using an admin SMB share',
       'legitimacy_evidence':[{'relation_id':'r'}]})
    assert any(i.code=='material_remote_action_not_authorized' for i in issues)


def test_v26_same_smb_principal_is_not_cross_identity():
    m=mproc(cmd=r'net use \\server\share /user:DOMAIN\alice [redacted]')
    m.observed_nodes['p']['properties']['user']=r'DOMAIN\alice'
    entity(m,'smb','network_connection',{'dst_ip':'10.0.0.10','dst_port':445})
    edge(m,'r','connected_to','p','smb')
    assert 'cross_identity_share' not in cats(m)
