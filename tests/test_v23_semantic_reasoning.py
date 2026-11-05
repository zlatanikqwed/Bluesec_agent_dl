"""v23 tests focus on truthfulness, safe pivots and backward compatibility."""
import asyncio

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v22 import SOCV22
from bluesec1_agent.soc_v23 import ReasonedEvidenceCaseState, SemanticEvidenceValidator
from test_v16_loop import FakeSession, finish


def mem(nid='process', typ='windows_process', **props):
    memory = InvestigationMemory()
    memory.focus_ids = {nid}
    memory.absorb({'id': nid, 'type': typ, 'properties': props})
    memory.fetched_ids.add(nid)
    return memory


def add(m, nid, typ, p, *, edge=None):
    m.absorb({'id': nid, 'type': typ, 'properties': p})
    m.fetched_ids.add(nid)
    if edge:
        rid, kind, actor = edge
        m.absorb({'id': rid, 'type': kind, 'source_id': actor, 'target_id': nid})
        m.fetched_ids.add(rid)


def codes(m, reasoning, verdict='benign'):
    return {x.code for x in SemanticEvidenceValidator().issues(m,
        {'verdict': verdict, 'reasoning': reasoning})}


def test_approved_scheduled_task_cannot_be_inferred_from_explorer():
    m = mem(cmdline='powershell.exe', user='DOMAIN\\svc_metrics')
    add(m, 'parent', 'windows_process', {'image_path':'C:\\Windows\\explorer.exe'},
        edge=('spawns','win_process_create','parent'))
    assert 'scheduled_task_not_observed' in codes(m, 'Approved scheduled task runs this process.')
    assert 'authorization_not_observed' in codes(m, 'Approved scheduled task runs this process.')


def test_genuine_scheduled_task_positive_metadata_eliminates_specific_issue():
    m = mem(cmdline='schtasks /run /tn nightlyjob')
    assert 'scheduled_task_not_observed' not in codes(m, 'A scheduled task runs this.')


def test_psexec_pipe_cannot_be_explained_by_microsoft_update_signature():
    m=mem(cmdline=r'C:\Windows\updater-7818.exe -service', user='SYSTEM')
    add(m, 'pipe', 'windows_pipe', {'pipe_name':r'\\.\pipe\PSEXESVC-OPS47-6000-stdin'},
        edge=('r','created_pipe','process'))
    issues=codes(m, 'This is routine Windows Update maintenance by a signed SYSTEM process.')
    assert 'update_explanation_conflicts_with_remote_pipe' in issues
    assert 'remote_execution_origin_unverified' in issues
    assert 'update_explanation_conflicts_with_remote_pipe' not in codes(m,
        'A remote execution pipe was created, but initiator and authorization remain unknown.')


def test_network_events_do_not_prove_ntlm_failure():
    m=mem(cmdline='System')
    for n in ('n1','n2'):
        add(m,n,'network_connection',{'src_ip':'192.168.91.45','dst_port':445},
            edge=('r'+n,'accepted_connection_from','process'))
    assert 'authentication_result_not_observed' in codes(m,
        'Only failed NTLM logons were observed, so this traffic is benign.')
    assert 'authentication_result_not_observed' not in codes(m,
        'Two SMB sessions were observed; the outcome of authentication is unknown.')


def test_dont_automatically_flip_network_anomaly():
    m=mem(cmdline='System')
    assert codes(m, 'Internal SMB activity; attacker intent is unknown.') == set()


def test_malicious_fabrication_is_also_challenged():
    m=mem(cmdline='powershell -NoProfile -Command Get-Date')
    assert 'credential_dump_not_observed' in codes(m,
        'This attack dumped LSASS memory.', 'malicious')


def test_semantic_pivot_is_grounded_and_single_use():
    m=mem(cmdline='powershell')
    add(m,'cmdlet','powershell_cmdlet_invocation',
        {'command_name':'Out-Null','script_block_id':'sbid-script-sql-update'},
        edge=('r','invoked_cmdlet','process'))
    state=ReasonedEvidenceCaseState(SOCV22(InvestigationDirector()))
    choice=state._semantic_pivot(m,{'search'})
    assert choice and choice.lead.arguments['query']=='sbid-script-sql-update'
    assert state._semantic_pivot(m,{'search'}) is None


def test_unguarded_search_hit_not_used_as_exec_evidence():
    m=mem(cmdline='powershell')
    m.absorb({'id':'search-only','type':'powershell_cmdlet_invocation',
              'properties':{'command_name':'Out-Null','script_block_id':'sbid-find-me'}})
    state=ReasonedEvidenceCaseState(SOCV22(InvestigationDirector()))
    assert state._semantic_pivot(m,{'search'}) is None


def test_v22_not_changed_by_optional_v23_flag():
    agent=SimpleSGRAgent(object(),soc_v22_mode=True)
    assert not agent.soc_v23_mode and agent.semantic_validator is None
    next_agent=SimpleSGRAgent(object(),soc_v23_mode=True)
    assert next_agent.soc_v22_mode and next_agent.soc_v21_mode
    assert next_agent.semantic_validator is not None


def test_full_loop_v23_default_benign_does_not_force_malicious():
    class LLM:
        def __init__(self): self.calls=0
        async def next_step(self,messages,*,finish_only=False):
            self.calls+=1
            return finish()
    s=FakeSession(); llm=LLM(); agent=SimpleSGRAgent(llm,soc_v23_mode=True,
        max_steps=12,trajectory_dir=None,review_enabled=True,gpt_oss_mode=True)
    result=asyncio.run(agent._investigate(s,[]))
    assert result.completion_reason=='terminated'
    assert s.calls[-1][1]['submission']['verdict']=='benign'


def test_cross_protocol_management_does_not_count_as_verified_authorization():
    m=mem(cmdline='svchost.exe -k netsvcs -p -s iphlpsvc',user='SYSTEM')
    for i, port in enumerate((445,5985)):
        add(m,f'net{i}','network_connection',{'src_ip':'192.168.194.230',
            'dst_ip':'192.168.159.181','dst_port':port},
            edge=(f'r{i}','connected_to','process'))
    assert 'cross_protocol_remote_intent_unverified' in codes(m,
        'These are legitimate routine maintenance connections.')
    assert 'cross_protocol_remote_intent_unverified' not in codes(m,
        'The SMB and WinRM destinations were contacted, but intent is unknown.')


def test_v23_full_loop_can_replace_unsupported_benign_after_final_review():
    import json
    from bluesec1_agent.models import NextStep
    from bluesec1_client import PublicTask, ToolCallResult, TaskResult

    class PipeSession(FakeSession):
        def __init__(self):
            super().__init__()
            self.task = PublicTask(task_id=self.task_id, observation={
                'alert_text': {'alert_description':'Unusual remote tool',
                    'trigger_entities':[{'id':'proc','type':'windows_process',
                        'properties':{'cmdline':r'C:\Windows\updater-7818.exe -service',
                                      'user':'SYSTEM'}}]},
                'available_tools':json.dumps([{'name':t,'arguments':[arg]} for t,arg in
                    (('get_entity','entity_id'),('get_relation','relation_id'),
                     ('finish_investigation','submission'))]),
            })
        async def call_tool(self,name,args):
            self.calls.append((name,args))
            if name=='get_entity' and args.get('entity_id')=='proc':
                observation={'id':'proc','type':'windows_process',
                    'properties':{'cmdline':r'C:\Windows\updater-7818.exe -service',
                                  'user':'SYSTEM'},'relation_ids':{'outgoing':['pipe-edge']}}
            elif name=='get_relation' and args.get('relation_id')=='pipe-edge':
                observation={'id':'pipe-edge','type':'created_pipe',
                    'source_id':'proc','target_id':'pipe'}
            elif name=='get_entity' and args.get('entity_id')=='pipe':
                observation={'id':'pipe','type':'windows_pipe',
                    'properties':{'pipe_name':r'\\.\pipe\PSEXESVC-OPS47-6000-stdin'}}
            elif name=='finish_investigation':
                return ToolCallResult(task_id=self.task_id,tool_name=name,terminated=True,
                    task_result=TaskResult(task_id=self.task_id,completion_reason='terminated'))
            else:
                raise AssertionError((name,args))
            return ToolCallResult(task_id=self.task_id,tool_name=name,
                observation={'last_tool_result':json.dumps(observation)},
                info={'tool_status':'ok'})

    def finish_with(verdict):
        sub=({'verdict':'malicious', 'reasoning':
              'The fetched pipe documents a remote-execution mechanism, not Windows Update.',
              'ir_artifacts':[{'entity_id':'proc','kind':'process_observed'}]} if verdict=='malicious' else
             {'verdict':'benign', 'reasoning':
              'The updater is routine Windows Update maintenance under SYSTEM.',
              'legitimacy_evidence':[{'anchor':'entity','entity_id':'proc',
                                       'property_fields':['cmdline','user']}]})
        return NextStep.model_validate({'current_state':'Ready to submit observed graph facts',
            'plan_remaining_steps_brief':['Submit'],'task_completed':True,
            'function':{'tool':'finish_investigation','submission':sub}})

    class LLM:
        def __init__(self):self.validations=0
        async def next_step(self,messages,*,finish_only=False):
            if any('skeptical DFIR fact validator' in m.get('content','') for m in messages):
                self.validations+=1
                return finish_with('malicious')
            return finish_with('benign')

    s=PipeSession(); model=LLM(); transcript=[]
    agent=SimpleSGRAgent(model,soc_v23_mode=True,max_steps=15,trajectory_dir=None,
                         review_enabled=False,gpt_oss_mode=True)
    result=asyncio.run(agent._investigate(s,transcript))
    assert result.completion_reason=='terminated'
    assert model.validations==1
    assert s.calls[-1][1]['submission']['verdict']=='malicious'
    assert any('v23_revised_verdict' in str(m) for m in transcript)
