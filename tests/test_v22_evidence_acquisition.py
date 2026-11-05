"""v22: do not confuse reading relation IDs with reading impacted objects."""
import asyncio

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v22 import SOCV22, EvidenceFocusedCaseState
from test_v16_loop import FakeSession, finish


def memory():
    m = InvestigationMemory()
    m.focus_ids = {'p'}
    m.absorb({'id':'p','type':'windows_process','properties':{'cmdline':'test.exe'}})
    m.fetched_ids.add('p')
    return m


def engine():
    return SOCV22(InvestigationDirector())


def edge(m, rid='r', kind='connected_to', dst='net', src='p'):
    m.absorb({'id':rid,'type':kind,'source_id':src,'target_id':dst})
    m.fetched_ids.add(rid)


def test_follows_real_network_endpoint_without_implicit_type():
    m = memory(); edge(m)
    assert 'net' not in m.entity_types
    selected = engine().next_inspection(m,{'get_entity','get_relation'})
    assert selected and selected.lead.tool == 'get_entity'
    assert selected.lead.arguments['entity_id'] == 'net'
    assert selected.phase == 'consequence-first'


def test_effect_endpoint_outranks_connection_endpoint():
    m = memory(); edge(m, 'n', 'connected_to', 'net'); edge(m,'w','wrote_file','file')
    selected = engine().next_inspection(m,{'get_entity','get_relation'})
    assert selected and selected.lead.arguments['entity_id'] == 'file'


def test_unrelated_search_result_cannot_be_selected():
    m=memory();edge(m)
    m.absorb({'id':'unrelated','type':'windows_file','properties':{'path':'a.dll'}})
    selected=engine()._endpoint(m, {'get_entity'})
    assert selected and selected.lead.arguments['entity_id']=='net'


def test_fetched_endpoint_not_visited_twice():
    m=memory();edge(m)
    m.fetched_ids.add('net')
    assert engine()._endpoint(m,{'get_entity'}) is None


def test_unknown_id_not_in_known_set_cannot_be_requested():
    m=memory(); edge(m)
    m.known_ids.discard('net')
    assert engine()._endpoint(m,{'get_entity'}) is None


def test_case_state_prioritizes_endpoint_over_other_relation():
    m=memory();edge(m)
    m.absorb({'id':'p','type':'windows_process','properties':{'cmdline':'test.exe'},
              'relation_ids':{'out':['other']}})
    state=EvidenceFocusedCaseState(engine())
    choice=state.select_acquisition(m,{'get_entity','get_relation'},step_index=3,max_steps=28)
    assert choice and choice.lead.tool=='get_entity'
    assert choice.lead.arguments['entity_id']=='net'


def test_service_cross_identity_is_not_low_risk_without_a_verdict_override():
    m=memory()
    m.absorb({'id':'p','type':'windows_process','properties':{
        'image_path':r'C:\Windows\monitor-3.exe','cmdline':r'C:\Windows\monitor-3.exe -service',
        'user':r'NT AUTHORITY\SYSTEM'}})
    m.absorb({'id':'child','type':'windows_process','properties':{
        'image_path':r'C:\Windows\Temp\python.exe','cmdline':r'C:\Windows\Temp\python.exe',
        'parent_image':r'C:\Windows\monitor-3.exe','user':r'DOMAIN\worker'}})
    edge(m,'e','win_process_create','child')
    m.fetched_ids.add('child')
    risk=EvidenceFocusedCaseState(engine()).risk_profile(m)
    assert risk.minimum>=9


def test_old_modes_remain_off_unless_opted_in():
    v21=SimpleSGRAgent(object(),soc_v21_mode=True)
    assert not v21.soc_v22_mode
    v22=SimpleSGRAgent(object(),soc_v22_mode=True)
    assert v22.soc_v22_mode and v22.soc_v21_mode


def test_full_loop_opens_endpoint_without_extra_llm_choice():
    class LLM:
        def __init__(self):self.calls=[]
        async def next_step(self,messages,*,finish_only=False):
            self.calls.append(finish_only)
            return finish()
    session=FakeSession();llm=LLM();transcript=[]
    agent=SimpleSGRAgent(llm,max_steps=12,trajectory_dir=None,review_enabled=True,
                         gpt_oss_mode=True,soc_v22_mode=True)
    result=asyncio.run(agent._investigate(session,transcript))
    assert result.completion_reason=='terminated'
    assert [name for name,_ in session.calls][:3]==['get_entity','get_relation','get_entity']
    assert all(llm.calls)


def test_grounded_cross_identity_search_never_uses_guessed_filename():
    m=memory()
    m.absorb({'id':'p','type':'windows_process','properties':{
        'image_path':r'C:\Windows\monitor-3.exe','cmdline':r'C:\Windows\monitor-3.exe -service',
        'user':r'NT AUTHORITY\SYSTEM'}})
    m.absorb({'id':'child','type':'windows_process','properties':{
        'image_path':r'C:\Windows\Temp\python.exe','cmdline':r'C:\Windows\Temp\python.exe',
        'parent_image':r'C:\Windows\monitor-3.exe','user':r'DOMAIN\worker'}})
    edge(m,'e','win_process_create','child')
    m.fetched_ids.add('child')
    plan=engine()._temp_execution_pivot(m,{'search'})
    assert plan and plan.lead.arguments['query']==r'C:\Windows\Temp\python.exe'
    m.cache[m.cache_key(plan.lead.tool,plan.lead.arguments)]={'status':'ok'}
    assert engine()._temp_execution_pivot(m,{'search'}) is None


def test_grounded_cross_identity_search_rejects_unconfirmed_process():
    m=memory()
    m.absorb({'id':'child','type':'windows_process','properties':{
        'image_path':r'C:\Windows\Temp\python.exe','user':r'DOMAIN\worker'}})
    assert engine()._temp_execution_pivot(m,{'search'}) is None
