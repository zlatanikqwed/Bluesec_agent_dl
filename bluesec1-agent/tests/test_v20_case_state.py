"""V20: evidence-frozen SOC review and deterministic investigation phases."""
import asyncio

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.models import NextStep
from bluesec1_agent.soc_v19 import SOCV19
from bluesec1_agent.soc_v20 import ForensicCaseState
from test_v16_loop import FakeSession, finish


def case():
    return ForensicCaseState(SOCV19(InvestigationDirector()))


def test_digest_tracks_changed_properties_not_only_counts():
    m=InvestigationMemory()
    m.absorb({'id':'p','type':'windows_process','properties':{'cmdline':'powershell -file x.ps1'}})
    first=case().revision(m)
    m.absorb({'id':'p','type':'windows_process','properties':{'cmdline':'powershell -file y.ps1'}})
    assert case().revision(m)!=first


def test_new_causal_edge_invalidates_completed_review():
    m=InvestigationMemory();m.absorb({'id':'p','type':'windows_process','properties':{'cmdline':'powershell.exe'}})
    c=case();c.update(m);c.move('DECIDE');c.mark_reviewed(m);c.mark_challenged(m)
    assert c.review_current(m) and c.challenge_current(m)
    m.absorb({'id':'r','type':'wrote_file','source_id':'p','target_id':'f'})
    assert c.update(m) and c.stage=='CORRELATE'
    assert not c.review_current(m) and not c.challenge_current(m)


def test_no_new_facts_does_not_repeat_review():
    m=InvestigationMemory();m.absorb({'id':'p','type':'windows_process'})
    c=case();c.update(m);c.move('DECIDE');c.mark_reviewed(m)
    assert not c.update(m)
    assert c.review_current(m)


def test_real_graph_step_before_decision():
    m=InvestigationMemory();m.focus_ids={'p'}
    m.absorb({'id':'p','type':'windows_process','properties':{'cmdline':'powershell -file foo.ps1'}})
    c=case();ins=c.select_acquisition(m,{'get_entity','get_relation'},step_index=1,max_steps=22)
    assert ins and ins.lead.tool=='get_entity' and ins.lead.arguments['entity_id']=='p'
    assert c.stage=='ACQUIRE'


def test_no_hallucinated_next_step_if_exhausted():
    m=InvestigationMemory();m.absorb({'id':'p','type':'windows_process'})
    m.fetched_ids.add('p')
    c=case();c.update(m)
    assert c.select_acquisition(m,{'get_entity','get_relation'},step_index=2,max_steps=22) is None
    assert c.stage=='DECIDE'


def test_near_budget_must_stop_acquiring():
    m=InvestigationMemory();m.absorb({'id':'p','type':'windows_process'})
    c=case()
    assert c.select_acquisition(m,{'get_entity'},step_index=9,max_steps=12) is None
    assert c.stage=='DECIDE'


def test_no_review_on_first_tool_when_action_chain_known():
    from test_v16_loop import FakeSession
    class AuditLLM:
        def __init__(self):self.calls=[]
        async def next_step(self,messages,*,finish_only=False):
            self.calls.append(finish_only)
            return finish()
    session=FakeSession(); llm=AuditLLM()
    agent=SimpleSGRAgent(llm,max_steps=12,trajectory_dir=None,
                         review_enabled=True,gpt_oss_mode=True,soc_v20_mode=True)
    transcript=[]
    result=asyncio.run(agent._investigate(session,transcript))
    assert result.completion_reason=='terminated'
    assert [n for n,_ in session.calls]==['get_entity','get_relation','get_entity','finish_investigation']
    # The analyst is NEVER asked for a verdict before the grounded chain was opened.
    assert llm.calls and all(llm.calls)
    assert sum('blind_review' in str(e) for e in transcript)==1
    assert sum('v20_phase' in str(e) and 'decision_attempts' in str(e) for e in transcript)==1
    assert any('v20_phase' in str(e) and 'VERIFY' in str(e) for e in transcript)
    assert any('v20_phase' in str(e) and 'SUBMIT' in str(e) for e in transcript)


def test_previous_mode_remains_independent():
    agent=SimpleSGRAgent(object(),soc_v19_mode=True)
    assert agent.soc_v19_mode and not agent.soc_v20_mode
    agent=SimpleSGRAgent(object(),soc_v20_mode=True)
    assert agent.soc_v19_mode and agent.soc_v20_mode
