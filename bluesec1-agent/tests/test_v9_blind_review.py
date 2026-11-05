"""General causal review/efficiency tests, independent of benchmark labels."""
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector


def build_case(*, missing_effect=False):
    m=InvestigationMemory()
    m.focus_ids={'proc-1'}
    m.absorb({'id':'proc-1','type':'windows_process','properties':{'cmdline':'worker --update'},
              'relation_ids':{'incoming':['r1'],'outgoing':['r2','r3','r4']}})
    m.absorb({'id':'proc-0','type':'windows_process','properties':{'cmdline':'scheduler'}})
    m.absorb({'id':'file-1','type':'windows_file','properties':{'path':'C:/shared/report'}})
    m.absorb({'id':'task-1','type':'scheduled_task','properties':{'task_name':'job'}})
    m.absorb({'id':'net-1','type':'network_connection','properties':{'dst_port':443,'dst_ip':'203.0.113.5'}})
    m.absorb({'id':'r1','type':'win_process_create','source_id':'proc-0','target_id':'proc-1'})
    m.absorb({'id':'r2','type':'wrote_file','source_id':'proc-1','target_id':'file-1'})
    m.absorb({'id':'r3','type':'created_task','source_id':'proc-1','target_id':'task-1'})
    m.absorb({'id':'r4','type':'connected_to','source_id':'proc-1','target_id':'net-1'})
    m.calls_made.extend(['get_entity']*13)
    m.fetched_ids.update({'proc-1','proc-0','file-1','task-1','net-1','r1','r2','r3','r4'})
    if missing_effect:
        m.fetched_ids.discard('task-1')
    return m


def test_blind_review_never_receives_prior_verdict_or_reasoning():
    m=build_case()
    original={'verdict':'benign','reasoning':'A unique secret conclusion SHOULD NOT BE HERE',
              'legitimacy_evidence':[]}
    packet=InvestigationDirector().independent_review_messages(m, original,remaining_steps=3)
    full='\n'.join(msg['content'] for msg in packet)
    assert 'unique secret conclusion' not in full.lower()
    assert 'wrote_file' in full and 'created_task' in full
    assert len(packet)==2 and packet[0]['role']=='system'


def test_third_assessor_sees_both_arguments_and_graph_only_on_disagreement():
    m=build_case()
    first={'verdict':'malicious','reasoning':'Suspected unauthorized change'}
    second={'verdict':'benign','reasoning':'Possible authorized job'}
    packet=InvestigationDirector().arbitration_messages(m,first,second)
    assert 'Suspected unauthorized change' in packet[1]['content']
    assert 'Possible authorized job' in packet[1]['content']
    assert '--wrote_file-->' in packet[1]['content']
    assert packet[0]['role']=='system'


def test_readiness_requires_linked_effects_and_fetched_endpoints():
    m=build_case()
    director=InvestigationDirector()
    ok,reason=director.readiness(m,steps_used=13)
    assert ok,reason
    assert not director.readiness(m,steps_used=6)[0]
    m2=build_case(missing_effect=True)
    assert not director.readiness(m2,steps_used=13)[0]


def test_reduced_context_preserves_first_alert_and_recent_pairs():
    agent=SimpleSGRAgent(llm=None,review_enabled=True, keep_recent_results=2)
    m=build_case()
    messages=[{'role':'system','content':'initial system'},
              {'role':'user','content':'initial alert'}]
    for i in range(11):
        messages.extend([{'role':'assistant','content':f'old opinion {i}'},
                         {'role':'tool','content':f'evidence {i}'}])
    packet=agent._request_messages(messages,m)
    assert packet[0]['content']=='initial system'
    assert packet[1]['content']=='initial alert'
    text=str(packet)
    assert 'old opinion 0' not in text
    assert 'old opinion 10' in text
    assert 'wrote_file' in text
