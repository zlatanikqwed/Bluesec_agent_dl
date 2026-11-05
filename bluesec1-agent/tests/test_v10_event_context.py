"""Tests for review dossier preserving edge-level outcomes and both hypotheses.

No incident IDs or expected leaderboard verdicts are embedded in the agent.
"""
from bluesec1_agent.agent import InvestigationMemory
from bluesec1_agent.investigation_director import InvestigationDirector


def sample_memory():
    memory = InvestigationMemory()
    memory.alert_description = 'Process service.exe on SERVER was started'
    memory.focus_ids = {'process-a'}
    memory.absorb({'id':'process-a','type':'windows_process',
                   'properties':{'cmdline':'service.exe','user':'NT AUTHORITY\\SYSTEM'}})
    memory.absorb({'id':'host-a','type':'host',
                   'properties':{'hostname':'SERVER'}})
    memory.absorb({'id':'user-a','type':'windows_user',
                   'properties':{'username':'operator'}})
    memory.absorb({'id':'relation-a','type':'logged_on_to',
                   'source_id':'user-a','target_id':'host-a',
                   'logon_properties': {'auth_failed': True,
                                        'logon_type':'remote_interactive',
                                        'source_ip':'10.2.3.4',
                                        'status_code':'0xc000006a'}})
    memory.absorb({'id':'relation-b','type':'wrote_file',
                   'source_id':'process-a','target_id':'file-a',
                   'properties':{'operation':'write','new_value':'changed'}})
    memory.absorb({'id':'file-a','type':'windows_file',
                   'properties':{'path':'C:/temp/output.bin'}})
    return memory


def test_event_fields_survive_blind_review_even_when_outside_alert_subgraph():
    memory=sample_memory()
    dossier=InvestigationDirector().review_dossier(memory)
    assert 'auth_failed=True' in dossier
    assert 'status_code=0xc000006a' in dossier
    assert 'source_ip=10.2.3.4' in dossier
    assert 'wrote_file' in dossier
    assert 'new_value=changed' in dossier
    assert 'ORIGINAL ALERT' in dossier
    assert 'username=operator' in dossier


def test_blind_and_arbitration_dossiers_retain_same_key_observations():
    director=InvestigationDirector()
    memory=sample_memory()
    packet=director.independent_review_messages(memory,{'verdict':'malicious','reasoning':'PRIVATE OPINION'},remaining_steps=2)
    messages='\n'.join(m['content'] for m in packet)
    assert 'PRIVATE OPINION' not in messages
    assert 'auth_failed=True' in messages
    assert 'status_code=0xc000006a' in messages
    first={'verdict':'malicious','reasoning':'Observed access attempts failed'}
    second={'verdict':'benign','reasoning':'Well-known process'}
    arbitration=director.arbitration_messages(memory,first,second)
    text=arbitration[1]['content']
    assert 'auth_failed=True' in text
    assert 'wrote_file' in text
    assert 'Well-known process' in text
    assert 'Observed access attempts failed' in text


def test_independent_review_not_leaking_prior_result_into_dossier():
    director=InvestigationDirector()
    memory=sample_memory()
    text=' '.join(m['content'] for m in director.independent_review_messages(
        memory,{'verdict':'benign','reasoning':'A secret prior verdict'},remaining_steps=1))
    assert 'A secret prior verdict' not in text
    assert 'logon_properties.auth_failed=True' in text


def test_windows_process_access_mask_is_interpreted_not_labeled_as_attack():
    memory=sample_memory()
    memory.absorb({'id':'target-process','type':'windows_process',
                   'properties':{'cmdline':'credential_service.exe'}})
    memory.absorb({'id':'handle-relation','type':'opened_handle',
                   'source_id':'process-a','target_id':'target-process',
                   'properties':{'granted_access':'0x1000'}})
    dossier=InvestigationDirector().review_dossier(memory)
    assert 'PROCESS_QUERY_LIMITED_INFORMATION' in dossier
    assert 'PROCESS_VM_READ' not in dossier
    memory.absorb({'id':'read-relation','type':'opened_handle',
                   'source_id':'process-a','target_id':'target-process',
                   'properties':{'granted_access':'0x1010'}})
    dossier=InvestigationDirector().review_dossier(memory)
    assert 'PROCESS_VM_READ' in dossier
