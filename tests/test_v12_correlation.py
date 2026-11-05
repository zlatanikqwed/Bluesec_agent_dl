"""Generic, case-independent tests for multi-event evidence interpretation."""
from bluesec1_agent.agent import InvestigationMemory
from bluesec1_agent.investigation_director import InvestigationDirector


def test_failed_auth_is_correlated_with_connections_and_does_not_claim_success():
    m = InvestigationMemory()
    m.focus_ids = {'sys-proc'}
    m.absorb({'id': 'sys-proc', 'type': 'windows_process',
              'properties': {'image_path': 'System'}})
    m.absorb({'id': 'peer-host', 'type': 'host', 'properties': {'ip': '10.1.1.10'}})
    m.absorb({'id': 'id-1', 'type': 'windows_user', 'properties': {'username': 'operator'}})
    for i, (port, protocol) in enumerate([(445, 'NTLM'), (3389, 'RDP'), (445, 'NTLM')]):
        m.absorb({'id': f'n{i}', 'type': 'network_connection', 'properties': {
            'src_ip': '10.22.33.44', 'dst_ip': '10.1.1.10', 'dst_port': port}})
        m.absorb({'id': f'auth{i}', 'type': 'logged_on_to', 'source_id': 'id-1',
                  'target_id': 'peer-host', 'logon_properties': {
                    'source_ip': '10.22.33.44', 'auth_failed': True,
                    'protocol': protocol}})
    director = InvestigationDirector()
    synthesis = director.correlate_observed_effects(m)
    assert 'failed=3' in synthesis
    assert "['NTLM', 'RDP']" in synthesis
    assert 'network sessions from that source=3' in synthesis
    assert 'does not prove access succeeded' in synthesis
    assert 'AUTH / NETWORK CORRELATION' in director.review_dossier(m)
    packet = director.arbitration_messages(m, {'verdict': 'malicious'}, {'verdict': 'benign'})
    assert 'failed=3' in packet[1]['content']


def test_successful_logon_is_never_labeled_as_failed():
    m = InvestigationMemory()
    m.absorb({'id': 'user', 'type': 'windows_user', 'properties': {'username': 'worker'}})
    m.absorb({'id': 'host', 'type': 'host', 'properties': {'ip': '10.0.0.1'}})
    m.absorb({'id': 'session', 'type': 'network_connection', 'properties': {
        'src_ip': '10.0.1.2', 'dst_ip': '10.0.0.1', 'dst_port': 445}})
    m.absorb({'id': 'auth', 'type': 'logged_on_to', 'source_id': 'user',
              'target_id': 'host', 'logon_properties': {
                'source_ip': '10.0.1.2', 'auth_failed': False}})
    synthesis = InvestigationDirector().correlate_observed_effects(m)
    assert 'succeeded=1' in synthesis
    assert 'failed=1' not in synthesis


def test_file_lifecycle_separates_observed_write_and_delete_from_inferred_execution():
    m = InvestigationMemory()
    m.focus_ids = {'shell'}
    m.absorb({'id': 'shell', 'type': 'windows_process', 'properties': {'cmdline': 'powershell.exe'}})
    m.absorb({'id': 'writer', 'type': 'windows_process', 'properties': {'cmdline': 'script runner'}})
    m.absorb({'id': 'obj', 'type': 'windows_file', 'properties': {
        'path': 'C:/Work/_scratch/intermediate.bin', 'signed': True}})
    m.absorb({'id': 'r-write', 'type': 'wrote_file', 'source_id': 'writer', 'target_id': 'obj'})
    m.absorb({'id': 'r-delete', 'type': 'deleted_file', 'source_id': 'shell', 'target_id': 'obj'})
    synthesis = InvestigationDirector().correlate_observed_effects(m)
    assert 'FILE LIFECYCLE' in synthesis
    assert 'observed writer=writer [r-write]' in synthesis
    assert 'observed deleter=shell [r-delete]' in synthesis
    assert 'does not establish that the file was executed' in synthesis
    assert 'FILE LIFECYCLE' in InvestigationDirector().independent_review_messages(
        m, remaining_steps=3)[1]['content']


def test_unrelated_auth_events_without_matching_sources_are_not_collapsed():
    m = InvestigationMemory()
    m.absorb({'id': 'identity', 'type': 'windows_user', 'properties': {'username': 'person'}})
    m.absorb({'id': 'host', 'type': 'host'})
    m.absorb({'id': 'conn', 'type': 'network_connection', 'properties': {
        'src_ip': '10.2.2.2', 'dst_ip': '10.3.3.3', 'dst_port': 445}})
    m.absorb({'id': 'auth', 'type': 'logged_on_to', 'source_id': 'identity',
              'target_id': 'host', 'logon_properties': {'source_ip': '10.9.9.9', 'auth_failed': True}})
    text = InvestigationDirector().correlate_observed_effects(m)
    assert 'AUTH / NETWORK CORRELATION' not in text


def test_same_source_ip_different_destination_is_not_marked_same_target():
    m = InvestigationMemory()
    m.absorb({'id': 'host-a', 'type': 'host', 'properties': {'ip': '10.0.0.1'}})
    m.absorb({'id': 'id-a', 'type': 'windows_user', 'properties': {'username': 'person'}})
    m.absorb({'id': 'net-b', 'type': 'network_connection', 'properties': {
        'src_ip': '10.2.2.2', 'dst_ip': '10.0.0.2', 'dst_port': 445}})
    m.absorb({'id': 'login-a', 'type': 'logged_on_to', 'source_id': 'id-a',
              'target_id': 'host-a', 'logon_properties': {
                  'source_ip': '10.2.2.2', 'auth_failed': True}})
    text = InvestigationDirector().correlate_observed_effects(m)
    assert 'matching-auth-target network sessions=0' in text
    assert 'network sessions from that source=1' in text
