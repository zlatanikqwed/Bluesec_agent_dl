"""Tests for general evidence semantics; no task-specific IDs or verdicts."""
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector


def memory_with_forwarding(*, matching_host=True, matching_target=True):
    m = InvestigationMemory()
    m.focus_ids.add('start')
    m.absorb({'id': 'start', 'type': 'windows_process', 'host_id': 'HOST-1',
              'properties': {'cmdline': 'C:\\Windows\\System32\\svchost.exe'}})
    m.absorb({'id': 'conn', 'type': 'network_connection', 'properties': {
        'src_ip': '10.20.0.5', 'dst_ip': '10.20.0.8', 'dst_port': 5985}})
    m.absorb({'id': 'edge', 'type': 'connected_to', 'source_id': 'start', 'target_id': 'conn'})
    host = 'HOST-1' if matching_host else 'HOST-2'
    target = '10.20.0.8' if matching_target else '10.20.0.9'
    m.absorb({'id': 'operator', 'type': 'windows_process', 'host_id': host,
              'properties': {'cmdline': ('netsh interface portproxy add v4tov4 '
                                         f'listenport=25555 connectaddress={target} connectport=5985'),
                             'user': 'CORP\\operator'}})
    return m


def test_forwarding_cmd_matched_to_alert_destination_without_asserting_success():
    m = memory_with_forwarding()
    director = InvestigationDirector()
    leads = director.unresolved_consequences(m)
    assert any('OBSERVED COMMAND INTENT' in q and 'same-host-and-matching-network-destination' in q
               and 'not proof of successful effect' in q for _, q, _ in leads)
    assert 'OBSERVED COMMAND INTENTS' in director.review_dossier(m)
    assert 'same-host-and-matching-network-destination' in director.review_dossier(m)
    gaps = director.benign_evidence_gaps(m, {
        'verdict': 'benign', 'reasoning': 'An administrator used normal utilities.',
        'legitimacy_evidence': [{'anchor': 'entity', 'entity_id': 'operator',
                                 'property_fields': ['cmdline']}]})
    assert gaps and 'COMMAND INTENT' in gaps[0]


def test_unrelated_host_or_different_destination_does_not_gain_false_linkage():
    for kwargs in ({'matching_host': False}, {'matching_target': False}):
        m = memory_with_forwarding(**kwargs)
        assert all('COMMAND INTENT' not in q for _, q, _
                   in InvestigationDirector().unresolved_consequences(m))


def test_focus_process_command_has_direct_provenance_even_without_network():
    m = InvestigationMemory()
    m.focus_ids.add('runner')
    m.absorb({'id': 'runner', 'type': 'windows_process', 'properties': {
        'cmdline': 'schtasks /create /tn Task /tr monitor.exe'}})
    gaps = InvestigationDirector().benign_evidence_gaps(m, {
        'verdict': 'benign', 'legitimacy_evidence': [{'anchor': 'entity',
                                                   'entity_id': 'runner', 'property_fields': ['cmdline']}]})
    assert len(gaps) == 1 and 'not proof of successful effect' in gaps[0]
    assert InvestigationDirector().benign_evidence_gaps(m, {'verdict': 'malicious'}) == []


def test_nonmutating_tool_is_not_assumed_to_change_system_configuration():
    m = InvestigationMemory()
    m.focus_ids.add('runner')
    m.absorb({'id': 'runner', 'type': 'windows_process', 'properties': {
        'cmdline': 'netsh interface portproxy show all'}})
    assert not InvestigationDirector().unresolved_consequences(m)


def test_process_access_mask_distinguishes_query_from_memory_read():
    m = InvestigationMemory()
    m.focus_ids.add('p')
    m.absorb({'id': 'p', 'type': 'windows_process', 'properties': {'cmdline': 'guard.exe'}})
    m.absorb({'id': 'target', 'type': 'windows_process', 'properties': {'cmdline': 'other.exe'}})
    m.absorb({'id': 'e1', 'type': 'opened_handle', 'source_id': 'p', 'target_id': 'target',
              'process_access_properties': {'granted_access': '0x1000'}})
    text = InvestigationDirector._event_attributes(m, 'e1')
    assert 'this_handle_grants_process_vm_read=False' in text
    assert 'PROCESS_QUERY_LIMITED_INFORMATION' in text
    m.absorb({'id': 'e2', 'type': 'opened_handle', 'source_id': 'p', 'target_id': 'target',
              'process_access_properties': {'granted_access': '0x1010'}})
    assert 'this_handle_grants_process_vm_read=True' in InvestigationDirector._event_attributes(m, 'e2')


def test_nested_citation_paths_are_validated_against_actual_tool_fields():
    event = {'id': 'edge', 'type': 'logged_on_to', 'logon_properties': {
        'auth_failed': True, 'status_code': '0xc000006d'}}
    observed = SimpleSGRAgent._grounded_property_fields(
        event, ['logon_properties.auth_failed', 'logon_properties.status_code',
                'logon_properties.auth_success', 'logon_properties.missing.deep',
                '__class__', 'type'])
    assert observed == ['logon_properties.auth_failed', 'logon_properties.status_code', 'type']


def test_no_causal_edges_no_inferred_authorization_or_verdict_override():
    m = memory_with_forwarding()
    submission = {'submission': {
        'verdict': 'benign', 'reasoning': 'The operator ran an administrative utility.',
        'legitimacy_evidence': [{'anchor': 'entity', 'entity_id': 'operator',
                                 'property_fields': ['cmdline']}],
    }}
    fixed, _ = SimpleSGRAgent._reconcile_final(submission, m)
    assert fixed['submission']['verdict'] == 'benign'
    assert fixed['submission'].get('ir_artifacts') is None
