"""Check dossier coverage without introducing expected task-specific answers."""

from bluesec1_agent.agent import InvestigationMemory
from bluesec1_agent.investigation_director import InvestigationDirector


def _memory():
    memory = InvestigationMemory()
    memory.alert_description = 'Process performed a possibly unusual operation.'
    memory.focus_ids = {'p1'}
    memory.absorb({'type': 'windows_process', 'id': 'p1', 'properties': {
        'cmdline': 'powershell.exe -File C:/ops/inspect.ps1', 'user': 'ACME\\svc_reports',
    }})
    return memory


def test_ad_account_lookup_is_not_omitted_or_confused_with_authorization():
    memory = _memory()
    memory.absorb({'id': 'u1', 'type': 'windows_user',
                   'properties': {'username': 'svc_reports', 'ad_object_id': 'a1'}})
    memory.absorb({'id': 'r1', 'type': 'executed_by',
                   'source_id': 'p1', 'target_id': 'u1'})
    # AD lookup uses top-level fields, not a `properties` wrapper.
    memory.absorb({'id': 'a1', 'type': 'user', 'kind': 'account',
                   'description': 'Data reporting identity',
                   'sam_account_name': 'svc_reports',
                   'member_of': [{'name': 'Report Operators'}],
                   'service_principal_names': ['MSSQLSvc/server.example']})
    dossier = InvestigationDirector().review_dossier(memory)
    assert 'description=Data reporting identity' in dossier
    assert 'Report Operators' in dossier
    assert 'MSSQLSvc/server.example' in dossier
    assert 'referenced-identity-lookup-NOT-authorization' in dossier


def test_script_body_and_cmdlet_parameters_are_retained_outside_fetched_graph():
    memory = _memory()
    # Returned by a real search but not yet fetched as a relation endpoint.
    memory.absorb({'id': 's1', 'type': 'powershell_script',
                   'properties': {'path': 'C:/ops/inspect.ps1',
                                  'script_text': 'Get-Service | ConvertTo-Html | Out-File C:/ops/result.html'}})
    memory.absorb({'id': 'c1', 'type': 'powershell_cmdlet_invocation',
                   'properties': {'command_name': 'Get-Service',
                                  'parameter_binding': {'Name': 'inventory'}}})
    dossier = InvestigationDirector().review_dossier(memory)
    assert 'Get-Service | ConvertTo-Html' in dossier
    assert 'parameter_binding={"Name":"inventory"}' in dossier
    assert '[not-yet-linked-to-alert]' in dossier


def test_task_payload_is_not_reduced_to_task_name():
    memory = _memory()
    memory.absorb({'id': 'task1', 'type': 'scheduled_task', 'properties': {
        'task_name': 'Inventory', 'run_as_account': 'SYSTEM',
        'action_target': 'powershell -File C:/tasks/inventory.ps1',
        'trigger_type': 'DAILY',
    }})
    memory.absorb({'id': 'relation1', 'type': 'ran_scheduled_task',
                   'source_id': 'task1', 'target_id': 'p1'})
    dossier = InvestigationDirector().review_dossier(memory)
    assert 'action_target=powershell -File C:/tasks/inventory.ps1' in dossier
    assert 'run_as_account=SYSTEM' in dossier
    assert 'trigger_type=DAILY' in dossier


def test_two_assessors_get_same_facts_but_first_has_no_earlier_answer():
    memory = _memory()
    director = InvestigationDirector()
    marker = 'SECRET_LEAK_TEST_DO_NOT_COPY'
    review = director.independent_review_messages(memory,
                  {'verdict': 'malicious', 'reasoning': marker}, remaining_steps=3)
    joined = '\n'.join(m['content'] for m in review)
    assert marker not in joined
    assert 'powershell.exe -File C:/ops/inspect.ps1' in joined
    arbitration = director.arbitration_messages(memory,
                  {'verdict': 'malicious', 'reasoning': 'A'},
                  {'verdict': 'benign', 'reasoning': 'B'})
    assert 'powershell.exe -File C:/ops/inspect.ps1' in arbitration[1]['content']
    assert 'missing a formal approval' in arbitration[0]['content'].lower()


def test_matching_audits_preserve_original_artifacts_and_merge_observed_effects():
    from bluesec1_agent.agent import SimpleSGRAgent

    memory = _memory()
    memory.absorb({'id': 'f1', 'type': 'windows_file',
                   'properties': {'path': 'C:/ops/result.html'}})
    memory.absorb({'id': 'r1', 'type': 'wrote_file',
                   'source_id': 'p1', 'target_id': 'f1'})
    investigator = {
        'verdict': 'malicious', 'reasoning': 'Observed file change',
        'ir_artifacts': [{'entity_id': 'p1', 'kind': 'process_observed'}],
    }
    reviewer = {
        'verdict': 'malicious', 'reasoning': 'Corroborated file change',
        'ir_artifacts': [{'entity_id': 'f1', 'kind': 'file_observed'},
                         {'entity_id': 'missing', 'kind': 'host_to_isolate'}],
    }
    agent = SimpleSGRAgent(llm=None)
    merged = agent._merge_agreed_evidence(investigator, reviewer, memory)
    assert merged['verdict'] == investigator['verdict']
    assert merged['reasoning'] == investigator['reasoning']
    assert merged['ir_artifacts'] == [
        {'entity_id': 'p1', 'kind': 'process_observed'},
        {'entity_id': 'f1', 'kind': 'file_observed'},
    ]


def test_matching_benign_audit_does_not_add_uncited_metadata():
    from bluesec1_agent.agent import SimpleSGRAgent

    memory = _memory()
    memory.absorb({'id': 'f1', 'type': 'windows_file',
                   'properties': {'path': 'C:/ops/result.html'}})
    memory.absorb({'id': 'r1', 'type': 'wrote_file',
                   'source_id': 'p1', 'target_id': 'f1'})
    investigator = {
        'verdict': 'benign', 'reasoning': 'Legitimate report export',
        'legitimacy_evidence': [
            {'anchor': 'entity', 'entity_id': 'p1', 'property_fields': ['cmdline']}],
    }
    reviewer = {
        'verdict': 'benign', 'reasoning': 'Consistent with report export',
        'legitimacy_evidence': [
            {'anchor': 'entity', 'entity_id': 'f1', 'property_fields': ['path']},
            {'anchor': 'relation', 'relation_id': 'r1', 'property_fields': ['type']},
            {'anchor': 'entity', 'entity_id': 'f1', 'property_fields': ['nonexistent']}],
    }
    merged = SimpleSGRAgent(llm=None)._merge_agreed_evidence(investigator, reviewer, memory)
    assert len(merged['legitimacy_evidence']) == 3
    assert merged['legitimacy_evidence'][0] == investigator['legitimacy_evidence'][0]


def test_investigator_keeps_high_value_payloads_after_history_compaction():
    from bluesec1_agent.agent import SimpleSGRAgent

    memory = _memory()
    memory.calls_made.extend(['get_entity(x)'] * 10)
    memory.absorb({'id': 's1', 'type': 'powershell_script', 'properties': {
        'script_text': 'Get-ADGroupMember -Identity "Administrators"',
        'path': 'C:/ops/inspect.ps1',
    }})
    messages = [
        {'role': 'system', 'content': 'system instructions'},
        {'role': 'user', 'content': 'original alert'},
    ]
    agent = SimpleSGRAgent(llm=None)
    packet = agent._request_messages(messages, memory, remaining_steps=5)
    assert 'Get-ADGroupMember -Identity "Administrators"' in packet[-1]['content']
    assert 'Unlinked search hits are not causal proof' in packet[-1]['content']
