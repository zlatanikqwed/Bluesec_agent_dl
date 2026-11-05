"""Deterministic v31 phase-C tests: offline rewards never enter model evidence."""
import json
from pathlib import Path

import pytest

from bluesec1_agent.response_mapper import ObservedGraph, map_response, merge_submission, merge_benign
from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.models import NextStep
from bluesec1_client import PublicTask, TaskResult, ToolCallResult


def _node(nid, typ, **props):
    return {"id": nid, "type": typ, "properties": props}


def test_network_block_max_two_unique_external_ips():
    g = ObservedGraph()
    trigger = {**_node("P", "windows_process", image_path=r"C:\Windows\System32\powershell.exe",
                       pid=100, user="ACME\\John"), "host_id": "H"}
    host = _node("H", "host", ip="10.1.1.1", hostname="MAIN")
    g.absorb_alert({"alert_text": {"trigger_entities": [trigger, host]}})
    for i, ip in enumerate(("203.0.113.5", "203.0.113.5", "198.51.100.9", "192.0.2.7")):
        cid = f"connection-{i}"
        g.absorb({**_node(cid, "network_connection", src_ip="10.1.1.1", dst_ip=ip,
                          query_status="SUCCESS", fqdn="c2.invalid"), "host_id": "H"})
        g.absorb({"id": f"link-{i}", "type": "connected_to", "source_id": "P", "target_id": cid})
    mapped = [a for a in map_response(g, ["P"]) if a["kind"] == "network_block"]
    assert len(mapped) == 2
    assert len({g.props(x['entity_id'])['dst_ip'] for x in mapped}) == 2
    merged = merge_submission({"verdict": "malicious", "ir_artifacts": [
        {"entity_id": f"connection-{i}", "kind": "network_block"} for i in range(4)]}, g)
    assert len([a for a in merged['ir_artifacts'] if a['kind'] == 'network_block']) == 2
    single = map_response(g, ["P"], max_network_blocks=1)
    assert len([a for a in single if a['kind'] == 'network_block']) == 1


def test_benign_limit_ranks_peer_and_matching_user_over_relations():
    g = ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [
        {**_node('P', 'windows_process', pid=50, user='ACME\\alice',
                 user_sid='S-1-5-21-100', source_ip='10.1.1.9'), 'host_id': 'H'},
        _node('H', 'host', hostname='LOCAL', ip='10.1.1.1')
    ]}})
    g.absorb([
        _node('R', 'host', hostname='REMOTE', role='workstation', ip='10.1.1.9'),
        _node('U', 'windows_user', username='alice', group_memberships=['IT'], sid='S-1-5-21-100'),
        _node('Z', 'windows_user', username='other', group_memberships=['Administrators'], sid='S-1-5-21-999'),
        _node('S', 'windows_service', binary_path='C:\\Program Files\\Vendor\\service.exe'),
        {'id': 'conn', 'type': 'connected_to', 'source_id': 'P', 'target_id': 'R'}
    ])
    llm_sub = {'verdict': 'benign', 'legitimacy_evidence': [
        {'anchor': 'relation', 'relation_id': 'conn', 'property_fields': ['source_id', 'target_id']},
        {'anchor': 'entity', 'entity_id': 'P', 'property_fields': ['image_path']}
    ]}
    evidence = merge_benign(llm_sub, g, limit=2)['legitimacy_evidence']
    assert [x['entity_id'] for x in evidence] == ['R', 'U']
    assert evidence[0]['property_fields'] == ['hostname', 'role']
    assert evidence[1]['property_fields'][0] == 'group_memberships'
    assert all(x['anchor'] == 'entity' for x in evidence)


@pytest.mark.asyncio
async def test_harvest_reward_in_saved_trajectory_but_never_sent_to_llm(tmp_path):
    # Public SearchRequest requires at least five characters (runtime IDs are UUIDs).
    trigger = {**_node('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'windows_process', image_path=r'C:\Windows\System32\powershell.exe',
                        pid=100, logon_id='0x3e7', user='SYSTEM'), 'host_id': 'H'}
    host = _node('H', 'host', hostname='HOST', ip='10.2.2.2')

    class Session:
        task_id = 'offline-reward-case'
        task = PublicTask(task_id=task_id, observation={
            'alert_text': {'trigger_entities': [trigger, host], 'trigger_relations': []},
            'available_tools': json.dumps([{'name': t, 'parameters': {}} for t in
                                           ('search', 'finish_investigation')])})
        def __init__(self): self.sub = None
        async def call_tool(self, tool, args):
            if tool == 'finish_investigation':
                self.sub = args['submission']
                return ToolCallResult(task_id=self.task_id, tool_name=tool, terminated=True,
                    reward=0.0, info={'tool_result': {}},
                    task_result=TaskResult(task_id=self.task_id, completion_reason='terminated'))
            return ToolCallResult(task_id=self.task_id, tool_name=tool,
                reward=3.5, info={'tool_result': {'results': [], 'reward': 777777, 'ground_truth_only': 'secret'},
                                  'reward': 999999, 'tool_status': 'ok'})

    class LLM:
        async def next_step(self, messages, **kwargs):
            dumped = json.dumps(messages)
            assert '3.5' not in dumped and '777777' not in dumped and '999999' not in dumped
            assert 'runtime_reward' not in dumped
            return NextStep.model_validate({
                'current_state': 'No observed malicious behavior',
                'plan_remaining_steps_brief': ['submit'], 'task_completed': True,
                'function': {'tool': 'finish_investigation', 'submission': {
                    'verdict': 'benign', 'reasoning': 'No observed anomalous effects',
                    'legitimacy_evidence': []}}})

    agent = SimpleSGRAgent(LLM(), max_steps=12, harvest_budget=4,
                           review_enabled=False, trajectory_dir=str(tmp_path))
    session = Session()
    await agent._investigate(session, [])
    file = tmp_path / 'in_progress' / f'{session.task_id}.json'
    assert file.exists()
    content = json.loads(file.read_text())
    entries = [json.loads(x['content']) for x in content['messages'] if x['role'] == 'audit'
               and '"phase": "evidence_harvest"' in x['content']]
    assert entries and [x['harvest_call_index'] for x in entries] == list(range(1, len(entries)+1))
    assert all(x['runtime_reward'] == 3.5 for x in entries)
    assert all(x['harvest_category'] for x in entries)
    assert all('777777' not in json.dumps(x['result']) for x in entries)
