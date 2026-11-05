"""Two-phase regressions for verified evidence acquisition and precision reports."""
import json

import pytest

from bluesec1_agent.decision_guard import unsupported_malicious_contradiction
from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.response_mapper import (
    ObservedGraph, benign_anchor_evidence, merge_benign, precision_scoping_pivots,
)
from bluesec1_client import ToolCallResult

HOST = '11111111-1111-4111-8111-111111111111'
TRIGGER = '22222222-2222-4222-8222-222222222222'
CHILD = '33333333-3333-4333-8333-333333333333'
FILE = '44444444-4444-4444-8444-444444444444'
PEER = '55555555-5555-4555-8555-555555555555'
CONN = '66666666-6666-4666-8666-666666666666'
NOISE = '77777777-7777-4777-8777-777777777777'
USER = '88888888-8888-4888-8888-888888888888'


def ent(nid, typ, **p):
    return {'id': nid, 'type': typ, 'properties': p}


@pytest.mark.asyncio
async def test_system_harvest_reinvests_calls_and_correlates_host_connections():
    """Includes second UUID page, file-origin, services, peer and child, not SID/session."""
    alert = {'trigger_entities': [
        ent(HOST, 'host', hostname='srv', ip='10.20.3.7'),
        {**ent(TRIGGER, 'windows_process', pid=35, logon_id='0x3e7',
               image_path=r'C:\ProgramData\staged.exe', user='SYSTEM'), 'host_id': HOST},
    ], 'trigger_relations': []}
    file = ent(FILE, 'windows_file', path=r'C:\ProgramData\staged.exe')
    conn = ent(CONN, 'network_connection', dst_ip='203.0.113.50', dst_port=443)
    noise = ent(NOISE, 'network_connection', dst_ip='198.51.100.90', dst_port=1234)
    child = {**ent(CHILD, 'windows_process', pid=36, parent_pid=35,
                   start_time='2026-10-25T08:00:00Z',
                   image_path=r'C:\Windows\System32\cmd.exe'), 'host_id': HOST}
    class Session:
        def __init__(self): self.calls=[]
        async def call_tool(self, tool, args):
            self.calls.append((tool, args))
            q = args.get('query')
            scope = (args.get('scope') or {}).get('type')
            raw = {'results': []}
            if q == TRIGGER and not scope:
                if args.get('page_id') == 1:
                    raw = {'relations': [
                        {'id':'rconn','type':'connected_to','source_id':TRIGGER,'target_id':CONN},
                        {'id':'rfile','type':'wrote_file','source_id':TRIGGER,'target_id':FILE},
                    ], 'next_page_id': 2}
                else:
                    raw = {'relations': [
                        {'id':'rchild','type':'win_process_create','source_id':TRIGGER,'target_id':CHILD}]}
            elif q == FILE and not scope:
                raw = {'relations':[{'id':'writer','type':'wrote_file','source_id':TRIGGER,'target_id':FILE}]}
            elif scope == 'network_connection':
                raw = {'results': [conn, noise]}
            elif scope == 'windows_file':
                raw = {'results': [file]}
            elif scope == 'windows_service':
                raw = {'results':[ent('service', 'windows_service', binary_path=r'C:\ProgramData\staged.exe')]}
            elif scope == 'host':
                raw = {'results':[ent(PEER, 'host', ip='203.0.113.50', hostname='external')]}
            elif q == CHILD:
                raw = {'results': [child]}
            elif tool == 'get_entity' and args.get('entity_id') == FILE:
                raw = file
            elif tool == 'get_entity' and args.get('entity_id') == CHILD:
                raw = child
            elif tool == 'get_entity' and args.get('entity_id') == CONN:
                raw = conn
            return ToolCallResult(task_id='system', tool_name=tool,
                                  info={'tool_result':raw,'tool_status':'ok'})
    sess = Session()
    captured=[]
    result = await EvidenceHarvester(budget=10).collect(
        sess, {'alert_text':alert}, {'search','get_entity'},
        lambda tool, args, response: captured.append((tool,args,response.info['tool_result'])))
    assert result.completed and 8 <= result.calls <= 10
    assert any(a.get('query') == TRIGGER and a.get('page_id') == 2 for t,a in sess.calls if t=='search')
    assert any((a.get('scope') or {}).get('type') == 'network_connection' for t,a in sess.calls if t=='search')
    assert not any(a.get('query') in ('0x3e7','S-1-5-18') for t,a in sess.calls if t=='search')
    for t, a, raw in captured:
        if (a.get('scope') or {}).get('type')=='network_connection':
            assert all(e['id'] != NOISE for e in raw.get('results',[]))
    assert not any(a.get('entity_id')==TRIGGER for t,a in sess.calls if t=='get_entity')


@pytest.mark.asyncio
@pytest.mark.parametrize('image', ['System', 'Registry', 'MemCompression'])
async def test_kernel_pseudo_images_not_searched(image):
    alert={'trigger_entities': [
        {**ent(TRIGGER, 'windows_process', image_path=image, logon_id='0x3e7'), 'host_id':HOST},
        ent(HOST, 'host')], 'trigger_relations':[]}
    calls=[]
    class S:
        async def call_tool(self, t, a):
            calls.append((t,a))
            return ToolCallResult(task_id='p',tool_name=t,
                                  info={'tool_result':{'results':[]},'tool_status':'ok'})
    await EvidenceHarvester(budget=10).collect(
        S(), {'alert_text':alert}, {'search'}, lambda *a:None)
    assert all(a.get('query')!=image for _,a in calls)


def test_false_malicious_only_while_contradiction_and_no_attack_facts():
    signed={TRIGGER: {**ent(TRIGGER,'windows_process',
                            image_path=r'C:\Windows\System32\svchost.exe',
                            is_signed=True, signer='Microsoft'), 'host_id':HOST}}
    reason='svchost.exe is an unsigned nonstandard binary in a suspicious path'
    assert unsupported_malicious_contradiction(reason,signed,{})
    # An executed payload plus an observable write is a material contradictory signal.
    payload={**signed,CHILD: {**ent(CHILD,'windows_process',
                                image_path=r'C:\Users\Public\run.exe'), 'host_id':HOST}}
    assert unsupported_malicious_contradiction(reason,payload,{}) is None
    assert unsupported_malicious_contradiction('malicious, confirmed command',signed,{}) is None


def test_benign_replaces_only_endpoint_fields_with_peer_and_identity():
    g=ObservedGraph()
    g.absorb_alert({'alert_text':{'trigger_entities': [
        {**ent(TRIGGER,'windows_process',user_sid='S-1-5-21-4',user='ACME\\alice'), 'host_id':HOST},
        ent(HOST,'host', ip='10.0.0.1')], 'trigger_relations':[]}})
    g.absorb([ent(PEER,'host',hostname='REMOTE',role='workstation',ip='10.0.0.7'),
              ent(USER,'windows_user',sid='S-1-5-21-4',username='alice',group_memberships=['operators']),
              {'id':'rsession','type':'logged_on_to','source_id':USER,'target_id':HOST,
               'properties':{'source_ip':'10.0.0.7'}}])
    sub={'verdict':'benign','legitimacy_evidence':[{'anchor':'relation','relation_id':'rsession',
                                                   'property_fields':['source_id','target_id']}],
         'reasoning':'Observed remote administration'}
    final=merge_benign(sub,g)
    assert final['legitimacy_evidence'][0] == {'anchor':'entity', 'entity_id':PEER,
                                               'property_fields':['hostname','role']}
    assert any(i['entity_id']==USER and 'group_memberships' in i['property_fields']
               for i in final['legitimacy_evidence'])
    assert not any(i['anchor']=='relation' or i.get('entity_id')==TRIGGER
                   for i in final['legitimacy_evidence'])


def test_precise_malicious_scoping_opens_only_not_yet_seen_effect_targets():
    g=ObservedGraph()
    g.absorb_alert({'alert_text':{'trigger_entities':[
        {**ent(TRIGGER,'windows_process',pid=10), 'host_id':HOST}]}})
    g.absorb([{'id':'w','type':'wrote_file','source_id':TRIGGER,'target_id':FILE},
              {'id':'c','type':'connected_to','source_id':TRIGGER,'target_id':CONN},
              {'id':'unrelated','type':'hosts','source_id':HOST,'target_id':TRIGGER}])
    pivots=precision_scoping_pivots(g,[TRIGGER],set(),set())
    assert [p[1]['entity_id'] for p in pivots]==[FILE,CONN]
    assert [p[1]['entity_id'] for p in precision_scoping_pivots(g,[TRIGGER],{FILE},set())]==[CONN]
    assert precision_scoping_pivots(g,[TRIGGER],{FILE,CONN},set())==[]
