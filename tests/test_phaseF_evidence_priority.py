"""Phase F: public-evidence priority and deterministic benign anchors."""
from types import SimpleNamespace

import pytest

from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.response_mapper import ObservedGraph, merge_benign
from bluesec1_agent.decision_guard import detect_attack_signals

TR = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
HO = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
US = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
CH = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
CON = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
PEER = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
SCR = '11111111-1111-4111-8111-111111111111'
FILE = '22222222-2222-4222-8222-222222222222'
MUT = '33333333-3333-4333-8333-333333333333'
LOGON = '0xabcd92'
SID = 'S-1-5-21-1000-1000-1000-1002'


def node(nid, typ, **props):
    return {'id': nid, 'type': typ, 'properties': props,
            'host_id': HO if typ == 'windows_process' else None}


def rel(nid, typ, src, dst):
    return {'id': nid, 'type': typ, 'source_id': src, 'target_id': dst}


def alert(*, image=r'C:\Windows\System32\cmd.exe', **props):
    return {'trigger_entities': [node(HO, 'host', ip='10.7.0.12', hostname='LOCAL'),
                                 node(TR, 'windows_process', image_path=image, pid=300,
                                      logon_id=LOGON, user_sid=SID, **props)], 'trigger_relations': []}


async def run(payload, dispatch, budget=8):
    calls, facts = [], []
    class Session:
        async def call_tool(self, tool, args):
            calls.append((tool, args))
            return SimpleNamespace(info={'tool_result': dispatch(tool, args)},
                                   observation={}, task_result=None, reward=4.0)
    result = await EvidenceHarvester(budget=budget).collect(
        Session(), {'alert_text': payload}, {'search','get_entity','get_relation'},
        lambda tool, args, resp: facts.append(resp.info['tool_result']))
    g = ObservedGraph()
    g.absorb_alert({'alert_text': payload})
    for fact in facts:
        g.absorb(fact)
    return result, calls, g


@pytest.mark.asyncio
async def test_uuid_spawn_disables_both_session_queries_and_keeps_sid():
    def dispatch(tool, args):
        if tool == 'search' and args['query'] == TR and not args.get('scope'):
            return {'relations': [rel('spawn', 'win_process_create', TR, CH)]}
        if tool == 'search' and args['query'] == SID:
            return {'results': [node(US,'windows_user',username='actor',sid=SID)]}
        if tool == 'get_entity' and args['entity_id'] == CH:
            return node(CH, 'windows_process',pid=301,parent_pid=300,image_path=r'C:\Windows\System32\whoami.exe')
        return {'results': []}
    result, calls, _ = await run(alert(), dispatch)
    assert calls[0][1]['query'] == TR
    assert calls[1][1]['query'] == SID
    assert not any(a.get('query') == LOGON for _, a in calls)
    assert result.calls <= 8


@pytest.mark.asyncio
async def test_connection_and_external_peer_precede_unproductive_children():
    children = [f'child-{i}' for i in range(3)]
    def dispatch(tool, args):
        if tool == 'search' and args['query'] == TR and not args.get('scope'):
            return {'relations': [rel(f's-{i}', 'win_process_create', TR, c)
                                  for i,c in enumerate(children)]
                    + [rel('n', 'connected_to', TR, CON)]}
        if tool == 'get_entity' and args['entity_id'] == CON:
            return node(CON, 'network_connection',src_ip='10.7.0.12',dst_ip='198.51.100.203',dst_port=443)
        if tool == 'search' and args.get('query') == '198.51.100.203':
            return {'results': [node(PEER, 'host', ip='198.51.100.203',role='external',hostname='REMOTE')]}
        if tool == 'get_entity' and args.get('entity_id') in children:
            return node(args['entity_id'], 'windows_process',image_path=r'C:\Windows\System32\systeminfo.exe')
        return {'results': []}
    _, calls, graph = await run(alert(), dispatch)
    conn_idx = next(i for i,(t,a) in enumerate(calls) if t == 'get_entity' and a.get('entity_id') == CON)
    peer_idx = next(i for i,(t,a) in enumerate(calls) if t == 'search' and a.get('query') == '198.51.100.203')
    child_idxs = [i for i,(t,a) in enumerate(calls) if t == 'get_entity' and a.get('entity_id') in children]
    assert conn_idx < peer_idx < min(child_idxs)
    assert PEER in graph.entities
    assert len(calls) <= 8


@pytest.mark.asyncio
async def test_powershell_script_opened_without_other_effects_and_in_digest():
    def dispatch(tool, args):
        if tool == 'search' and args['query'] == TR and not args.get('scope'):
            return {'relations': [rel('scr', 'executed_script', TR, SCR)]}
        if tool == 'get_entity' and args.get('entity_id') == SCR:
            return node(SCR, 'powershell_script',script_text='IEX (New-Object Net.WebClient).DownloadString($url)')
        return {'results': []}
    result, calls, graph = await run(alert(image=r'C:\Windows\System32\powershell.exe'), dispatch)
    assert any(t == 'get_entity' and a.get('entity_id') == SCR for t,a in calls)
    assert 'DownloadString' in result.digest
    names = [s.name for s in detect_attack_signals(graph.entities, {
        k:(r['type'],r['source_id'],r['target_id']) for k,r in graph.relations.items()})]
    assert 'download and immediate in-memory execution' in names


def test_benign_changed_member_peer_and_written_file_win_over_llm_and_actor():
    g = ObservedGraph()
    g.absorb_alert({'alert_text':alert(user='ACME\\actor',source_ip='10.7.0.15')})
    g.absorb([
        node(US,'windows_user',username='actor',sid=SID,group_memberships=['User']),
        node(MUT,'windows_user',username='new_member',group_memberships=['Domain Admins']),
        node(PEER,'host',hostname='REMOTE',role='workstation',ip='10.7.0.15'),
        node(FILE,'windows_file',path=r'C:\Windows\Temp\report.result'),
        rel('group','added_to_group', MUT,'admins'),
        rel('write','wrote_file',TR,FILE),
    ])
    sub = {'verdict':'benign','legitimacy_evidence':[
        {'anchor':'relation','relation_id':'group','property_fields':['source_id','target_id']},
        {'anchor':'entity','entity_id':TR,'property_fields':['image_path']} ]}
    refs=merge_benign(sub,g,limit=3)['legitimacy_evidence']
    assert [r['entity_id'] for r in refs] == [MUT,PEER,FILE]
    assert refs[0]['property_fields'] == ['group_memberships','username']
    assert all(r['anchor'] == 'entity' for r in refs)


def test_changed_service_has_higher_priority_than_unrelated_service():
    g=ObservedGraph()
    g.absorb_alert({'alert_text':alert()})
    g.absorb([node('serv-old','windows_service',binary_path='C:/Old.exe'),
              node('serv-new','windows_service',binary_path='C:/New.exe'),
              rel('start','started_service',TR,'serv-new')])
    assert merge_benign({'verdict':'benign','legitimacy_evidence':[]},g,limit=1)['legitimacy_evidence'][0]['entity_id']=='serv-new'

@pytest.mark.asyncio
async def test_non_system_child_uuid_connection_leads_to_host_without_session():
    def dispatch(tool, args):
        if tool == 'search' and args['query'] == TR and not args.get('scope'):
            return {'relations': [rel('spawn', 'win_process_create', TR, CH)]}
        if tool == 'get_entity' and args['entity_id'] == CH:
            return node(CH, 'windows_process', pid=301, parent_pid=300,
                        image_path=r'C:\Users\Public\service.exe')
        if tool == 'search' and args['query'] == CH and not args.get('scope'):
            return {'relations': [rel('c-out', 'connected_to', CH, CON)]}
        if tool == 'get_entity' and args['entity_id'] == CON:
            return node(CON, 'network_connection', dst_ip='198.51.100.203', dst_port=443)
        if tool == 'search' and args['query'] == '198.51.100.203':
            return {'results': [node(PEER, 'host', ip='198.51.100.203', role='external')]}
        return {'results': []}
    _, calls, graph = await run(alert(), dispatch, budget=8)
    assert graph.etype(PEER) == 'host'
    assert all(args.get('query') != LOGON for _, args in calls)
    assert len(calls) <= 8


@pytest.mark.asyncio
async def test_script_edge_as_typed_reference_resolves_and_opens_script():
    payload = alert(image=r'C:\Windows\System32\powershell.exe')
    payload['trigger_entities'][1]['relation_ids'] = {'out:executed_script': ['script-ref']}
    def dispatch(tool, args):
        if tool == 'get_relation' and args['relation_id'] == 'script-ref':
            return rel('script-ref','executed_script',TR,SCR)
        if tool == 'get_entity' and args['entity_id'] == SCR:
            return node(SCR,'powershell_script',script_text='Get-Process')
        return {'results': []}
    result, calls, _ = await run(payload, dispatch)
    assert any(t == 'get_relation' and a.get('relation_id') == 'script-ref' for t,a in calls)
    assert any(t == 'get_entity' and a.get('entity_id') == SCR for t,a in calls)
    assert 'Get-Process' in result.digest


def test_changed_ad_user_object_is_cited_before_initiator():
    g = ObservedGraph()
    g.absorb_alert({'alert_text':alert(user='ACME\\actor')})
    g.absorb([node(US,'windows_user',username='actor',sid=SID,group_memberships=['Users']),
              node(MUT,'ad_object',username='added',group_memberships=['Admins']),
              rel('added','added_to_group', MUT,'group-id')])
    assert merge_benign({'verdict':'benign','legitimacy_evidence':[]},g,limit=1)['legitimacy_evidence'][0]['entity_id'] == MUT

@pytest.mark.asyncio
async def test_external_peer_gets_priority_over_multiple_internal_peers():
    cids = ['conn-int-1', 'conn-int-2', 'conn-external']
    ips = ['10.2.0.2','10.2.0.3','198.51.100.203']
    def dispatch(tool, args):
        if tool == 'search' and args['query'] == TR and not args.get('scope'):
            return {'relations': [rel(f'r{i}', 'connected_to', TR, c)
                                  for i,c in enumerate(cids)],
                    'entities': [node(c, 'network_connection', dst_ip=ip)
                                 for c,ip in zip(cids,ips)]}
        return {'results': []}
    _, calls, _ = await run(alert(), dispatch, budget=5)
    lookups = [a['query'] for t,a in calls if t == 'search' and
               a.get('scope',{}).get('type') == 'host']
    assert lookups and lookups[0] == '198.51.100.203'
    assert len(lookups) <= 2
