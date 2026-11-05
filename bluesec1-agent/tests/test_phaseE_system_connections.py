"""Phase E: evidence-first system connections and veto regression checks."""
from types import SimpleNamespace

import pytest

from bluesec1_agent.decision_guard import detect_attack_signals, decisive_signals
from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.response_mapper import ObservedGraph

TR = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
HO = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
CH = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
US = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
SI = 'S-1-5-21-1000-1000-1000-1025'


def node(id, type, **properties):
    return dict(id=id, type=type, properties=properties, host_id=HO if type == 'windows_process' else None)


def relation(id, type, src, dst):
    return dict(id=id, type=type, source_id=src, target_id=dst)


async def run_harvest(alert, dispatcher, budget=10):
    calls = []
    recorded = []
    class Session:
        async def call_tool(self, tool, args):
            calls.append((tool, args))
            return SimpleNamespace(info={'tool_result': dispatcher(tool, args)},
                                   observation={}, task_result=None, reward=3.0)
    h = EvidenceHarvester(budget=budget)
    await h.collect(Session(), {'alert_text': alert}, {'search', 'get_entity', 'get_relation'},
                    lambda tool, args, response: recorded.append(response.info['tool_result']))
    graph = ObservedGraph()
    graph.absorb_alert({'alert_text': alert})
    for result in recorded:
        graph.absorb(result)
    return calls, graph


@pytest.mark.asyncio
async def test_system_network_batch_gets_second_page_and_only_linked_sessions():
    ids = [f'conn-{i}' for i in range(6)]
    attached = [relation(f'rel-{i}', 'accepted_connection_from' if i < 3 else 'connected_to', TR, ids[i])
                for i in range(6)]
    # Ten entries on page one triggers pagination, but five aren't linked
    first = [node(f'conn-{i}', 'network_connection', src_ip='203.0.113.24' if i < 3 else '10.1.0.2',
                  dst_ip='10.1.0.10' if i < 3 else '10.1.0.11', dst_port=445 if i < 3 else 3389)
             for i in range(5)]
    first.extend([node(f'NOISE-{i}', 'network_connection', src_ip='203.0.113.100',
                       dst_ip='10.1.0.10', dst_port=445) for i in range(5)])
    second = [node('conn-5', 'network_connection', src_ip='10.1.0.10', dst_ip='10.1.0.18', dst_port=445)]
    alert = {'trigger_entities': [node(HO, 'host', ip='10.1.0.10', role='workstation'),
                                  node(TR, 'windows_process', pid=5, image_path='System',
                                       logon_id='0x3e7', user_sid='S-1-5-18')],
             'trigger_relations': []}

    def dispatcher(tool, args):
        if tool == 'search' and args.get('query') == TR and not args.get('scope'):
            return {'relations': attached}
        if tool == 'search' and args.get('scope', {}).get('type') == 'network_connection':
            return {'results': first if args['page_id'] == 1 else second}
        if tool == 'search' and args.get('scope', {}).get('type') == 'host':
            return {'results': [node('BROKER', 'host', ip='203.0.113.24', role='external')]}
        return {'results': []}

    calls, graph = await run_harvest(alert, dispatcher)
    network = [(t, a) for t, a in calls if a.get('scope', {}).get('type') == 'network_connection']
    assert [a['page_id'] for _, a in network] == [1, 2]
    assert all(a['query'] == '10.1.0.10' for _, a in network)
    assert 'conn-0' in graph.entities and 'conn-5' in graph.entities
    assert not any(n.startswith('NOISE') for n in graph.entities)
    assert 'BROKER' in graph.entities
    assert not any(t == 'get_entity' and a.get('entity_id', '').startswith('conn-') for t, a in calls)
    signal_names = {s.name for s in decisive_signals(detect_attack_signals(
        graph.entities, {k:(r['type'],r['source_id'],r['target_id']) for k,r in graph.relations.items()}))}
    assert 'incoming SMB session from externally classified host' in signal_names
    assert len(calls) <= 10


@pytest.mark.asyncio
async def test_sid_precedes_children_and_child_uuid_limited_to_two():
    children = [node(f'child-{i}', 'windows_process', image_path=r'C:\Users\Public\odd.exe',
                     parent_pid=100, pid=101+i, user='DOMAIN\\u') for i in range(3)]
    alert = {'trigger_entities':[node(HO, 'host', ip='10.0.0.1'),
                  node(TR,'windows_process',pid=100,user_sid=SI, logon_id='0x9911',
                       image_path=r'C:\Windows\System32\winrm.exe')], 'trigger_relations': []}
    def dispatcher(tool, args):
        if tool == 'search' and args.get('query') == TR and 'scope' not in args:
            return {'relations':[relation(f'spawn-{i}', 'win_process_create',TR,ch['id'])
                                 for i,ch in enumerate(children)]}
        if tool == 'search' and args.get('query') == SI:
            return {'results': [node(US, 'windows_user', sid=SI, group_memberships=['Domain Users'])]}
        if tool == 'get_entity':
            return next((c for c in children if c['id'] == args.get('entity_id')), {})
        return {'results': []}
    calls, graph = await run_harvest(alert, dispatcher, budget=9)
    assert calls[0][1]['query'] == TR
    assert calls[1][1]['query'] == SI
    assert US in graph.entities
    kid_queries = [a for t,a in calls if t == 'search' and a.get('query','').startswith('child-')]
    assert len(kid_queries) <= 2
    assert len(calls) <= 9


def test_system_nonstandard_windows_root_and_service_domain_child():
    nodes = {'p':node('p','windows_process',pid=10,user=r'NT AUTHORITY\SYSTEM',
                      image_path=r'C:\Windows\launcher-83133.exe', cmdline='launcher -service'),
             'c':node('c','windows_process',pid=11,parent_pid=10,user=r'DOMAIN\operator',
                      image_path=r'C:\Windows\Temp\python.exe')}
    named = {s.name for s in decisive_signals(detect_attack_signals(nodes, {}))}
    assert 'SYSTEM process executed a non-system-location image' in named
    assert 'SYSTEM service spawned domain-user executable from writable path' in named


def test_external_host_role_alone_or_unrelated_smb_not_veto():
    nodes = {'p': node('p','windows_process',pid=10,image_path='System',logon_id='0x3e7'),
             'outside':node('outside','host',ip='203.0.113.24',role='external'),
             'c':node('c','network_connection',src_ip='203.0.113.24',dst_port=445)}
    assert 'incoming SMB session from externally classified host' not in {
        s.name for s in detect_attack_signals(nodes, {})}
    edges = {'e':('accepted_connection_from','p','c')}
    assert 'incoming SMB session from externally classified host' in {
        s.name for s in decisive_signals(detect_attack_signals(nodes, edges))}


def test_relay_guard_receives_inbound_and_outbound_network_properties():
    base = {'p': node('p', 'windows_process', pid=4, image_path='System', logon_id='0x3e7'),
            HO: node(HO, 'host', ip='10.1.1.1', role='workstation')}
    base['p']['host_id'] = HO
    connections = [
        ('a', 'accepted_connection_from', '10.2.1.7', '10.1.1.1', 445),
        ('b', 'accepted_connection_from', '10.2.1.8', '10.1.1.1', 445),
        ('c', 'connected_to', '10.1.1.1', '10.9.0.3', 445),
        ('d', 'connected_to', '10.1.1.1', '10.9.0.4', 5985),
        ('e', 'connected_to', '10.1.1.1', '203.0.113.19', 443),
    ]
    edges = {}
    for nid, typ, src, dst, port in connections:
        base[nid] = node(nid, 'network_connection', src_ip=src, dst_ip=dst, dst_port=port)
        edges['edge-' + nid] = (typ, 'p', nid)
    names = {s.name for s in decisive_signals(detect_attack_signals(base, edges))}
    assert 'workstation process relayed inbound sessions into SMB/WinRM and an additional network destination' in names
    # Without hydrated connection properties the guard must not assume a relay.
    for nid, *_ in connections:
        base[nid]['properties'] = {}
    names = {s.name for s in decisive_signals(detect_attack_signals(base, edges))}
    assert 'workstation process relayed inbound sessions into SMB/WinRM and an additional network destination' not in names
