"""Phase L single-factor benign entity acquisition and citation experiments."""
from types import SimpleNamespace

import pytest

from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.phaseL_evidence import script_name_from_command, interactive_source_ips
from bluesec1_agent.report_experiments import apply_report_experiment, PHASE_L_MODES
from bluesec1_agent.response_mapper import ObservedGraph

TR='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
HO='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
TA='cccccccc-cccc-4ccc-8ccc-cccccccccccc'
FI='dddddddd-dddd-4ddd-8ddd-dddddddddddd'
PE='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
SC='ffffffff-ffff-4fff-8fff-ffffffffffff'
LO='0x12345'
SID='S-1-5-21-999-1000'


def ent(nid, typ, **props):
    return {'id':nid, 'type':typ, 'properties':props,
            **({'host_id':HO} if typ in {'windows_process','windows_file'} else {})}


def rel(nid, typ, src, dst, **extra):
    return {'id':nid, 'type':typ, 'source_id':src, 'target_id':dst, **extra}


def alert(image, cmd=''):
    return {'trigger_entities': [ent(HO, 'host', hostname='LOCAL', ip='10.1.1.1'),
                                 ent(TR, 'windows_process', image_path=image, cmdline=cmd,
                                     pid=400, logon_id=LO, user_sid=SID)]}


async def harvest(mode, alert_text, responses):
    calls, public = [], []
    class Session:
        async def call_tool(self, tool, args):
            calls.append((tool,args))
            result = responses(tool,args)
            return SimpleNamespace(info={'tool_result': result}, observation={}, task_result=None)
    harvested = await EvidenceHarvester(budget=8, service_probe=True, inbound_probe=True,
                                       evidence_probe=mode).collect(
        Session(), {'alert_text': alert_text}, {'search','get_entity','get_relation'},
        lambda tool,args,response: public.append(response.info['tool_result']))
    graph = ObservedGraph()
    graph.absorb_alert({'alert_text': alert_text})
    for value in public:
        graph.absorb(value)
    return harvested,calls,graph


def report(graph, mode, *, count=1):
    return apply_report_experiment({'verdict':'benign','reasoning':'routine',
                                     'legitimacy_evidence':[]},graph,mode,
                                   benign_limit=count)


@pytest.mark.asyncio
async def test_schedule_incoming_task_opened_and_cited():
    alert_text=alert(r'C:\Windows\System32\svchost.exe')
    def dispatch(tool,args):
        if tool=='search' and args['query']==TR and not args.get('scope'):
            return {'relations':[rel('ran','ran_scheduled_task',TA,TR)]}
        if tool=='get_entity' and args.get('entity_id')==TA:
            return ent(TA,'scheduled_task',task_name='Device Sync',
                       action_target=r'C:\Admin\Sync-DeviceInventory.ps1')
        return {'results':[]}
    _,calls,g=await harvest('scheduled_task',alert_text,dispatch)
    assert any(t=='get_entity' and a.get('entity_id')==TA for t,a in calls)
    assert report(g,'scheduled_task')['legitimacy_evidence']==[
        {'anchor':'entity','entity_id':TA,'property_fields':['task_name','action_target']}]
    assert report(g,'inbound_guard')['legitimacy_evidence']==[]
    assert len(calls)<=8


@pytest.mark.asyncio
async def test_schedule_typed_incoming_relation_opened():
    alert_text=alert(r'C:\Windows\System32\svchost.exe')
    alert_text['trigger_entities'][1]['relation_ids']={'in:ran_scheduled_task':['typed-task']}
    def dispatch(tool,args):
        if tool=='get_relation':
            return rel('typed-task','ran_scheduled_task',TA,TR)
        if tool=='get_entity' and args.get('entity_id')==TA:
            return ent(TA,'scheduled_task',task_name='Ops Service',action_target='ops.ps1')
        return {'results':[]}
    _,calls,g=await harvest('scheduled_task',alert_text,dispatch)
    assert any(t=='get_relation' for t,_ in calls)
    assert report(g,'scheduled_task')['legitimacy_evidence'][0]['entity_id']==TA


@pytest.mark.asyncio
async def test_script_file_search_basename_and_cite_path_only():
    alert_text=alert(r'C:\Windows\System32\powershell.exe',
                     r'powershell.exe -NoProfile -File "C:\Program Files\Admin\Sync-DeviceInventory.ps1"')
    def dispatch(tool,args):
        if tool=='search' and (args.get('scope') or {}).get('type')=='windows_file':
            assert args['query']=='Sync-DeviceInventory.ps1'
            return {'entities':[ent(FI,'windows_file',path=r'C:\Program Files\Admin\Sync-DeviceInventory.ps1')]}
        return {'results':[]}
    _,calls,g=await harvest('script_file',alert_text,dispatch)
    assert script_name_from_command(alert_text['trigger_entities'][1]['properties']['cmdline'])=='Sync-DeviceInventory.ps1'
    assert any((a.get('scope') or {}).get('type')=='windows_file' for _,a in calls)
    assert report(g,'script_file')['legitimacy_evidence']==[
        {'anchor':'entity','entity_id':FI,'property_fields':['path']}]
    assert len(calls)<=8


@pytest.mark.asyncio
async def test_userinit_interactive_logon_search_and_peer_citation():
    alert_text=alert(r'C:\Windows\System32\userinit.exe')
    login=rel('login','logged_on_to','current-user',HO,
              logon_properties={'logon_id':LO, 'logon_type':10, 'source_ip':'10.99.88.42'})
    def dispatch(tool,args):
        if tool=='search' and (args.get('scope') or {}).get('type')=='logged_on_to':
            return {'relations':[login]}
        if tool=='search' and (args.get('scope') or {}).get('type')=='host':
            assert args['query']=='10.99.88.42'
            return {'entities':[ent(PE,'host',hostname='VDI01',role='workstation',ip='10.99.88.42')]}
        return {'results':[]}
    _,calls,g=await harvest('interactive_logon',alert_text,dispatch)
    assert interactive_source_ips(g,TR)==['10.99.88.42']
    assert report(g,'interactive_logon')['legitimacy_evidence']==[
        {'anchor':'entity','entity_id':PE,'property_fields':['hostname','role']}]
    assert len(calls)<=8


@pytest.mark.asyncio
async def test_protection_handles_equal_harvest_and_different_citations():
    alert_text=alert(r'C:\Program Files\ESET\ekrn.exe')
    def dispatch(tool,args):
        if tool=='search' and args['query']==TR and not args.get('scope'):
            return {'relations':[rel('handle','opened_handle',TR,TA)]}
        if tool=='get_entity' and args.get('entity_id')==TA:
            return ent(TA,'windows_process',image_path=r'C:\Windows\System32\cmd.exe', name='cmd.exe')
        return {'results':[]}
    _,cite_calls,cited=await harvest('agent_handles',alert_text,dispatch)
    _,empty_calls,empty=await harvest('agent_handles_nocite',alert_text,dispatch)
    assert [(t,{k:v for k,v in a.items() if k!='reasoning'}) for t,a in cite_calls]==[
           (t,{k:v for k,v in a.items() if k!='reasoning'}) for t,a in empty_calls]
    assert any(t=='get_entity' and a.get('entity_id')==TA for t,a in cite_calls)
    assert report(cited,'agent_handles')['legitimacy_evidence']==[
        {'anchor':'entity','entity_id':TA,'property_fields':['image_path','name']}]
    assert report(empty,'agent_handles_nocite')['legitimacy_evidence']==[]


def test_no_false_citations_on_unrelated_graph_entities():
    a=alert(r'C:\Windows\System32\userinit.exe')
    g=ObservedGraph();g.absorb_alert({'alert_text':a})
    g.absorb(ent(PE,'host',hostname='unrelated',role='external',ip='10.4.5.6'))
    assert not report(g,'interactive_logon')['legitimacy_evidence']
    g.absorb(rel('failed','logged_on_to','other-user',HO,
                 logon_properties={'logon_id':'0xDIFFERENT','source_ip':'10.4.5.6'}))
    assert not report(g,'interactive_logon')['legitimacy_evidence']
    assert not interactive_source_ips(g,TR)


def test_other_modes_unchanged_and_all_arms_validated():
    assert len(PHASE_L_MODES)==5
    a=alert(r'C:\Windows\System32\svchost.exe')
    g=ObservedGraph();g.absorb_alert({'alert_text':a})
    before={'verdict':'malicious','reasoning':'verified','ir_artifacts':[]}
    for mode in PHASE_L_MODES:
        assert apply_report_experiment(before,g,mode)==apply_report_experiment(before,g,'inbound_guard')
