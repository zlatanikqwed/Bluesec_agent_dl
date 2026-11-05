"""Phase J: seeded control, authenticated incoming sources, and service mapping."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.report_experiments import apply_report_experiment, _opened_service_matches_process
from bluesec1_agent.response_mapper import ObservedGraph
from bluesec1_agent.settings import Settings


def n(nid, typ, host_id=None, **props):
    return {"id":nid,"type":typ,"host_id":host_id,"properties":props}


def r(rid, typ, src, dst, **props):
    return {"id":rid,"type":typ,"source_id":src,"target_id":dst,"properties":props}


def graph():
    g=ObservedGraph()
    g.absorb_alert({"alert_text":{"trigger_entities":[
        n("trigger_uuid_0001","windows_process","here",image_path=r"C:\Windows\System32\powershell.exe",
          cmdline="powershell -NoLogo",parent_image=r"C:\Windows\System32\wsmprovhost.exe",
          user_sid="S-1-5-21-9000",logon_id="0x0124"),
        n("here","host",ip="10.0.0.1")
    ]}})
    g.absorb([n("external","host",ip="203.0.113.169",role="external"),
              n("internal","host",ip="10.0.0.19",role="workstation"),
              n("zip","archive_file",path=r"C:\Temp\package.zip"),
              r("wrote","wrote_file","trigger_uuid_0001","zip"),
              r("remote0","logged_on_to","user","here",logon_id="0x0124",
                status="SUCCESS",logon_type=3,source_ip="203.0.113.169"),
              r("remote1","logged_on_to","user","here",logon_id="0x0124",
                status="SUCCESS",logon_type=3,source_ip="10.0.0.19")])
    return g


def malicious():
    return {"verdict":"malicious","reasoning":"original","ir_artifacts":[
        {"entity_id":"here","kind":"host_to_isolate"}]}


def actions(report):
    return {(item["entity_id"],item["kind"]) for item in report["ir_artifacts"]}


def test_baseline_archives_includes_written_zip_and_preserves_reasoning():
    g=graph(); original=malicious(); frozen=deepcopy(original)
    out=apply_report_experiment(original,g,"baseline_archives")
    assert ("zip","file_to_delete") in actions(out)
    assert ("external","network_block") not in actions(out) # no causal TCP evidence
    assert out["reasoning"]=="original" and original == frozen


def test_inbound_sources_adds_external_block_and_verified_internal_isolation():
    g=graph()
    out=apply_report_experiment(malicious(),g,"inbound_sources")
    assert ("external","network_block") in actions(out)
    assert ("internal","host_to_isolate") in actions(out)
    assert ("zip","file_to_delete") in actions(out)


def test_inbound_sources_rejects_unrelated_and_failed_authentication():
    g=graph()
    g.relations["remote0"]["properties"]["status"]="FAILED"
    g.relations["remote1"]["properties"]["logon_id"]="other-session"
    out=apply_report_experiment(malicious(),g,"inbound_sources")
    assert ("external","network_block") not in actions(out)
    assert ("internal","host_to_isolate") not in actions(out)


def test_inbound_source_cap_honors_existing_connection_blocks():
    g=graph()
    g.absorb([n("other-ext","host",ip="198.51.100.203",role="external"),
              r("remote2","logged_on_to","user","here",logon_id="0x0124",
                status="SUCCESS",source_ip="198.51.100.203")])
    before=malicious()
    before["ir_artifacts"].append({"entity_id":"net-old","kind":"network_block"})
    out=apply_report_experiment(before,g,"inbound_sources")
    assert sum(a["kind"]=="network_block" for a in out["ir_artifacts"]) <= 2


def test_service_persistence_adds_matching_quoted_service_not_unrelated():
    g=graph()
    tr=g.entities["trigger_uuid_0001"]["properties"]
    tr.update(image_path=r"C:\Windows\launcher-99.exe",cmdline=r"C:\Windows\launcher-99.exe -service",
              parent_image=r"C:\Windows\System32\services.exe")
    g.absorb([n("svc","windows_service",binary_path='"C:\\Windows\\launcher-99.exe" -service'),
              n("other","windows_service",binary_path=r"C:\Windows\other.exe -service")])
    assert _opened_service_matches_process(g) == ["svc"]
    out=apply_report_experiment(malicious(),g,"service_persistence_v2")
    assert ("svc","persistence_to_remove") in actions(out)
    assert ("other","persistence_to_remove") not in actions(out)


def test_service_persistence_needs_opened_service_and_proven_parent():
    g=graph()
    tr=g.entities["trigger_uuid_0001"]["properties"]
    tr.update(image_path=r"C:\Windows\launcher-99.exe",cmdline=r"C:\Windows\launcher-99.exe -service")
    g.absorb([n("svc","windows_service",binary_path=r"C:\Windows\launcher-99.exe -service")])
    assert ("svc","persistence_to_remove") not in actions(apply_report_experiment(
        malicious(),g,"service_persistence_v2"))
    tr["parent_image"]=r"C:\Windows\System32\services.exe"
    g.entities.pop("svc")
    assert ("svc","persistence_to_remove") not in actions(apply_report_experiment(
        malicious(),g,"service_persistence_v2"))


@pytest.mark.asyncio
async def test_inbound_probe_uses_scoped_login_search_even_when_spawn_edge_exists():
    alert={"trigger_entities":[
        n("here","host",ip="10.0.0.1"),
        n("trigger_uuid_0001","windows_process","here",pid=111,image_path=r"C:\Windows\System32\powershell.exe",
          cmdline="powershell -NoLogo",parent_image=r"C:\Windows\System32\wsmprovhost.exe",
          logon_id="0x0124", user_sid="S-1-5-21-9000")
    ]}
    calls=[]; facts=[]
    class S:
        async def call_tool(self,tool,args):
            calls.append((tool,args))
            if tool=='search' and args.get('query')=='trigger_uuid_0001' and not args.get('scope'):
                data={'relations':[r('spawn','win_process_create','trigger_uuid_0001','child')]}
            elif tool=='search' and args.get('query')=='0x0124' and args.get('scope',{}).get('type')=='logged_on_to':
                data={'relations':[r('remote','logged_on_to','user','here',logon_id='0x0124',status='SUCCESS',source_ip='203.0.113.169')]}
            elif tool=='search' and args.get('query')=='203.0.113.169':
                data={'entities':[n('peer','host',ip='203.0.113.169',role='external')]}
            else: data={'results': []}
            return SimpleNamespace(info={'tool_result':data},observation={},task_result=None,reward=0)
    result=await EvidenceHarvester(budget=8,service_probe=True,inbound_probe=True).collect(
        S(),{'alert_text':alert},{'search','get_entity','get_relation'},
        lambda t,a,res: facts.append(res.info['tool_result']))
    assert result.calls<=8
    assert any(a.get('query')=='0x0124' and a.get('scope',{}).get('type')=='logged_on_to' for t,a in calls), calls
    assert any(a.get('query')=='203.0.113.169' and a.get('scope',{}).get('type')=='host' for t,a in calls)
    graph2=ObservedGraph();graph2.absorb_alert({'alert_text':alert})
    for data in facts: graph2.absorb(data)
    assert 'peer' in graph2.entities


@pytest.mark.asyncio
async def test_baseline_does_not_spend_special_inbound_search():
    alert={"trigger_entities":[
        n("here","host",ip="10.0.0.1"),
        n("trigger_uuid_0001","windows_process","here",pid=111,image_path=r"C:\Windows\System32\powershell.exe",
          cmdline="powershell -NoLogo",parent_image=r"C:\Windows\System32\wsmprovhost.exe",
          logon_id="0x0124", user_sid="S-1-5-21-9000")
    ]}
    calls=[]
    class S:
        async def call_tool(self,tool,args):
            calls.append((tool,args))
            data={'relations':[r('spawn','win_process_create','trigger_uuid_0001','child')]} if args.get('query')=='trigger_uuid_0001' else {'results':[]}
            return SimpleNamespace(info={'tool_result':data},observation={},task_result=None,reward=0)
    await EvidenceHarvester(budget=8,service_probe=True,inbound_probe=False).collect(
        S(),{'alert_text':alert},{'search','get_entity','get_relation'},lambda *args:None)
    assert not any(a.get('query')=='0x0124' and a.get('scope',{}).get('type')=='logged_on_to' for t,a in calls)
