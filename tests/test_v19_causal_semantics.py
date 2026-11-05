"""Cross-source and service-provenance semantics; no task-specific indicators or verdicts."""
from types import SimpleNamespace

from bluesec1_agent.security_reasoning import collect_security_findings, security_case_summary


def _service_case(*, has_service=True, registry_image=None, process_image=None,
                  same_host=True, has_launch=True):
    path = r"C:\Windows\helper.exe"
    nodes = {
        'system': {'type': 'windows_process', 'host_id': 'h1',
                   'properties': {'image_path': r'C:\Windows\System32\services.exe', 'signed': True}},
        'binary': {'type': 'windows_process', 'host_id': 'h1' if same_host else 'h2',
                   'properties': {'image_path': process_image or path}},
        'child': {'type': 'windows_process', 'host_id': 'h1',
                  'properties': {'image_path': r'C:\Windows\Temp\python.exe'}},
        'registry': {'type': 'registry_key', 'host_id': 'h1',
                     'properties': {'path': r'HKLM\SYSTEM\CurrentControlSet\Services\HelperService\ImagePath',
                                    'value_data': registry_image or path}},
    }
    if has_service:
        nodes['svc']={'type':'windows_service','host_id':'h1',
                      'properties':{'service_name':'HelperService'}}
    edges={'reg_evt':('set_registry_value','system','registry'),
           'child_evt':('win_process_create','binary','child')}
    if has_launch:
        edges['launch_evt']=('win_process_create','system','binary')
    return SimpleNamespace(observed_nodes=nodes, graph_edges=edges, relation_ids=set(edges),
                           focus_ids={'binary'})


def test_correlates_service_registry_launch_and_child_without_auto_verdict():
    m=_service_case()
    facts=[f for f in collect_security_findings(m) if f.kind=='service-binary-lineage']
    assert len(facts)==1
    assert 'HelperService' in facts[0].observation
    assert 'registry-change=reg_evt' in facts[0].observation
    assert 'spawned=child' in facts[0].observation
    assert 'NOT whether' in facts[0].limitation
    assert 'malicious' not in facts[0].observation.lower()


def test_service_chain_requires_observed_launch():
    assert not [f for f in collect_security_findings(_service_case(has_launch=False))
                if f.kind=='service-binary-lineage']


def test_service_chain_requires_matching_host_and_image():
    for m in (_service_case(same_host=False),
              _service_case(process_image=r'C:\Elsewhere\other.exe'),
              _service_case(registry_image=r'C:\Windows\other.exe')):
        assert not [f for f in collect_security_findings(m) if f.kind=='service-binary-lineage']


def test_service_chain_requires_observed_service_entity():
    assert not [f for f in collect_security_findings(_service_case(has_service=False))
                if f.kind=='service-binary-lineage']


def test_exact_hash_provenance_discloses_full_ids_and_limits_causality():
    digest='a'*64
    source='e2d9493d-01d6-48d9-8235-9bc79a2d118a'
    fileid='64c6122d-7383-463b-bc09-5430fa77d96f'
    procid='10189c17-72b8-4c90-9674-15277078b852'
    nodes={fileid: {'type':'windows_file','host_id':'host',
                    'properties':{'path':r'C:\Temp\report.exe','sha256':digest}},
           procid: {'type':'windows_process','host_id':'host',
                    'properties':{'image_path':r'C:\Temp\report.exe','sha256':digest}}}
    m=SimpleNamespace(observed_nodes=nodes,
                      graph_edges={'e':('wrote_file',source,fileid)},
                      relation_ids={'e'},focus_ids={source})
    findings=collect_security_findings(m)
    rendered=security_case_summary(m)
    assert findings[0].kind=='file-process-provenance'
    assert fileid in rendered and procid in rendered
    assert 'writer=' + source in rendered
    assert 'does NOT establish that the writer launched' in rendered


def test_rootdse_write_is_reported_as_capability_not_proven_change():
    m=SimpleNamespace(observed_nodes={'script':{'type':'powershell_script',
        'properties': {'script_text':'$entry = [ADSI]"LDAP://server/RootDSE"; $entry.Put("flag",1)'}}},
        graph_edges={},relation_ids=set(),focus_ids={'script'})
    facts=collect_security_findings(m)
    assert 'command-capability:directory-object-operation' in [f.kind for f in facts]
    assert 'not necessarily success or abuse' in facts[0].limitation


def test_service_image_executable_with_arguments_is_correlated():
    m = _service_case(registry_image=r'"C:\Windows\helper.exe" -service')
    facts = [f for f in collect_security_findings(m) if f.kind == 'service-binary-lineage']
    assert len(facts) == 1
    assert 'HelperService' in facts[0].observation


def test_service_image_without_literal_executable_cannot_be_joined():
    m = _service_case(registry_image=r'%SYSTEMROOT%\variable.exe -service')
    assert not [f for f in collect_security_findings(m) if f.kind == 'service-binary-lineage']
