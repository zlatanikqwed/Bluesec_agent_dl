"""Portable synthetic regression tests: no case-specific UUIDs or saved answers."""
from bluesec1_agent.decision_guard import (
    decisive_signals, detect_attack_signals, minimal_artifacts,
)


def observations(*nodes, edges=None):
    return {n["id"]: n for n in nodes}, edges or {}


def test_destructive_child_cannot_be_dismissed_because_of_signed_parent():
    nodes, edges = observations(
        {"id": "p", "type": "windows_process", "host_id": "h", "properties": {
            "cmdline": "vssadmin.exe delete shadows /all /quiet", "signed": True,
            "signer": "Microsoft Windows"}},
        {"id": "h", "type": "host", "properties": {"role": "server"}},
    )
    strong = decisive_signals(detect_attack_signals(nodes, edges))
    assert any("shadow copies" in s.name for s in strong)
    artifacts = minimal_artifacts(nodes, edges, {"p"}, strong)
    assert {a["kind"] for a in artifacts} == {"process_observed", "host_to_isolate"}


def test_forensics_cleanup_must_not_be_mistaken_for_staged_binary_deletion():
    nodes, edges = observations(
        {"id": "triage", "type": "windows_process", "properties": {"cmdline": "powershell.exe"}},
        {"id": "helper", "type": "windows_process", "properties": {
            "image_path": r"C:\Windows\Temp\IR_Tools\helper.exe"}},
        edges={
            "a": ("deleted_file", "triage", "e1"),
            "b": ("deleted_file", "triage", "e2"),
        },
    )
    assert not decisive_signals(detect_attack_signals(nodes, edges))


def test_staged_binary_itself_deleting_data_is_critical():
    nodes, edges = observations(
        {"id": "staged", "type": "windows_process", "properties": {
            "image_path": r"C:\Users\Public\update96.exe"}},
        edges={
            "a": ("deleted_file", "staged", "e1"),
            "b": ("deleted_file", "staged", "e2"),
        },
    )
    assert decisive_signals(detect_attack_signals(nodes, edges))


def test_service_account_and_normal_backup_command_are_not_an_attack():
    nodes, edges = observations({"id": "p", "type": "windows_process", "properties": {
        "cmdline": r"powershell -File C:\Scripts\check-backup.ps1",
        "user": r"ACME\svc_backup", "signer": "Microsoft Windows"}})
    assert not decisive_signals(detect_attack_signals(nodes, edges))


def test_sql_bank_destination_change_is_captured():
    nodes, edges = observations({"id": "p", "type": "powershell_script", "properties": {
        "script_text": "sqlcmd -Q 'UPDATE dbo.Payee SET account_no = 12345 WHERE id = 1'"}})
    assert decisive_signals(detect_attack_signals(nodes, edges))


def test_smb_single_connection_not_decisive():
    nodes, edges = observations(
        {"id": "n", "type": "network_connection", "properties": {
            "src_ip": "10.0.2.1", "dst_ip": "10.0.2.2", "dst_port": 445}}
    )
    assert not decisive_signals(detect_attack_signals(nodes, edges))


def test_reserved_invalid_dns_with_successful_network_connection():
    nodes, edges = observations({"id": "net", "type": "network_connection", "properties": {
        "fqdn": "logon.example.invalid", "dst_ip": "192.0.2.25", "query_status": "SUCCESS"}})
    signals = detect_attack_signals(nodes, edges)
    assert signals and decisive_signals(signals)


def test_workstation_pivot_requires_correlated_inbound_and_two_admin_outbound():
    nodes, edges = observations(
        {"id": "h", "type": "host", "properties": {"role": "workstation"}},
        {"id": "p", "type": "windows_process", "host_id": "h", "properties": {
            "image_path": r"C:\Windows\System32\svchost.exe", "signed": True}},
        {"id": "in1", "type": "network_connection", "properties": {"src_ip": "10.0.0.8", "dst_ip": "10.0.0.9", "dst_port": 50001}},
        {"id": "in2", "type": "network_connection", "properties": {"src_ip": "10.0.0.8", "dst_ip": "10.0.0.9", "dst_port": 50002}},
        {"id": "smb", "type": "network_connection", "properties": {"dst_ip": "10.0.0.11", "dst_port": 445}},
        {"id": "winrm", "type": "network_connection", "properties": {"dst_ip": "10.0.0.11", "dst_port": 5985}},
        {"id": "web", "type": "network_connection", "properties": {"dst_ip": "203.0.113.15", "dst_port": 443}},
        edges={
            "a": ("accepted_connection_from", "p", "in1"),
            "b": ("accepted_connection_from", "p", "in2"),
            "c": ("connected_to", "p", "smb"),
            "d": ("connected_to", "p", "winrm"),
            "e": ("connected_to", "p", "web"),
        },
    )
    signals = decisive_signals(detect_attack_signals(nodes, edges))
    assert any("relayed inbound sessions" in s.name for s in signals)
    # Only outgoing destinations should be considered for blocking.
    artifacts = minimal_artifacts(nodes, edges, {"p"}, signals)
    assert {a["entity_id"] for a in artifacts if a["kind"] == "network_block"} == {
        "smb", "winrm", "web"
    }


def test_normal_inbound_fileserver_smb_is_not_automatically_malicious():
    nodes, edges = observations(
        {"id": "h", "type": "host", "properties": {"role": "server"}},
        {"id": "p", "type": "windows_process", "host_id": "h", "properties": {
            "image_path": "System"}},
        *[{"id": f"n{i}", "type": "network_connection", "properties": {
            "src_ip": "10.0.0.2", "dst_ip": "10.0.0.3", "dst_port": 445}}
          for i in range(9)],
        edges={f"e{i}": ("accepted_connection_from", "p", f"n{i}") for i in range(9)},
    )
    assert not decisive_signals(detect_attack_signals(nodes, edges))
