"""Location/launcher rules: decisive for alert trigger processes only."""
from bluesec1_agent.decision_guard import decisive_signals, detect_attack_signals, execution_location_signals


def sig(props):
    return {s.name for s in execution_location_signals("p", props)}


def test_user_writable_image_and_script_host_parent():
    s = sig({"image_path": r"C:\Users\c.h\AppData\Local\Temp\update_client_8489.exe",
             "parent_image": r"C:\Windows\System32\mshta.exe"})
    assert "process executed from user-writable or shared-data folder" in s
    assert "script host or regsvr32 launched a process" in s


def test_recon_from_programdata_parent():
    s = sig({"image_path": r"C:\Windows\System32\cmd.exe", "cmdline": "cmd.exe /c whoami",
             "parent_image": r"C:\ProgramData\viewer9814.exe"})
    assert "discovery command run by an untrusted launcher" in s


def test_known_installs_and_windows_temp_are_not_flagged():
    assert sig({"image_path": r"C:\Users\a\AppData\Local\Microsoft\Teams\current\Teams.exe"}) == set()
    assert sig({"image_path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"}) == set()
    assert sig({"image_path": r"C:\Windows\System32\msiexec.exe",
                "parent_image": r"C:\Windows\Temp\vmware-SYSTEM\setup64.exe"}) == set()
    assert sig({"image_path": r"C:\Windows\System32\whoami.exe", "cmdline": "whoami",
                "parent_image": r"C:\Windows\System32\cmd.exe"}) == set()


def test_rules_apply_only_to_trigger_processes():
    nodes = {"ctx": {"type": "windows_process", "properties": {
        "image_path": r"C:\Users\dev\AppData\Local\Postman\app-11\Postman.exe"}}}
    assert not decisive_signals(detect_attack_signals(nodes, {}))
    assert not decisive_signals(detect_attack_signals(nodes, {}, {"other"}))
    assert decisive_signals(detect_attack_signals(nodes, {}, {"ctx"}))


def test_discovery_burst_needs_three_distinct_tools_from_one_parent():
    def proc(cmd, ppid="100"):
        return {"type": "windows_process", "properties": {"cmdline": cmd, "parent_pid": ppid, "host_id": "h"}}
    burst = {"a": proc("whoami /all"), "b": proc("systeminfo"), "c": proc("net view \\\\fs01")}
    assert decisive_signals(detect_attack_signals(burst, {}))
    two = {"a": proc("whoami"), "b": proc("ipconfig /all")}
    assert not decisive_signals(detect_attack_signals(two, {}))
    split = {"a": proc("whoami", "1"), "b": proc("systeminfo", "2"), "c": proc("nltest /dclist:x", "3")}
    assert not decisive_signals(detect_attack_signals(split, {}))
