"""Generic tests of semantic action coverage; no benchmark case answers."""
from bluesec1_agent.agent import InvestigationMemory
from bluesec1_agent.investigation_director import InvestigationDirector


def _build_file_case():
    memory = InvestigationMemory()
    memory.focus_ids = {'runner'}
    memory.absorb({'id': 'runner', 'type': 'windows_process', 'properties': {
        'cmdline': 'powershell.exe -File task.ps1', 'user': 'DOMAIN\\service'}})
    memory.absorb({'id': 'child', 'type': 'windows_process', 'properties': {
        'cmdline': 'C:\\ProgramData\\Example\\worker.exe', 'user': 'DOMAIN\\service'}})
    memory.absorb({'id': 'file', 'type': 'windows_file', 'properties': {
        'path': 'D:\\Shares\\Reports\\summary.dat'}})
    memory.absorb({'id': 'created', 'type': 'win_process_create',
                   'source_id': 'runner', 'target_id': 'child'})
    memory.absorb({'id': 'write', 'type': 'wrote_file',
                   'source_id': 'child', 'target_id': 'file'})
    memory.calls_made = ['get_entity(file)'] * 10
    return memory


def test_follows_observed_effect_not_signed_parent_or_bare_identity():
    memory = _build_file_case()
    director = InvestigationDirector()
    gaps = director.unresolved_consequences(memory)
    assert len(gaps) == 1
    assert 'wrote_file' in gaps[0][1] and 'summary.dat' in gaps[0][1]
    benign = {'verdict': 'benign', 'legitimacy_evidence': [{
        'anchor': 'entity', 'entity_id': 'runner', 'property_fields': ['cmdline', 'user']}]}
    assert director.benign_evidence_gaps(memory, benign)
    challenge = director.agreed_benign_challenge_messages(memory, director.benign_evidence_gaps(memory, benign))
    assert 'wrote_file' in challenge[1]['content']
    assert 'both' not in challenge[0]['content'].lower() or 'neither' not in challenge[0]['content'].lower()


def test_grounded_effect_citation_eliminates_coverage_warning():
    memory = _build_file_case()
    director = InvestigationDirector()
    benign = {'verdict': 'benign', 'legitimacy_evidence': [{
        'anchor': 'entity', 'entity_id': 'file', 'property_fields': ['path']}]}
    assert director.benign_evidence_gaps(memory, benign) == []
    benign['verdict'] = 'malicious'
    assert director.benign_evidence_gaps(memory, benign) == []


def test_one_bounded_filename_search_uses_observed_file_path():
    memory = _build_file_case()
    director = InvestigationDirector()
    q = director.targeted_content_search(memory)
    assert q and q[0] == 'summary.dat'
    memory.targeted_content_searches = 1
    assert director.targeted_content_search(memory) is None
    memory.targeted_content_searches = 0
    memory.calls_made += ['search({"query":"summary.dat"})']
    assert director.targeted_content_search(memory) is None


def test_content_present_needs_no_search():
    memory = _build_file_case()
    memory.absorb({'id': 'file', 'type': 'windows_file', 'properties': {
        'path': 'D:\\Shares\\Reports\\summary.dat', 'script_text': 'observed body'}})
    assert InvestigationDirector().targeted_content_search(memory) is None


def test_cross_identity_use_is_an_evidence_question_not_an_attack_verdict():
    memory = InvestigationMemory()
    memory.focus_ids = {'proc'}
    memory.absorb({'id': 'proc', 'type': 'windows_process', 'properties': {
        'cmdline': 'net use \\\\server\\Logs$ /user:EXAMPLE\\administrator',
        'user': 'HOST\\operator'}})
    director = InvestigationDirector()
    gaps = director.unresolved_consequences(memory)
    assert len(gaps) == 1 and 'IDENTITY SCOPE' in gaps[0][1]
    assert 'not proof' in gaps[0][1]
    assert director.targeted_content_search(memory) is None


def test_same_identity_not_misclassified_and_unlinked_actions_ignored():
    memory = InvestigationMemory()
    memory.focus_ids = {'p1'}
    memory.absorb({'id': 'p1', 'type': 'windows_process', 'properties': {
        'cmdline': 'net use \\\\host\\share /user:DOMAIN\\worker', 'user': 'DOMAIN\\worker'}})
    memory.absorb({'id': 'unlinked', 'type': 'windows_process', 'properties': {
        'cmdline': 'something /user:DOMAIN\\outsider', 'user': 'DOMAIN\\worker'}})
    assert InvestigationDirector().unresolved_consequences(memory) == []
