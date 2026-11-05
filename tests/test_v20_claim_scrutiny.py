"""Generalized reasoning-quality checks; never rely on a benchmark answer."""
from types import SimpleNamespace

from bluesec1_agent.evidence_claims import unsupported_claims, audit_disagreement
from bluesec1_agent.investigation_director import InvestigationDirector


def _memory():
    return SimpleNamespace(observed_nodes={
        'actor': {'id': 'actor', 'type': 'windows_user', 'properties': {'username': 'EXAMPLE\\administrator'}},
        'process': {'id': 'process', 'type': 'windows_process', 'properties': {'cmdline': 'net use ...'}},
        'effect': {'id': 'effect', 'type': 'wrote_file', 'source_id': 'process', 'target_id': 'file'},
        'file': {'id': 'file', 'type': 'windows_file', 'properties': {'path': '/srv/export.dat'}},
    })


def test_unauthorized_identity_must_not_be_inferred_from_membership_alone():
    submission = {'verdict': 'benign', 'reasoning':
        'The service account belongs to the admin group; this is authorized normal activity.',
        'legitimacy_evidence': [{'anchor':'entity', 'entity_id':'actor', 'property_fields':['username','group_memberships']}]}
    concerns = unsupported_claims(_memory(), submission)
    assert any('AUTHORIZATION CLAIM' in s for s in concerns)
    assert any('CITATION GAP' in s for s in concerns)


def test_missing_authorization_ticket_is_not_attack_evidence():
    submission = {'verdict': 'malicious', 'reasoning':
        'A scheduled task runs a cleanup script. No explicit approval record exists.'}
    concerns = unsupported_claims(_memory(), submission)
    assert any('MISSING-APPROVAL' in s for s in concerns)
    assert any('unknown' in s for s in concerns)


def test_no_categorical_verdict_is_injected_into_critic_output():
    benign = {'verdict': 'benign', 'reasoning': 'A signed admin process is part of routine workflow.',
              'legitimacy_evidence': [{'anchor':'entity','entity_id':'process','property_fields':['signed']}]}
    threat = {'verdict': 'malicious', 'reasoning': 'No authorization ticket exists.'}
    text = audit_disagreement(_memory(), benign, threat)
    assert 'AUTHORIZATION CLAIM' in text and 'MISSING-APPROVAL FALLACY' in text
    assert 'questions only' in text and 'NOT labels' in text


def test_positive_activity_with_no_shortcut_claims_is_not_challenged():
    submission = {'verdict': 'benign', 'reasoning':
        'Observed process wrote /srv/export.dat, later moved it to a trusted local archive, matching the documented maintenance script.',
        'legitimacy_evidence': [{'anchor':'relation','relation_id':'effect','property_fields':['type']}]}
    assert unsupported_claims(_memory(), submission) == []


def test_cited_missing_ids_warn_but_never_label_outcome():
    submission = {'verdict': 'malicious', 'reasoning': 'Observed actor changed configuration.',
                  'ir_artifacts': [{'entity_id':'invented-id', 'kind':'process_observed'}]}
    concerns = unsupported_claims(_memory(), submission)
    assert len(concerns) == 1 and 'CITATION COVERAGE' in concerns[0]


def test_arbitrator_gets_symmetric_factual_critique_not_only_verdict_arguments():
    memory = _memory()
    # Dossier only requires graph fields. The warnings themselves are produced independently.
    memory.alert_description = 'A process wrote a file'
    memory.focus_ids = {'process'}
    memory.graph_edges = {'effect': ('wrote_file','process','file')}
    memory.relation_ids = {'effect'}
    memory.entity_types = {k: x['type'] for k,x in memory.observed_nodes.items()}
    memory.trigger_ids = {'process'}
    memory.ad_object_ids = set()
    memory.calls_made = []
    memory.relation_owner = {}
    memory.known_ids = set(memory.observed_nodes)
    memory.fetched_ids = set(memory.observed_nodes)
    memory.discovery_order = {k: i for i, k in enumerate(memory.observed_nodes)}
    a = {'verdict':'benign', 'reasoning':'Signed administrator, authorized normal operation.'}
    b = {'verdict':'malicious', 'reasoning':'No known approval ticket.'}
    request = InvestigationDirector().arbitration_messages(memory,a,b)
    assert 'NON-VERDICT CLAIM AUDIT' in request[1]['content']
    assert 'AUTHORIZATION CLAIM' in request[1]['content']
    assert 'MISSING-APPROVAL FALLACY' in request[1]['content']
    assert request[0]['role'] == 'system'
