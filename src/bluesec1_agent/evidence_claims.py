"""Detect unsupported *claims*, not suspicious product names or benchmark answers.

The checker is intentionally non-classifying. It challenges a proposed explanation
by asking whether an assertion is established by cited action/outcome evidence.
A checker finding is an uncertainty to adjudicate, NEVER grounds for a verdict flip.
"""
from __future__ import annotations

import re
from typing import Any


_IDENTITY_FIELDS = {"username", "user", "group_memberships", "member_of", "is_privileged",
                    "account_type", "description", "account", "domain", "signed", "signer",
                    "image_path", "company", "integrity_level"}


def _citation_ids(submission: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    all_ids: set[str] = set()
    action_ids: set[str] = set()
    identity_ids: set[str] = set()
    for row in submission.get("legitimacy_evidence") or []:
        if not isinstance(row, dict):
            continue
        identifier = row.get("relation_id") or row.get("entity_id")
        if not isinstance(identifier, str) or not identifier:
            continue
        all_ids.add(identifier)
        fields = set(x for x in (row.get("property_fields") or []) if isinstance(x, str))
        if row.get("anchor") == "relation" or fields - _IDENTITY_FIELDS:
            action_ids.add(identifier)
        if fields and fields <= _IDENTITY_FIELDS:
            identity_ids.add(identifier)
    for row in submission.get("ir_artifacts") or []:
        if isinstance(row, dict) and isinstance(row.get("entity_id"), str):
            all_ids.add(row["entity_id"])
    return all_ids, action_ids, identity_ids


def unsupported_claims(memory: Any, submission: dict[str, Any], *, limit: int = 4) -> list[str]:
    """Surface attribution/causality gaps without presuming ground truth.

    Uses only text the analyst actually claimed and ids returned by tools. It
    does not look at case IDs or benchmark verdicts and never chooses a class.
    """
    if not isinstance(submission, dict):
        return []
    verdict = submission.get("verdict")
    if verdict not in {"benign", "malicious"}:
        return []
    explanation = str(submission.get("reasoning") or "")
    rationale = explanation.casefold()
    all_ids, action_ids, identity_ids = _citation_ids(submission)
    available = set(getattr(memory, "observed_nodes", {}))
    concerns: list[str] = []
    missing = all_ids - available
    if missing:
        concerns.append(f"CITATION COVERAGE: {len(missing)} cited entity/relation identifiers do not exist in the observed graph; do not rely on these citations.")

    # Important distinction: ACLs and group membership grant capability, not
    # evidence that a particular write, remote execution or logon was approved.
    if verdict == "benign":
        claims_workflow = bool(re.search(
            r"\b(?:authorized|legitimate|normal|routine|approved|expected|part of|consistent with|aligns with)\b",
            rationale))
        named_identity = bool(re.search(
            r"\b(?:privileg|admin|service.account|svc_|group.member|membership|role|signed|signer|system)\b",
            rationale))
        if claims_workflow and named_identity:
            concerns.append(
                "AUTHORIZATION CLAIM: a role, signature or privileged account establishes capability/identity, "
                "not permission for the specific observed operation. Identify a positive workflow/provenance "
                "link accounting for the affected object and result; otherwise describe legitimacy as a hypothesis."
            )
        if not action_ids and identity_ids:
            concerns.append(
                "CITATION GAP: benign citations mainly establish identity/trust, not the operation's "
                "observed outcome. Compare the actual actor-action-target chain before concluding it is normal."
            )
        # A lack of observed credential theft is NOT affirmative proof that
        # explicit credentials supplied for an action were legitimately used.
        if re.search(r"(?:no (?:direct )?evidence|not observed|cannot confirm|not proven)", rationale) and re.search(
            r"(?:credential|unauthorized|misuse|malicious|compromise)", rationale):
            concerns.append(
                "ABSENCE-OF-PROOF: not observing credential theft, misuse or a compromise "
                "does not affirmatively establish an authorized use of the account."
            )
    else:
        no_approval = bool(re.search(
            r"(?:no |without |lack of |absence of |not |never |unknown |unverified |missing )"
            r"(?:explicit |known |documented |recorded )?"
            r"(?:approv|authoriz|ticket|change.request|permission)", rationale))
        if no_approval:
            concerns.append(
                "MISSING-APPROVAL FALLACY: absence of a ticket/authorization record is unknown, "
                "not evidence of malicious intent. Find a positive contradictory action or behavioral "
                "context before relying on unauthorized status."
            )
        if re.search(r"(?:could |may |might |potentially |suspicious|unusual)", rationale) and not re.search(
            r"(?:observed|executed|changed|wrote|deleted|attempted|failed|success)", rationale):
            concerns.append(
                "POSSIBILITY VS. OBSERVATION: a potential capability/odd location by itself "
                "does not prove it was executed or abused; check the observed result."
            )
    return concerns[:limit]


def audit_disagreement(memory: Any, first: dict[str, Any], second: dict[str, Any]) -> str:
    lines: list[str] = []
    for name, sub in (("ANALYST A", first), ("ANALYST B", second)):
        warnings = unsupported_claims(memory, sub)
        if warnings:
            lines.extend(f"- {name}: {warning}" for warning in warnings)
    if not lines:
        return "No formulaic claim weakness detected. Both hypotheses still require direct evaluation."
    return ("NON-VERDICT CLAIM AUDIT (questions only; NOT labels or answer hints). "
            "Resolve each against the dossier, without automatically rejecting either conclusion:\n"
            + "\n".join(lines))
