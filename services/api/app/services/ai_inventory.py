"""Risk scoring and reads for the observed AI estate.

Depth plan 6.1.

One home for the number
-----------------------
``score_risk`` is the only place a risk score is computed. The fusion
recorder calls it on write and stores the result; the console reads the
stored value. Nothing recomputes it in a query. That is deliberate: this
repository has already shipped two surfaces disagreeing about the same rows
because each owned its own SQL expression for a figure, and the way they
disagreed — one averaging over a column nothing writes — was invisible until
somebody compared them by hand.

What the score is, and what it is not
-------------------------------------
It is an **exposure** score, not a verdict. It answers "how much could this
asset reach, and how little do we know about it", which is the question an
inventory can answer from what it has. It does not claim the asset is
malicious; that is what the detections in 6.5 are for, and they read the same
rows.

Every component below adds a *reason string* alongside its points, so the
console shows why rather than a bare number and a reviewer can disagree with
a sentence. A score with no reasons would be the kind of figure nobody can
act on and nobody can refute.
"""

from __future__ import annotations

from typing import Any

#: Points per signal. Capped at 100 by `score_risk`, which also means adding a
#: new signal cannot silently rescale the existing ones.
_POINTS = {
    "unlinked_principal": 15,
    "unlinked_device": 10,
    "undeclared": 20,
    "refused": 30,
    "privileged_permissions": 25,
    "prompts_disabled": 25,
    "unvetted_source": 20,
    "secret_in_prompt": 20,
    "high_risk_tool": 15,
    "broad_oauth_scope": 25,
}

#: OAuth scopes that let an AI application read or alter a mailbox, a drive or
#: a repository wholesale. Each is a real scope string from the provider's own
#: reference, not a category we invented: an AI note-taker with
#: ``https://mail.google.com/`` can read every message the grantee can.
BROAD_OAUTH_SCOPES: frozenset[str] = frozenset(
    {
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/admin.directory.user",
        "Mail.ReadWrite",
        "Mail.Read",
        "Files.ReadWrite.All",
        "Sites.ReadWrite.All",
        "Directory.ReadWrite.All",
        "repo",
        "admin:org",
    }
)

#: Tool names whose effect is a change to an estate rather than a read. An
#: agent that has called one of these is a different asset from one that has
#: only ever searched.
HIGH_RISK_TOOLS: frozenset[str] = frozenset(
    {
        "execute_command",
        "run_shell",
        "write_file",
        "delete_file",
        "send_email",
        "create_user",
        "grant_permission",
        "deploy",
        "terraform_apply",
        "database_write",
    }
)


def score_risk(
    *,
    kind: str,
    principal: str | None,
    device: str | None,
    sanctioned: bool | None,
    attributes: dict[str, Any] | None,
    effective_permissions: dict[str, Any] | None,
) -> tuple[int, list[str]]:
    """Return ``(score, reasons)`` for one asset.

    ``sanctioned`` is tri-state and each state scores differently, which is
    the part that is easy to get wrong: ``None`` means nobody has looked
    (a modest amount of risk, because an unreviewed asset is unmanaged),
    ``False`` means somebody looked and said no (a lot, because it is running
    anyway), and ``True`` means approved (nothing).
    """
    attributes = attributes or {}
    reasons: list[str] = []
    score = 0

    if not principal:
        score += _POINTS["unlinked_principal"]
        reasons.append("No person is linked: nobody is accountable for what it does.")
    if not device and kind in {"coding_agent", "ide_extension", "mcp_server"}:
        score += _POINTS["unlinked_device"]
        reasons.append("No device is linked, so containment has nowhere to act.")

    if sanctioned is False:
        score += _POINTS["refused"]
        reasons.append("Reviewed and refused, and still running.")
    elif sanctioned is None:
        score += _POINTS["undeclared"]
        reasons.append("Not declared in the inventory: nobody has reviewed it.")

    if attributes.get("permission_prompts_disabled"):
        score += _POINTS["prompts_disabled"]
        reasons.append("Started with its permission prompts disabled, so a human confirms nothing.")

    source = str(attributes.get("install_source") or "")
    if source and source not in {"official", "vendor", "internal"}:
        score += _POINTS["unvetted_source"]
        reasons.append(f"Installed from an unvetted source ({source}).")

    secret_kinds = attributes.get("prompt_secret_kinds") or []
    if secret_kinds:
        score += _POINTS["secret_in_prompt"]
        kinds = ", ".join(sorted(str(k) for k in secret_kinds)[:3])
        reasons.append(f"Credential material has appeared in its prompts ({kinds}).")

    tools = {str(t) for t in (attributes.get("tools") or [])}
    risky = sorted(tools & HIGH_RISK_TOOLS)
    if risky:
        score += _POINTS["high_risk_tool"]
        reasons.append(f"Calls tools that change an estate ({', '.join(risky[:3])}).")

    scopes = {str(s) for s in (attributes.get("scopes") or [])}
    broad = sorted(scopes & BROAD_OAUTH_SCOPES)
    if broad:
        score += _POINTS["broad_oauth_scope"]
        reasons.append(f"Holds an OAuth scope covering a whole mailbox, drive or org ({broad[0]}).")

    if _is_privileged(effective_permissions):
        score += _POINTS["privileged_permissions"]
        reasons.append("The linked principal holds administrative permissions.")

    return min(score, 100), reasons


def _is_privileged(effective_permissions: dict[str, Any] | None) -> bool:
    """Whether the Phase 2.5 snapshot says the principal is administrative.

    Reads the resolver's own output shape rather than guessing at a provider
    format. Returns ``False`` for ``None``, which is the honest answer when
    no snapshot was collected — scoring an unknown as privileged would make
    every asset on a deployment without posture collection look severe.
    """
    if not effective_permissions:
        return False
    if effective_permissions.get("is_admin") is True:
        return True
    roles = effective_permissions.get("admin_roles") or []
    return bool(roles)
