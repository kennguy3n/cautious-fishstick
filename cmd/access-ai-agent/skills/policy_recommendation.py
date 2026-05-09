"""policy_recommendation skill.

Suggests access policies from an org-structure summary. The Go side
calls this when an admin asks "what policies should I have?" — the
agent returns a structured ``recommendations`` array each item of
which is one suggested policy in the same shape the policy service
accepts.

Phase 4 stub: returns a small canned set of recommendations keyed
off ``team_kind`` per team. Phase 5 swaps in an LLM-backed generator.
"""
from __future__ import annotations

from typing import Any, Dict, List


# Canned recommendations per team kind. Each entry is a partial
# Policy DTO the admin UI can render and the policy service can
# accept directly via POST /access/policies.
TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "engineering": [
        {
            "name": "Engineering -> github write",
            "subject_team": "engineering",
            "resource_kind": "github_repo",
            "action": "write",
            "auto_provision": True,
        },
        {
            "name": "Engineering -> staging k8s read",
            "subject_team": "engineering",
            "resource_kind": "k8s_namespace",
            "action": "read",
            "scope": {"environment": "staging"},
            "auto_provision": True,
        },
    ],
    "data": [
        {
            "name": "Data -> warehouse read",
            "subject_team": "data",
            "resource_kind": "snowflake_role",
            "action": "read",
            "auto_provision": True,
        },
    ],
    "sre": [
        {
            "name": "SRE -> prod k8s admin",
            "subject_team": "sre",
            "resource_kind": "k8s_namespace",
            "action": "admin",
            "scope": {"environment": "production"},
            "auto_provision": False,  # SRE prod admin is high-risk → manual approval
        },
    ],
}


class SkillError(ValueError):
    """Raised when the payload is malformed."""


def run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return policy recommendations for the supplied org structure.

    Required keys:
        - teams (list[dict]): each dict has ``name`` and ``kind``.
    """
    if not isinstance(payload, dict):
        raise SkillError("payload must be an object")
    teams = payload.get("teams")
    if not isinstance(teams, list):
        raise SkillError("teams is required and must be a list")

    recs: List[Dict[str, Any]] = []
    explanations: List[str] = []
    for t in teams:
        if not isinstance(t, dict):
            continue
        kind = t.get("kind", "").lower() if isinstance(t.get("kind"), str) else ""
        templates = TEMPLATES.get(kind, [])
        for tmpl in templates:
            rec = dict(tmpl)
            # Personalise to the actual team name when present.
            name = t.get("name")
            if isinstance(name, str) and name:
                rec["subject_team"] = name
                rec["name"] = rec["name"].replace(f"{kind.title()} ->", f"{name} ->")
            recs.append(rec)
        if templates:
            explanations.append(f"team {t.get('name')!r} kind={kind!r}: {len(templates)} templates")

    return {
        "explanation": (
            f"Phase 4 stub generated {len(recs)} recommendations from {len(teams)} teams: "
            + "; ".join(explanations) if explanations else
            "No matching team kinds found; no recommendations generated."
        ),
        "recommendations": recs,
    }
