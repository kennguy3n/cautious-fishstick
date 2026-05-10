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

import logging
from typing import Any, Dict, List

from .llm import LLMUnavailable, call_llm, parse_json_response


logger = logging.getLogger(__name__)


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
            # Templates use mixed prefix styles ("Engineering ->" vs.
            # "SRE -> ..."), so we cannot reconstruct the prefix from
            # ``kind.title()`` (that only handles single-word title
            # case and silently no-ops for acronyms like "SRE"). Split
            # on the canonical " -> " separator instead, which works
            # for any prefix style and is forwards-compatible with
            # future template names.
            name = t.get("name")
            if isinstance(name, str) and name:
                rec["subject_team"] = name
                _, sep, suffix = rec["name"].partition(" -> ")
                if sep:
                    rec["name"] = f"{name} -> {suffix}"
            recs.append(rec)
        if templates:
            explanations.append(f"team {t.get('name')!r} kind={kind!r}: {len(templates)} templates")

    deterministic = {
        "explanation": (
            f"Phase 4 stub generated {len(recs)} recommendations from {len(teams)} teams: "
            + "; ".join(explanations) if explanations else
            "No matching team kinds found; no recommendations generated."
        ),
        "recommendations": recs,
    }

    # Phase 5: ask the LLM to expand recommendations using the
    # supplied org context. The LLM result is APPENDED to the
    # deterministic templates rather than replacing them, so the
    # canned policies are always present even when the model
    # returns nothing useful.
    try:
        extra = _llm_recommendations(teams, payload, deterministic)
    except LLMUnavailable as exc:
        logger.debug("llm policy recommendation unavailable: %s", exc)
        return deterministic
    if extra.get("recommendations"):
        merged = list(recs) + list(extra["recommendations"])
        return {
            "explanation": extra.get("explanation") or deterministic["explanation"],
            "recommendations": merged,
        }
    return deterministic


def _llm_recommendations(
    teams: List[Any], payload: Dict[str, Any], baseline: Dict[str, Any]
) -> Dict[str, Any]:
    team_summaries = []
    for t in teams:
        if not isinstance(t, dict):
            continue
        team_summaries.append({
            "name": t.get("name"),
            "kind": t.get("kind"),
            "member_count": t.get("member_count"),
        })
    resources = payload.get("resources") or []
    historical = payload.get("historical_request_counts") or {}
    prompt = (
        "Suggest additional access policies for this organisation. Respond"
        " with strict JSON {\"explanation\": one sentence, \"recommendations\":"
        " array of {name, subject_team, resource_kind, action, auto_provision,"
        " rationale}}.\n"
        f"teams: {team_summaries}\n"
        f"resources: {resources}\n"
        f"historical_request_counts: {historical}\n"
        f"already_recommended: {[r.get('name') for r in baseline['recommendations']]}\n"
    )
    result = call_llm(prompt, system="You are an access-policy authoring assistant.")
    parsed = parse_json_response(result.text)
    extra = parsed.get("recommendations")
    if not isinstance(extra, list):
        raise LLMUnavailable("llm recommendations is not a list")
    sanitised: List[Dict[str, Any]] = []
    for item in extra:
        if not isinstance(item, dict):
            continue
        if not isinstance(item.get("name"), str) or not item["name"].strip():
            continue
        sanitised.append(item)
    return {
        "explanation": parsed.get("explanation") if isinstance(parsed.get("explanation"), str) else None,
        "recommendations": sanitised,
    }
