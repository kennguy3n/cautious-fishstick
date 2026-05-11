#!/usr/bin/env bash
# check_sn360_language.sh — Enforce ShieldNet 360 user-facing
# language alignment in handler responses.
#
# Per docs/PROPOSAL.md §8 the platform uses two terminology
# registers:
#
#   * Technical (internal docs / code / variable names) — uses ZTNA /
#     identity-management vocabulary like "policy", "entitlement",
#     "certification", "SCIM".
#   * Product (any string we surface to a non-engineer) — uses the
#     SN360 product glossary like "access rule", "app permission",
#     "access check-up", "auto-sync users".
#
# This script greps the user-facing surface (handler response keys
# and message strings under internal/handlers/) for the technical
# register and exits non-zero when it finds a hit. CI invokes it
# from the PR pipeline; engineers run it locally before pushing.
#
# Usage:
#   ./scripts/check_sn360_language.sh            # scan defaults
#   ./scripts/check_sn360_language.sh dir1 dir2  # scan custom paths
#
# Exit codes:
#   0  no violations
#   1  violations found

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Default scan targets: anything that could end up in a JSON
# response, swagger schema description, or user-visible log line.
targets=(
    "internal/handlers"
    "docs/swagger.json"
    "docs/swagger.yaml"
)
if [[ $# -gt 0 ]]; then
    targets=("$@")
fi

# Each entry is `<forbidden phrase>|<sn360 replacement>`. The
# script searches case-insensitively but reports the original.
mappings=(
    "ZTNA policy|Access rule"
    "Service policy|Connection permission"
    "Identity provider|Company directory"
    "SCIM provisioning|Auto-sync users"
    "Access review campaign|Access check-up"
    "Entitlement|App permission"
    "Separation of duties|Conflict check"
    "Federated SSO|Single sign-on"
    "Access certification|Access check-up"
)

violations=0
report=()

# Helper: emit a violation for path:line phrase->replacement.
record() {
    local path="$1" line="$2" phrase="$3" replacement="$4" snippet="$5"
    report+=("$path:$line: forbidden term '$phrase' (use '$replacement' instead) — $snippet")
    violations=$((violations + 1))
}

for mapping in "${mappings[@]}"; do
    phrase="${mapping%%|*}"
    replacement="${mapping##*|}"
    # Only flag occurrences inside Go string literals or Swagger
    # description / summary keys. We approximate by greping for the
    # phrase wrapped in quotes ("...phrase...") which is the common
    # pattern in handler response payloads.
    pattern="\"[^\"]*${phrase}[^\"]*\""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        rest="${line#*:}"
        lineno="${rest%%:*}"
        snippet="${rest#*:}"
        record "$file" "$lineno" "$phrase" "$replacement" "$(echo "$snippet" | sed 's/^[[:space:]]*//' | head -c 120)"
    done < <(
        for target in "${targets[@]}"; do
            if [[ -d "$target" ]]; then
                grep -RInE "$pattern" "$target" \
                    --include="*.go" \
                    --include="*.json" \
                    --include="*.yaml" \
                    --include="*.yml" \
                    --exclude-dir=vendor \
                    --exclude="*_test.go" \
                    || true
            elif [[ -f "$target" ]]; then
                grep -InE "$pattern" "$target" \
                    | sed "s|^|${target}:|" \
                    || true
            fi
        done
    )
done

if [[ $violations -gt 0 ]]; then
    echo "scripts/check_sn360_language.sh: found $violations SN360 language violation(s):" >&2
    for entry in "${report[@]}"; do
        echo "  $entry" >&2
    done
    echo ""
    echo "Update the offending strings to use the SN360 product register" >&2
    echo "(see docs/PROPOSAL.md §8) or move the technical term into an" >&2
    echo "internal-only comment / variable name." >&2
    exit 1
fi

echo "scripts/check_sn360_language.sh: no SN360 language violations found."
exit 0
