#!/usr/bin/env bash
# check_stale_references.sh — CI guard against retired doc filenames.
#
# Several files were retired during the public-docs rewrite (PR #87)
# and replaced by lowercase successors:
#
#   docs/PROPOSAL.md        → docs/architecture.md
#   docs/ARCHITECTURE.md    → docs/architecture.md
#   docs/LISTCONNECTORS.md  → docs/connectors.md
#   docs/SDK_CONTRACTS.md   → docs/sdk.md
#
# This guard fails if any tracked file outside docs/internal/ still
# references the retired names. docs/internal/ is allowed because the
# internal trackers (PROGRESS.md, PHASES.md) intentionally preserve
# historical phase labels. CHANGELOG.md is also allowed because the
# retirement note explicitly lists the old filenames.
#
# Usage:
#   ./scripts/check_stale_references.sh
#
# Exit codes:
#   0 — no stale references found
#   1 — at least one stale reference found (full grep output printed)

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Retired doc-file basenames AND bare shorthand. Matched via `git
# grep -nE` (extended regex, no `-w`), so the literal `\.md` suffix
# enforces filename specificity. The second alternation catches bare
# shorthand like `PROPOSAL §5.3` or `ARCHITECTURE §10` — those still
# cite the retired document even without the `.md` extension and need
# to be rewritten to the lowercase successors.
#
# Word boundaries: POSIX ERE has no portable `\b` / `\<` / `\>`
# (those are GNU extensions and may silently fail to match if `git`
# is built against a non-GNU regex backend). Instead we enforce the
# left boundary explicitly with `(^|[^A-Za-z0-9_])` (start-of-line
# or a non-word character) so we don't false-match on substrings.
# The right boundary is enforced implicitly by the `(\.md|[[:space:]]+§)`
# alternation: both branches begin with a non-word character.
#
# The allowlist below drops paths that are allowed to mention the
# retired filenames in prose (the script itself, the CHANGELOG
# retirement note, and the internal trackers under docs/internal/).
patterns='(^|[^A-Za-z0-9_])(PROPOSAL|ARCHITECTURE|LISTCONNECTORS|SDK_CONTRACTS)(\.md|[[:space:]]+§)'

# Search everything tracked by git so vendored or generated trees we
# do not own are ignored automatically. Per-file allowlist suppresses:
#   - docs/internal/**         (internal trackers; historical refs OK)
#   - CHANGELOG.md             (intentional retirement note)
#   - CONTRIBUTING.md          (documents the names this script flags)
#   - scripts/check_stale_references.sh (this script lists the names
#                                        it is checking for)
allowlist_regex='^(docs/internal/|CHANGELOG\.md$|CONTRIBUTING\.md$|scripts/check_stale_references\.sh$)'

# git grep -E supports extended regex; -n prints line numbers. We
# capture failures into a temp file so we can render a friendly
# summary instead of dumping raw grep output.
matches="$(git grep -nE "$patterns" -- ':!.git' 2>/dev/null || true)"

if [[ -z "$matches" ]]; then
    echo "check_stale_references: ok (no retired doc filenames found)"
    exit 0
fi

# Filter out allowlisted paths.
violations="$(printf '%s\n' "$matches" | awk -F: -v skip="$allowlist_regex" '
    {
        path = $1
        if (path ~ skip) next
        print
    }
')"

if [[ -z "$violations" ]]; then
    echo "check_stale_references: ok (only allowlisted references remain)"
    exit 0
fi

echo "check_stale_references: FAIL — retired doc filenames still referenced:" >&2
echo "" >&2
printf '%s\n' "$violations" >&2
echo "" >&2
echo "Replace with the lowercase successors (docs/architecture.md," >&2
echo "docs/connectors.md, docs/sdk.md) and re-run this script." >&2
exit 1
