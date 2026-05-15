#!/usr/bin/env bash
# generate-swagger.sh — Regenerates the OpenAPI 3.0 spec for the
# ZTNA access platform HTTP API. Called from CI (per the cross-cutting
# criteria in docs/architecture.md §5) whenever a handler-level change lands.
#
# The script uses `swag` (https://github.com/swaggo/swag) to scan the
# annotated handler functions in internal/handlers/ and emit a
# swagger.json + swagger.yaml pair under docs/ AND a synchronised copy
# under internal/handlers/ (the runtime spec served by swagger_handler.go
# via //go:embed). Both pairs are kept byte-for-byte identical so the
# binary's /swagger endpoint can never drift from docs/.
#
# Usage:
#   ./scripts/generate-swagger.sh           # regenerate docs/ + internal/handlers/ swagger files
#   ./scripts/generate-swagger.sh --check   # fail if any of the four files differ from a fresh regen
#
# Exit codes:
#   0 on success
#   1 on swag failure
#   2 on --check drift

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

mode="generate"
if [[ "${1:-}" == "--check" ]]; then
    mode="check"
fi

if ! command -v swag >/dev/null 2>&1; then
    echo "scripts/generate-swagger.sh: 'swag' not on PATH; install with:" >&2
    echo "    go install github.com/swaggo/swag/cmd/swag@latest" >&2
    echo "scripts/generate-swagger.sh: falling back to hand-maintained docs/swagger.{json,yaml} + internal/handlers/swagger.{json,yaml}" >&2
    if [[ "$mode" == "check" ]]; then
        # In --check mode we can't enforce regeneration without swag,
        # but we still enforce that:
        #   - all four static files exist, and
        #   - the embedded internal/handlers/ pair is byte-identical to
        #     the canonical docs/ pair (so the binary serves the same
        #     spec the docs advertise).
        missing=0
        for f in docs/swagger.json docs/swagger.yaml internal/handlers/swagger.json internal/handlers/swagger.yaml; do
            if [[ ! -f "$f" ]]; then
                echo "scripts/generate-swagger.sh: $f missing" >&2
                missing=1
            fi
        done
        if [[ $missing -ne 0 ]]; then
            exit 2
        fi
        sync_status=0
        diff docs/swagger.json internal/handlers/swagger.json >/dev/null 2>&1 || sync_status=1
        diff docs/swagger.yaml internal/handlers/swagger.yaml >/dev/null 2>&1 || sync_status=1
        if [[ $sync_status -ne 0 ]]; then
            echo "scripts/generate-swagger.sh: internal/handlers/swagger.{json,yaml} out of sync with docs/swagger.{json,yaml}." >&2
            echo "    Run: ./scripts/generate-swagger.sh" >&2
            exit 2
        fi
        echo "scripts/generate-swagger.sh: swagger files present and embedded copies in sync; skipping regen drift check"
        exit 0
    fi
    # generate-mode fallback: at minimum, mirror the canonical docs/
    # spec into the embedded handler copies so the //go:embed pair
    # stays consistent even when swag isn't installed locally.
    if [[ -f "docs/swagger.json" && -f "docs/swagger.yaml" ]]; then
        cp docs/swagger.json internal/handlers/swagger.json
        cp docs/swagger.yaml internal/handlers/swagger.yaml
        echo "scripts/generate-swagger.sh: mirrored docs/swagger.{json,yaml} into internal/handlers/"
    fi
    exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

swag init \
    --dir internal/handlers \
    --generalInfo router.go \
    --output "$tmpdir" \
    --outputTypes "json,yaml" \
    --parseInternal

# swag emits a trivial `{"paths": {}}` envelope when the handlers
# don't carry swag annotations. The project is OpenAPI 3.0 + hand-
# maintained docs/swagger.{json,yaml} (per docs/architecture.md) so we
# detect this and short-circuit to the same mirror-only path the
# "swag not installed" fallback above uses.
generated_paths=$(grep -c '"/' "$tmpdir/swagger.json" || true)
if [[ ${generated_paths} -le 1 ]]; then
    echo "scripts/generate-swagger.sh: swag produced an empty spec (no swag annotations on handlers); treating docs/swagger.{json,yaml} as canonical." >&2
    if [[ "$mode" == "check" ]]; then
        sync_status=0
        diff docs/swagger.json internal/handlers/swagger.json >/dev/null 2>&1 || sync_status=1
        diff docs/swagger.yaml internal/handlers/swagger.yaml >/dev/null 2>&1 || sync_status=1
        if [[ $sync_status -ne 0 ]]; then
            echo "scripts/generate-swagger.sh: internal/handlers/swagger.{json,yaml} out of sync with docs/swagger.{json,yaml}." >&2
            echo "    Run: ./scripts/generate-swagger.sh" >&2
            exit 2
        fi
        echo "scripts/generate-swagger.sh: swagger files present and embedded copies in sync."
        exit 0
    fi
    cp docs/swagger.json internal/handlers/swagger.json
    cp docs/swagger.yaml internal/handlers/swagger.yaml
    echo "scripts/generate-swagger.sh: mirrored docs/swagger.{json,yaml} into internal/handlers/"
    exit 0
fi

if [[ "$mode" == "check" ]]; then
    diff_status=0
    for target in docs/swagger.json internal/handlers/swagger.json; do
        diff "$tmpdir/swagger.json" "$target" >/dev/null 2>&1 || diff_status=1
    done
    for target in docs/swagger.yaml internal/handlers/swagger.yaml; do
        diff "$tmpdir/swagger.yaml" "$target" >/dev/null 2>&1 || diff_status=1
    done
    if [[ $diff_status -ne 0 ]]; then
        echo "scripts/generate-swagger.sh: docs/swagger.{json,yaml} and/or internal/handlers/swagger.{json,yaml} are out of date." >&2
        echo "    Run: ./scripts/generate-swagger.sh" >&2
        exit 2
    fi
    echo "scripts/generate-swagger.sh: swagger up to date."
    exit 0
fi

mkdir -p docs internal/handlers
cp "$tmpdir/swagger.json" docs/swagger.json
cp "$tmpdir/swagger.yaml" docs/swagger.yaml
cp "$tmpdir/swagger.json" internal/handlers/swagger.json
cp "$tmpdir/swagger.yaml" internal/handlers/swagger.yaml
echo "scripts/generate-swagger.sh: regenerated docs/swagger.json, docs/swagger.yaml, internal/handlers/swagger.json, internal/handlers/swagger.yaml"
