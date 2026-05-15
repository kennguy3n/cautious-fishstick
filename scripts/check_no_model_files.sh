#!/usr/bin/env bash
# check_no_model_files.sh — Enforce the "no on-device inference" rule
# from docs/sdk.md ("no on-device inference" rule). Mobile / desktop
# criterion.
#
# The Mobile SDKs and Desktop Extension are thin REST clients. They must
# not bundle, load, or run any AI model locally. This script fails CI if
# any of the following extensions appears anywhere under `sdk/`:
#
#   .mlmodel   — Apple CoreML model
#   .tflite    — TensorFlow Lite model
#   .onnx      — ONNX Runtime model
#   .gguf      — llama.cpp quantized weights
#
# Usage:
#   ./scripts/check_no_model_files.sh            # scan defaults (sdk/)
#   ./scripts/check_no_model_files.sh dir1 dir2  # scan custom paths
#
# Exit codes:
#   0  no model files found
#   1  one or more model files found
#
# Driven from go test via scripts/check_no_model_files_test.go.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Default scan target: anything under sdk/.
targets=("sdk")
if [[ $# -gt 0 ]]; then
    targets=("$@")
fi

forbidden_extensions=(
    "mlmodel"
    "tflite"
    "onnx"
    "gguf"
)

violations=0
report=()

for target in "${targets[@]}"; do
    if [[ ! -e "$target" ]]; then
        # Missing target is not an error — the SDKs may not have landed
        # yet on this branch.
        continue
    fi
    for ext in "${forbidden_extensions[@]}"; do
        while IFS= read -r -d '' path; do
            report+=("$path: forbidden on-device model file (.$ext)")
            violations=$((violations + 1))
        done < <(find "$target" -type f -name "*.${ext}" -print0)
    done
done

if [[ $violations -gt 0 ]]; then
    echo "scripts/check_no_model_files.sh: found $violations on-device model file(s) under sdk/:" >&2
    for entry in "${report[@]}"; do
        echo "  $entry" >&2
    done
    echo "" >&2
    echo "The SDKs are REST clients only. See docs/sdk.md for the" >&2
    echo "contract. If on-device inference becomes a real requirement," >&2
    echo "update docs/sdk.md and docs/architecture.md first, and" >&2
    echo "this script together." >&2
    exit 1
fi

echo "scripts/check_no_model_files.sh: no on-device model files found under sdk/."
exit 0
