#!/usr/bin/env bash
#MISE description="Validate Kubernetes manifests against relevant JSON schemas."
set -eo pipefail

# ==========================================
# Stage Git changes
# ==========================================
git add .
gum log --level info "[✅] Git changes staged."

# ==========================================
# Run Pre-Commit Hooks
# ==========================================
if gum spin --spinner meter --title " [🐙] Running Prek hooks..." -- prek run --all-files; then
    gum log --level info "[✅] Prek hooks passed successfully."
    exit 0
fi

# ==========================================
# Retry Pre-Commit Hooks
# ==========================================
gum log --level warn "[❌] Prek found issues, attempting auto-fix. Re-running..."

if output=$(gum spin --spinner pulse --title " [🐙] Retrying Prek hooks..." -- prek run --all-files 2>&1); then
    gum log --level info "[✅] Prek hooks passed successfully after retry."
    git add .
    gum log --level info "[✅] Git changes staged."
else
    gum log --level error "[❌] Prek hooks failed twice; fix the remaining issues manually:"
    echo "$output"
    exit 1
fi
