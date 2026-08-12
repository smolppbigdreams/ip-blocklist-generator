#!/usr/bin/env bash
#MISE description="Install project dependencies."
set -eo pipefail

FLUX_SCHEMA_VERSION="0.11.0"

gum spin --spinner minidot --title " [📦] Installing Mise..." \
    -- mise install
gum log --level info "[✅] Mise is now installed."

gum spin --spinner pulse --title " [📦] Installing Prek..." \
    -- prek install
gum log --level info "[✅] Prek is now installed."
