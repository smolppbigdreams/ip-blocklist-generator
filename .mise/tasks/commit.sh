#!/usr/bin/env bash
#MISE description="Git commit with interactive review and optional push."

set -eo pipefail

if [ -z "$OPENROUTER_API_KEY" ]; then
    gum log --level error "[❌] No OpenRouter API key found. Exiting."
    exit 0
fi

mise validate

DIFF=$(git diff --cached)
if [ -z "$DIFF" ]; then
    gum log --level error "[🙈] No staged changes found. Exiting."
    exit 0
fi

SCHEMA='{
  "type": "object",
  "properties": {
    "type": {
      "type": "string",
      "enum": ["feat", "fix", "docs", "style", "refactor", "perf", "test", "chore", "ci", "build"]
    },
    "subject": {
      "type": "string",
      "description": "Ultra-concise description of the change in imperative mood WITHOUT the commit type prefix. Maximum 5 to 8 words."
    }
  },
  "required": ["type", "subject"],
  "additionalProperties": false
}'
PAYLOAD=$(jq -n \
  --arg model "deepseek/deepseek-v4-flash:nitro" \
  --arg content "Analyze the following git diff and generate a short, punchy conventional commit: $DIFF" \
  --argjson schema "$SCHEMA" \
  '{
    model: $model,
    messages: [
      {
        role: "system",
        content: "You are an automated Git commit convention generator. Be extremely concise. Keep the subject line short, direct, and under 50 characters if possible."
      },
      {
        role: "user",
        content: $content
      }
    ],
    reasoning: {
        effort: "medium"
    },
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "conventional_commit",
        strict: true,
        schema: $schema
      }
    }
  }'
)

RESPONSE=$(gum spin --spinner points --title " [📝] Generating commit message..." -- \
    curl -s https://openrouter.ai/api/v1/chat/completions \
        -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD"
)
gum log --level info "[✅] Generated commit message."

PARSED_JSON=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty')
if [ -z "$PARSED_JSON" ]; then
    gum log --level error "[❌] Failed to parse model response. Raw output:"
    echo "$RESPONSE"
    exit 1
fi

COMMIT_TYPE=$(echo "$PARSED_JSON" | jq -r '.type')
COMMIT_SUBJECT=$(echo "$PARSED_JSON" | jq -r '.subject')
COMMIT_SUBJECT=$(echo "$COMMIT_SUBJECT" | sed -E "s/^${COMMIT_TYPE}(\([^)]+\))?:\s*//i")

COMMIT_MSG=$(echo "${COMMIT_TYPE}: ${COMMIT_SUBJECT}" | tr '[:upper:]' '[:lower:]')
BOXED_MSG=$(gum style \
    --border normal \
    --border-foreground 217 \
    --padding "0 2" \
    --margin "0 0" \
    "$COMMIT_MSG")

if gum confirm "$BOXED_MSG"$'\n'"Commit with this message?"; then
    git commit --no-verify -m "$COMMIT_MSG" > /dev/null
    gum log --level info "[✅] Git commit approved."

    if gum confirm "Do you want to push to remote?"; then
        TMP_LOG=$(mktemp)
        if gum spin --spinner pulse --title "Pushing to Git..." -- bash -c "git push > '$TMP_LOG' 2>&1"; then
            gum log --level info "[✅] Git push successful."
            rm -f "$TMP_LOG"
        else
            gum log --level error "[❌] Git push failed:"
            cat "$TMP_LOG"
            rm -f "$TMP_LOG"
            exit 1
        fi
    else
        gum log --level info "[❌] Git push skipped."
    fi
else
    gum log --level error "[❌] Commit aborted. Changes are still staged."
    exit 0
fi
