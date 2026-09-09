#!/usr/bin/env bash
# Scan the full git history for high-signal secret patterns.
# Usage: tools/scan_secrets.sh [--json]
set -euo pipefail
cd "$(dirname "$0")/.."

PATTERNS=(
  'BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY'
  'AKIA[0-9A-Z]{16}'
  'sk-ant-[A-Za-z0-9]{10,}'
  'sk-proj-[A-Za-z0-9]{10,}'
  'ghp_[A-Za-z0-9]{20,}'
  'CTFD_TOKEN[=:][[:space:]]*[A-Za-z0-9._-]{8,}'
  'Authorization:[[:space:]]*(Bearer|Basic)[[:space:]]+[A-Za-z0-9._=+/]{12,}'
  'api[_-]?key["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9._-]{16,}'
)

GREP_ARGS=(-nEi)
if [[ "${1:-}" == "--json" ]]; then
  GREP_ARGS=(-niE)
fi

HITS=$(git log --all -p 2>/dev/null | grep "${GREP_ARGS[@]}" \
  -e "$(IFS='|'; echo "${PATTERNS[*]}")" || true)

if [[ -n "$HITS" ]]; then
  echo "Potential secrets found in git history:" >&2
  echo "$HITS" | head -50 >&2
  exit 1
fi
echo "scan-secrets: no high-signal patterns found in git history."
