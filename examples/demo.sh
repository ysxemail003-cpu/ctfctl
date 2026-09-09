#!/usr/bin/env bash
# ctf-agent end-to-end demo (no model API required)
#
#   environment check -> init a synthetic crypto challenge -> hashid + john crack
#   -> evidence record -> trajectory export -> benchmark subset
#
# Usage: examples/demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CTFCTL="$ROOT/tools/ctfctl"
PY="${PYTHON:-python3}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ctf-agent-demo.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

echo "== 1. environment =="
"$CTFCTL" doctor | sed -n '1,16p'

echo
echo "== 2. init a synthetic crypto challenge =="
WS="$TMP/workspace"
"$CTFCTL" init \
  --workspace "$WS" --event demo --challenge crypto-demo \
  --category crypto --mode AI_NATIVE \
  --confirm-authorization --no-current >/dev/null
CH="$WS/contests/demo/crypto-demo"
mkdir -p "$CH/original" "$CH/work"
cp "$ROOT/bench/challenges/crypto/hash-crack/original/hash.txt" "$CH/original/"
printf 'letmein\n123456\nsunshine\nqwerty\n' > "$CH/work/words.txt"
HASH="$(cat "$CH/original/hash.txt")"
echo "challenge dir: $CH"

echo
echo "== 3. identify the hash =="
"$CTFCTL" -C "$CH" tool hashid "$HASH" \
  | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print("suggested:", (d.get("suggested") or {}).get("name"))'

if command -v john >/dev/null 2>&1; then
  echo
  echo "== 4. crack with john (bundled wordlist) =="
  "$CTFCTL" -C "$CH" tool crack "$HASH" --wordlist "$CH/work/words.txt" --tool john \
    | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print("crack status:", d["status"], "plaintexts:", d.get("plaintexts"))'
else
  echo
  echo "== 4. skip cracking: john is not installed =="
fi

echo
echo "== 5. record evidence through the runtime =="
LOG_ID="$("$CTFCTL" -C "$CH" run --tag evidence-probe -- printf 'demo probe ok' \
  | "$PY" -c 'import json,sys; lines=[l for l in sys.stdin if l.strip().startswith("{")]; print(json.loads(lines[-1])["id"])')"
"$CTFCTL" -C "$CH" evidence add --source "$LOG_ID" \
  --observation "demo probe executed" --meaning "demo evidence lifecycle"

echo
echo "== 6. export the trajectory =="
"$CTFCTL" -C "$CH" trajectory export \
  | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print("verdict:", d["verdict"], "| actions:", d["summary"]["action_count"], "| outputs:", d["outputs"])'

echo
echo "== 7. benchmark subset (script driver) =="
if command -v john >/dev/null 2>&1; then
  "$CTFCTL" bench --only hash-crack --out "$TMP/bench-results"
else
  echo "john not installed; bench hash-crack requires it. Try: make bench"
fi

echo
echo "Demo finished. Workspace artifacts were kept only inside a temp dir."
echo "See README.md and docs/SOLVER_ARCHITECTURE.md for the full story."
