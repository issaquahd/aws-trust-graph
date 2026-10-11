#!/usr/bin/env bash
# Collect IAM roles in AWS CloudShell and draw the trust graph. Read-only: creates nothing in AWS.
# Usage: ./collect.sh                 (list-roles only)
#        WITH_GET_ROLE=1 ./collect.sh (also get-role per role, for RoleLastUsed etc.)
# Raw files in out/ contain real account IDs (gitignored). The .mmd and .md outputs are redacted.
set -u
cd "$(dirname "$0")" || exit 1
OUT="${OUT_DIR:-out}"
mkdir -p "$OUT" || exit 1

echo "== aws iam list-roles (the CLI follows pagination for you)"
aws iam list-roles --output json > "$OUT/list-roles.json" || exit 1
count=$(jq '.Roles | length' "$OUT/list-roles.json")
echo "  $count roles"

args=()
if [ "${WITH_GET_ROLE:-0}" = "1" ]; then
  mkdir -p "$OUT/get-role"
  n=0
  for name in $(jq -r '.Roles[].RoleName' "$OUT/list-roles.json"); do
    aws iam get-role --role-name "$name" --output json > "$OUT/get-role/$name.json" || exit 1
    n=$((n + 1))
    [ $((n % 25)) -eq 0 ] && echo "  get-role: $n/$count"
  done
  args+=(--get-role-dir "$OUT/get-role")
fi

python3 trust_graph.py "$OUT/list-roles.json" ${args[@]+"${args[@]}"} \
  --out "$OUT/trust-graph.mmd" --findings "$OUT/findings.md" ${INCLUDE_SERVICE_LINKED:+--include-service-linked}
echo
echo "Redacted outputs: $OUT/trust-graph.mmd  $OUT/findings.md"
echo "Paste the .mmd into https://mermaid.live or a Markdown file to render it."
echo "Clean up the raw (unredacted) files when done: rm -rf $OUT"
