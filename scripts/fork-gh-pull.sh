#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MAP_PATH="$ROOT_DIR/config/fork/fork-map.json"
UPSTREAM_DEFAULT="openclaw"
BASE_BRANCH_DEFAULT="main"

if [[ ! -f "$MAP_PATH" ]]; then
  echo "Missing fork map: $MAP_PATH" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for scripts/fork-gh-pull.sh" >&2
  exit 1
fi

UPSTREAM_REMOTE="${1:-$UPSTREAM_DEFAULT}"
BASE_BRANCH="${2:-$BASE_BRANCH_DEFAULT}"

cd "$ROOT_DIR"

if ! git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
  echo "Remote '$UPSTREAM_REMOTE' not found. Add it first, for example:" >&2
  echo "  git remote add $UPSTREAM_REMOTE https://github.com/openclaw/openclaw.git" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is dirty. Commit or stash before running fork-gh-pull." >&2
  exit 1
fi

echo "==> Fetching upstream: $UPSTREAM_REMOTE/$BASE_BRANCH"
git fetch "$UPSTREAM_REMOTE" "$BASE_BRANCH"

echo "==> Divergence (local...upstream):"
git rev-list --left-right --count "HEAD...$UPSTREAM_REMOTE/$BASE_BRANCH"

echo "==> Changed files upstream since merge-base"
MERGE_BASE="$(git merge-base HEAD "$UPSTREAM_REMOTE/$BASE_BRANCH")"
git diff --name-only "$MERGE_BASE" "$UPSTREAM_REMOTE/$BASE_BRANCH" > /tmp/fork-upstream-files.txt
cat /tmp/fork-upstream-files.txt

echo
echo "==> Classifying files using fork-map sync rules"
python - <<'PY'
import json
from pathlib import Path

root = Path(".")
map_path = root / "config/fork/fork-map.json"
files_path = Path("/tmp/fork-upstream-files.txt")

rules = json.loads(map_path.read_text())["syncClassificationRules"]
files = [line.strip() for line in files_path.read_text().splitlines() if line.strip()]

def classify(path: str):
    for r in rules:
        if "matchExact" in r and path in r["matchExact"]:
            return r
        if "matchPrefixes" in r and any(path.startswith(pref) for pref in r["matchPrefixes"]):
            return r
    for r in rules:
        if r.get("name") == "default":
            return r
    return {"name":"default","action":"review","reason":"No rule"}

buckets = {}
for p in files:
    rule = classify(p)
    key = f'{rule["action"]} | {rule.get("name","rule")}'
    buckets.setdefault(key, {"reason": rule.get("reason",""), "files":[]})["files"].append(p)

for key, payload in buckets.items():
    print(f"\n[{key}]")
    print(f"reason: {payload['reason']}")
    for f in payload["files"]:
        print(f"  - {f}")
PY

echo
echo "==> Guardrail: no automatic merge/rebase performed."
echo "Use the classified output above to cherry-pick or manually replay upstream changes."
echo
echo "Suggested follow-up:"
echo "  1) Create a work branch for sync"
echo "  2) Cherry-pick selected upstream commits"
echo "  3) Re-run: pnpm tsgo && pnpm check"
