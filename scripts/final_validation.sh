#!/usr/bin/env bash
# Phase 12 — fresh-environment validation.   Usage: scripts/final_validation.sh <git-url-or-local-path>
set -euo pipefail
SRC="${1:?usage: final_validation.sh <git-url-or-local-path>}"
WORK="$(mktemp -d)"
echo "== workdir: $WORK"
if [ -d "$SRC" ]; then mkdir "$WORK/repo" && cp -r "$SRC"/. "$WORK/repo"/ && rm -rf "$WORK/repo/venv" "$WORK/repo/.venv" "$WORK/repo/agentsentry.db" "$WORK/repo/models"
else git clone --quiet "$SRC" "$WORK/repo"; fi
cd "$WORK/repo"
python3 -m venv .venv && . .venv/bin/activate
pip install -q -r requirements.txt
[ -f requirements-member2.txt ] && pip install -q -r requirements-member2.txt || true
echo "== pytest"; pytest -q
echo "== proxied demo"; python agent/demo_agent.py --proxy >/dev/null && echo "demo OK"
if [ -f benchmark/run_benchmark.py ]; then echo "== benchmark"; python benchmark/run_benchmark.py > /tmp/agentsentry_bench.txt && head -12 /tmp/agentsentry_bench.txt; fi
echo "== VALIDATION PASSED (fresh env: $WORK)"
