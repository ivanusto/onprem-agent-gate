#!/bin/sh
# smoke-mcp: the stdio protocol end to end through bin/gate-mcp.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/state"; touch "$tmp/state/CR-2026-0015.state"
cat > "$tmp/config.json" <<JSON
{"principal": "agent:ops", "changes_dir": "$here/tests/fixtures/changes", "state_dir": "$tmp/state",
 "tools": "$here/tests/fixtures/tools.json", "audit": "$tmp/audit.jsonl", "approvals_dir": "$tmp/approvals",
 "stop_file": "$tmp/STOP", "ssh": ["$here/tests/fixtures/fake-ssh"], "logger": "$here/tests/fixtures/fake-logger",
 "targets": {"qdevice/Debian": "gate@qdevice", "pve1/Proxmox VE": "gate@pve1", "collector/Ubuntu": "local"}}
JSON
export GATE_NOW=2026-10-13T12:30:00Z
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pve.quorum_status","arguments":{"cr":"CR-2026-0015"}}}' \
 '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"qdevice.reboot","arguments":{"cr":"CR-2026-0015"}}}' \
 '{"jsonrpc":"2.0","id":5,"method":"ping"}' \
 | python3 "$here/bin/gate-mcp" --config "$tmp/config.json" > "$tmp/out.jsonl"
[ "$(wc -l < "$tmp/out.jsonl")" = 5 ] || { echo "want 5 replies"; cat "$tmp/out.jsonl"; exit 1; }
python3 - "$tmp/out.jsonl" <<'PY'
import json, sys
r = [json.loads(l) for l in open(sys.argv[1])]
assert r[0]["id"] == 1 and r[0]["result"]["serverInfo"]["name"] == "onprem-agent-gate", r[0]
names = [t["name"] for t in r[1]["result"]["tools"]]
assert "qdevice.reboot" in names and "pve.quorum_status" in names, names
c = r[2]["result"]; assert c["structuredContent"]["decision"] == "ALLOW" and "votes=3/3" in c["content"][0]["text"], c
p = r[3]["result"]; assert p["structuredContent"]["decision"] == "PENDING", p
assert r[4]["id"] == 5 and r[4]["result"] == {}, r[4]
print("smoke-mcp: OK")
PY
[ "$(wc -l < "$tmp/audit.jsonl")" = 2 ] || { echo "two decisions must be audited"; exit 1; }
