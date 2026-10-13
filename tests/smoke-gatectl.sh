#!/bin/sh
# smoke-gatectl: the operator's commands end to end on the fixtures, with a
# fake ssh, a fake logger (this journal is uploaded on a real site) and a
# frozen clock inside CR-2026-0015's window.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/state"
cat > "$tmp/config.json" <<JSON
{"principal": "agent:ops", "changes_dir": "$here/tests/fixtures/changes", "state_dir": "$tmp/state",
 "tools": "$here/tests/fixtures/tools.json", "audit": "$tmp/audit.jsonl", "approvals_dir": "$tmp/approvals",
 "stop_file": "$tmp/STOP", "ssh": ["$here/tests/fixtures/fake-ssh"], "logger": "$here/tests/fixtures/fake-logger",
 "targets": {"qdevice/Debian": "gate@qdevice", "pve1/Proxmox VE": "gate@pve1", "collector/Ubuntu": "local"}}
JSON
export GATE_CONFIG="$tmp/config.json" GATE_NOW=2026-10-13T12:30:00Z LOGGER_LOG="$tmp/logger.log" FAKE_SSH_LOG="$tmp/ssh.log"
g="$here/bin/gatectl"

"$g" tools | grep -q '^qdevice.reboot .*L3 ' || { echo "tools listing"; exit 1; }

# L1 allowed; L2 denied without the begin mark; then allowed with it
"$g" call CR-2026-0015 pve.quorum_status > "$tmp/1.json"
grep -q '"decision": "ALLOW"' "$tmp/1.json" || { cat "$tmp/1.json"; exit 1; }
if "$g" call CR-2026-0015 qdevice.restart_service unit=corosync-qnetd.service > "$tmp/2.json"; then echo "L2 without begin mark must fail"; exit 1; fi
grep -q 'begin mark' "$tmp/2.json" || { cat "$tmp/2.json"; exit 1; }
touch "$tmp/state/CR-2026-0015.state"
"$g" call CR-2026-0015 qdevice.restart_service unit=corosync-qnetd.service > "$tmp/3.json"
grep -q 'restarted corosync-qnetd.service' "$tmp/3.json" || { cat "$tmp/3.json"; exit 1; }

# L3: pending, approve as ivan (SUDO_USER), call again with the seq, single use
rc=0; "$g" call CR-2026-0015 qdevice.reboot > "$tmp/4.json" || rc=$?
[ "$rc" = 1 ] || { echo "PENDING must exit 1"; exit 1; }
seq=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["request"])' "$tmp/4.json")
"$g" pending | grep -q "seq=$seq .*qdevice.reboot" || { "$g" pending; exit 1; }
if SUDO_USER=mallory "$g" approve "$seq" 2>"$tmp/err"; then echo "mallory must not approve"; exit 1; fi
grep -q 'is not the implementer or approver' "$tmp/err" || { cat "$tmp/err"; exit 1; }
SUDO_USER=ivan "$g" approve "$seq" | grep -q "approved request $seq .*by ivan" || exit 1
"$g" pending | grep -q 'no pending requests' || exit 1
"$g" call CR-2026-0015 qdevice.reboot --approval "$seq" > "$tmp/5.json"
grep -q '"decision": "ALLOW"' "$tmp/5.json" || { cat "$tmp/5.json"; exit 1; }
grep -q 'approved by ivan' "$tmp/5.json" || { cat "$tmp/5.json"; exit 1; }
rc=0; "$g" call CR-2026-0015 qdevice.reboot --approval "$seq" > "$tmp/6.json" || rc=$?
grep -q '"decision": "PENDING"' "$tmp/6.json" || { echo "approval must be single use"; cat "$tmp/6.json"; exit 1; }

# stop / resume
SUDO_USER=ivan "$g" stop | grep -q 'STOP engaged' || exit 1
rc=0; "$g" call CR-2026-0015 pve.quorum_status > "$tmp/7.json" || rc=$?
grep -q 'stopped' "$tmp/7.json" || { cat "$tmp/7.json"; exit 1; }
SUDO_USER=ivan "$g" resume | grep -q '^resumed' || exit 1
"$g" call CR-2026-0015 pve.quorum_status | grep -q '"decision": "ALLOW"' || exit 1

# chain, tail, textfile, journal
"$g" verify | grep -q '^chain: ok (' || { "$g" verify; exit 1; }
"$g" tail 3 | grep -c 'seq=' | grep -qx 3 || exit 1
"$g" textfile > "$tmp/gate.prom"
grep -q '^agent_gate_decisions_total{tool="qdevice.reboot",level="L3",decision="PENDING"} 2$' "$tmp/gate.prom" || { cat "$tmp/gate.prom"; exit 1; }
grep -q '^agent_gate_stopped 0$' "$tmp/gate.prom" || exit 1
grep -q '^agent_gate_chain_ok 1$' "$tmp/gate.prom" || exit 1
grep -q 'decision=STOP' "$tmp/logger.log" || { cat "$tmp/logger.log"; exit 1; }
grep -q 'decision=APPROVED' "$tmp/logger.log" || { cat "$tmp/logger.log"; exit 1; }
n_audit=$(wc -l < "$tmp/audit.jsonl"); n_journal=$(grep -c 'agent-gate -p notice seq=' "$tmp/logger.log")
[ "$n_audit" = "$n_journal" ] || { echo "audit $n_audit lines, journal $n_journal"; exit 1; }
# tamper: verify fails
sed -i '2s/"decision":"DENY"/"decision":"ALLOW"/' "$tmp/audit.jsonl"
if "$g" verify > "$tmp/v.out"; then echo "tampered chain must fail"; cat "$tmp/v.out"; exit 1; fi
grep -q 'BROKEN' "$tmp/v.out" || { cat "$tmp/v.out"; exit 1; }
echo "smoke-gatectl: OK ($n_audit records)"
