# onprem-agent-gate

[繁體中文](README.zh-TW.md)

The one door an AI agent uses to touch a small on-prem site. The agent gets
a list of tools, each a fixed command on one asset; every call must name a
change record ([onprem-changes](https://github.com/ivanusto/onprem-changes),
Day 26), and the gate lets it through only as far as that record, its
window, and a human allow. Every decision is a hash-chained audit record
and a journal line that lands in the same WORM archive as everything else
on the site (Day 21, 27).

```
agent (any MCP client) --ssh, forced command--> gate-mcp on the collector
                                                  |  decide: record, agent:, assets, status,
                                                  |          window, begin mark, level, approval
                                                  |  audit:  audit.jsonl (sha256 chain) + journal line
                                                  v
                                            ssh gate@target -- <fixed argv>
```

| Level | Means | Needs |
|---|---|---|
| L1 | read-only (status, journal, a bounded query) | record `approved`, `scheduled` or `in_progress`; names this agent in `agent:`; lists the asset |
| L2 | reversible change (restart a service) | L1 plus `in_progress`, now inside the window, and the begin mark on file (`change-mark.sh begin` ran, `end` has not) |
| L3 | irreversible (reboot) | L2 plus one human approval, single use, 10 minutes, bound to the exact call (`sudo -u agent-gate gatectl approve <seq>`) |

A `STOP` file denies everything (`gatectl stop` / `resume`). Unknown tool,
parameter outside its regex, record without the agent or the asset: DENY,
with the reason in the audit and in the reply the model reads.

## Layout

| Path | What |
|---|---|
| `gate/core.py` | the decision, the execution (local or `ssh target -- argv`), the chain, approvals |
| `gate/mcp_server.py`, `bin/gate-mcp` | MCP over stdio: `initialize`, `tools/list`, `tools/call`, `ping` |
| `bin/gatectl` | the operator's side: `call`, `tools`, `pending`, `approve`, `stop`, `resume`, `verify [--vl]`, `tail`, `textfile` |
| `gate/textfile.py` | `agent-gate.prom` for node_exporter |
| `tools.json` | the tools of this site: id, level, asset, argv with `{param}` placeholders, one regex per param |
| `config.json.example` | principal, paths (records clone, change-mark state dir, audit, approvals, STOP), ssh command, asset to target map |
| `prometheus/agent.yml`, `tests/rules_agent_test.yml` | five rules, a copy; the one Prometheus loads is in onprem-metrics |
| `collector.cron` | the textfile every 5 minutes |
| `docs/targets.md` | the `gate` user on each target: `restrict,from=` key line, sudoers for exactly the argv |
| `docs/mcp-clients.md` | one key per agent with a forced command; Claude Code and other clients |
| `docs/iso27001.md` | which Annex A control each piece speaks to, and what it does not |
| `tests/` | `unittest` (policy, approvals, chain, textfile, MCP), `smoke-gatectl.sh`, `smoke-mcp.sh`, `promtool test rules` |

## Run

```sh
# collector, once: user, dirs, key, config, clone access (docs/targets.md)
sudo install -m 0644 tools.json /etc/onprem-agent-gate/tools.json
sudo install -m 0644 config.json.example /etc/onprem-agent-gate/config.json && sudoedit /etc/onprem-agent-gate/config.json

# a record that names the agent, with a window; the operator opens it
sudo -u metrics /opt/onprem-changes/scripts/change-mark.sh begin CR-2026-0015

# what the agent sees, from a shell
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.service_status unit=corosync-qnetd.service   # L1: ALLOW
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.restart_service unit=corosync-qnetd.service  # L2: ALLOW inside the window
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.reboot                                       # L3: PENDING, request 7
sudo -u agent-gate gatectl approve 7                                                              # as the record's implementer or approver
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.reboot --approval 7                          # ALLOW, single use

# the agent itself: Claude Code on the workstation, one ssh key with a forced command on the collector
claude mcp add --transport stdio onprem-gate -- ssh -i ~/.ssh/id_agent_ops agent-gate@collector

# evidence
sudo -u agent-gate gatectl tail 20
sudo -u agent-gate gatectl verify --vl http://127.0.0.1:9428      # chain, and every record's hash prefix in VictoriaLogs
sudo -u metrics /opt/onprem-logs/audit/audit-report.py --since <window start>   # the gate's lines attributed to the record
```

## Audit record

```json
{"seq":12,"ts":"2026-10-13T12:31:07Z","prev":"<hash of seq 11>","principal":"agent:ops","operator":"ivan",
 "cr":"CR-2026-0015","tool":"qdevice.restart_service","level":"L2","params":{"unit":"corosync-qnetd.service"},
 "decision":"ALLOW","reason":"L2 inside an open window with the begin mark",
 "action_hash":"<sha256 of principal+cr+tool+params>","approval":null,
 "exec":{"rc":0,"duration_s":1.42,"stdout_sha256":"...","stdout_bytes":0,"timed_out":false},
 "hash":"<sha256 of prev + canonical record>"}
```

Journal line, same moment, tag `agent-gate`:

```
seq=12 principal=agent:ops operator=ivan cr=CR-2026-0015 tool=qdevice.restart_service level=L2 decision=ALLOW rc=0 hash=3f9c2a71b0e4d5c6
```

The file is one host's file. The journal line is uploaded within seconds
and archived to WORM the next morning; `gatectl verify --vl` checks every
record against its line. Editing the file breaks the chain; replacing the
file leaves lines in WORM with no record behind them.

## Not in scope

Which model, which runtime, which prompt. The gate sees a tool call with a
`cr`; it does not care who composed it. A human running `gatectl call` is
treated the same way, which is also how the tests work. See
[docs/iso27001.md](docs/iso27001.md) for the boundaries.

## Lineage

The ticket-as-authorization, action levels, single-use approval and
hash-chained audit come from TrustedOps, a hackathon design (August 2026,
Governed Agent Trust Layer). That design separated the control plane from
the enforcement host and used a web dashboard for approvals; this repo
collapses both onto the collector, makes the ticket a git-tracked change
record, and replaces the dashboard with sudo, because that is what this
site already has an audit trail for.

## License

Apache-2.0
