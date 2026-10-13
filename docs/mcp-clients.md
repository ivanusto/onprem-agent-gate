# Pointing an agent at the gate

The gate speaks MCP over stdio (`bin/gate-mcp`). The agent's identity is an
ssh key whose only permitted command on the collector is `gate-mcp`, so
"which agent is this" is answered by sshd, not by anything the model says.

## On the collector: one key per agent, forced command

```sh
# the agent's key lands here; the forced command is the gate, nothing else
sudo -u agent-gate tee -a /var/lib/onprem-agent-gate/.ssh/authorized_keys <<'EOF'
restrict,command="/opt/onprem-agent-gate/bin/gate-mcp --config /etc/onprem-agent-gate/config.json" ssh-ed25519 AAAA... agent:ops@workstation
EOF
```

`config.json`'s `principal` is the agent's name as the records write it in
`agent:`. Two agents (say a diagnosing one and a patching one) are two
config files with two principals, two forced-command lines, two keys. The
`agent:` field of a record then says which of them may work under it.

## Claude Code (workstation)

```sh
claude mcp add --transport stdio onprem-gate -- ssh -i ~/.ssh/id_agent_ops agent-gate@collector
```

Claude Code starts the command, sshd runs the forced `gate-mcp`, and the
tools from tools.json appear as `mcp__onprem-gate__<tool>` (dots become
underscores: `mcp__onprem-gate__pve_quorum_status`) with the level
and asset in each description. The `cr` argument is required on every
tool; the model learns from the `initialize` instructions that DENY and
PENDING are answers to report, not errors to retry around. A sensible
system prompt for the session names the record:

> You work under change record CR-2026-0015 on this site. Call tools with
> cr=CR-2026-0015 only. Read before you change. If a result is PENDING,
> stop and tell me the request seq; do not call the tool again until I say
> I approved it.

The same stdio line works for Claude Desktop (`claude_desktop_config.json`,
`"command": "ssh", "args": [...]`), for a local model behind any MCP-capable
runtime, and for a shell test with `tests/smoke-mcp.sh`'s JSON lines.

## What the agent does not get

- No key to any target. The gate's key never leaves the collector.
- No tool outside tools.json, no parameter outside the regexes.
- No way to open a window (`change-mark.sh begin` is the operator's, under
  `metrics`), to approve an L3 (`gatectl approve` is sudo for the record's
  implementer or approver), or to lift a stop.
- No way to touch audit.jsonl: it is owned by `agent-gate`, the agent's
  session is the forced command, and the chain plus the uploaded journal
  lines would show an edit anyway (`gatectl verify --vl`).

## Trying it without an agent

`gatectl call` is the same code path as a tools/call:

```sh
sudo -u agent-gate gatectl call CR-2026-0015 qdevice.service_status unit=corosync-qnetd.service
```

For the protocol itself, `tests/smoke-mcp.sh` pipes initialize, tools/list
and two tools/call lines through `gate-mcp` against the fixtures.
