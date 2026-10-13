# The gate's foothold on each target

The gate runs on the collector as its own user, `agent-gate`. It reaches a
target over ssh as a dedicated user `gate` whose key is restricted to come
from the collector and to do nothing interactive, and whose sudo covers
exactly the argv in tools.json. The agent never sees this key: it talks to
the gate (docs/mcp-clients.md), the gate talks to the target. Three layers,
each one narrow:

| Layer | Where | What it limits |
|---|---|---|
| tools.json | gate | which argv exist at all, with which parameters (regex) |
| authorized_keys | target | which host the gate's key may come from, no pty, no forwarding |
| sudoers | target | which of those argv may run as root, nothing else |

## Collector

```sh
sudo useradd --system --home /var/lib/onprem-agent-gate --shell /bin/sh agent-gate   # sshd runs the forced command through the login shell; nologin would refuse it
sudo install -d -o agent-gate -g agent-gate -m 0750 /var/lib/onprem-agent-gate /var/lib/onprem-agent-gate/approvals /var/lib/onprem-agent-gate/.ssh
sudo install -d -m 0755 /etc/onprem-agent-gate
sudo install -m 0644 tools.json /etc/onprem-agent-gate/tools.json
sudo install -m 0644 config.json.example /etc/onprem-agent-gate/config.json   # then edit targets
sudo -u agent-gate ssh-keygen -t ed25519 -N '' -f /var/lib/onprem-agent-gate/.ssh/id_gate -C agent-gate@collector
sudo -u agent-gate ssh-keyscan pve1 qdevice | sudo -u agent-gate tee /var/lib/onprem-agent-gate/.ssh/known_hosts   # StrictHostKeyChecking=yes
sudo install -d -o root -g root -m 0755 /opt/onprem-agent-gate && sudo cp -r bin gate /opt/onprem-agent-gate/
sudo ln -s /opt/onprem-agent-gate/bin/gatectl /usr/local/bin/gatectl
```

The gate reads the collector's clone of onprem-changes (`/opt/onprem-changes`,
owned by `metrics`, pulled every 15 minutes since Day 26) and change-mark's
state directory (`/var/lib/onprem-changes`). Both need read access for
`agent-gate`:

```sh
sudo setfacl -m u:agent-gate:rx /var/lib/onprem-changes       # the begin marks
sudo setfacl -R -m u:agent-gate:rX /opt/onprem-changes        # the records
```

`gatectl approve`, `stop` and `resume` are run by a human with sudo so
that the approver's name is `$SUDO_USER` and the approval itself is a sudo
line in the journal (Day 27's audit report lists it next to the gate's own
line):

```
# /etc/sudoers.d/agent-gate
ivan ALL=(agent-gate) NOPASSWD: /opt/onprem-agent-gate/bin/gatectl approve *, /opt/onprem-agent-gate/bin/gatectl stop, /opt/onprem-agent-gate/bin/gatectl resume
```

Run as `sudo -u agent-gate gatectl approve 12`. `who()` in gatectl takes
`SUDO_USER` first, so the approval record says `ivan`, and the gate checks
that name against the record's `implementer` and `approver`.

Cron, every 5 minutes, the textfile (see collector.cron):

```
*/5 * * * * agent-gate /opt/onprem-agent-gate/bin/gatectl textfile --out /var/lib/node_exporter/textfile/agent-gate.prom
```

`/var/lib/node_exporter/textfile` must be writable by `agent-gate` (a group,
or an ACL as above).

## pve1

```sh
useradd --system --home /var/lib/gate --create-home --shell /bin/sh gate
install -d -m 0700 -o gate -g gate /var/lib/gate/.ssh
cat > /var/lib/gate/.ssh/authorized_keys <<'EOF'
restrict,from="192.168.2.49" ssh-ed25519 AAAA... agent-gate@collector
EOF
chown gate:gate /var/lib/gate/.ssh/authorized_keys; chmod 0600 /var/lib/gate/.ssh/authorized_keys
```

`restrict` (OpenSSH 7.2 and later) turns off port forwarding, agent
forwarding, X11, pty allocation and user rc. The two L1 tools on pve1
(`check.sh`, `pvecm status`) run as root today; give `gate` exactly those:

```
# /etc/sudoers.d/gate
gate ALL=(root) NOPASSWD: /root/pve-qdevice-on-qnap/check.sh, /usr/bin/pvecm status
```

The repo's tools.json runs both with `sudo -n`, matching these two lines.

## QDevice VM

Same user and key line. The L1 tools (`systemctl status`, `journalctl -u`)
work without root when `gate` is in the `systemd-journal` group. The L2
restart and the L3 reboot are the only sudo entries:

```
# /etc/sudoers.d/gate
gate ALL=(root) NOPASSWD: /usr/bin/systemctl restart corosync-qnetd.service, /usr/bin/systemctl restart systemd-journal-upload.service, /usr/bin/systemctl reboot
```

`sudo -n` in the argv makes a missing entry fail immediately (rc 1, "a
password is required") instead of hanging, and that refusal is a sudo line
in the VM's journal. Note the VM's own journal is not uploaded (Day 27,
section six); the gate's record of the call is on the collector, the VM's
sudo line is not. Day 29's record lists this as a known gap.

## FortiGate

Not a target today. The read-only REST account from Day 27 could be a
`local` tool with curl and a token file readable only by `agent-gate`; the
write side (Day 24's policy changes, Day 27's syslogd3) would be L2 tools.
Both are left out of tools.json until a record needs them: every tool in
the file is reachable by the agent the moment a record names the asset.

## What a target sees

A gate call on the QDevice VM leaves, in the VM's journal: the `sshd`
Accepted line for `gate` from the collector (with the key fingerprint), the
`sudo` line (`gate : ... USER=root ; COMMAND=/usr/bin/systemctl restart
corosync-qnetd.service`), and the service's own restart lines. On the
collector: the `agent-gate` journal line with seq, cr, tool, level,
decision, rc and the first 16 hex of the chained hash. Day 27's
`audit-report.py` reads the latter as its seventh source (onprem-logs
v0.5.4) and attributes it to the window of the `cr=` it names.
