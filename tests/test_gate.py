import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "gate"))
import core  # noqa: E402
import mcp_server  # noqa: E402
import textfile  # noqa: E402

IN_WINDOW = "2026-10-13T12:30:00Z"      # 20:30 +08:00, inside CR-2026-0015's window
BEFORE_WINDOW = "2026-10-13T11:00:00Z"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state = os.path.join(self.tmp, "state")
        os.makedirs(self.state)
        self.logger_log = os.path.join(self.tmp, "logger.log")
        os.environ["LOGGER_LOG"] = self.logger_log
        os.environ["FAKE_SSH_LOG"] = os.path.join(self.tmp, "ssh.log")
        os.environ["GATE_NOW"] = IN_WINDOW
        self.cfg = dict(core.DEFAULTS)
        self.cfg.update({
            "principal": "agent:ops",
            "changes_dir": str(FIX / "changes"),
            "state_dir": self.state,
            "tools": str(FIX / "tools.json"),
            "audit": os.path.join(self.tmp, "audit.jsonl"),
            "approvals_dir": os.path.join(self.tmp, "approvals"),
            "stop_file": os.path.join(self.tmp, "STOP"),
            "ssh": [str(FIX / "fake-ssh"), "-o", "BatchMode=yes"],
            "targets": {"qdevice/Debian": "gate@qdevice", "pve1/Proxmox VE": "gate@pve1", "collector/Ubuntu": "local"},
            "logger": str(FIX / "fake-logger"),
            "approval_ttl_s": 600,
        })
        self.gate = core.Gate(self.cfg)

    def tearDown(self):
        shutil.rmtree(self.tmp)
        os.environ.pop("GATE_NOW", None)

    def begin(self, cr="CR-2026-0015"):
        with open(os.path.join(self.state, f"{cr}.state"), "w") as f:
            f.write("annotation=1\n")

    def journal(self):
        try:
            return Path(self.logger_log).read_text()
        except OSError:
            return ""


class Policy(Base):
    def test_l1_on_in_progress_record(self):
        r = self.gate.call("CR-2026-0015", "pve.quorum_status", {})
        self.assertEqual(r["decision"], "ALLOW", r)
        self.assertEqual(r["rc"], 0)
        self.assertIn("votes=3/3", r["stdout"])
        self.assertIn("target gate@pve1", Path(os.environ["FAKE_SSH_LOG"]).read_text())
        self.assertIn("seq=1 principal=agent:ops operator=ivan cr=CR-2026-0015 tool=pve.quorum_status level=L1 decision=ALLOW rc=0 hash=", self.journal())

    def test_l1_params_are_checked(self):
        ok = self.gate.call("CR-2026-0015", "qdevice.service_status", {"unit": "nftables.service"})
        self.assertEqual(ok["decision"], "ALLOW")
        self.assertEqual(ok["stdout"].strip(), "status nftables.service")
        bad = self.gate.call("CR-2026-0015", "qdevice.service_status", {"unit": "nftables.service; rm -rf /"})
        self.assertEqual(bad["decision"], "DENY")
        self.assertIn("does not match", bad["reason"])
        extra = self.gate.call("CR-2026-0015", "qdevice.service_status", {"unit": "nftables.service", "x": "1"})
        self.assertEqual(extra["decision"], "DENY")
        missing = self.gate.call("CR-2026-0015", "pve.quorum_status", {"unit": "nftables.service"})
        self.assertEqual(missing["decision"], "DENY")

    def test_deny_reasons(self):
        self.assertIn("unknown tool", self.gate.call("CR-2026-0015", "nope", {})["reason"])
        self.assertIn("CR-YYYY-NNNN", self.gate.call("cr-15", "pve.quorum_status", {})["reason"])
        self.assertIn("no such change record", self.gate.call("CR-2026-9999", "pve.quorum_status", {})["reason"])
        self.assertIn("does not name agent:ops", self.gate.call("CR-2026-0016", "qdevice.service_status", {"unit": "nftables.service"})["reason"])
        self.assertIn("does not list asset", self.gate.call("CR-2026-0017", "pve.quorum_status", {})["reason"])
        self.assertIn("is done", self.gate.call("CR-2026-0017", "qdevice.service_status", {"unit": "nftables.service"})["reason"])

    def test_l2_needs_in_progress_window_and_begin_mark(self):
        r = self.gate.call("CR-2026-0015", "qdevice.restart_service", {"unit": "corosync-qnetd.service"})
        self.assertEqual(r["decision"], "DENY")
        self.assertIn("begin mark", r["reason"])
        self.begin()
        os.environ["GATE_NOW"] = BEFORE_WINDOW
        r = self.gate.call("CR-2026-0015", "qdevice.restart_service", {"unit": "corosync-qnetd.service"})
        self.assertEqual(r["decision"], "DENY")
        self.assertIn("inside the window", r["reason"])
        os.environ["GATE_NOW"] = IN_WINDOW
        r = self.gate.call("CR-2026-0015", "qdevice.restart_service", {"unit": "corosync-qnetd.service"})
        self.assertEqual(r["decision"], "ALLOW", r)
        self.assertEqual(r["stdout"].strip(), "restarted corosync-qnetd.service")
        # end mark removes the state file: the next L2 is denied
        os.remove(os.path.join(self.state, "CR-2026-0015.state"))
        r = self.gate.call("CR-2026-0015", "qdevice.restart_service", {"unit": "corosync-qnetd.service"})
        self.assertEqual(r["decision"], "DENY")

    def test_stop_file_denies_everything(self):
        open(self.cfg["stop_file"], "w").close()
        r = self.gate.call("CR-2026-0015", "pve.quorum_status", {})
        self.assertEqual(r["decision"], "DENY")
        self.assertIn("stopped", r["reason"])

    def test_execution_details(self):
        r = self.gate.call("CR-2026-0015", "local.fail", {})
        self.assertEqual((r["decision"], r["rc"]), ("ALLOW", 3))
        self.assertIn("bad", r["stderr"])
        r = self.gate.call("CR-2026-0015", "local.slow", {})
        self.assertTrue(r["timed_out"])
        self.assertEqual(r["rc"], 124)
        r = self.gate.call("CR-2026-0015", "local.big", {})
        self.assertTrue(r["truncated"])
        self.assertEqual(len(r["stdout"]), 65536)
        rec = self.gate.records()[-1]
        self.assertEqual(rec["exec"]["stdout_bytes"], 100000)
        self.assertEqual(len(rec["exec"]["stdout_sha256"]), 64)


class Approvals(Base):
    def setUp(self):
        super().setUp()
        self.begin()

    def test_l3_pending_then_approved_single_use(self):
        r = self.gate.call("CR-2026-0015", "qdevice.reboot", {})
        self.assertEqual(r["decision"], "PENDING")
        self.assertEqual(r["approve_with"], f"sudo -u agent-gate gatectl approve {r['seq']}")
        self.assertEqual([p["seq"] for p in self.gate.pending()], [r["seq"]])
        # the agent cannot approve, a stranger cannot approve
        with self.assertRaises(core.GateError):
            self.gate.approve(r["seq"], "agent:ops")
        with self.assertRaises(core.GateError):
            self.gate.approve(r["seq"], "mallory")
        ap = self.gate.approve(r["seq"], "ivan")
        self.assertEqual(ap["approved_by"], "ivan")
        self.assertEqual(self.gate.pending(), [])
        self.assertIn("decision=APPROVED", self.journal())
        # wrong seq on the call: still pending
        wrong = self.gate.call("CR-2026-0015", "qdevice.reboot", {}, approval="999")
        self.assertEqual(wrong["decision"], "PENDING")
        # right seq: allowed and executed
        ok = self.gate.call("CR-2026-0015", "qdevice.reboot", {}, approval=str(r["seq"]))
        self.assertEqual(ok["decision"], "ALLOW", ok)
        self.assertIn("approved by ivan", ok["reason"])
        self.assertEqual(ok["stdout"].strip(), "rebooting")
        # single use
        again = self.gate.call("CR-2026-0015", "qdevice.reboot", {}, approval=str(r["seq"]))
        self.assertEqual(again["decision"], "PENDING")
        self.assertIn("no approval on file", again["reason"])
        self.assertEqual([p["seq"] for p in self.gate.pending()], [again["seq"], wrong["seq"]])
        # the window closes with that request unapproved: it stops counting and cannot be approved
        os.remove(os.path.join(self.state, "CR-2026-0015.state"))
        self.assertEqual(self.gate.pending(), [])
        with self.assertRaises(core.GateError):
            self.gate.approve(again["seq"], "ivan")

    def test_approval_is_bound_to_the_action_and_expires(self):
        r = self.gate.call("CR-2026-0015", "qdevice.reboot", {})
        self.gate.approve(r["seq"], "ivan")
        # a different action under the same approval seq: not this action's hash
        other = self.gate.call("CR-2026-0015", "qdevice.restart_service", {"unit": "corosync-qnetd.service"}, approval=str(r["seq"]))
        self.assertEqual(other["decision"], "ALLOW")           # L2 ignores approval, that is fine
        os.environ["GATE_NOW"] = "2026-10-13T12:41:00Z"        # 11 minutes later, ttl 600 s
        late = self.gate.call("CR-2026-0015", "qdevice.reboot", {}, approval=str(r["seq"]))
        self.assertEqual(late["decision"], "PENDING")
        self.assertIn("expired", late["reason"])
        self.assertTrue(os.path.exists(self.gate.approval_path(r["action_hash"] if "action_hash" in r else self.gate.action_hash("CR-2026-0015", "qdevice.reboot", {})) + ".expired"))

    def test_approve_rejects_non_pending(self):
        ok = self.gate.call("CR-2026-0015", "pve.quorum_status", {})
        with self.assertRaises(core.GateError):
            self.gate.approve(ok["seq"], "ivan")
        with self.assertRaises(core.GateError):
            self.gate.approve(12345, "ivan")


class Chain(Base):
    def test_chain_verifies_and_detects_tampering(self):
        for _ in range(3):
            self.gate.call("CR-2026-0015", "pve.quorum_status", {})
        self.gate.call("CR-2026-0015", "nope", {})
        ok, n, bad = self.gate.verify()
        self.assertEqual((ok, n, bad), (True, 4, None))
        recs = self.gate.records()
        self.assertEqual([r["seq"] for r in recs], [1, 2, 3, 4])
        self.assertEqual(recs[0]["prev"], "0" * 64)
        self.assertEqual(recs[1]["prev"], recs[0]["hash"])
        # tamper with record 2's reason
        lines = Path(self.cfg["audit"]).read_text().splitlines()
        r2 = json.loads(lines[1])
        r2["reason"] = "edited"
        lines[1] = core.canonical(r2)
        with open(self.cfg["audit"], "w") as f:
            f.write("\n".join(lines) + "\n")
        ok, n, bad = self.gate.verify()
        self.assertEqual((ok, bad), (False, 2))
        # the journal carries the first 16 hex of every hash
        for r in recs:
            self.assertIn(f"seq={r['seq']} ", self.journal())
            self.assertIn(f"hash={r['hash'][:16]}", self.journal())


class Textfile(Base):
    def test_metrics(self):
        self.begin()
        self.gate.call("CR-2026-0015", "pve.quorum_status", {})
        self.gate.call("CR-2026-0015", "nope", {})
        self.gate.call("CR-2026-0015", "qdevice.reboot", {})
        t = textfile.render(self.gate, 1_800_000_000)
        self.assertIn('agent_gate_decisions_total{tool="pve.quorum_status",level="L1",decision="ALLOW"} 1', t)
        self.assertIn('agent_gate_decisions_total{tool="nope",level="?",decision="DENY"} 1', t)
        self.assertIn('agent_gate_decisions_total{tool="qdevice.reboot",level="L3",decision="PENDING"} 1', t)
        self.assertIn("agent_gate_pending_approvals 1", t)
        self.assertIn("agent_gate_stopped 0", t)
        self.assertIn("agent_gate_chain_length 3", t)
        self.assertIn("agent_gate_chain_ok 1", t)
        self.assertIn("agent_gate_last_decision_timestamp 1791894600", t)   # 2026-10-13T12:30:00Z
        if shutil.which("promtool"):
            p = subprocess.run(["promtool", "check", "metrics"], input=t, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


class Mcp(Base):
    def rpc(self, *msgs):
        inp = io.StringIO("\n".join(json.dumps(m) for m in msgs) + "\n")
        out = io.StringIO()
        mcp_server.serve(self.gate, inp, out)
        return [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]

    def test_initialize_list_call(self):
        self.begin()
        res = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "qdevice.restart_service", "arguments": {"cr": "CR-2026-0015", "unit": "corosync-qnetd.service"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "qdevice.reboot", "arguments": {"cr": "CR-2026-0015"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "nope"},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "pve.quorum_status", "arguments": {}}},
        )
        self.assertEqual(res[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(res[0]["result"]["serverInfo"]["name"], "onprem-agent-gate")
        tools = {t["name"]: t for t in res[1]["result"]["tools"]}
        self.assertIn("qdevice.reboot", tools)
        self.assertEqual(tools["qdevice.restart_service"]["inputSchema"]["required"], ["cr", "unit"])
        self.assertIn("approval", tools["qdevice.reboot"]["inputSchema"]["properties"])
        self.assertNotIn("approval", tools["pve.quorum_status"]["inputSchema"]["properties"])
        self.assertTrue(tools["qdevice.reboot"]["description"].startswith("[L3 on qdevice/Debian]"))
        call = res[2]["result"]
        self.assertFalse(call["isError"])
        self.assertEqual(call["structuredContent"]["decision"], "ALLOW")
        self.assertIn("stdout", call["structuredContent"])          # Claude Code reads this, not the text
        self.assertIn('"stdout": "restarted corosync-qnetd.service', call["content"][0]["text"])
        self.assertEqual(res[3]["result"]["structuredContent"]["decision"], "PENDING")
        self.assertEqual(res[4]["error"]["code"], -32601)
        self.assertEqual(res[5]["result"]["structuredContent"]["decision"], "DENY")   # no cr
        self.assertEqual(len(self.gate.records()), 3)

    def test_parse_error(self):
        out = io.StringIO()
        mcp_server.serve(self.gate, io.StringIO("not json\n"), out)
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], -32700)


class ToolsFile(unittest.TestCase):
    def test_repo_tools_json_loads(self):
        tools = core.load_tools(str(ROOT / "tools.json"))
        self.assertIn("qdevice.reboot", tools)
        self.assertEqual(tools["qdevice.reboot"]["level"], "L3")
        for t in tools.values():
            self.assertNotIn("cr", t["params"])

    def test_bad_tools(self):
        d = tempfile.mkdtemp()
        try:
            for bad in ([{"id": "a.b", "level": "L9", "asset": "x", "argv": ["x"], "description": ""}],
                        [{"id": "a.b", "level": "L1", "asset": "x", "argv": ["{p}"], "description": ""}],
                        [{"id": "a.b", "level": "L1", "asset": "x", "argv": ["x"], "params": {"cr": {"re": "x"}}, "description": ""}],
                        [{"id": "a.b", "level": "L1", "asset": "x", "argv": ["x"], "description": ""}] * 2):
                p = os.path.join(d, "t.json")
                with open(p, "w") as f:
                    json.dump(bad, f)
                with self.assertRaises(core.GateError):
                    core.load_tools(p)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
