"""onprem-agent-gate: the one door an AI agent uses to touch this site.

The agent never gets a shell, an API token or a key. It gets a list of
tools (tools.json), each a fixed argv on one asset, and every call goes
through decide() first:

    ticket      the call names a change record (Day 26, onprem-changes); the
                record must exist, name this agent in `agent:`, list the
                asset, and be in a status that allows the level
    level       L1 read-only: record approved, scheduled or in_progress
                L2 reversible: record in_progress, now inside its window, and
                   the begin mark on file (change-mark.sh begin ran, end has
                   not) -- a human opened the window, the agent cannot
                L3 irreversible: L2 plus a single-use human approval bound to
                   this exact action (gatectl approve <seq>)
    stop        a STOP file denies everything (emergency stop)
    params      every parameter matches the tool's regex, or DENY

Every decision -- ALLOW, DENY, PENDING, APPROVED -- is one record in a
hash-chained audit.jsonl (sha256 over the previous hash and the canonical
record) and one journal line with tag agent-gate, so Day 21's upload puts
it in VictoriaLogs and the WORM archive, and Day 27's audit-report.py
attributes it to the change window like any other admin action.

No third-party modules. Python 3.9 or later.
"""
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from frontmatter import parse, FrontMatterError  # noqa: E402

LEVELS = ("L1", "L2", "L3")
L1_STATUSES = ("approved", "scheduled", "in_progress")
CR_RE = re.compile(r"^CR-\d{4}-\d{4}$")
TOOL_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")

DEFAULTS = {
    "principal": "agent:ops",
    "changes_dir": "/opt/onprem-changes/changes",
    "state_dir": "/var/lib/onprem-changes",
    "tools": "/etc/onprem-agent-gate/tools.json",
    "audit": "/var/lib/onprem-agent-gate/audit.jsonl",
    "approvals_dir": "/var/lib/onprem-agent-gate/approvals",
    "stop_file": "/etc/onprem-agent-gate/STOP",
    "ssh": ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes"],
    "targets": {},
    "approval_ttl_s": 600,
    "approvers": ["implementer", "approver"],
    "logger": "logger",
    "stdout_limit": 65536,
}


class GateError(Exception):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def now():
    """UTC now, or GATE_NOW (RFC 3339) for tests."""
    s = os.environ.get("GATE_NOW")
    if s:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def rfc3339(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(s):
    try:
        d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
        return d.astimezone(timezone.utc) if d.tzinfo else None
    except (ValueError, AttributeError):
        return None


def load_config(path):
    cfg = dict(DEFAULTS)
    if path:
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def load_tools(path):
    with open(path, encoding="utf-8") as f:
        tools = json.load(f)
    out = {}
    for t in tools:
        for k in ("id", "level", "asset", "argv", "description"):
            if k not in t:
                raise GateError(f"tools.json: {t.get('id', '?')} lacks {k}")
        if not TOOL_RE.match(t["id"]):
            raise GateError(f"tools.json: bad tool id {t['id']!r}")
        if t["level"] not in LEVELS:
            raise GateError(f"tools.json: {t['id']}: level must be one of {LEVELS}")
        if t["id"] in out:
            raise GateError(f"tools.json: duplicate tool id {t['id']}")
        params = t.setdefault("params", {})
        used = {m for a in t["argv"] for m in PLACEHOLDER_RE.findall(a)}
        if used != set(params):
            raise GateError(f"tools.json: {t['id']}: argv placeholders {sorted(used)} vs params {sorted(params)}")
        for name, spec in params.items():
            if name in ("cr", "approval"):
                raise GateError(f"tools.json: {t['id']}: param name {name} is reserved for the call itself")
            if "re" not in spec:
                raise GateError(f"tools.json: {t['id']}: param {name} needs a regex 're'")
            re.compile(spec["re"])
        t.setdefault("timeout_s", 30)
        out[t["id"]] = t
    return out


class Gate:
    def __init__(self, cfg):
        self.cfg = cfg
        self.tools = load_tools(cfg["tools"])

    # ---- the ticket -------------------------------------------------------
    def record(self, cr):
        d = self.cfg["changes_dir"]
        try:
            names = sorted(n for n in os.listdir(d) if n.startswith(cr + "-") and n.endswith(".md"))
        except OSError:
            return None
        if not names:
            return None
        with open(os.path.join(d, names[0]), encoding="utf-8") as f:
            try:
                meta, _, _ = parse(f.read())
            except FrontMatterError:
                return None
        return meta

    def begin_mark_present(self, cr):
        return os.path.exists(os.path.join(self.cfg["state_dir"], f"{cr}.state"))

    # ---- the decision -----------------------------------------------------
    def decide(self, cr, tool_id, params, approval=None):
        """-> (decision, reason, meta). decision ALLOW | DENY | PENDING."""
        if os.path.exists(self.cfg["stop_file"]):
            return "DENY", "stopped: STOP file present", None
        if not isinstance(cr, str) or not CR_RE.match(cr):
            return "DENY", "cr must be CR-YYYY-NNNN", None
        tool = self.tools.get(tool_id)
        if tool is None:
            return "DENY", f"unknown tool {tool_id}", None
        if not isinstance(params, dict):
            return "DENY", "params must be an object", None
        if set(params) != set(tool["params"]):
            return "DENY", f"params must be exactly {sorted(tool['params'])}", None
        for name, spec in tool["params"].items():
            v = params.get(name)
            if not isinstance(v, str) or not re.fullmatch(spec["re"], v):
                return "DENY", f"param {name} does not match {spec['re']}", None
        meta = self.record(cr)
        if meta is None:
            return "DENY", f"{cr}: no such change record", None
        agents = meta.get("agent", "")
        agents = agents if isinstance(agents, list) else [a.strip() for a in str(agents).split(",") if a.strip()]
        if self.cfg["principal"] not in agents:
            return "DENY", f"{cr} does not name {self.cfg['principal']} in agent:", meta
        assets = meta.get("assets", [])
        assets = assets if isinstance(assets, list) else [assets]
        if tool["asset"] not in assets:
            return "DENY", f"{cr} does not list asset {tool['asset']}", meta
        status = meta.get("status", "")
        if status not in L1_STATUSES:
            return "DENY", f"{cr} is {status or 'without status'}; need one of {', '.join(L1_STATUSES)}", meta
        if tool["level"] == "L1":
            return "ALLOW", "L1 read on a live record", meta
        if status != "in_progress":
            return "DENY", f"{tool['level']} needs status in_progress, record is {status}", meta
        ws, we = parse_time(meta.get("window_start", "")), parse_time(meta.get("window_end", ""))
        t = now()
        if ws is None or we is None or not (ws <= t < we):
            return "DENY", f"{tool['level']} needs now inside the window {meta.get('window_start', '?')} to {meta.get('window_end', '?')}", meta
        if not self.begin_mark_present(cr):
            return "DENY", f"{tool['level']} needs the begin mark (change-mark.sh begin {cr}) on file", meta
        if tool["level"] == "L2":
            return "ALLOW", "L2 inside an open window with the begin mark", meta
        # L3: a human approval bound to this exact action
        ah = self.action_hash(cr, tool_id, params)
        ok, why = self.consume_approval(ah, approval)
        if ok:
            return "ALLOW", f"L3 approved by {why}", meta
        return "PENDING", why, meta

    def action_hash(self, cr, tool_id, params):
        return sha256(canonical({"principal": self.cfg["principal"], "cr": cr, "tool": tool_id, "params": params}))

    # ---- approvals (L3) ---------------------------------------------------
    def approval_path(self, action_hash):
        return os.path.join(self.cfg["approvals_dir"], action_hash + ".json")

    def consume_approval(self, action_hash, approval):
        """Single use: the file is renamed .used the moment it is accepted."""
        p = self.approval_path(action_hash)
        if approval is None:
            return False, "L3 needs a human approval: ask the operator to run `gatectl approve <seq>` for this request"
        try:
            with open(p, encoding="utf-8") as f:
                a = json.load(f)
        except OSError:
            return False, "L3: no approval on file for this exact action (same cr, tool and params)"
        if str(a.get("request_seq")) != str(approval):
            return False, f"L3: approval on file is for request {a.get('request_seq')}, call said {approval}"
        if parse_time(a.get("expires", "")) is None or now() >= parse_time(a["expires"]):
            os.replace(p, p + ".expired")
            return False, "L3: approval expired, ask again"
        os.replace(p, p + ".used")
        return True, f"{a.get('approved_by', '?')} (request {a['request_seq']})"

    def approve(self, seq, approved_by):
        """A human approves PENDING request <seq>. Returns the approval dict."""
        rec = self.find_record(seq)
        if rec is None:
            raise GateError(f"no audit record with seq {seq}")
        if rec["decision"] != "PENDING":
            raise GateError(f"request {seq} is {rec['decision']}, only PENDING can be approved")
        meta = self.record(rec["cr"])
        if meta is None:
            raise GateError(f"{rec['cr']} no longer exists")
        allowed = {str(meta.get(k, "")).strip() for k in self.cfg["approvers"]} - {""}
        if approved_by not in allowed:
            raise GateError(f"{approved_by} is not the {' or '.join(self.cfg['approvers'])} of {rec['cr']} ({', '.join(sorted(allowed))})")
        if approved_by == self.cfg["principal"]:
            raise GateError("the agent cannot approve its own request")
        os.makedirs(self.cfg["approvals_dir"], exist_ok=True)
        exp = now().timestamp() + int(self.cfg["approval_ttl_s"])
        a = {"action_hash": rec["action_hash"], "request_seq": rec["seq"], "approved_by": approved_by,
             "at": rfc3339(now()), "expires": rfc3339(datetime.fromtimestamp(exp, timezone.utc)),
             "cr": rec["cr"], "tool": rec["tool"], "params": rec["params"]}
        with open(self.approval_path(rec["action_hash"]), "w", encoding="utf-8") as f:
            json.dump(a, f)
        self.audit({"principal": approved_by, "operator": approved_by, "cr": rec["cr"], "tool": rec["tool"],
                    "level": rec["level"], "params": rec["params"], "decision": "APPROVED",
                    "reason": f"approved request {rec['seq']}, valid until {a['expires']}",
                    "action_hash": rec["action_hash"], "approval": rec["seq"], "exec": None})
        return a

    def pending(self):
        """PENDING requests that still have no approval, newest first."""
        out = []
        approved = set()
        for r in self.records():
            if r["decision"] == "APPROVED":
                approved.add(r["approval"])
        for r in self.records():
            if r["decision"] == "PENDING" and r["seq"] not in approved:
                out.append(r)
        return list(reversed(out))

    # ---- the audit chain --------------------------------------------------
    def records(self):
        try:
            with open(self.cfg["audit"], encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        except OSError:
            return []

    def find_record(self, seq):
        for r in self.records():
            if str(r["seq"]) == str(seq):
                return r
        return None

    def last(self):
        try:
            with open(self.cfg["audit"], "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 65536))
                tail = f.read().decode("utf-8", "replace").strip().splitlines()
            return json.loads(tail[-1]) if tail else None
        except OSError:
            return None

    def audit(self, fields):
        """Append one chained record; returns it (with seq and hash)."""
        last = self.last()
        rec = {"seq": (last["seq"] + 1) if last else 1, "ts": rfc3339(now()),
               "prev": last["hash"] if last else "0" * 64}
        rec.update(fields)
        rec["hash"] = sha256(rec["prev"] + "\n" + canonical({k: v for k, v in rec.items() if k != "hash"}))
        os.makedirs(os.path.dirname(os.path.abspath(self.cfg["audit"])), exist_ok=True)
        with open(self.cfg["audit"], "a", encoding="utf-8") as f:
            f.write(canonical(rec) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.journal(rec)
        return rec

    def journal(self, rec):
        ex = rec.get("exec") or {}
        line = (f"seq={rec['seq']} principal={rec['principal']} operator={rec.get('operator', '')} cr={rec['cr']} "
                f"tool={rec['tool']} level={rec['level']} decision={rec['decision']}"
                + (f" rc={ex['rc']}" if "rc" in ex else "") + f" hash={rec['hash'][:16]}")
        try:
            subprocess.run([self.cfg["logger"], "-t", "agent-gate", "-p", "notice", line], check=False, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def verify(self):
        """Recompute the chain. Returns (ok, n, first_bad_seq_or_None)."""
        prev = "0" * 64
        n = 0
        for r in self.records():
            n += 1
            body = {k: v for k, v in r.items() if k != "hash"}
            if r.get("prev") != prev or sha256(prev + "\n" + canonical(body)) != r.get("hash"):
                return False, n, r.get("seq")
            prev = r["hash"]
        return True, n, None

    # ---- the call ---------------------------------------------------------
    def call(self, cr, tool_id, params, approval=None):
        """Decide, execute when allowed, audit. Returns the response dict."""
        params = params or {}
        decision, reason, meta = self.decide(cr, tool_id, params, approval)
        tool = self.tools.get(tool_id, {"level": "?", "asset": "?"})
        rec = {"principal": self.cfg["principal"],
               "operator": (meta or {}).get("implementer", "") if meta else "",
               "cr": cr if isinstance(cr, str) else str(cr), "tool": str(tool_id), "level": tool["level"],
               "params": params if isinstance(params, dict) else {"_": str(params)},
               "decision": decision, "reason": reason,
               "action_hash": self.action_hash(str(cr), str(tool_id), params if isinstance(params, dict) else {}),
               "approval": approval, "exec": None}
        out = None
        if decision == "ALLOW":
            out = self.execute(tool, params)
            rec["exec"] = {k: out[k] for k in ("rc", "duration_s", "stdout_sha256", "stdout_bytes", "timed_out")}
        saved = self.audit(rec)
        resp = {"decision": decision, "reason": reason, "seq": saved["seq"], "hash": saved["hash"],
                "cr": rec["cr"], "tool": rec["tool"], "level": rec["level"]}
        if decision == "PENDING":
            resp["request"] = saved["seq"]
            resp["approve_with"] = f"sudo gatectl approve {saved['seq']}"
        if out is not None:
            resp.update({"rc": out["rc"], "stdout": out["stdout"], "stderr": out["stderr"],
                         "truncated": out["truncated"], "timed_out": out["timed_out"]})
        return resp

    def argv_for(self, tool, params):
        argv = [PLACEHOLDER_RE.sub(lambda m: params[m.group(1)], a) for a in tool["argv"]]
        target = self.cfg["targets"].get(tool["asset"])
        if target is None:
            raise GateError(f"no target configured for asset {tool['asset']}")
        if target == "local":
            return argv
        return list(self.cfg["ssh"]) + [target, "--", " ".join(shlex.quote(a) for a in argv)]

    def execute(self, tool, params):
        argv = self.argv_for(tool, params)
        t0 = time.monotonic()
        timed_out = False
        try:
            p = subprocess.run(argv, capture_output=True, timeout=tool["timeout_s"])
            rc, so, se = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            rc, so, se, timed_out = 124, e.stdout or b"", e.stderr or b"", True
        except OSError as e:
            rc, so, se = 127, b"", str(e).encode()
        lim = int(self.cfg["stdout_limit"])
        return {"rc": rc, "duration_s": round(time.monotonic() - t0, 3),
                "stdout_sha256": hashlib.sha256(so).hexdigest(), "stdout_bytes": len(so),
                "stdout": so[:lim].decode("utf-8", "replace"), "stderr": se[:4096].decode("utf-8", "replace"),
                "truncated": len(so) > lim, "timed_out": timed_out}

    # ---- for the MCP server -----------------------------------------------
    def tool_schemas(self):
        out = []
        for t in self.tools.values():
            props = {"cr": {"type": "string", "pattern": CR_RE.pattern,
                            "description": "the change record (onprem-changes) this call runs under"}}
            for name, spec in t["params"].items():
                props[name] = {"type": "string", "pattern": spec["re"], "description": spec.get("description", "")}
            if t["level"] == "L3":
                props["approval"] = {"type": "string", "description": "request seq a human approved with gatectl approve"}
            out.append({"name": t["id"],
                        "description": f"[{t['level']} on {t['asset']}] {t['description']}",
                        "inputSchema": {"type": "object", "properties": props,
                                        "required": ["cr"] + sorted(t["params"]), "additionalProperties": False}})
        return out
