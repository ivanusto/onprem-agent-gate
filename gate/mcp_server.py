"""A minimal MCP server (JSON-RPC 2.0 over stdio, one message per line) that
exposes the gate's tools. Any MCP client -- Claude Code, Claude Desktop, an
Open WebUI tool server, a local Harness -- can be pointed at it:

    gate-mcp --config /etc/onprem-agent-gate/config.json

Methods: initialize, notifications/initialized, ping, tools/list,
tools/call. Every tools/call becomes Gate.call(); the result text is the
JSON response (decision, reason, seq, hash, stdout...). A DENY or PENDING is
a normal result, not a protocol error: the model is meant to read the
reason and tell the operator. Protocol errors (bad JSON, unknown method)
are JSON-RPC errors.

Only the stdio transport is implemented: the gate runs on the collector
as its own user, and the client connects over ssh (restricted to this
command) or runs on the same host. No network listener, nothing to
authenticate twice.
"""
import json
import sys

from core import Gate, GateError, load_config  # noqa: E402  (sys.path set by core)

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


def reply(out, id_, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    out.write(json.dumps(msg, ensure_ascii=False) + "\n")
    out.flush()


def handle(gate, msg, out):
    method = msg.get("method")
    id_ = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        v = params.get("protocolVersion")
        reply(out, id_, {"protocolVersion": v if v in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                         "capabilities": {"tools": {"listChanged": False}},
                         "serverInfo": {"name": "onprem-agent-gate", "version": "0.1.0"},
                         "instructions": ("Every tool needs `cr`, the change record you work under. "
                                          "A DENY or PENDING result is a policy decision: report the reason "
                                          "to the operator; for PENDING, wait for the operator's approval and "
                                          "call again with `approval` set to the request seq.")})
    elif method == "notifications/initialized" or (method or "").startswith("notifications/"):
        return                                      # notifications have no reply
    elif method == "ping":
        reply(out, id_, {})
    elif method == "tools/list":
        reply(out, id_, {"tools": gate.tool_schemas()})
    elif method == "tools/call":
        name = params.get("name")
        args = dict(params.get("arguments") or {})
        cr = args.pop("cr", None)
        approval = args.pop("approval", None)
        try:
            res = gate.call(cr, name, args, approval)
        except GateError as e:
            reply(out, id_, {"content": [{"type": "text", "text": f"gate error: {e}"}], "isError": True})
            return
        text = json.dumps(res, ensure_ascii=False, indent=1)
        # structuredContent is the whole response, stdout included: Claude Code
        # shows the model structuredContent instead of the text when both are
        # present, and a subset there hid every command's output.
        reply(out, id_, {"content": [{"type": "text", "text": text}], "isError": False,
                         "structuredContent": res})
    elif id_ is not None:
        reply(out, id_, error={"code": -32601, "message": f"method not found: {method}"})


def serve(gate, inp=sys.stdin, out=sys.stdout):
    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply(out, None, error={"code": -32700, "message": "parse error"})
            continue
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            reply(out, msg.get("id") if isinstance(msg, dict) else None, error={"code": -32600, "message": "invalid request"})
            continue
        handle(gate, msg, out)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default="/etc/onprem-agent-gate/config.json")
    a = ap.parse_args(argv)
    gate = Gate(load_config(a.config))
    serve(gate)
    return 0


if __name__ == "__main__":
    sys.exit(main())
