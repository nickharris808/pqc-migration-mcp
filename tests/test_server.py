"""Tests for the PQC migration MCP server.

Two levels:
  * handle() directly, for protocol and tool semantics; and
  * the real stdio loop as a subprocess, because that is how a client drives it
    and a server that works in-process but deadlocks on stdio is not a server.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from pqc_migration_mcp.server import PROTOCOL_VERSION, TOOLS, handle, serve

ROOT = Path(__file__).resolve().parent.parent


def rpc(method, params=None, rid=1):
    return handle({"jsonrpc": "2.0", "id": rid, "method": method,
                   "params": params or {}})


def call(name, **args):
    return rpc("tools/call", {"name": name, "arguments": args})


def payload(resp):
    """Decode the JSON a tool returned in its text content."""
    return json.loads(resp["result"]["content"][0]["text"])


# ------------------------------------------------------------ protocol

def test_initialize_reports_protocol_and_server():
    r = rpc("initialize")
    assert r["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert r["result"]["serverInfo"]["name"] == "pqc-migration"
    assert "tools" in r["result"]["capabilities"]


def test_tools_list_matches_the_registry():
    r = rpc("tools/list")
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == set(TOOLS)
    for t in r["result"]["tools"]:
        assert t["description"]
        assert t["inputSchema"]["type"] == "object"


def test_unknown_method_is_method_not_found():
    assert rpc("nope")["error"]["code"] == -32601


def test_unknown_tool_is_method_not_found():
    assert call("nope")["error"]["code"] == -32601


def test_bad_jsonrpc_version_is_invalid_request():
    r = handle({"jsonrpc": "1.0", "id": 1, "method": "ping"})
    assert r["error"]["code"] == -32600


def test_notification_gets_no_response():
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_ping():
    assert rpc("ping")["result"] == {}


def test_bad_arguments_are_invalid_params():
    r = call("fragments", wrong_arg=1)
    assert r["error"]["code"] == -32602


# --------------------------------------------------------------- tools

def test_credential_size():
    p = payload(call("credential_size", kem="ML-KEM-768", sig="ML-DSA-65"))
    assert p["total_bytes"] == 7533
    assert sum(p["breakdown"].values()) == 7533


def test_credential_size_defaults():
    assert payload(call("credential_size"))["total_bytes"] == 7533


def test_unknown_algorithm_is_a_tool_error_not_a_crash():
    """A domain error must come back as isError so the agent can self-correct."""
    r = call("credential_size", kem="NOPE")
    assert r["result"]["isError"] is True
    assert "unknown KEM" in r["result"]["content"][0]["text"]


def test_fragments():
    p = payload(call("fragments", object_bytes=7533, frame_payload=384))
    assert p["fragments"] == 20
    assert p["fragmentation_required"] is True


def test_fragments_single_frame():
    p = payload(call("fragments", object_bytes=32, frame_payload=384))
    assert p["fragments"] == 1
    assert p["fragmentation_required"] is False


def test_reassembly_window_ok():
    p = payload(call("reassembly_window", largest_legitimate_object=12000,
                     memory_budget=65536, concurrency=4))
    assert p["is_empty"] is False
    assert p["ceiling"] == 16384
    assert p["max_safe_concurrency"] == 5


def test_reassembly_window_empty_reports_a_fix():
    p = payload(call("reassembly_window", largest_legitimate_object=12000,
                     memory_budget=32768, concurrency=3))
    assert p["is_empty"] is True
    assert p["recommended_cap"] is None
    assert p["max_safe_concurrency"] == 2
    assert "EMPTY WINDOW" in p["explanation"]


def test_list_failure_families():
    p = payload(call("list_failure_families"))
    assert p["n_families"] == 39
    assert all(f["n_cases"] >= 1 for f in p["families"])


def test_describe_family():
    p = payload(call("describe_family", family="krack_retransmission"))
    assert p["n_cases"] >= 1
    assert p["cases"][0]["naive_detail"]
    assert "repair is not exposed" in p["note"]


def test_describe_unknown_family_lists_the_valid_ones():
    r = call("describe_family", family="not_a_family")
    assert r["result"]["isError"] is True
    assert "known:" in r["result"]["content"][0]["text"]


def test_score_submission():
    from pqc_mfb import load_cases, perfect_submission

    p = payload(call("score_submission", submission=perfect_submission(load_cases())))
    assert p["coverage_pct"] == 100.0
    assert p["n_regressions"] == 0


def test_score_submission_rejects_a_non_object():
    r = call("score_submission", submission=[1, 2, 3])
    assert r["result"]["isError"] is True


# ----------------------------------------------------------------- moat

def test_no_tool_returns_a_repair_mechanism():
    """The whole boundary. If any tool leaks the incidence matrix, this fails."""
    from pqc_mfb import load_cases

    responses = [
        call("list_failure_families"),
        call("describe_family", family="krack_retransmission"),
        call("credential_size"),
        call("score_submission", submission={}),
    ]
    for fam in {c.family for c in load_cases()}:
        responses.append(call("describe_family", family=fam))

    blob = json.dumps(responses)
    for banned in ("repair_mechanism", "repaired_detail", "repaired_held"):
        assert banned not in blob, f"{banned} leaked through the MCP surface"


def test_tool_registry_contains_no_repair_tool():
    for name in TOOLS:
        assert "repair" not in name and "fix" not in name and "patch" not in name


# ---------------------------------------------------------------- stdio

def test_stdio_loop_end_to_end(tmp_path):
    """Drive the real server as a client would: line-delimited JSON on stdin."""
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "credential_size", "arguments": {}}},
    ]
    stdin = "\n".join(json.dumps(r) for r in reqs) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "pqc_migration_mcp"],
        input=stdin, capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": ":".join(sys.path)},
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(x) for x in proc.stdout.splitlines() if x.strip()]
    # 3 requests with ids -> 3 responses; the notification gets none.
    assert [x["id"] for x in lines] == [1, 2, 3]
    assert lines[0]["result"]["serverInfo"]["name"] == "pqc-migration"
    assert len(lines[1]["result"]["tools"]) == len(TOOLS)
    assert json.loads(lines[2]["result"]["content"][0]["text"])["total_bytes"] == 7533


def test_malformed_line_gets_a_parse_error_and_the_loop_survives():
    import io

    out = io.StringIO()
    serve(io.StringIO('not json\n{"jsonrpc":"2.0","id":9,"method":"ping"}\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines() if x.strip()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1]["id"] == 9          # loop continued after the bad line


def test_blank_lines_are_ignored():
    import io

    out = io.StringIO()
    serve(io.StringIO('\n\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n\n'), out)
    assert len([x for x in out.getvalue().splitlines() if x.strip()]) == 1


def test_stdio_transport_emits_nothing_on_stderr():
    """MCP clients read stdout as protocol. Stray stderr noise (e.g. a runpy
    RuntimeWarning from invoking the module rather than the package) can confuse
    a client, so the documented entry point must be silent."""
    proc = subprocess.run(
        [sys.executable, "-m", "pqc_migration_mcp"],
        input='{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
        capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": ":".join(sys.path)},
    )
    assert proc.returncode == 0
    assert proc.stderr == "", f"unexpected stderr: {proc.stderr!r}"
    assert json.loads(proc.stdout)["result"] == {}
