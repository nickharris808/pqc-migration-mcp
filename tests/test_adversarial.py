"""Adversarial protocol and argument tests for the MCP server.

Oracle: NO INPUT MAY PRODUCE A CONFIDENT-LOOKING ANSWER THAT IS WRONG.

An MCP server answers an agent, not a person, and an agent will act on whatever it
is told. So a wrong-but-plausible tool result is worse here than almost anywhere
else in the portfolio: it gets turned into a code change without a human reading it.

These cover three failure modes:
  * implementation detail leaking as a domain answer (CPython's "invalid literal
    for int()" was reaching agents as the tool result);
  * a malformed line killing the stream instead of being reported;
  * the moat boundary -- repairs must never appear in any response.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

WITHHELD = ("repair_mechanism", "repaired_detail", "repaired_held")


def call(*lines: str) -> tuple[list[dict], str]:
    """Drive the real stdio transport as a subprocess; return (responses, stderr)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pqc_migration_mcp"],
        input="\n".join(lines) + "\n",
        capture_output=True, text=True, timeout=120,
    )
    out = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
    return out, proc.stderr


def tool(name: str, args: dict, rid: int = 1) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                       "params": {"name": name, "arguments": args}})


def text_of(resp: dict) -> str:
    return resp["result"]["content"][0]["text"]


# ------------------------------------------------- no implementation detail leaks

@pytest.mark.parametrize("value,expect", [
    ("big", "integer number of bytes"),
    (True, "boolean"),
    (1.5, "whole number"),
    (None, "integer number of bytes"),
    ([1, 2], "integer number of bytes"),
])
def test_bad_argument_types_produce_domain_errors(value, expect):
    out, _ = call(tool("fragments", {"object_bytes": value, "frame_payload": 384}))
    body = text_of(out[0])
    assert out[0]["result"]["isError"] is True
    assert expect in body
    # CPython's own wording must never reach the agent.
    assert "invalid literal" not in body
    assert "Traceback" not in body


def test_numeric_strings_are_accepted():
    """Agents routinely send numbers as strings; that is not an error."""
    out, _ = call(tool("fragments", {"object_bytes": "7533", "frame_payload": "384"}))
    assert out[0]["result"]["isError"] is False
    assert json.loads(text_of(out[0]))["fragments"] == 20


# ------------------------------------------------------------------ protocol errors

def test_malformed_line_does_not_kill_the_stream():
    out, _ = call("not json at all",
                  tool("fragments", {"object_bytes": 7533, "frame_payload": 384}, rid=2))
    assert out[0]["error"]["code"] == -32700
    assert out[1]["id"] == 2
    assert out[1]["result"]["isError"] is False


def test_unknown_tool_and_method_are_protocol_errors():
    out, _ = call(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "nope", "params": {}}),
        tool("ghost_tool", {}, rid=2),
    )
    assert out[0]["error"]["code"] == -32601
    assert out[1]["error"]["code"] == -32601


def test_missing_required_arguments_is_invalid_params():
    out, _ = call(tool("reassembly_window", {}))
    assert out[0]["error"]["code"] == -32602


def test_stderr_stays_empty():
    """MCP clients parse stdout as protocol; stray output on stderr confuses them."""
    _, err = call(tool("fragments", {"object_bytes": 7533, "frame_payload": 384}),
                  "garbage",
                  tool("list_failure_families", {}, rid=3))
    assert err.strip() == ""


def test_many_requests_in_one_stream():
    lines = [tool("fragments", {"object_bytes": 7533, "frame_payload": 384}, rid=i)
             for i in range(200)]
    out, _ = call(*lines)
    assert len(out) == 200
    assert {r["id"] for r in out} == set(range(200))


def test_a_very_long_line_is_handled():
    out, _ = call(tool("score_submission",
                       {"submission": {f"junk::{i}": True for i in range(20000)}}))
    assert "result" in out[0] or "error" in out[0]


# ------------------------------------------------------- domain errors stay results

def test_unsafe_configuration_is_a_result_not_an_error():
    """An empty window is a finding the agent must see, not a protocol failure."""
    out, _ = call(tool("reassembly_window", {
        "largest_legitimate_object": 12000, "memory_budget": 32768, "concurrency": 3}))
    payload = json.loads(text_of(out[0]))
    assert payload["is_empty"] is True
    assert payload["max_safe_concurrency"] == 2
    assert out[0]["result"]["isError"] is False


def test_negative_dimensions_are_refused_not_answered():
    out, _ = call(tool("reassembly_window", {
        "largest_legitimate_object": -1, "memory_budget": 100, "concurrency": 1}))
    assert out[0]["result"]["isError"] is True


# ------------------------------------------------------------------- moat boundary

def test_no_response_ever_contains_a_repair():
    """Every tool, every family, one grep. Detection ships; repairs do not."""
    fams, _ = call(tool("list_failure_families", {}))
    families = [f["family"] for f in json.loads(text_of(fams[0]))["families"]]
    assert len(families) == 39

    lines = [tool("describe_family", {"family": f}, rid=i)
             for i, f in enumerate(families)]
    lines += [
        tool("credential_size", {}, rid=100),
        tool("fragments", {"object_bytes": 7533, "frame_payload": 384}, rid=101),
        tool("reassembly_window", {"largest_legitimate_object": 12000,
                                   "memory_budget": 32768, "concurrency": 3}, rid=102),
        tool("list_failure_families", {}, rid=103),
        tool("score_submission", {"submission": {}}, rid=104),
    ]
    out, _ = call(*lines)
    blob = json.dumps(out)
    for field in WITHHELD:
        assert field not in blob, f"{field} leaked through the MCP surface"


def test_score_submission_reports_the_verdict_not_just_a_number():
    """An agent must be able to see that an empty submission is not a pass."""
    out, _ = call(tool("score_submission", {"submission": {}}))
    payload = json.loads(text_of(out[0]))
    assert payload.get("verdict") == "INCOMPLETE"
    assert payload.get("passed") is False
