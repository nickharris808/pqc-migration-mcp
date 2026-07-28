"""Differential tests: three surfaces, one answer.

`pqc-sizes` is reachable as a library, as a CLI, and as an MCP tool. A user who
gets one answer from the command line and a different one from their agent has a
tool that cannot be trusted, and neither surface would look wrong on its own.

Nothing asserted this before. The surfaces were each tested against their own
expectations, which is not the same as testing them against each other.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys

import pytest

from pqc_migration_mcp.server import handle


def mcp(name: str, **args):
    response = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": args}})
    result = response["result"]
    if result.get("isError"):
        return {"error": result["content"][0]["text"]}
    return json.loads(result["content"][0]["text"])


def cli(*args: str):
    proc = subprocess.run([sys.executable, "-m", "pqc_sizes.cli", "--json", *args],
                          capture_output=True, text=True, timeout=60)
    return (json.loads(proc.stdout) if proc.stdout.strip() else None), proc.returncode


CASES = [(12000, 32768, 3), (7533, 65536, 4), (19392, 65536, 4),
         (1, 1, 1), (65535, 65536, 2), (1024, 1_000_000, 999)]


@pytest.mark.parametrize("obj,budget,conc", CASES)
def test_window_agrees_across_library_cli_and_mcp(obj, budget, conc):
    from pqc_sizes import max_concurrent_contexts, reassembly_window

    lib = reassembly_window(obj, budget, conc)
    payload, rc = cli("window", "--largest-object", str(obj),
                      "--budget", str(budget), "--concurrency", str(conc))
    tool = mcp("reassembly_window", largest_legitimate_object=obj,
               memory_budget=budget, concurrency=conc)

    assert lib.ceiling == payload["ceiling"] == tool["ceiling"]
    assert lib.is_empty == payload["empty"] == tool["is_empty"]
    assert lib.recommended == payload["recommended_cap"] == tool["recommended_cap"]
    assert (max_concurrent_contexts(obj, budget)
            == payload["max_safe_concurrency"] == tool["max_safe_concurrency"])
    # The exit code must agree with the verdict the other two report.
    assert (rc == 1) == lib.is_empty


@pytest.mark.parametrize("kem,sig", [
    ("ML-KEM-768", "ML-DSA-65"), ("ML-KEM-512", "Falcon-512"),
    ("ML-KEM-1024", "SLH-DSA-SHA2-128f"),
])
def test_credential_size_agrees_across_surfaces(kem, sig):
    from pqc_sizes import credential_bytes

    lib = credential_bytes(kem, sig)
    payload, _ = cli("credential", "--kem", kem, "--sig", sig)
    tool = mcp("credential_size", kem=kem, sig=sig)
    assert lib == payload["total_bytes"] == tool["total_bytes"]


def test_fragment_counts_agree_over_random_inputs():
    from pqc_sizes import fragments_for

    random.seed(5)
    for _ in range(60):
        obj = random.randint(1, 2_000_000)
        frame = random.randint(1, 9000)
        lib = fragments_for(obj, frame)
        payload, _ = cli("fragments", str(frame), "--bytes", str(obj))
        tool = mcp("fragments", object_bytes=obj, frame_payload=frame)
        assert lib == payload["fragments"] == tool["fragments"], (obj, frame)


def test_benchmark_scoring_agrees_between_library_and_mcp():
    from pqc_mfb import load_cases
    from pqc_mfb.score import score_submission

    cases = load_cases()
    random.seed(7)
    for _ in range(25):
        sub = {c.case_id: random.random() < 0.5
               for c in cases if random.random() < 0.8}
        lib = score_submission(sub, cases)
        tool = mcp("score_submission", submission=sub)
        assert lib.n_closed == tool["n_closed"]
        assert lib.verdict == tool["verdict"]
        assert lib.passed == tool["passed"]
        assert sorted(lib.zero_families) == sorted(tool["zero_families"])


def test_the_taxonomy_agrees_between_library_and_mcp():
    from pqc_mfb import families

    lib = {f.name: f.n_cases for f in families()}
    tool = {f["family"]: f["n_cases"] for f in mcp("list_failure_families")["families"]}
    assert lib == tool


@pytest.mark.parametrize("obj,budget,conc", [(0, 100, 1), (100, 0, 1), (100, 100, 0)])
def test_all_three_surfaces_refuse_the_same_degenerate_inputs(obj, budget, conc):
    """Refusal must be as consistent as agreement: a surface that answers where
    another refuses is the one likely to be wrong."""
    from pqc_sizes import reassembly_window

    with pytest.raises(ValueError):
        reassembly_window(obj, budget, conc)

    _, rc = cli("window", "--largest-object", str(obj),
                "--budget", str(budget), "--concurrency", str(conc))
    assert rc == 2, "the CLI answered an input the library refuses"

    tool = mcp("reassembly_window", largest_legitimate_object=obj,
               memory_budget=budget, concurrency=conc)
    assert "error" in tool, "the MCP tool answered an input the library refuses"
