"""MCP server exposing post-quantum migration analysis to AI agents.

Implements the Model Context Protocol over stdio with no third-party dependencies --
the protocol is JSON-RPC 2.0 over line-delimited stdin/stdout, which is small enough
to implement directly and keeps the install trivial.

WHAT IS EXPOSED, AND WHAT IS NOT
--------------------------------
Exposed: sizing arithmetic, fragmentation, the reassembly window, the failure
taxonomy, and benchmark scoring. All of it detection and measurement.

NOT exposed: repair mechanisms. An agent can learn from this server that a design
fails `krack_retransmission`, and what the unrepaired design did. It cannot obtain
the repair. That boundary is deliberate -- an MCP tool that returned repairs would
let any user enumerate the entire closed set in an afternoon.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "pqc-migration"
SERVER_VERSION = "0.1.0"

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# --------------------------------------------------------------- tools


def _as_int(field: str, value: object) -> int:
    """Coerce a tool argument to int, or raise a message an agent can act on.

    A bare ``int(value)`` surfaces CPython's own wording -- "invalid literal for
    int() with base 10: 'big'" -- as the tool result. That leaks the
    implementation and tells the agent nothing about which argument to fix.
    """
    if isinstance(value, bool):
        raise ValueError(
            f"{field} must be an integer number of bytes, got a boolean. "
            f"Pass a number, not true/false."
        )
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != int(value):
            raise ValueError(
                f"{field} must be a whole number of bytes, got {value}."
            )
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            raise ValueError(
                f"{field} must be an integer number of bytes, got the string "
                f"{value!r}. Pass a number such as 12000."
            ) from None
    raise ValueError(
        f"{field} must be an integer number of bytes, got "
        f"{type(value).__name__}."
    )


def _tool_credential_size(kem: str = "ML-KEM-768", sig: str = "ML-DSA-65") -> dict:
    from pqc_sizes import ALGORITHMS, Credential

    if kem not in ALGORITHMS:
        raise ValueError(f"unknown KEM {kem!r}; known: {', '.join(sorted(ALGORITHMS))}")
    if sig not in ALGORITHMS:
        raise ValueError(f"unknown signature {sig!r}")
    cred = Credential(ALGORITHMS[kem], ALGORITHMS[sig])
    return {"kem": kem, "sig": sig, "total_bytes": cred.total_bytes,
            "breakdown": cred.breakdown}


def _tool_fragments(object_bytes: int, frame_payload: int) -> dict:
    from pqc_sizes import fragments_for

    object_bytes = _as_int("object_bytes", object_bytes)
    frame_payload = _as_int("frame_payload", frame_payload)
    n = fragments_for(object_bytes, frame_payload)
    return {
        "object_bytes": object_bytes,
        "frame_payload": frame_payload,
        "fragments": n,
        "fragmentation_required": n > 1,
        "note": ("The receiver holds partial, unauthenticated state across "
                 f"{n} frames.") if n > 1 else "Fits in a single frame.",
    }


def _tool_reassembly_window(largest_legitimate_object: int, memory_budget: int,
                            concurrency: int) -> dict:
    from pqc_sizes import max_concurrent_contexts, reassembly_window

    largest_legitimate_object = _as_int("largest_legitimate_object",
                                        largest_legitimate_object)
    memory_budget = _as_int("memory_budget", memory_budget)
    concurrency = _as_int("concurrency", concurrency)

    win = reassembly_window(largest_legitimate_object, memory_budget, concurrency)
    return {
        "floor": win.floor, "ceiling": win.ceiling,
        "budget": win.budget, "concurrency": win.concurrency,
        "is_empty": win.is_empty,
        "recommended_cap": win.recommended,
        "max_safe_concurrency": max_concurrent_contexts(
            largest_legitimate_object, memory_budget),
        "explanation": win.explain(),
    }


def _tool_list_failure_families() -> dict:
    # The taxonomy is a pure function of the corpus, so pqc_mfb derives and caches
    # it once rather than every consumer rebuilding it per request.
    from pqc_mfb import families

    out = [{"family": f.name, "n_cases": f.n_cases,
            "designs": list(f.designs),
            "prior_art_analogues": list(f.prior_art_analogues)}
           for f in families()]
    return {"n_families": len(out), "families": out}


def _tool_describe_family(family: str) -> dict:
    from pqc_mfb import load_cases

    # One load, not two: the error path used to re-read the whole corpus purely to
    # build the "known families" list.
    everything = load_cases()
    cases = [c for c in everything if c.family == family]
    if not cases:
        known = sorted({c.family for c in everything})
        raise ValueError(f"unknown family {family!r}; known: {', '.join(known)}")
    return {
        "family": family,
        "n_cases": len(cases),
        "invariants": sorted({c.invariant for c in cases}),
        "prior_art_analogues": sorted({c.prior_art_analogue for c in cases
                                       if c.prior_art_analogue}),
        "cases": [{"case_id": c.case_id, "design": c.design,
                   "is_failure": c.is_failure, "naive_detail": c.naive_detail}
                  for c in cases],
        "note": ("This describes the failure. The repair is not exposed by this "
                 "server."),
    }


def _tool_score_submission(submission: dict) -> dict:
    from pqc_mfb import load_cases, score_submission

    if not isinstance(submission, dict):
        raise ValueError("submission must be an object of {case_id: bool}")
    sc = score_submission({k: bool(v) for k, v in submission.items()}, load_cases())
    return sc.to_dict()


TOOLS: dict[str, tuple[Callable[..., Any], dict]] = {
    "credential_size": (_tool_credential_size, {
        "description": "Total on-wire bytes for a KEM + signature credential, with a "
                       "per-component breakdown.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kem": {"type": "string", "default": "ML-KEM-768",
                        "description": "KEM name, e.g. ML-KEM-768"},
                "sig": {"type": "string", "default": "ML-DSA-65",
                        "description": "Signature name, e.g. ML-DSA-65"},
            },
        },
    }),
    "fragments": (_tool_fragments, {
        "description": "How many fragments an object becomes on a transport, and "
                       "whether fragmentation is therefore mandatory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_bytes": {"type": "integer"},
                "frame_payload": {"type": "integer",
                                  "description": "usable payload bytes per frame"},
            },
            "required": ["object_bytes", "frame_payload"],
        },
    }),
    "reassembly_window": (_tool_reassembly_window, {
        "description": "The two-sided reassembly-capacity window. Returns is_empty=true "
                       "when NO capacity cap is both feasible and safe, plus the maximum "
                       "concurrency that would be safe.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "largest_legitimate_object": {"type": "integer"},
                "memory_budget": {"type": "integer"},
                "concurrency": {"type": "integer"},
            },
            "required": ["largest_legitimate_object", "memory_budget", "concurrency"],
        },
    }),
    "list_failure_families": (_tool_list_failure_families, {
        "description": "All 39 post-quantum migration failure families, with case "
                       "counts and published prior-art analogues.",
        "inputSchema": {"type": "object", "properties": {}},
    }),
    "describe_family": (_tool_describe_family, {
        "description": "Detail for one failure family: the invariants it breaks, the "
                       "unrepaired designs that fail it, and what each did. Does not "
                       "return repairs.",
        "inputSchema": {
            "type": "object",
            "properties": {"family": {"type": "string"}},
            "required": ["family"],
        },
    }),
    "score_submission": (_tool_score_submission, {
        "description": "Score a PQC-MFB submission ({case_id: bool}). Returns coverage, "
                       "regressions, and which families have zero coverage.",
        "inputSchema": {
            "type": "object",
            "properties": {"submission": {"type": "object"}},
            "required": ["submission"],
        },
    }),
}


# ------------------------------------------------------------- protocol


def _result(rid, payload):
    return {"jsonrpc": "2.0", "id": rid, "result": payload}


def _error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(req: dict) -> dict | None:
    """Handle one JSON-RPC request. Returns None for notifications."""
    if req.get("jsonrpc") != "2.0":
        return _error(req.get("id"), INVALID_REQUEST, "jsonrpc must be '2.0'")

    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}

    # Notifications carry no id and expect no response.
    if rid is None and method and method.startswith("notifications/"):
        return None

    if method == "initialize":
        return _result(rid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })

    if method == "tools/list":
        return _result(rid, {"tools": [
            {"name": name, "description": meta["description"],
             "inputSchema": meta["inputSchema"]}
            for name, (_fn, meta) in sorted(TOOLS.items())
        ]})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name not in TOOLS:
            return _error(rid, METHOD_NOT_FOUND, f"unknown tool: {name}")
        fn, _meta = TOOLS[name]
        try:
            payload = fn(**args)
        except TypeError as exc:
            return _error(rid, INVALID_PARAMS, f"bad arguments for {name}: {exc}")
        except ValueError as exc:
            # A domain error is a tool result, not a protocol error: the agent
            # should see it and correct itself.
            return _result(rid, {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            })
        except Exception as exc:  # surface unexpected failures as protocol errors
            return _error(rid, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
        return _result(rid, {
            "content": [{"type": "text",
                         "text": json.dumps(payload, indent=2, sort_keys=True)}],
            "isError": False,
        })

    if method == "ping":
        return _result(rid, {})

    return _error(rid, METHOD_NOT_FOUND, f"unknown method: {method}")


def serve(stdin=None, stdout=None) -> int:
    """Read line-delimited JSON-RPC from stdin, write responses to stdout."""
    inp = stdin or sys.stdin
    out = stdout or sys.stdout
    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            out.write(json.dumps(_error(None, PARSE_ERROR, str(exc))) + "\n")
            out.flush()
            continue
        resp = handle(req)
        if resp is not None:
            out.write(json.dumps(resp) + "\n")
            out.flush()
    return 0


def main() -> int:
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
