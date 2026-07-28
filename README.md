# pqc-migration-mcp

[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![mcp](https://img.shields.io/badge/MCP-2024--11--05-blueviolet.svg)](#)
[![tests](https://img.shields.io/badge/tests-26%20passing-brightgreen.svg)](tests/)
[![deps](https://img.shields.io/badge/protocol%20deps-none-brightgreen.svg)](pyproject.toml)

**Give your AI agent the post-quantum migration facts it keeps guessing at.**

Six tools over MCP: credential sizes, fragment counts, the reassembly window, the
39-family failure taxonomy, and benchmark scoring. Ask Claude *"will our ML-KEM-768
handshake fit in a BLE MTU?"* and it computes the answer instead of estimating one.

---

## Why this exists

Agents are increasingly doing PQC migration work, and they are confidently wrong about
exactly the things that matter: how big a credential actually is, how many fragments it
becomes, and whether a safe reassembly cap exists at your concurrency. Those are
arithmetic, not judgement — so hand the agent the arithmetic.

The protocol layer here is dependency-free. MCP is JSON-RPC 2.0 over line-delimited
stdio, which is small enough to implement directly and keeps the install trivial.

## Install

```bash
pip install pqc-migration-mcp        # once published
pip install -e .                     # from a clone, today
```

## 30-second quickstart

```bash
# talk to it directly -- it is line-delimited JSON-RPC on stdio
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | pqc-migration-mcp
```

## Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pqc-migration": {
      "command": "pqc-migration-mcp"
    }
  }
}
```

Restart Claude Desktop. The six tools appear under the connector.

## Tools

| Tool | Answers |
|---|---|
| `credential_size` | How many bytes is a KEM+signature credential, component by component? |
| `fragments` | How many fragments on this transport — and is fragmentation now mandatory? |
| `reassembly_window` | Does a safe capacity cap exist at all? If not, what concurrency *would* work? |
| `list_failure_families` | All 39 failure families, with case counts and published analogues |
| `describe_family` | What breaks in this family, in which designs, and what did each do? |
| `score_submission` | Score a PQC-MFB submission: coverage, regressions, zero-coverage families |

## Worked example — actual output

```
$ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reassembly_window",
    "arguments":{"largest_legitimate_object":12000,"memory_budget":32768,"concurrency":3}}}' \
  | pqc-migration-mcp
```

```json
{
  "is_empty": true,
  "ceiling": 10922,
  "recommended_cap": null,
  "max_safe_concurrency": 2,
  "explanation": "EMPTY WINDOW: floor 12,000 B > ceiling 10,922 B (short by 1,078 B).
    No capacity cap is both feasible and safe. Raise the budget to at least 36,000 B,
    reduce concurrency to at most 2, or choose a smaller credential."
}
```

The agent gets a verdict **and** the number that would fix it, so it can propose a
concrete change rather than reporting a problem.

## What this server will not tell you

**It exposes detection. It does not expose repairs.**

An agent can learn that a design fails `krack_retransmission` and exactly what the
unrepaired design did. It cannot obtain the mechanism that closes it. That boundary is
deliberate: an MCP tool returning repairs would let any user enumerate the entire closed
set in an afternoon.

There is a test that calls `describe_family` for **all 39 families** plus every other
tool, concatenates the responses, and fails if `repair_mechanism`, `repaired_detail` or
`repaired_held` appears anywhere in the output.

## Error semantics

Domain errors — an unknown algorithm, an unknown family — come back as a **tool result**
with `isError: true` and a message naming the valid options, so the agent can correct
itself. Only protocol faults become JSON-RPC errors (`-32601` unknown method/tool,
`-32602` bad arguments, `-32700` unparseable line).

A malformed line does not kill the loop; the server replies with a parse error and keeps
serving.

## Tests

```bash
pip install -e ".[dev]" && pytest      # 26 passed
```

Tests cover the protocol, every tool, the moat boundary, and the real stdio transport
driven as a subprocess — including a check that **stderr stays empty**, since MCP
clients read stdout as protocol and stray warnings confuse them.

## Scope

Arithmetic, taxonomy lookup and scoring. No cryptography, no network, no telemetry. It
does not inspect your implementation. A clean answer means your *configuration* is sound,
not that your code enforces it.

## Related

[`pqc-sizes`](../pqc-sizes) · [`pqc-mfb`](../pqc-mfb) ·
[`pqc-guard-action`](../pqc-guard-action) · [`pqc-dos-embedded`](../pqc-dos-embedded)

Closing the 39 families is what the closed core does. Relevant subject matter is covered
by a filed provisional patent application. For commercial use of the full envelope, open a
[GitHub Discussion](https://github.com/nickharris808) or an issue on this repository.

## License

Apache-2.0. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
