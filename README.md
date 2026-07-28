# pqc-migration-mcp

[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![mcp](https://img.shields.io/badge/MCP-2024--11--05-blueviolet.svg)](#)
[![tests](https://img.shields.io/badge/tests-57%20passing-brightgreen.svg)](tests/)
[![deps](https://img.shields.io/badge/protocol%20deps-none-brightgreen.svg)](pyproject.toml)

**Give your AI agent the post-quantum migration facts it keeps guessing at.**

Six tools over MCP: credential sizes, fragment counts, the reassembly window, the
39-family failure taxonomy, and benchmark scoring. Ask Claude *"will our ML-KEM-768
handshake fit in a BLE MTU?"* and it computes the answer instead of estimating one.

**📖 Full documentation, tutorial and conceptual guide: <https://nickharris808.github.io/pqc-toolkit/>**

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
pip install git+https://github.com/nickharris808/pqc-migration-mcp
```

This pulls `pqc-sizes` and `pqc-mfb` from their repositories too. Not on PyPI
yet, so `pip install pqc-migration-mcp` does not work today.

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

The transport is **line-delimited** JSON — one complete object per line. Keep the
request on a single line; a request wrapped across two lines arrives as two
incomplete ones and comes back as two `-32700` parse errors.

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reassembly_window","arguments":{"largest_legitimate_object":12000,"memory_budget":32768,"concurrency":3}}}' | pqc-migration-mcp
```

The server replies with one JSON object per line. Pretty-printed, the `content`
payload of that reply is:

```json
{
  "budget": 32768,
  "ceiling": 10922,
  "concurrency": 3,
  "explanation": "EMPTY WINDOW: floor 12,000 B > ceiling 10,922 B (short by 1,078 B). No capacity cap is both feasible and safe. Raise the budget to at least 36,000 B, reduce concurrency to at most 2, or choose a smaller credential.",
  "floor": 12000,
  "is_empty": true,
  "max_safe_concurrency": 2,
  "recommended_cap": null
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
pip install -e ".[dev]" && pytest      # 57 passed
```

Tests cover the protocol, every tool, the moat boundary, and the real stdio transport
driven as a subprocess — including a check that **stderr stays empty**, since MCP
clients read stdout as protocol and stray warnings confuse them.

## Scope

Arithmetic, taxonomy lookup and scoring. No cryptography, no network, no telemetry. It
does not inspect your implementation. A clean answer means your *configuration* is sound,
not that your code enforces it.

## Related

[`pqc-sizes`](https://github.com/nickharris808/pqc-sizes) · [`pqc-mfb`](https://github.com/nickharris808/pqc-mfb) ·
[`pqc-guard-action`](https://github.com/nickharris808/pqc-guard-action) · [`pqc-dos-embedded`](https://github.com/nickharris808/pqc-dos-embedded)

Closing the 39 families is what the closed core does. Relevant subject matter is covered
by a filed provisional patent application. For commercial use of the full envelope, open a
[GitHub Discussion](https://github.com/nickharris808) or an issue on this repository.

## Honest scope

**What this proves.** That the arithmetic and taxonomy an agent is reasoning
with are correct: real credential sizes, real fragment counts, a real window
verdict, and the real failure taxonomy.

**What it does NOT prove.**

- **Not that the agent used the answer.** This supplies facts; it does not
  supervise what is done with them.
- **Not an inspection of your code.** No tool here reads your implementation.
- **Not a repair channel.** Every tool exposes detection only. A test calls
  `describe_family` for all 39 families plus every other tool and fails if a
  repair field appears anywhere in the output.

**Errors.** Domain problems come back as tool results with `isError: true` and a
message naming valid options, so an agent can self-correct. Only protocol faults
become JSON-RPC errors.

---

## The PQC migration toolkit

Eleven free tools for teams moving authenticated key exchange to post-quantum. They **find and measure**; they do not repair.

| Tool | What it does | Where |
|---|---|---|
| [pqc-sizes](https://github.com/nickharris808/pqc-sizes) | Sizes, fragment counts, and the two-sided reassembly window | PyPI |
| [pqc-sizes-js](https://github.com/nickharris808/pqc-sizes-js) | The same arithmetic for Node and the browser | npm |
| [pqc-guard-action](https://github.com/nickharris808/pqc-guard-action) | Fail the build when the window is empty | GitHub Action |
| [pqc-dos-embedded](https://github.com/nickharris808/pqc-dos-embedded) | 169 lines of C: the failure on a real 64 KB device | source |
| [farkas-check](https://github.com/nickharris808/farkas-check) | Re-verify the bound on-device, no SMT solver | source |
| **pqc-migration-mcp** ← you are here | Six MCP tools for AI agents | PyPI |
| [pqc-mfb](https://github.com/nickharris808/pqc-mfb) | 322 cases · 39 failure families · scorer | PyPI |
| [pqc-mfb (data)](https://huggingface.co/datasets/nickh007/pqc-mfb) | The benchmark as a dataset | HF |
| [pqc-formal-corpus](https://huggingface.co/datasets/nickh007/pqc-formal-corpus) | 122 named formal results, 6 provers | HF |
| [pqc-bounds-lean](https://github.com/nickharris808/pqc-bounds-lean) | The same bound in Lean 4 — 0 `sorry`, 0 imports | source |
| [pqc-dos-gate-rtl](https://github.com/nickharris808/pqc-dos-gate-rtl) | The gate in synthesizable RTL, 5 Yosys proofs | source |
| [pqc-explorer](https://huggingface.co/spaces/nickh007/pqc-explorer) | Try it in your browser, no install | HF Space |

**New here?** The [end-to-end tutorial](https://github.com/nickharris808/pqc-sizes/blob/main/TUTORIAL.md) walks one realistic migration through all of them in about ten minutes: sizes -> window -> CI gate -> benchmark.

**In a hurry?** [`pqc-sizes`](https://github.com/nickharris808/pqc-sizes) tells you in five seconds whether your credential fragments and whether a safe cap exists. [`pqc-explorer`](https://huggingface.co/spaces/nickh007/pqc-explorer) does the same in a browser, with no install.

### The closed core

Closing the 39 failure families — downgrade binding, retransmission-safe installation, fragmentation transcripts, roaming forward secrecy, multi-link key separation, admission control, group-key binding — is a separate proprietary codebase. Relevant subject matter is covered by a filed provisional patent application.

That split is measured, not asserted: under a replicate noise control only **4 of 32** repair mechanisms are externally distinguishable, so publishing these detectors does not disclose the repairs.

For commercial licensing, open a [GitHub Discussion](https://github.com/nickharris808/pqc-sizes/discussions) or an issue on any of these repos.

## License

Apache-2.0. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
