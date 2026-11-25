# Nablus

**An autonomous, scope-enforced web & API penetration-testing engine.** Hybrid
**black-box + white-box**: it attacks a running target like an external adversary,
*and* (when source is available) reads the code to find the bugs that only show up
when you can see them — then reconciles both into one queue and **only reports a
finding it has proven with a working proof-of-concept**.

> No PoC, no report. Every finding is backed by a confirm oracle (a reproduced
> cross-user read, a sqlmap-proven injection, an executed XSS), never a pattern match.

Nablus runs only against assets listed in a `scope.json` you control; it refuses any
host not explicitly authorized, before it sends a single packet.

---

## Why this exists / how it compares

The mature open-source agents (Shannon, Strix, PentAGI, HexStrike) are excellent and
Nablus borrows their best ideas openly — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Nablus's niche is the combination most of them don't cover in one tool:

- **Scope enforcement as a hard gate**, not a prompt instruction the model may ignore.
- **Black-box first** (authorized external targets where you have no source), with a
  **white-box SAST stream** bolted on for when you do — Shannon is white-box-first;
  Strix is black-box. Nablus runs **both** and reconciles.
- **Deterministic confirm oracles** we own (`idor.py` anon-baseline, `sqlmap` proof),
  so findings are reproducible without trusting an LLM's say-so.

## Status (honest)

| Layer | State |
|---|---|
| Recon (naabu/httpx/subfinder/amass/gau) | working |
| Black-box crawl + surface/param discovery | working |
| **IDOR** detector + blind two-session harness | **validated** (real range, 0 FP) |
| **SQLi** harness + sqlmap oracle (authed) | **validated** (real range, 0 FP) |
| **White-box SAST stream** (semgrep custom rules + bandit) | **validated** — maps sink → route+param |
| **Coordinated pipeline + reconciliation** (`pipeline.py`) | **validated** — cross-links white-box sinks to black-box PoCs |
| XSS confirm (dalfox) | wired, confirm layer pending |
| Target generalization (beyond range BASE) + physical repo foldering | next |
| MCP server (Claude Code as orchestrator) | planned |

A single `pipeline.py` run fires black-box IDOR + SQLi + white-box SAST, then
reconciles: a code sink whose param matches a black-box PoC is marked **corroborated**
(both streams agree) — the highest-confidence finding class. Proven on the range:
12 black-box confirmed + 4 corroborated, 0 false positives.

## Quickstart

```bash
# 1. Author scope (the engine refuses anything not listed here)
cp scope.example.json scope.json   # edit authorized_assets + authorization_ref

# 2. One coordinated scan: black-box IDOR + SQLi + white-box SAST, reconciled
py -3 pipeline.py --source /path/to/target/source

# or run a single stream directly:
py -3 idor_harness.py                              # black-box IDOR
py -3 sqli_harness.py                              # black-box SQLi (+ sqlmap)
py -3 sast_scan.py --source /path/to/source        # white-box only
```

## Layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full module map and the
target package structure. Top level:

```
core/        importable engine + detectors (idor, sqli, confirm, scope, session, ...)
harness/     blind discovery front-ends (idor_harness, sqli_harness, crawlers)
recon/       recon orchestration
sast/        white-box source analysis (planned)
skills/      per-vuln-class methodology the agents follow
benchmark/   scored harness + fixtures (vulnweb, juice-shop)
tests/       unit tests + local vulnerable target apps + pos/neg corpora
tools/       operational PowerShell helpers
docs/        architecture + runbooks
```

## Authorization & safety

Authorized testing only. Scope-gated, detection-only by default (no table dumps, no
`--os-shell`, no state-changing writes without an explicit human gate). Egress is the
box's VPN exit; allowlist it with the client on real engagements. See ARCHITECTURE.
