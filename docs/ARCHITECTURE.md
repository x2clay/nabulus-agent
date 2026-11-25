# Nablus — Architecture

## 1. Design principle: one pipeline, two discovery streams, one proof gate

```
                    ┌─────────────── BLACK-BOX STREAM ───────────────┐
  scope.json ─▶ recon ─▶ authed crawl ─▶ surface/param discovery ─▶ candidate attack points
   (hard gate)                                                            │
                    ┌─────────────── WHITE-BOX STREAM (when source given) ┤
                      SAST (semgrep/bandit/slither) ─▶ source→sink / taint / missing-authz
                                                                          │
                                                   ┌──────────────────────▼─────────┐
                                                   │  RECONCILIATION                │
                                                   │  merge + dedup both streams     │
                                                   │  into one exploitation queue    │
                                                   └──────────────────────┬─────────┘
                                                                          ▼
                              per-vuln-class detectors (IDOR / SQLi / XSS / SSRF / authz / ...)
                                                                          ▼
                                                   ┌──────────────────────────────┐
                                                   │  CONFIRM / PoC ORACLE          │
                                                   │  no reproduction ⇒ no finding  │
                                                   └──────────────────────┬─────────┘
                                                                          ▼
                                                              notebook.json ─▶ report
```

**Why two streams + reconciliation (borrowed from Shannon):** black-box finds what's
*reachable*; white-box finds what's *there* (an unlinked route, a sink with no
reachable trigger yet). Each covers the other's blind spot. Reconciliation dedups the
overlap so we don't test the same thing twice and so a white-box lead gets a black-box
PoC attempt. **The confirm gate is the same for both** — a lead is only a finding once
an oracle reproduces it.

## 2. Confirm oracles (the thing we will not compromise)

| Class | Discovery | Confirm oracle |
|---|---|---|
| IDOR/BOLA | `harness/idor_harness.py` (two-session, body-id harvest, selectivity gate) | `core/idor.py` — anon-baseline (`_denied_to_anon`) + cross-user body match |
| SQLi | `harness/sqli_harness.py` (param enum + boolean/error pre-screen) | `core/sqli_probe.py` → **sqlmap** proven injection point |
| XSS | dalfox / katana | executed-payload reflection in a real browser (pending) |
| SSRF | `core/ssrf_probe.py` | OOB callback (interactsh) |
| Authz | `core/authz_probe.py` | differential access + anon baseline |

A pattern match is a *lead*, never a finding. This is Shannon's "no exploit, no
report" and our prior independent convergence on anon-baseline confirm.

## 3. Scope enforcement

`core/runner.py:Scope` + `authz_probe.in_scope` gate every outbound request against
`scope.json.authorized_assets` **before** the request. Model/agent instructions to
"stay in scope" are not trusted — the gate is mechanical. `scope.json` requires an
`authorization_ref` (engagement id / owner attestation / bounty URL).

## 4. Relationship to the mature OSS agents (decided)

Our spine stays **ours** and runs on this box's reality — local model finds, DeepSeek
extracts, deterministic oracles confirm — because Shannon/Strix are tuned for frontier
API brains (no API credits here beyond DeepSeek) and would under-run on local/DeepSeek.
They are a **knowledge source and a sparring partner, not the engine**:

- **Mine (free, primary):** port their techniques, payloads, per-vuln-class agent
  logic, PoC methods, and prompts into our detectors + `skills/`. This is where the
  scraped pentest-skill corpus also lands.
- **Spar (cheap, optional, deferred):** run Strix (black-box) + Shannon (white-box,
  given the range source) on DeepSeek against the de-blinded range ONCE as an eval to
  find our blind spots, then fold gaps in. Needs a WSL2 + Docker setup (not yet built).
- **White-box is ours:** the reconciliation idea is Shannon's, but our white-box stream
  is `sast_scan.py` (semgrep custom rules + bandit, offline/local) — no frontier-brain
  dependency. `pipeline.py` reconciles it with the black-box PoCs (**built + validated**).
- **MCP (planned):** expose the detectors as an MCP server so Claude Code can drive
  them (HexStrike/PentestGPT/Executioner are all converging here).
- License: internal use, so studying AGPL Shannon is fine; our code stays clean-room
  so a future "sell the shovels" pivot isn't poisoned.

## 5. Skills

`skills/` holds the per-vuln-class methodology the agents follow (currently: idor,
authz_playbook, authentication_jwt, false_positives, nextjs). Plan: ingest the scraped
pentest-skill corpus + distill Shannon/Strix per-class agent prompts into skills, one
file per class, each with: signals, discovery moves, confirm steps, FP traps.

## 6. Target structure + migration (import-safe, staged)

The 19 entrypoints use `sys.path.insert(0, <own dir>)` + bare imports (`import idor`).
A naive folder move breaks that. Migration is **staged with verification after each
group** so the validated IDOR/SQLi harnesses never stay broken:

```
core/      idor.py runner.py authz_probe.py session.py browser.py confirm.py
           surface.py battery.py probes.py extractor.py normalizer.py playbook.py
           inject.py sqli_probe.py ssrf_probe.py xss_probe.py  (+ __init__.py)
engine/    (existing) coordinator worker http policy contracts autonomous
harness/   idor_harness.py sqli_harness.py crawl.py active_crawl.py
recon/     recon job builders
sast/      (new) semgrep/bandit/slither wrappers + source→route mapper
tests/     test_*.py  *_target.py (local vuln apps)  *_pos.json *_neg.json
tools/     *.ps1
docs/      ARCHITECTURE.md + runbooks
skills/ benchmark/ (unchanged)
```

Mechanism: core libs land together in `core/`; each entrypoint adds `core/` to
`sys.path` (one uniform edit), so bare cross-imports keep resolving. Order:
1. docs/ + tools/ + tests fixtures (no python-import impact) — safe first.
2. `core/` package; fix the ~19 `sys.path` entrypoints; **run idor_harness + sqli_harness, confirm still 0-FP** before commit.

### Status
- **DONE:** coordinated pipeline (`pipeline.py`) runs black-box IDOR + SQLi + white-box
  SAST (`sast_scan.py` + `nablus_rules.yml`) and reconciles them, cross-linking code
  sinks to black-box PoCs. Validated on the range: 12 confirmed + 4 corroborated, 0 FP.
- **NEXT:** physical folder move (above, import-sensitive, staged + verified) · target
  generalization beyond the range BASE (env/arg) · XSS confirm layer · MCP exposure ·
  (optional) the Shannon/Strix DeepSeek spar once WSL2+Docker is provisioned.
```
