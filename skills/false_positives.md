# Skill: False-Positive Catalog (web authz / access-control testing)

The #1 reason an autonomous web tester looks useless is it cries wolf. Every candidate must
survive these rule-outs before it becomes a finding. Golden rule: **a finding needs positive
proof of impact (content retrieved that shouldn't be, or a privilege diff), reproduced once.**
"Status != 404" is NOT a finding.

## FP-1  SPA soft-404 (the big one)
Modern SPAs (Next.js, Angular, React-Router) return **HTTP 200 for every path**, serving the
app shell; the real routing/gating happens in the browser.
- Oracle: fingerprint the soft-404 by GETting 3 random nonexistent paths (status + body len).
  If a candidate's response is `text/html` and contains the shell markers (`<!doctype html`,
  `_next/static`, `main.*.js`, `ng-version`), it is the shell — **not** an exposure.
- Only flag when the body is a real file (pdf/json/csv/zip/octet-stream) or API data, or its
  content materially differs from the shell.

## FP-2  403 / 401 is protection, not exposure
A `.env`, `/admin`, `/api/*` returning 401/403 means access control *worked*.
- Oracle: never flag 401/403. Only 200 + real content counts.

## FP-3  Redirect-to-login counts as gated
A 3xx whose `Location` points at `/login`, `/signin`, or an IdP = access control working.
- Oracle: treat 301/302/303/307/308 toward an auth page as "gated", not a finding.

## FP-4  Generic WAF / platform error pages
Vercel/Cloudflare/Akamai serve fixed-size generic pages for blocked or missing resources.
- Oracle: baseline those pages' size/hash; responses matching them are not findings.

## FP-5  Reflected `?next=`/`?url=` without an actual redirect
Seeing your value echoed in HTML is not an open redirect.
- Oracle: only flag open-redirect when a **3xx** is returned AND `Location` resolves to an
  off-origin host you supplied. No 3xx off-origin = no finding.

## FP-6  405 / method-not-allowed on an API route
Hitting `/api/x` with GET and getting 405 just means it wants POST. Not a vuln.

## FP-7  Intended-public assets
`robots.txt`, `sitemap.xml`, `/public/*`, marketing PDFs, a public `/papers/legal.md`.
- Oracle: a file being reachable is only a finding if it's meant to be gated/paid. Mark these
  `needs_human_confirm` — a human decides sensitivity; the tool proposes, it doesn't assert.

## FP-8  Tech/version banners
`Server: Vercel`, `X-Powered-By` = info disclosure at most. Not a finding unless it maps to a
known, exploitable CVE for that exact version.

## FP-9  Permissive CORS / headers with no PoC
`Access-Control-Allow-Origin: *` on a public, unauthenticated endpoint is not exploitable.
- Oracle: only flag if the endpoint returns authenticated data AND reflects an arbitrary origin
  with credentials. Needs a working PoC.

## FP-10  Self-XSS / theoretical issues
No cross-user or cross-privilege impact = not a reportable finding.

---
### Confirmation requirements (promote candidate -> finding)
1. **Reproduce** the request a second time; same result.
2. **Prove impact**, minimally:
   - file exposure: the first bytes of the real file (`%PDF`, JSON keys) — not the whole file.
   - authz/IDOR: a **differential** — identity B obtains identity A's object/content.
   - open redirect: the 3xx `Location` off-origin.
3. Everything else is a **lead**, not a finding. Leads go to a review queue, not the report.
