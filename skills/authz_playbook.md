# Skill: Authorization / Business-Logic Test Playbook

The valuable, hard-to-automate layer. Template scanners miss all of this. Source methodology:
OWASP WSTG (Authorization, Session, Business Logic), OWASP API Top 10 (BOLA/BFLA).

## Core principle: ONE identity cannot prove authz
Authorization bugs are *differential*. You need multiple contexts and you compare responses:
- `anon`  (no session)
- `userA` (low-priv test account #1)
- `userB` (low-priv test account #2, owns different objects than A)
- `admin` (if available)
A finding exists when a lower-privileged context obtains something only a higher/other one should.

## Classes, detection, and the confirmation oracle

### BOLA / IDOR (broken object-level authz)  — highest value on data apps
- Find object references as userA (IDs in URLs, `/api/x/{id}`, JSON `id`/`ownerId` fields).
- Replay the exact request as userB (and anon). 
- **TP oracle:** userB's response contains userA's object/data. Proof = the record, one row.
- Common shapes: sequential ints, guessable UUIDs, `/rest/basket/{id}`, `/api/orders/{id}`.

### Broken function-level access (BFLA)
- Enumerate admin/privileged routes + their APIs.
- **TP oracle:** anon or userA hits an admin API and gets 200 + real admin data (not the SPA shell).
- Note: the HTML admin *page* returning a 200 shell is FP-1 — test the **API** it calls.

### Unauthenticated file / resource exposure
- GET sensitive-looking paths as anon: backups, `/ftp/*`, keys, `.kdbx`, gated PDFs, exports.
- **TP oracle:** 200 + real non-shell file bytes (correct content-type), reproduced.
- Root-cause pattern: gated files served as static assets by path instead of behind an auth
  API / signed expiring URL.

### Paywall / entitlement bypass
- Call the unlock/entitlement API or fetch the gated resource as an un-entitled identity.
- **TP oracle:** gated content or an unlock token returned to someone who didn't pay.

### Open redirect
- Manipulate `?next=/url=/return=` to an off-origin URL you control.
- **TP oracle:** a 3xx with `Location` pointing off-origin (see FP-5).

### Auth weaknesses (read-only probes)
- Login rate-limit: N rapid attempts with a **bogus** username (never lock a real account);
  TP = no throttle/lockout after many failures.
- JWT: `alg:none` / signature strip accepted; secret is weak/guessable; token carried in URL.
- Session: token not rotated on login, no expiry, predictable reset tokens.

### Mass assignment  — STATE-CHANGING, queue for approval
- POST/PUT a profile/object with extra fields (`role:admin`, `entitlement:paid`, `verified:true`).
- **TP oracle:** the extra field persists / elevates. Because this writes, it is NEVER auto-run
  — propose it to the human review queue.

## Evidence discipline
Prove **access**, don't hoard **data**. One record / the file's first bytes / the privilege diff
is the finding. Mass-extracting a target's data increases their breach exposure, puts their
crown-jewel data on your box, and (if ever sent to an external model/API) breaches engagement
confidentiality. Capture the minimum that proves impact, then stop.

## Scope discipline
Every request host must be in the authorized scope (exact or subdomain of an authorized apex).
Out-of-scope hosts discovered in responses are recorded, never actively tested.
