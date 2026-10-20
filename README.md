# cleansbom — Dependabot + Trivy SBOM demo

A small two-language app (npm frontend/BFF + uv-managed Python backend) whose lockfiles were
resolved **as of 2024-03-01** (`npm install --before`, `uv lock --exclude-newer`), so it carries a
realistic spread of vulnerable dependencies. It demonstrates:

1. Direct vs transitive security updates — and the transitive ones that **cannot** be fixed
2. devDependencies vs production dependencies
3. Why npm, uv and a plain `requirements.txt` behave differently
4. Pinning an unfixable transitive dependency — and what that costs
5. One container SBOM where Trivy discovers OS + npm + Python packages from the image itself

All numbers below come from running Trivy 0.76.0 against this repo on 2026-10-20. Re-run
`scripts/sbom.sh` and they will drift as new advisories are published — that is the point.

```
frontend/                 Vite SPA + Express BFF  (package.json, package-lock.json)
  test/request-smoke.cjs  exercises every transitive dep of `request` we might pin
backend/                  FastAPI app managed by uv (pyproject.toml, uv.lock)
  legacy/                 the same deps as requirements.txt, pinned and unpinned
examples/
  frontend-pinned/        npm `overrides` that fix request's transitive deps (works)
  frontend-pinned-broken/ same + uuid override (breaks request at load time)
  backend-override/       uv `override-dependencies` forcing starlette (breaks fastapi)
Dockerfile                multi-stage; final image has node + python, no dev deps, no SBOM
.github/dependabot.yml    npm + uv + docker + actions, security PRs grouped by prod/dev
.github/workflows/        ci, sbom generation, Dependabot PR triage/auto-merge
.trivyignore.yaml         accepted-risk register (statement + expiry) for unfixable findings
scripts/sbom.sh           generates every SBOM + a triage report
scripts/report.py         summarises Trivy JSON by direct/transitive × prod/dev
```

## Quickstart

```sh
(cd frontend && npm ci)                 # local dev
(cd backend && uv sync)
docker build -t cleansbom-demo:latest .
docker run --rm -p 3000:3000 cleansbom-demo:latest   # http://localhost:3000

./scripts/sbom.sh                       # all SBOMs -> sbom/*.cdx.json, scans -> sbom/scans/
python3 -I scripts/report.py sbom/scans/frontend.dev.json --detail
```

Report output (abridged):

```
frontend      :: package-lock.json [npm]   pkgs=111 vulns=57   direct/prod=34 transitive/prod=23
frontend.dev  :: package-lock.json [npm]   pkgs=156 vulns=85   … direct/dev=16 transitive/dev=12
backend       :: uv.lock [uv]              pkgs=20  vulns=29   direct/prod=7  transitive/prod=22
backend.dev   :: uv.lock [uv]              pkgs=28  vulns=31   … direct/dev=2
backend-legacy-requirements :: requirements.txt [pip]  pkgs=4  vulns=7   unknown=7
image :: debian 12.15 [debian]             pkgs=105 vulns=282  unknown=282
image :: Node.js [node-pkg]                pkgs=112 vulns=57   unknown=57
image :: Python [python-pkg]               pkgs=19  vulns=35   unknown=35
```

---

## 1. Direct vs transitive security updates

Dependabot **version updates** (the `schedule:` in `dependabot.yml`) only touch direct deps.
Dependabot **security updates** start from an alert, which can be on a transitive dep, and are
opened as soon as the alert fires regardless of schedule. Every vulnerable package here falls into
one of four buckets — and the bucket, not the severity, decides what the fix looks like:

| Bucket | npm examples | Python examples | What the fix PR changes |
|---|---|---|---|
| **A. Direct** | `axios` 1.6.7, `express` 4.18.3 | `requests` 2.31.0, `jinja2` 3.1.3 | manifest (if range needs it) + lockfile |
| **B. Transitive, fix fits parent's range** | `follow-redirects` 1.15.5 (axios wants `^1.15.4`), `form-data` 4.0.0 (axios `^4.0.0`), `ajv` 6.12.6 (har-validator `^6.12.3`), `proxy-addr` 2.0.7 (express `~2.0.7`) | `urllib3` 2.2.1, `idna` 3.6, `certifi` (requests `<3`, `<4`, `>=`), `h11` 0.14.0 (uvicorn `>=0.8`), `anyio` 4.3.0 (starlette `<5`) | **lockfile only** — manifest untouched |
| **C. Transitive, parent must move** | `body-parser` 1.20.2, `path-to-regexp` 0.1.7, `cookie`, `send`, `serve-static`, `qs` 6.11.0 — express 4.18.3 pins them exactly or with `~`; express **4.22.3** allows the fixes | `starlette` 0.36.3 — fastapi 0.110.0 declares `starlette<0.37.0`; current fastapi declares `>=0.46.0` | **parent's version** in manifest + lockfile. PR title names the parent, but it's a security PR |
| **D. Transitive, unfixable** | everything under `request` 2.88.2 (deprecated, no release since 2020): `form-data` 2.3.3 (`~2.3.2`, CRITICAL CVE-2025-7783, fix 2.5.4), `qs` 6.5.3 (`~6.5.2`, fix 6.14.1), `tough-cookie` 2.5.0 (`~2.5.0`, fix 4.1.3), `uuid` 3.4.0 (`^3.3.2`, fix 11.x), and `request` itself (CVE-2023-28155, no fix exists) | — | **nothing** — Dependabot can't open a PR; the alert shows why. See §4 |

Commands to reproduce the classification yourself:

```sh
cd frontend && npm explain form-data          # two copies: 4.0.0 via axios, 2.3.3 via request
npm view request@2.88.2 dependencies          # the ~ ranges that trap the vulnerable versions
cd ../backend && uv tree --invert --package starlette   # who holds starlette back
```

> **Trivy's "Fixed Version" column only says a fixed release exists.** It doesn't say
> your parent will accept it. `tough-cookie` shows `fix=4.1.3`, but nothing short of replacing
> `request` gets you there legitimately. Bucket D only shows up once you compare the fixed
> version against the parent's range.

## 2. devDependencies vs production dependencies

| | Production | Development |
|---|---|---|
| npm | `dependencies` | `devDependencies` (`vite`, and transitively `esbuild`, `rollup`, `postcss`, `nanoid`) |
| uv | `[project].dependencies` | `[dependency-groups].dev` (`pytest`, `black`) |
| Trivy `fs` default | **scanned** | **hidden** — needs `--include-dev-deps` (57 → 85 npm findings) |
| Dependabot | alert scope `runtime` | alert scope `development`; the config groups dev security PRs separately so they don't queue behind (or block) prod fixes |
| Container | installed (`npm ci --omit=dev`, `uv sync --no-dev`) | **absent** — verified, no vite/esbuild/rollup/black/pytest in `sbom/image.cdx.json` |
| CycloneDX SBOM | — | **the dev flag is lost.** Trivy keeps the dependency graph, but re-scanning the SBOM returns `Dev: null`. Downstream tools like Dependency-Track can't tell them apart — generate `frontend.cdx.json` (prod) and `frontend.dev.cdx.json` separately, as `sbom.sh` does |

Dev doesn't automatically mean safe to ignore. A compromised build tool runs on dev machines and
CI with secrets in scope, and some (vite's dev server, `GHSA-67mh` in esbuild's serve mode) are
network-exposed during development. Treat dev findings as lower **urgency**, not zero risk.
Note too that the dev bucket has its own bucket-C problem: `esbuild` 0.19 needs vite **6** (major)
to reach the fix, and several vite CVEs are only fixed in 6.4.3+, while the latest 5.x is 5.4.21.

## 3. Language differences — and why `requirements.txt` isn't enough

**npm nests; Python doesn't.** npm installs `form-data` 4.0.0 for axios *and* 2.3.3 for request
side by side. That lets you fix one consumer's copy without touching the other (the scoped
`overrides` in §4). A Python environment has exactly **one** `urllib3`, so every bump or pin
applies to every consumer at once. Resolution is global, and conflicts are harder.

**What each file actually tells a scanner:**

| File | Transitive deps visible? | Direct/transitive known? | Dev/prod known? | Trivy finds |
|---|---|---|---|---|
| `frontend/package-lock.json` | yes, with ranges | yes | yes | 57 (prod) |
| `backend/uv.lock` | yes | yes | yes (groups) | 29 (prod) |
| `backend/legacy/requirements.txt` (`==` pins) | **no** — only the 4 listed packages | no | no | **7** — misses starlette, urllib3, idna, certifi, h11, anyio |
| `backend/legacy/requirements-unpinned.txt` (`>=`) | no | no | no | **0 packages** — no versions, nothing to match |

Dependabot has the same blind spot. The dependency graph only sees what's in the file, so
transitive alerts and transitive security PRs can't happen for a hand-written requirements file.
Teams on pip usually get closer with `pip-compile` (the `# via` comments make it a lockfile),
but uv gives you a real lockfile, dependency groups, and `package-ecosystem: "uv"` support in
Dependabot.

Ecosystem caveats worth checking against current GitHub docs: Dependabot's transitive
security-update coverage differs per ecosystem, and uv support is newer than npm's. If a uv
security PR doesn't appear for a bucket B package, the manual fix is one command:
`uv lock --upgrade-package urllib3`.

## 4. The unfixable transitive dependency — and pinning it

`request` is the textbook case: deprecated, every vulnerable child is held back by a `~` range,
and no new `request` release will ever widen them. Your options, from best to worst:

1. **Remove the parent.** Replace `request` with axios or `fetch` (it's only used by
   `/api/legacy`). This is the only option that clears everything, including `request`'s own CVE.
2. **Pin the children with npm `overrides`**, scoped to `request` so axios's copy is unaffected:

   ```json
   "overrides": {
     "request": { "form-data": "2.5.6", "qs": "6.16.1", "tough-cookie": "4.1.4" }
   }
   ```

   See `examples/frontend-pinned/`. Result: the request subtree drops from 7 findings to 2,
   and `test/request-smoke.cjs` still passes.
3. **Accept the risk explicitly** for what's left (`request` itself and `uuid`) in
   `.trivyignore.yaml`, with a statement and an `expired_at`, so it resurfaces for review.
   `trivy … --ignorefile .trivyignore.yaml --show-suppressed` keeps it visible in reports.

### The risks of pinning (all demonstrated here)

- **You're running a combination nobody tested.** `request` declares `tough-cookie ~2.5.0`; you're
  giving it a 4.x major. It works *here* because the smoke test covers the cookie-jar path. Without
  that test you'd be guessing.
- **It can just break.** `examples/frontend-pinned-broken/` also overrides `uuid` to 14.x.
  `request` does `require('uuid/v4')`, a deep import uuid removed in v8. The result is
  `ERR_PACKAGE_PATH_NOT_EXPORTED` the moment `request` loads. npm install succeeds silently.
- **The blast radius is bigger than the pin.** Three overrides changed or added ~20 *other*
  packages in the lockfile: `tough-cookie` 4 pulls in `url-parse`/`querystringify`/`universalify`,
  and `qs` 6.16 replaces the whole `side-channel`/`get-intrinsic` tree. All of that is new code
  to review and new attack surface.
- **Python pins are global and ignore declared ranges.** `examples/backend-override/` uses
  `[tool.uv] override-dependencies = ["starlette==1.3.1"]` to clear 7 starlette findings while
  keeping fastapi 0.110.0. `uv lock` succeeds, Trivy reports 0 starlette vulns, and the app dies on
  import: `TypeError: Router.__init__() got an unexpected keyword argument 'on_startup'`.
  The right fix for that one is bucket C: bump fastapi. (`constraint-dependencies` is the safer
  uv tool — it narrows within declared ranges instead of overriding them.)
- **Pins rot.** An override is a hard-coded version outside your manifest's normal ranges.
  Review each one when the parent changes or on a fixed cadence, and delete it when the parent is
  gone. Otherwise it quietly becomes the next stale dependency.
- **A green scanner isn't proof the app works.** In both broken examples the SBOM looks
  better than before. Gate pins on tests that exercise the pinned code path. `ci.yml` runs the
  smoke test for exactly this reason.

## 5. The container SBOM

The final image is `python:3.12-slim-bookworm` + a Node binary copied from `node:22-bookworm-slim`
+ production `node_modules` + a uv-built `.venv`. **No SBOM or lockfile analysis is copied in**.
Trivy works it out from the filesystem:

```sh
trivy image --format cyclonedx -o sbom/image.cdx.json cleansbom-demo:latest
# 105 deb (dpkg status), 112 npm (node_modules/*/package.json), 19 pypi (*.dist-info/METADATA)
```

What the image scan tells you that the source scans don't:

- **OS packages:** 282 Debian findings (2 CRITICAL, 61 HIGH). **None** are fixable by an apt
  upgrade: 212 `affected`, 53 `fix_deferred`, 17 `will_not_fix`. The levers are base-image bumps
  (the `docker` entry in `dependabot.yml`), a smaller base (distroless, chainguard), or
  `--ignore-unfixed` in gates, which is why `sbom.yml` reports OS findings but doesn't gate on them.
- **Things outside your lockfiles:** the base image's own `pip` 25.0.1 shows up with 6 findings.
  That's why the image has 35 Python findings vs `uv.lock`'s 29. Neither Dependabot's uv
  updates nor `uv.lock` will ever touch it. Only a base-image bump will.
- **Proof dev deps didn't ship:** the image matches the prod-only lockfile scan (57 npm) and
  contains none of the dev bucket.

What the image scan **loses or can't see** (this is why you scan both):

- **Direct vs transitive.** Every npm/Python package in the image is `Relationship: unknown`,
  because installed metadata has no dependency intent. Triage (bucket A–D) needs the lockfile scan.
- **The Node runtime.** `/usr/local/bin/node` was copied in as a bare binary, so it isn't in the
  SBOM at all. Node CVEs would go unreported.
- **The Python interpreter.** Official Python images build CPython from source into `/usr/local`,
  not via dpkg, so CPython itself isn't listed either. Only `pip` is.
  Track both runtimes via the base image tags (Dependabot `docker`) and record their versions
  explicitly if you need them in the SBOM.

## Dependabot setup notes

- Turn on **Dependabot alerts** and **Dependabot security updates** in repo settings. The YAML
  alone only configures version updates.
- `dependabot.yml` groups **prod security** and **dev security** PRs separately per ecosystem, so a
  vite major bump can't hold up an express security fix.
- `dependabot-triage.yml` labels each PR with `scope:direct:production` / `scope:direct:development` /
  `scope:indirect` and `security`, then enables auto-merge for non-major security fixes once
  `ci.yml` passes. This needs branch protection with required checks. `alert-lookup` may
  need a token with Dependabot-alert read access.
- The dependency graph will also detect `backend/legacy/requirements*.txt` and everything under
  `examples/`. That's useful for the demo, noisy in a real repo.
- For the backlog of things that can't be fixed yet: open Dependabot alerts (filter by
  scope/severity in security overview), `.trivyignore.yaml` entries with expiry, and the SBOMs from
  `sbom.yml` fed into Dependency-Track if you want analysis state and VEX across repos.
