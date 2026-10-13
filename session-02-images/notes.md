# Session 02 — Images, layers, and supply-chain risk

## Objective
Crack open an image's layers, extract a "deleted" secret that still lives in layer history,
and scan images for known vulnerabilities and secrets with Trivy — i.e. assess attack
surface #1 (supply chain) before anything runs.

## Theory

### An image is an append-only stack of layers
- Each Dockerfile instruction (`FROM`, `COPY`, `RUN`) freezes a new layer — a filesystem diff.
  At runtime Docker adds a thin writable layer on top.
- Analogy: a stack of transparent projector sheets. You see the combined picture, but every
  sheet is still there underneath.
- **Layers are append-only. "Deleting" a file in a later layer just draws over it on a higher
  sheet — the original is still in the layer where it was added, fully recoverable.**

### Five supply-chain threats
1. Known-vulnerable packages (CVEs) — highest volume; what Trivy mainly finds
2. Embedded secrets (COPY+rm trap, ENV, hardcoded keys) — T1552.001
3. Malicious images — typosquatting, poisoned/backdoored images — T1525
4. Vulnerable/malicious base images (inherited risk — turtles down several FROMs)
5. Tag mutability — `latest` is a pointer, not an identity; pin to an immutable digest

### SBOM + scanning
- SBOM = full machine-readable inventory of everything in an image (the ingredients label).
  You can't assess what you can't enumerate. Log4Shell: orgs with SBOMs just grepped for log4j.
- Scanning = cross-reference the SBOM against vuln databases (NVD/CVE) → "package X vY has
  CVE-Z, severity HIGH, fixed in W".
- Workflow: scan before running → shift left (scan in CI) → policy gate (fail build on
  fixable HIGH/CRITICAL).

## Lab A — the secret that wouldn't die (T1552.001)
- Built `leaky:v1` from the Dockerfile (COPY secret, then `cat > config && rm` it).
- Running container shows no `secrets.env` → looks clean.
- `docker history leaky:v1` → COPY and RUN(rm) are **separate layers**. The "cleanup" (rm)
  layer was **12.3 kB** — same size as the COPY layer — because it ADDED `/app/config`
  (a copy of the secret). The rm reclaimed nothing; the secret now exists in TWO layers.
- Extracted layers (`docker save` → unpack `blobs/sha256/*`) and `grep AWS_SECRET` →
  **recovered the key** from a layer, in an image where the file was "deleted".
- `<missing>` layer IDs in `docker history` are normal (only the top layer keeps a full ID).

## Lab B — Trivy

### Secret scanning has a blind spot
- `trivy image --scanners secret leaky:v1` → found NOTHING (Secrets: `-`).
- Why: Trivy's secret scanner reads the **flattened final filesystem**, not individual
  historical layers. The secret was deleted in the final view, so the surface scan — the same
  clean view that fooled the developer — misses it. History-aware tools (trufflehog, dive,
  manual layer extraction) are needed for buried-then-deleted secrets.
- Lesson: **know which layer of the artifact your scanner actually inspects.** "Clean" means
  "clean at the layer it looked", not "clean everywhere".

### Reading a CVE report (see evidence/trivy-*.txt)
Anatomy of a finding: Library · Vulnerability (CVE) · Severity · **Status** · Installed
Version · Fixed Version · Title.
- **Status** drives triage: `fixed` = patch exists, actionable → hand to ops. `affected` /
  `will_not_fix` = no patch → compensating controls + detection (my job).
- Duplicated CVEs across packages (CVE-2024-58251 under busybox/busybox-binsh/ssl_client) =
  the dependency graph; why the SBOM matters. 10 "findings" was really ~4 distinct CVEs.
- Installed→Fixed version gap IS the remediation instruction.

### The EOL trap (the real finding)
Comparing bases — same Dockerfile, different base:

| Image | Base | HIGH count | Notes |
|-------|------|-----------|-------|
| leaky:v1 | alpine 3.19.9 | 2 (musl) | **EOL** — Trivy WARNs: "no longer supported", "detection may be insufficient" |
| leaky:v321 | alpine 3.21.8 | 4 (openssl) | supported, all `fixed` (r1→r2), patchable today |

- **A newer base showed MORE HIGHs, not fewer** — different package set, different CVEs.
  Vulnerability *count* is a bad metric.
- `leaky:v1` (2 HIGH) is **more dangerous** than `leaky:v321` (4 HIGH): its base is EOL, so
  no patches are coming AND the scanner's vuln DB for that branch is frozen (the "2" is a
  floor, not a ceiling). The patchable 4 are easy; the EOL 2 require migrating off the base.
- **Running on an EOL base is itself a critical finding, independent of CVE count.**

### SBOM
- `trivy image --format cyclonedx --output sbom.json leaky:v1` → 16 components in a
  "do-nothing" ~8MB Alpine image. A real app image would be hundreds. That's the grep-able
  inventory for the next Log4Shell.

## Policy gate (CI shift-left)
- `trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed <image>` →
  non-zero exit fails the build. `--ignore-unfixed` = only block on vulns that HAVE a fix
  ("patch available = no excuse; no fix = don't block, route to detection").
- **Gotcha proved hands-on:** `--ignore-unfixed` trusts the "Fixed Version" field. On the
  EOL leaky:v1 the CVE feed still lists a fix (r6) that Alpine never shipped to 3.19, so the
  vuln is NOT filtered out → gate exits 1 (blocks) — correctly, but for the wrong *stated*
  reason ("apply r6") when the real fix is "get off the dead base".
- Robust gating needs TWO checks: the vuln gate AND an explicit EOL gate
  (`trivy image --exit-on-eol 1 <image>` → exited 1 for the honest reason). One exit code
  hides *why*; mature policy distinguishes "you were lazy (patch available)" from "your base
  is dead (migrate)" from "nobody can fix this (detect it)".

## Secrets done right (the fix neither leaky version uses)
- Principle: a secret must NEVER enter a layer (not COPY, not ENV, not a RUN referencing it).
- Build-time secret → BuildKit `--mount=type=secret` (tmpfs, never written to a layer).
- Runtime secret → mounted file or env at `docker run`, ideally from a secrets manager
  (Vault / cloud KMS) fetched at startup — gives rotation + audit.
- K8s Secrets are base64, NOT encrypted — needs encryption-at-rest + CSI secrets driver.

## Check questions — answered
1. The deleted secret is still a breach because it lives in the COPY layer permanently —
   anyone pulling the image extracts it from layer history. Needs history-aware scanning
   (surface scanners read the flattened fs and miss it); better: never put it in a layer.
2. leaky:v1 (2 HIGH) is more dangerous than leaky:v321 (4 HIGH). Count is wrong to triage on;
   the two real signals are **Status (fixed/unfixed)** and **base support status (EOL vs supported)**.
3. The `--ignore-unfixed` gate only *happened* to block the EOL image (phantom fix field) and
   won't reliably block an EOL image whose HIGH has no fix listed. Need a second explicit
   EOL check (`--exit-on-eol`) because the vuln gate structurally doesn't test for EOL.

## ATT&CK
T1552.001 (credentials in files) · T1525 (implant image) · T1612 (build to evade registry scan)
