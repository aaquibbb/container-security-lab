# container-security-lab

Hands-on container and Kubernetes **security** study — defender/detection-engineering focused.
Every session: theory (security angle first) → hands-on lab on Linux → attack + defend →
detect → notes. Labs run on Ubuntu 24.04 LTS with Docker and (later) kind.

The through-line: understand Docker and Kubernetes only as far as securing, attacking, and
**detecting** them requires. Every concept maps back to — what can go wrong, how an attacker
abuses it, how to harden it, and how a SOC detects it. Attacks are tagged to the
MITRE ATT&CK Containers matrix.

## Sessions

| # | Topic | Key takeaway |
|---|-------|--------------|
| 01 | Container threat model | A container is a disguised host process; isolation is subtractive; blast radius of an escape = the whole host |
| 02 | Images, layers, supply chain | Layers are append-only — "deleted" secrets persist; scan before running (Trivy); EOL base is worse than a higher CVE count |
| 03 | Docker daemon & socket | The daemon is root; the socket is its unauthenticated remote control; two independent paths to host-root (bind mount vs socket) |
| 04 | Kubernetes fundamentals | Centralised control plane = cluster-wide blast radius; every pod carries a service-account token; attack ladder = pod → node → control plane |

## Environment

- Ubuntu 24.04 LTS
- Docker Engine 29.6.1
- Trivy 0.74.0 (image/secret/vuln scanning)
- kind 0.24.0 + kubectl v1.37.1 (local Kubernetes)

## Recurring lesson (detection engineering)

Across every session the same meta-lesson kept surfacing: **there is more than one route
to an attacker's objective, and a detection that watches only the famous route is blind to
the others.** Examples found hands-on:

- `CapEff` hex string vs the `Privileged` config flag (kernel-version dependent)
- `--privileged` vs `--cap-add` (privileged leaves `CapAdd` empty)
- `-v /:/host` bind mount vs `--privileged` (the mount reads host files without privilege)
- bind-mount path vs Docker-socket path to host-root
- `--ignore-unfixed` vs an EOL base (the fix field can't tell a backported fix from a phantom one)

Good detection enumerates *all* paths to an objective — which is exactly what the MITRE
ATT&CK matrix is for.
