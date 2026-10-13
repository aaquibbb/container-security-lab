# Session 03 — The Docker daemon and socket

## Objective
Escape a container to full root on the host by abusing a mounted Docker socket, then harden
against it and know what a defender watches for.

> SAFETY: the socket escape gives real root on the real host. Only ever on a personal lab box
> you own. It's the actual technique used in real breaches, not a toy.

## Theory

### The daemon is root; the socket is its unauthenticated remote control
- `docker` (client) just sends requests to `dockerd` (daemon), which runs as **root** and does
  the actual work. They talk over `/var/run/docker.sock` — the daemon's API exposed as a file.
- **Anything that can write to the socket can command the root daemon = root on host.** No
  second auth layer. The socket IS the trust boundary — just a file with Unix permissions.
- Socket perms seen: `srw-rw---- 1 root docker` (mode 660). So: root + anyone in the `docker`
  group. That's why `docker` group membership = root-equivalent (audit it like sudoers).

### Two INDEPENDENT paths to host-root

| Path | What you mount | Mechanism | Needs the daemon? |
|------|----------------|-----------|-------------------|
| A — bind mount | `-v /:/host` | host fs is already in your container; `cat /host/etc/shadow` | No |
| B — socket escape | `-v /var/run/docker.sock` | hold the daemon's remote control; ask it to spawn a privileged container that mounts `/` | Yes |

- Path B is **borrowed authority**: the compromised container is NOT privileged itself — it
  just holds the radio to the root daemon and asks the daemon to build a privileged container.
  The isolation was never bypassed; it was made irrelevant.
- These are detected differently — a privileged-only rule misses both the bind-mount path and
  the socket path (neither needs `--privileged`).

## Lab A — the socket escape (T1610 → T1611)
1. `docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock docker:cli sh`
   — an ordinary, UNPRIVILEGED container that happens to have the socket mounted (like a CI
   runner or monitoring agent).
2. Inside: `docker ps` → lists the HOST's containers (talking to the host daemon). T1613.
3. `docker run -it --rm --privileged -v /:/host alpine sh` → asks the host daemon to spawn a
   privileged sibling that mounts the host fs.
4. Inside that: `cat /host/etc/shadow` → **host root hashes**; wrote `/host/tmp/escape_proof.txt`.
   Verified the file on the host afterwards. Full host compromise, no kernel exploit.

### `--privileged` vs `-v /:/host` (proved)
- Reading host files via `-v /:/host` works WITHOUT `--privileged` (container-root + mount is
  enough). `--privileged` adds device access (`ls /dev` shows far more) but isn't needed for
  file reads.
- A `Privileged: true`-only detection rule misses the bind-mount attack entirely.

### `--privileged` vs `--cap-add` (proved)
- `--privileged` flips a master switch (`Privileged: true`) and leaves `.HostConfig.CapAdd`
  **empty**. `--cap-add SYS_ADMIN` populates `CapAdd` but leaves `Privileged: false`.
- Two routes to too-much-privilege → a rule checking only `CapAdd` misses privileged containers,
  and vice versa. Check both (and ideally effective caps at runtime).

## Lab B — hardening

### Defence 1: socket proxy (least privilege for the API)
- `tecnativa/docker-socket-proxy` holds the real socket; other containers talk to it over a
  localhost port. `CONTAINERS=1` allows read/list, `POST=0` forbids all mutating calls.
- Result: compromised monitoring container can `docker ps` (works) but the escape
  `docker run --privileged ...` → **403 Forbidden** (creation is a POST).
- Caveat: only as good as its policy (`POST=1`/`EXEC=1` reopens the hole); the proxy still
  holds the raw socket, so compromising the proxy = full daemon access. Mitigation, not cure.

### Defence 2: rootless Docker (structural fix)
- Run the whole daemon as a non-root user. The socket escape still *runs* (spawns a container),
  but container-root is mapped via user namespaces to the unprivileged host user — so
  `cat /host/etc/shadow` → **Permission denied**. Same host file, downgraded identity.
- Neutralises the entire attack class: escape lands as an unprivileged user, not root.

| Scenario | Socket escape result |
|----------|----------------------|
| Root daemon | host /etc/shadow readable → full host compromise |
| Rootless daemon | Permission denied → escape neutralised |

## Detect

### Config-time IOCs (`docker inspect`)
Alert if a container's `Binds` contains `/var/run/docker.sock` OR a sensitive host path
(`/`, `/etc`, `/root`, `/var`) OR `Privileged: true` OR `CapAdd` has SYS_ADMIN/BPF. Note the
**OR** — any one alone is a breach. (Also: a container that exits immediately, like
`alpine sh` with no TTY, won't show in `docker ps` — needs `sleep 3600` or `-it` to stay up.)

### Runtime IOCs (Falco — catches what config-time misses, incl. `--rm` containers)
- Path B: a process INSIDE a container opening `/var/run/docker.sock` (containers don't manage
  containers). `container.id != host` is the key discriminator.
- Path A: a containerized process reading `/host/etc/shadow` or other sensitive host files.
- A new container starting `privileged=true`.
Two separate rules for two separate paths, different ATT&CK tags (T1611 escape vs T1552 creds).

## Check questions — answered
1. Privileged-only rule does NOT fire on a socket-mounted container (it's `Privileged: false`),
   but the container IS dangerous — the mounted socket lets it command the root daemon. Gap:
   the rule watches the wrong indicator; must also key on `docker.sock` in `Binds`.
2. Under rootless Docker the escape fails because the spawned container's "root" is mapped via
   user namespaces to an unprivileged host user — same host /etc/shadow, but the effective
   identity lacks permission to read it. Under the rootful daemon container-root = real root.
3. A `POST=0` proxy is not "the socket is now safe" — it's only as good as its policy
   (one misconfig like POST=1/EXEC=1 reopens it), the proxy still holds the raw socket, and a
   read-only call can still leak secrets. Structural fix is rootless, not a filter.

## ATT&CK
T1610 Deploy Container · T1611 Escape to Host · T1613 Discovery · T1552.007 Creds from Container API
