# Session 01 — Container security threat model

## Objective
Prove, on my own machine, that a container is just a namespaced process sharing the host
kernel — and explain why that single fact defines the entire container threat model.

## Theory

### A container is NOT a VM — it's a process on the host wearing a disguise
- VM = separate house, own kernel, hypervisor wall between it and hardware. Escaping a VM
  means beating the hypervisor — rare and hard.
- Container = apartment in a shared building. Own locked door, but **one shared foundation:
  the host kernel.** No hypervisor.
- **Blast radius of a container escape = the entire host and every container on it.**
- Container escapes are usually a *misconfiguration* away, not a kernel exploit — a much
  lower bar for an attacker.

### The process really runs on the host (proved in lab)
- `sleep 3600` inside the container = PID 1. On the host = PID 7729, owned by root.
- One single process, two identities. The container didn't make a separate machine — it
  wrapped a host process in namespaces.
- Isolation is **subtractive**: a process starts with full host reach and has things taken
  away (namespaces, dropped capabilities, seccomp). Misconfigs forget to take something away.
  → "default-deny, add back what's needed" is the whole discipline.

### The three primitives that build the disguise (see / use / do)

| Primitive | Job | Question it answers |
|-----------|-----|---------------------|
| Namespaces | Isolation | What can this process **see**? (PID, mount, net, user) |
| cgroups | Limits | What can it **use**? (CPU, memory, PIDs — stops DoS on neighbours) |
| Capabilities (+ seccomp, LSM) | Privilege | What can it **do**? (which of ~40 root powers it holds) |

- User namespace (maps root-inside to unprivileged-outside) is a strong control and is
  **off by default** in Docker.
- `CAP_SYS_ADMIN` = "the new root". `--privileged` = all caps + host device access =
  "give this container root on my host".

### Five attack surfaces a defender watches
1. Malicious/vulnerable images (supply chain)
2. Misconfiguration (`--privileged`, host bind mounts, exposed Docker socket) — most incidents
3. Container escape (kernel vuln, or more often #2)
4. Secrets baked into image layers or passed as env vars
5. The daemon itself runs as root — reaching `/var/run/docker.sock` = root on host

### MITRE ATT&CK (Containers)
- T1610 Deploy Container · T1611 Escape to Host · T1613 Container & Resource Discovery
- T1612 Build Image on Host · T1609 Container Administration Command · T1525 Implant Internal Image

## Lab — what I ran and saw
- `docker exec demo ps` → sleep is PID 1 inside.
- `docker inspect --format '{{.State.Pid}}' demo` → host PID 7729, owned by root.
- `sudo lsns -p <pid>` vs `sudo lsns -p $$` → different namespace inode numbers = isolated views.
- `docker exec demo uname -r` == host `uname -r` → identical kernel. One shared foundation.

## Attack + Defend
- **Attack (T1611):** `docker run --rm -it -v /:/host alpine sh` → `cat /host/etc/shadow`.
  Read host password hashes from inside a "sandboxed" container. No exploit — just one flag.
  Read-write too.
- **Defend:** `--read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 100 --memory 256m`,
  and **don't mount sensitive host paths at all**. Hardened container: `CapEff: 0000000000000000`,
  `touch` fails (read-only fs).
- Privileged container `CapEff` = `000001ffffffffff` (41 caps on this kernel — cap 0..40,
  includes CAP_BPF, CAP_PERFMON, CAP_CHECKPOINT_RESTORE). The "all caps" value is
  **kernel-version dependent** — older kernels showed `0000003fffffffff` (cap 0..37).

## Detect
- `docker events --filter 'event=start'` fires on container start — but doesn't say it was privileged.
- IOCs (from `docker inspect`): `Privileged: true`, sensitive `Binds` (`/`, `/etc`, `/root`, docker.sock).
- Host `auditd` catches the execve (it IS a host process) but lacks container context
  (which image, privileged or not). That gap is why Falco (runtime detection with container
  context) exists.
- Falco rule keys on `container.privileged=true` — the **config flag**, never a capability
  hex string.

## Key realisations
- Detection belongs **on the host**, under all containers — the container can't hide from
  the kernel it runs on; host sensors are tamper-resistant, catch `--rm` self-deleting
  containers, and add container context.
- Nesting containers does NOT deepen isolation — every process runs on the one host kernel
  regardless of depth. Docker-in-Docker usually *weakens* security (privileged or socket mount).

## Check questions — answered
1. Container escape is worse than VM escape because containers share the **host kernel** (no
   hypervisor); break out and you're in the shared foundation next to every other container.
2. Namespaces decide what a process can **see**; capabilities decide what it can **do**.
   Matters for hardening because a perfectly-namespaced process can still be dangerous if it
   holds too much privilege.
3. `docker` group / docker.sock access = command over the root daemon = root on host.
