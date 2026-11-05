# Session 06 — Falco: runtime detection (the capstone)

## Objective
Run Falco, trigger earlier attacks against it live, and AUTHOR + TUNE a custom detection rule
— the detection-content skill at the core of the detection-engineering role.

## What Falco is
- Runtime security tool: watches the Linux kernel's **syscalls** in real time, enriches each
  event with container/pod context, and alerts on rule matches.
- Audit log (Session 5) = CCTV for the API server. Falco = CCTV for the **kernel**. Together they
  cover API-abuse AND in-container behaviour.
- Unites the two detection worlds: syscall-level (Sessions 1-3) + K8s audit events (Sessions 4-5).

## How a detection flows (the pipeline)
```
syscall happens (e.g. execve)
  -> caught by eBPF probe at the kernel (before anything else)
raw event
  -> Falco enriches with container id / user / process / image
enriched event
  -> checked against each rule's condition
match -> alert (output fields filled in)
```
A rule is just: which enriched events do I care about (condition) + what to say (output) + priority.

## Key mechanics (reasoned out hands-on)
- **God view from the shared kernel:** Falco (privileged, eBPF-attached) sees EVERY syscall on the
  host, across all containers — not just its own. The container can't hide from the kernel it runs
  on (Session 1's core truth paying off).
- **Container attribution via cgroups:** each process is tagged by the kernel with its cgroup; the
  cgroup name contains the container id. Falco reads it (via /host/proc) and maps id -> image via
  the Docker socket. The SAME cgroup/namespace that ISOLATES a container is what IDENTIFIES it.
- **Per-node coverage:** Falco watches ONE kernel = one node. A shell on another node is MISSED
  unless Falco runs there too. Production: deploy as a **DaemonSet** (one Falco pod per node).
  Verify no node is uncovered (tainted control-plane nodes, managed EKS/GKE control planes = gaps
  an attacker can aim for via scheduling abuse).
- **eBPF vs kernel module:** eBPF runs SAFE, verified programs in the kernel (can't crash it, no
  module to build, portable/CO-RE). The default kmod driver failed to build (scap_init error);
  `-o engine.kind=modern_ebpf` fixed it. eBPF = the modern, safe kernel tap.

## The run command, decoded
- `--privileged` — needed to load the eBPF probe (CAP_BPF/PERFMON/SYS_ADMIN).
- `-v /sys/kernel/tracing` — tracefs; eBPF reads syscall tracepoint IDs here to attach (the mount
  that fixed the scap_init error). Docker bind mounts aren't recursive, so mount the tracefs mount
  point directly, not /sys/kernel/debug.
- `-v /proc:/host/proc:ro` — read every process's cgroup/namespaces to attribute to a container.
- `-v /var/run/docker.sock` — resolve container id -> image name.
- Each mount = one pipeline job: attach / identify / name.
- IRONY: Falco itself is a privileged container with the Docker socket mounted — exactly the
  Session 3 socket-escape pattern it would detect. => context matters; ALLOWLIST legit tools
  (Falco) while alerting on everything else that's privileged+socket. (Same FP-tuning lesson as S5.)

## Rules: default + custom
- Falco ships a community default ruleset at /etc/falco/falco_rules.yaml (hundreds of rules;
  "Terminal shell in container" is one — it fired on `docker run -it alpine sh`).
- Custom rules go in /etc/falco/falco_rules.local.yaml or /etc/falco/rules.d/*.yaml.
- Mount custom rules from the host (don't edit in-container — the --rm filesystem is disposable,
  Session 2). This keeps them persistent and version-controlled ("detection as code").

## The capstone — authored + tuned a custom rule (see rules/credential-file-read.yaml)
- v1: `fd.name contains "shadow"` — WORKED but over-matched (would false-fire on
  /app/shadow-config.json, /var/log/shadowd.log, etc.).
- v2 (tuned): a `list` of exact credential files + `fd.name endswith "/shadow"` (covers the
  bind-mount variant /host-etc/shadow). Precise, ATT&CK-mapped (T1552.001).
- A/B PROVEN (see evidence/detection-ab-test.txt): real /host-etc/shadow -> FIRES CRITICAL;
  lookalike /app/shadow-config.json -> SILENT. The full loop: author -> test -> tune -> validate.

## Rule anatomy (reference)
```yaml
- list: credential_files            # reusable set of values
  items: ["/etc/shadow", ...]
- rule: <name>                      # shows in the alert
  desc: <human description>
  condition: <logic - stack macros/fields with and/or>   # WHEN to fire
  output: <alert text with %fields> # WHAT to say
  priority: CRITICAL|WARNING|...    # severity
  tags: [..., T1552.001]            # ATT&CK mapping
```
- macros = named reusable condition pieces (open_read, container, shell_procs).
- lists = named reusable value sets (credential_files).
- Build small pieces, snap them into conditions — reads like English.

## ATT&CK
T1552.001 (credentials in files) · T1059 (shell execution) · plus the Session 1-5 techniques Falco
can also catch at runtime (T1610/T1611 escape, etc.)
