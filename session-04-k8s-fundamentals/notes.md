# Session 04 — Kubernetes fundamentals through a security lens

## Objective
Stand up a local cluster, name the core components and what each is an attack surface for,
and explain why securing K8s differs from securing a single Docker host.

## Theory

### Why K8s exists = where its attack surface comes from
- Docker runs containers on one host. K8s is an **orchestrator**: declare "I want 3 copies
  running" and it schedules them across machines, restarts them on crash, scales, networks.
- Analogy: Docker = one chef in one kitchen; K8s = head office commanding a restaurant chain.
- **Blast radius: Docker compromise = one host. K8s compromise = potentially the whole
  cluster** — because it's a centralised control plane with authority over everything.
- K8s doesn't replace container security — it wraps a distributed control layer around it. A
  pod is still containers sharing the node's host kernel (Sessions 1–3 still apply).

### Vocabulary ladder (smallest → biggest)
- **container** — one process in isolation, shares host kernel.
- **pod** — smallest DEPLOYABLE unit; wraps 1+ containers that share one network address +
  storage. K8s schedules pods, not bare containers. (A sidecar shares everything with the main
  container in the same pod — matters for compromise.)
- **node** — a machine (physical/VM) that runs pods. The "host" from the Docker sessions.
- **cluster** — all nodes managed together as one system.
- **control plane** — the brain: API server, etcd, scheduler, controller-manager.
- **declarative / desired state** — you declare the goal; K8s continuously reconciles reality
  to it (thermostat). Watched it live: deleted a pod, a fresh one (new name) respawned.

### Architecture + attack surface

CONTROL PLANE (the brain — attack GOAL):
- **API server** — the front door; every action is an authenticated request to it. #1 target
  (misconfigured RBAC / unauthenticated exposure = command the cluster) AND #1 detection
  source (one audit log of everything). Well-positioned to defend, not "easy".
- **etcd** — the database behind the API server. Stores all cluster state + **every Secret,
  base64 (NOT encrypted) by default**. The vault. See below — it's the RBAC bypass.
- **scheduler** — decides which node runs each pod (filter feasible nodes → score → assign).
  Abused via nodeName/affinity to place a malicious pod on a target node; DaemonSet = foothold
  on every node at once.
- **controller-manager** — reconciles desired vs actual state; holds powerful credentials.

WORKER NODE (where an attack usually STARTS):
- **kubelet** — node agent; takes orders from the API server and starts containers. Has its
  own API — if exposed/unauthenticated, exec into any pod on that node, no API-server auth.
- **kube-proxy** — pod networking; relevant to lateral movement.
- **pods** — your containers; where most attacks begin (compromised app).

### Why etcd is so sensitive (and how it's protected)
- Reading etcd leaks every secret; writing etcd = inject admin SAs / rewrite RBAC / plant pods.
- **Reaching etcd directly BYPASSES RBAC and audit entirely** — because RBAC/audit are enforced
  by the API SERVER, and etcd sits *behind* that enforcement point. Go to etcd = skip the door.
- etcd DOES authenticate (mTLS, client certs) — the point isn't "no auth", it's "behind the
  enforcement point". Base64 isn't weak crypto, it's NO crypto (fix: encryption-at-rest, off by
  default). Defence: network-isolate (only the API server reaches port 2379), client certs,
  encryption-at-rest (ideally external KMS), protect /var/lib/etcd + backups.
- Detect: anything other than the API server talking to etcd:2379 is high-signal (narrow,
  boring legit traffic → sharp anomalies).

### The attack ladder (the whole K8s security model)
> Attacker lands in a POD (bottom); the game is CLIMBING to the control plane (top).
> pod → node → control plane → cluster. Every hardening control breaks one rung.

| Where | What they have | How they got here |
|-------|----------------|-------------------|
| Pod | the pod's SA token, restricted view | compromised app / `kubectl exec` |
| Node | kubelet, ALL pods' tokens on that node, node creds | ESCAPE the pod (privileged, host mount, socket) |
| Control plane | etcd, API server — the whole cluster | from a node, or via an over-permissioned token |

## Lab — concepts made concrete (kind)
- `kind create cluster --name sec-lab` → `docker ps` shows `sec-lab-control-plane`.
  **The "node" is literally a Docker container** you can `docker exec` into. kind = Kubernetes
  IN Docker = Docker-in-Docker at cluster scale.
  - CAVEAT: node = a container here, so isolation boundaries are WEAKER than production (shared
    kernel). Learn the mechanics here, NOT the blast radius.
- `kubectl get pods -n kube-system` → the control plane runs itself as pods (etcd-,
  kube-apiserver-, kube-scheduler-, kube-controller-manager-).
- `kubectl create deployment web --image=nginx` → `kubectl scale ... --replicas=3` →
  deleted one pod → watched K8s instantly respawn a replacement (desired-state reconciliation).
- `kubectl exec` puts you in a POD (a container), NEVER the node. Pod → node is an ESCAPE.

## Security payoff — the service-account token
- **Every pod carries a SA token by default** at
  `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}` — a control-plane
  credential, whether the app needs it or not. It's the attacker's first prize.
- From inside a pod, used the token to hit the API server:
  - SelfSubjectReview → identity = `system:serviceaccount:default:default`.
  - SelfSubjectAccessReview (list secrets / create pods / get nodes) → **`allowed: false`**.
- The DEFAULT SA is correctly minimal now (good). The attack ladder exists when someone grants
  a token MORE than it needs — over-permissioned RBAC is the #1 K8s misconfig (next session).

### Why a "powerless" pod foothold is still valuable
1. "No privilege" is the default, not what you'll find — real clusters over-permission SAs
   constantly; the foothold lets the attacker hunt for one that's over-permissioned.
2. Launchpad regardless of token: network reach (other pods, internal services, cloud metadata
   169.254.169.254), escape attempts to the node, kubelet exploitation.
3. "No persistence in the pod" ≠ no persistence — pivot to durable targets: the image (T1525),
   the deployment spec in etcd, the node, cloud creds. Ephemerality pushes attackers toward the
   control plane + supply chain.

### Pod ephemerality = a detection gift
- Pod filesystems are isolated + revert to the image on restart (replicas are "cattle, not
  pets"; new pods get new names). An attacker's change to a running pod dies on restart.
- Therefore: **a pod's filesystem should match its image — drift from the image is a red flag**
  (runtime tampering, T1610). Watch for filesystem drift; protect the image + deployment spec.

## Environment
Ubuntu 24.04 · kind 0.24.0 · kubectl v1.37.1 · cluster name sec-lab (single node)

## Check questions — answered
1. The credential is the service-account token at
   /var/run/secrets/kubernetes.io/serviceaccount/token, mounted into every pod by default;
   first prize because whoever holds it inherits whatever that token can do against the API server.
2. "Pods have no perms + don't persist = useless" is wrong because (a) a token that can reach
   the API server is cluster compromise if over-permissioned, and the foothold lets you hunt
   for one; (b) even a powerless pod is inside the perimeter — recon, network reach, credential
   probing, and escape to the node.
3. Reading etcd directly defeats API-server RBAC/audit because those controls are enforced AT
   the API server, and etcd sits behind it — reaching etcd goes around the enforcement entirely,
   handing you raw state (secrets are base64, i.e. unencrypted) with no logging.

## ATT&CK
T1609 Container Admin Command · T1613 Discovery · T1525 Implant Image · (next: RBAC abuse)
