# Session 05 — The attack ladder weaponised: RBAC + API audit detection

## Objective
Grant a pod's service account too much (the #1 real-world K8s misconfig), watch the climb
from pod to cluster-secret-theft succeed, lock it down with least-privilege RBAC, and
detect the climb in the API server audit log.

## Theory

### RBAC = identity + permission-set + binding
- **Subject** — who is asking (user, group, or service account — the one pods use).
- **Role / ClusterRole** — a permission set = **verbs x resources** ("get,list on secrets").
  Role = namespace-scoped; ClusterRole = cluster-wide.
- **RoleBinding / ClusterRoleBinding** — the glue that grants a Role to a Subject.
- Every grant reads as one sentence: "Subject X can Verb (get/list/...) Resource Y in scope Z."
- IAM parallel: ServiceAccount = user, Role = policy, Binding = attach policy to user.

### Verbs x resources — which combos are secretly takeover
Most combos are harmless recon. The dangerous ones let the holder reach a MORE privileged state:
| Permission | Why dangerous | ATT&CK |
|---|---|---|
| get/list **secrets** | steal creds + other SA tokens | T1552 |
| create **pods** | privileged pod -> node compromise | T1610->T1611 |
| create **pods/exec** | run code in any workload | T1609 |
| **escalate / bind** on roles | promote self to cluster-admin | T1078 |
| **impersonate** | act as any identity | T1078 |
| `*` on `*` (cluster-admin) | own everything | T1078.001 |
- RBAC audit red flags: **secrets, create pods, escalate/bind/impersonate, wildcards.**

### RBAC is ADDITIVE (the lesson most people miss)
- There is NO "deny." An identity's power = the UNION of every binding attached to it.
- Adding a tight Role does NOT remove a broad one. To reduce access you must DELETE the broad
  binding, not layer a narrow one on top.

## Lab A — the attack (RBAC abuse, through the API server)
- Planted secret `db-creds`. Created `app-sa`, a `secret-reader` ClusterRole (get,list secrets),
  bound cluster-wide with a ClusterRoleBinding. Ran `attacker-pod` with serviceAccountName: app-sa.
- From inside the pod, used the mounted token to GET db-creds -> 200 + base64 data. Breach.
- The pod's `serviceAccountName` field is what makes it inherit app-sa's identity + token + perms.

## Lab A contrast — default SA fails
- Identical pod/image/attack with the `default` SA -> `allowed: false` / 403 Forbidden.
- Only difference = the RBAC grant. The vulnerability was never the pod/image/attacker — it was
  the permission. (`default` SA has only the baseline: selfsubject* reviews + discovery/health
  URLs; no `secrets` line.)

## Lab B — least-privilege fix
- Scoped Role (namespaced, not ClusterRole) with `resourceNames: ["db-creds"]` and `verbs: ["get"]`
  — read ONE named secret, no `list`. Bound with a RoleBinding (namespaced).
- CRUCIAL: deleted the broad `app-sa-binding` ClusterRoleBinding (RBAC is additive).
- Result: `get secret/db-creds` = yes, `list secrets` = no, `get other` = no. App works, blast
  radius gone. The `list` attack now returns 403.
- Note: env-var / volume secret mounts need NO secret RBAC at all (kubelet injects them) — so the
  over-grant was often unnecessary in the first place. Only apps that query the API dynamically
  (and operators) need `get` on specific secrets.

## Two bypasses discovered
- **Bearer token:** the SA token is a bearer credential — whoever holds it AND can reach the API
  server IS that identity, from anywhere (proved by reading the secret from the laptop with the
  stolen token, no pod involved). => guard tokens + guard who can reach the API server; prefer
  short-lived projected tokens.
- **etcd / node bypass:** reading the secret directly from etcd on the control-plane node returned
  `SuperSecret123` in PLAINTEXT — no RBAC, no 403. RBAC is enforced at the API server; etcd sits
  behind it. => node access = game over; enable encryption-at-rest; need node-level detection
  (Falco) as well as API-level.

## Lab C — detection in the audit log
- Everything was an API call; the audit log recorded it. Found the theft by filtering for
  app-sa + db-creds.
- Trustworthy (server-asserted, UNSPOOFABLE) fields to key detection on:
  `user.username`, `verb`, `objectRef.resource/name`, `responseStatus.code`,
  and the `authorization.k8s.io/reason` annotation (names the exact binding that allowed it).
- Spoofable (client-set) fields — booster ONLY, never a primary key: `userAgent`, `sourceIPs`.
  PROVED by re-running the attack with `curl --user-agent "kubectl/v1.31.0..."` — the UA lied,
  but the detection still fired because it keys on server-asserted fields.
- `list` >> `get` for malice: get = targeted (legit apps read their own named secret);
  list = enumeration (attacker dumping everything because they don't know the names yet).

## The audit-log-leaks-secrets trap (found hands-on)
- Logging secrets at `RequestResponse` level writes the secret VALUE into the audit log ->
  shipped to the SIEM -> credentials duplicated across logging infra, readable by anyone with
  log access. Often worse than the original exposure.
- Fix: log secrets at **Metadata** level (who/what/when, no body). Confirmed: the Metadata-level
  event has NO responseObject/secret data, but all detection-useful fields remain. You don't need
  the secret value to detect the attack.
- Broader principle: logs become sensitive data the moment they capture sensitive things (env-var
  dumps, auth headers, etc.). Log metadata not payloads; redact at ingestion; protect the SIEM.

## Tuning the detection (reduce false positives)
1. Allowlist known-good SAs (exclude kube-system controllers that legitimately read secrets).
2. Weight the verb: `list secrets` = HIGH (enumeration, almost always malicious); `get <name>`
   = low/info (often an app reading its own secret).
3. Baseline then alert on deviation: SA reading a secret it never read before; a `list` when it
   only ever did `get`s; a burst of reads; reads from a new pod/IP/time. This catches a STOLEN
   token (the SA is known-good; only its behaviour gives it away).
4. Score weak signals instead of binary rules; alert over a threshold.
- The dial between false negatives (miss attacks) and false positives (alert fatigue) is the job;
  there's no perfect setting, only "appropriate for this environment."

## Check questions — answered
1. The tight Role stacks on top; RBAC is additive, so the broad ClusterRoleBinding still grants
   `list`. Fix = DELETE the broad binding, not just add a narrow one.
2. No — user-agent is client-set and spoofable (proved by faking kubectl). Key on server-asserted
   fields instead: user.username, verb, objectRef, responseStatus.code — the attacker can't forge
   which identity they are or what the server recorded.
3. Both read secret data, but `get` is targeted (needs the name; often legit) while `list`
   enumerates everything (recon move; attacker doesn't know the names yet) — so list earns far
   higher detection weight.

## ATT&CK
T1552 (unsecured credentials) · T1078 (valid accounts / escalation) · T1609 (container admin cmd)
· T1613 (discovery)
