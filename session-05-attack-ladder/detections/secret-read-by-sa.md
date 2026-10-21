# Detection — service account reading a Secret via the API

**What it catches:** RBAC-abuse credential theft — a service account (often a stolen token)
reading/enumerating Secrets through the API server. Maps to ATT&CK T1552.

**Data source:** Kubernetes API server audit log.

## Detection logic (plain English)

> Alert when a **service account** successfully performs a **get/list** on **secrets**.
> `list` = HIGH (enumeration). `get` = MEDIUM/info (often a legit app reading its own secret).
> Raise severity if the user-agent looks like a manual tool (curl/wget/python) — BOOSTER ONLY.

## Key on server-asserted (unspoofable) fields ONLY

| Field | Set by | Use |
|---|---|---|
| `user.username` | API server (from validated token) | primary — the identity, cannot be forged |
| `verb` | API server | primary — get vs list |
| `objectRef.resource` / `.name` | API server | primary — what was touched |
| `responseStatus.code` | API server | primary — 200 = success, 403 = blocked |
| `authorization.k8s.io/reason` | API server authorizer | names the exact binding that allowed it |
| `userAgent` | the CLIENT | BOOSTER ONLY — spoofable (proved by faking kubectl) |
| `sourceIPs` | network | context only — spoofable/NAT'd |

## jq implementation (prototype; translate to Splunk/Elastic/Sigma for prod)

```bash
docker exec sec-lab-control-plane sh -c '
cat /var/log/kubernetes/audit.log | jq -c "
  select(
    (.user.username | startswith(\"system:serviceaccount:\")) and
    (.objectRef.resource == \"secrets\") and
    (.verb == \"get\" or .verb == \"list\") and
    (.responseStatus.code == 200)
  )
  | {
      severity: (if .verb == \"list\" then \"HIGH\" else \"MEDIUM\" end),
      tool_flag: (if (.userAgent | test(\"curl|wget|python\")) then \"manual-tool\" else \"sdk\" end),
      who: .user.username, verb, secret: .objectRef.name,
      pod: .user.extra[\"authentication.kubernetes.io/pod-name\"][0]
    }
"'
```

## Tuning (cut false positives — legit apps read secrets too)

1. **Allowlist** known-good SAs (exclude kube-system controllers):
   add `and (.user.username | startswith("system:serviceaccount:kube-system:") | not)`
2. **Weight the verb:** `list secrets` is almost always malicious; a single `get <name>` is often
   an app reading its own secret. Alert hard on `list`, info on `get`.
3. **Baseline, then deviation:** flag a SA reading a secret it never read before, a `list` where
   it only ever did `get`s, a burst of reads, or reads from a new pod/IP/time. This is what catches
   a STOLEN token — the SA is known-good, only its behaviour is off.
4. **Score weak signals** instead of binary rules; alert over a threshold.

## Notes / gotchas

- Log secrets at **Metadata** level, not RequestResponse — otherwise the secret value is written
  into the audit log and shipped to the SIEM (credential leak). Detection needs only metadata.
- This rule catches attacks that go THROUGH the API server. An attacker on the node reads etcd
  directly and bypasses the audit log entirely — needs separate node-level detection (Falco).
