# kubectl cheat sheet — security lab

## The pattern behind (almost) every command

```
kubectl <verb> <resource> [name] [flags]
```

- **verb** — what to do: `get`, `describe`, `create`, `delete`, `exec`, `logs`, `scale`
- **resource** — what kind: `pods`, `nodes`, `deployments`, `services`, `secrets`
- **name** — (optional) the specific one; omit to act on all of that type
- **flags** — modifiers: `-n <namespace>`, `-o wide`, `-it`

Example: `kubectl get pods` = list all pods. `kubectl delete pod web-abc` = delete that one.

Read-only verbs (`get`, `describe`, `logs`) can't break anything — explore freely.
Only `create`, `delete`, `scale`, `apply` change state.

---

## Looking at things (read-only, use constantly)

| Command | What it does |
|---|---|
| `kubectl get pods` | list pods in current namespace |
| `kubectl get pods -o wide` | pods + which node + pod IP |
| `kubectl get nodes` | list nodes |
| `kubectl get deployments` | list deployments |
| `kubectl get all` | overview of everything in namespace |
| `kubectl get pods -n kube-system` | pods in a specific namespace |
| `kubectl get pods -A` | pods in ALL namespaces |

## Looking at ONE thing in detail

| Command | What it does |
|---|---|
| `kubectl describe pod web-abc` | full details + Events (why it failed) |
| `kubectl logs web-abc` | the container's stdout (app logs) |
| `kubectl get pod web-abc -o yaml` | the full raw config of the pod |

`describe` is the debugging tool — when a pod won't start, read the Events section at the bottom.

## Making / changing things

| Command | What it does |
|---|---|
| `kubectl create deployment web --image=nginx` | create a deployment |
| `kubectl scale deployment web --replicas=3` | change replica count |
| `kubectl delete pod web-abc` | delete one pod (deployment respawns it) |
| `kubectl delete deployment web` | delete a deployment and all its pods |
| `kubectl apply -f file.yaml` | create/update from a manifest file |

## Getting inside a pod (the security one)

| Command | What it does |
|---|---|
| `kubectl exec -it web-abc -- bash` | interactive shell inside a pod |
| `kubectl exec web-abc -- ls /tmp` | run one command in a pod, no shell |

The `--` separates kubectl's flags from the command run *inside* the pod.
`-it` = interactive terminal (needed for a shell).
`kubectl exec` targets a CONTAINER inside a POD — never the node.

---

## Flags worth knowing

| Flag | Means | Use |
|---|---|---|
| `-n <namespace>` | which namespace | `-n kube-system` for control plane |
| `-o wide` | more columns | node + IP on `get pods` |
| `-o yaml` | full raw config | everything about a resource |
| `-it` | interactive terminal | needed for `exec ... bash` |
| `-w` | watch (live stream) | watch pods change in real time |
| `-A` / `--all-namespaces` | every namespace | cluster-wide view |

---

## Security-relevant one-liners (from the labs)

```bash
# which node is each pod on (attacker reads this to map placement):
kubectl get pods -o wide

# the control plane, running as pods:
kubectl get pods -n kube-system

# shell into a pod (simulate a compromised app):
kubectl exec -it deployment/web -- bash

# the service-account token mounted into EVERY pod by default:
#   /var/run/secrets/kubernetes.io/serviceaccount/token

# what is a pod's token allowed to do? (run from inside the pod)
APISERVER=https://kubernetes.default.svc
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# "who am I?"
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authentication.k8s.io/v1/selfsubjectreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

# "am I allowed to read secrets?" (swap verb/resource to probe other powers)
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}'
```

---

## kind (cluster management)

| Command | What it does |
|---|---|
| `kind create cluster --name sec-lab` | create the lab cluster |
| `kind get clusters` | list clusters |
| `kind delete cluster --name sec-lab` | tear it down |
| `docker ps` | see the node (a container named sec-lab-control-plane) |
| `docker exec -it sec-lab-control-plane bash` | shell into the NODE |

---

## Quality-of-life setup

```bash
echo 'source <(kubectl completion bash)' >> ~/.bashrc
echo 'alias k=kubectl' >> ~/.bashrc
source ~/.bashrc
# now: k get po<TAB> completes, pod names tab-complete too
```

---

## Mental model

- **node** = a machine (here, a Docker container you can `docker exec` into)
- **pod** = smallest deployable unit; wraps 1+ containers sharing network + storage
- **cluster** = all nodes managed as one
- **control plane** = the brain (API server, etcd, scheduler, controller-manager)
- **declarative / desired state** = you declare the goal; K8s continuously reconciles reality to it
- `kubectl exec` puts you in a POD, not the node. Pod -> node is an ESCAPE, not a command.
