#!/usr/bin/env bash
# Session 01 — commands run (reference; run manually, not as a script)

# --- Prove a container is a disguised host process ---
docker run -d --name demo alpine sleep 3600
docker exec demo ps                                   # sleep = PID 1 inside
docker inspect --format '{{.State.Pid}}' demo         # host PID (e.g. 7729, root-owned)
ps -ef | grep "sleep 3600" | grep -v grep

PID=$(docker inspect --format '{{.State.Pid}}' demo)
sudo lsns -p $PID                                     # container namespaces
sudo lsns -p $$                                       # this shell's namespaces (different)

docker exec demo uname -r && uname -r                 # identical kernel
docker exec demo grep Cap /proc/1/status              # reduced default capability set

# --- Attack: bind-mount the host (T1611) ---
docker run --rm -it -v /:/host alpine sh
#   inside: cat /host/etc/shadow     -> host password hashes, read-write

# --- Privileged capability contrast ---
docker run --rm --privileged alpine sh -c 'grep CapEff /proc/1/status'
#   -> CapEff: 000001ffffffffff   (all 41 caps on Ubuntu 24.04 kernel)
capsh --decode=000001ffffffffff

# --- Defend: hardened run ---
docker run --rm -it \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 100 \
  --memory 256m \
  alpine sh
#   inside: grep CapEff /proc/1/status  -> 0000000000000000
#           touch /test                 -> Read-only file system

# --- Detect ---
docker events --filter 'event=start' &
docker run --rm --privileged alpine true
docker inspect --format '{{.HostConfig.Privileged}} {{.HostConfig.Binds}}' <id>

docker rm -f demo
