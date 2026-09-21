#!/usr/bin/env bash
# Build + deploy FLEET: 2 Node.js pods in kind, Tor gateway routing /node/ to them.
set -euo pipefail
cd "$(dirname "$0")"

KIND_CLUSTER="${KIND_CLUSTER:-py-box}"
CTX="kind-${KIND_CLUSTER}"
IMAGE="fleet-node:0.1.0"

for bin in docker kind kubectl; do command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 1; }; done
kind get clusters | grep -qx "$KIND_CLUSTER" || { echo "kind cluster '$KIND_CLUSTER' not found" >&2; exit 1; }

if [ ! -s gateway/ssh/authorized_keys ]; then
  cp "${SSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}" gateway/ssh/authorized_keys
fi

echo "==> build $IMAGE"
docker build -t "$IMAGE" node
echo "==> load into kind/$KIND_CLUSTER"
kind load docker-image "$IMAGE" --name "$KIND_CLUSTER"
echo "==> apply k8s"
kubectl --context "$CTX" apply -f k8s/node.yaml
kubectl --context "$CTX" -n fleet rollout restart deployment/fleet-node
kubectl --context "$CTX" -n fleet rollout status deployment/fleet-node --timeout=120s

echo "==> gateway"
docker compose -f gateway/compose.yaml up -d --build

echo "==> smoke test (inside gateway)"
for i in $(seq 1 20); do
  if out=$(docker exec tor-gateway wget -qO- "http://127.0.0.1/node/chain/a?input=fleet" 2>/dev/null); then break; fi
  sleep 2
done
echo "chain a: ${out:-FAILED}"
echo "chain b: $(docker exec tor-gateway wget -qO- 'http://127.0.0.1/node/chain/b?input=fleet' 2>/dev/null || echo FAILED)"
echo "onion:   http://$(docker exec tor-gateway cat /var/lib/tor/hs/hostname)/node/chain/a"
echo "mac:     ./gateway/forward.sh  then  curl http://127.0.0.1:8088/node/chain/a"
