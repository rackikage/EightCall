# plasma/node — dual-chain Node.js pod service

The container image behind `plasma-node` (see `../k8s/node.yaml`). A small HTTP
service (`src/node.ts` → `dist/node.js`) that a worker/authority pair runs
inside kind. Built by `../deploy.sh` and loaded into kind (`imagePullPolicy:
Never`); it is never published to the Mac.

## Binding

The binary binds `127.0.0.1:8080` by default (`HOST`/`PORT` env). The k8s
Deployment is the one reviewed place that sets `HOST=0.0.0.0`, because a pod
must bind the wildcard for kube-proxy (NodePort 30090) and the kubelet probes
to reach it. That NodePort lives only on the private kind network — kind maps
nothing onto macOS. Run it outside k8s and it stays on loopback.

## Safety

Only test electronics you own. Authorized systems only. Loopback-bound by
default (`127.0.0.1`/`::1`) — the sole wildcard bind is the reviewed k8s pod,
never a Mac/LAN interface. No evasion. No arbitrary execution — typed
capabilities only. No secrets in git.
