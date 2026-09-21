# plasma/k8s — kind manifests for the node service

`node.yaml`: Namespace `plasma`, a 2-replica Deployment of `plasma-node:0.1.0`,
and a NodePort Service (30090). Applied by `../deploy.sh` into a local kind
cluster. The pod is hardened: `runAsNonRoot`, `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, `capabilities: drop [ALL]`, seccomp
`RuntimeDefault`, `automountServiceAccountToken: false`, pinned image tag.

## Binding

The Service is `NodePort 30090`, reachable only on the private kind Docker
network (the gateway proxies to `py-box-control-plane:30090`). kind maps
nothing onto macOS, so it is not a host publish. The pod's `HOST=0.0.0.0` env
is the one reviewed wildcard bind — required for kube-proxy and probes to reach
the container; see `../node/README.md`.

## Safety

Only test electronics you own. Authorized systems only. Loopback-bound by
default (`127.0.0.1`/`::1`); the only wildcard is the in-cluster pod, never
published to the Mac/LAN. No evasion. No arbitrary execution — typed
capabilities only. No secrets in git.
