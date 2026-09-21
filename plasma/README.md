# FLEET

Two Node.js pods in the `py-box` kind cluster, reachable only through the Tor gateway container.

```text
.onion ─▶ Tor ─▶ tor-gateway nginx 0.0.0.0:80 (IPv4)
                   ├── /node/  ─▶ private docker "kind" network ─▶ py-box-control-plane:30090
                   │                ─▶ Service fleet/fleet-node ─▶ pod ×2 (Node.js)
                   └── /       ─▶ 127.0.0.1:8080 loopback sidecar
```

Nothing new is published on macOS. NodePort 30090 is only reachable from the kind network.

The gateway runs pod-style: a `pause` container owns the network namespace, so restarting `tor-gateway` or the sidecar never strands the other.

## Layout

```text
FLEET/
├── deploy.sh              build image → kind load → kubectl apply → gateway up → smoke test
├── bundle.sh              pack into dist/FLEET.tar.gz (+ .sha256)
├── node/
│   ├── src/node.ts        HTTP server + the two chains (alphaSteps, betaSteps)
│   ├── Dockerfile         multi-stage node:22-alpine, runs as uid 1000
│   ├── package.json
│   ├── package-lock.json  locked deps (npm ci)
│   └── tsconfig.json
├── k8s/node.yaml          Namespace fleet, Deployment (2 replicas), NodePort Service 30090
└── gateway/               (self-contained Docker build context; see gateway/README.md)
    ├── compose.yaml       net (pause, owns netns + kind network) · tor-gateway · sidecar
    ├── Dockerfile         Alpine: nginx, tor, openssh, tini (COPYs from config/)
    ├── entrypoint.sh      sshd -> nginx -> exec tor
    ├── config/
    │   ├── nginx/default.conf
    │   ├── tor/torrc          onion :80 → 127.0.0.1:80
    │   └── ssh/sshd_config    key-only, user gw, forwarding limited to 127.0.0.1:80/8080
    └── ops/
        ├── install-forward-agent.sh  LaunchAgent: Mac loopback 127.0.0.1:8088 / :2222, auto-start + reconnect
        └── forward.sh         same forwards, one-off (manual start/stop)
```

## Deploy

```bash
./deploy.sh                     # KIND_CLUSTER=py-box by default
KIND_CLUSTER=other ./deploy.sh  # also change py-box-control-plane in gateway/nginx/default.conf
```

`deploy.sh` copies `~/.ssh/id_ed25519.pub` to `gateway/ssh/authorized_keys` when that file is missing (override with `SSH_PUBKEY=`).

## Endpoints

| Path | Method | Result |
|---|---|---|
| `/node/chain/a` | GET `?input=` or POST body | runs `alphaSteps` (name from `CHAIN_A_NAME`, default `alpha`) |
| `/node/chain/b` | GET `?input=` or POST body | runs `betaSteps` (name from `CHAIN_B_NAME`, default `beta`) |
| `/node/healthz` | GET | liveness |
| `/node/readyz` | GET | readiness (503 while shutting down) |

Bodies are capped at 64 KB (413). Responses include the serving pod name.

## Access

```bash
docker exec tor-gateway cat /var/lib/tor/hs/hostname     # onion address
./gateway/install-forward-agent.sh        # once; survives logout/reboot/Colima restarts
curl 'http://127.0.0.1:8088/node/chain/a?input=hi'
ssh -p 2222 gw@127.0.0.1
./gateway/install-forward-agent.sh uninstall
```

Colima never forwards `127.0.0.1` container publishes, and its auto-forwarder binds `*:` (LAN), so FLEET forwards over its own ssh connection bound to Mac loopback only (`ControlPath=none`, since Colima's ssh_config would otherwise hand the forwards to its shared master). Log: `/tmp/com.fleet.forward.log`.

## Pod hardening

2 replicas · requests 10m CPU / 24Mi · limit 128Mi (V8 heap 96 MB) · runAsNonRoot uid 1000 · seccomp RuntimeDefault · read-only root FS · all capabilities dropped · no privilege escalation · no service-account token · liveness + readiness probes · 5 s preStop drain (zero dropped requests when a pod is replaced) · `X-Forwarded-For` / `X-Real-IP` stripped at the gateway (no client-IP reconstruction).

## Adding real chain logic

Edit the `alphaSteps` / `betaSteps` arrays in `node/src/node.ts`. Each step is `{ name, run(ctx) }` and returns the next `ctx`; async steps are fine. Then `./deploy.sh`.

## Remove

```bash
kubectl --context kind-py-box delete namespace fleet
docker compose -f gateway/compose.yaml down        # add -v to also delete the onion key
./gateway/install-forward-agent.sh uninstall
```
