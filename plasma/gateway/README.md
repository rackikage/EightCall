# gateway node — hardened loopback Tor onion-service

A single self-contained Docker build context (this folder is the build context;
`compose.yaml` uses `build: .`). It is one of the managed **nodes**, so it lives
under `fleet/` bundled with its operator scripts.

```
gateway/
├── compose.yaml      # net (pause) + gateway + backend; loopback 8088/2222; external `kind` net
├── Dockerfile        # alpine + nginx/tor/sshd; COPYs from config/ + entrypoint.sh
├── entrypoint.sh     # container init: sshd -> nginx -> exec tor
├── config/           # runtime config mounted into the image
│   ├── nginx/default.conf
│   ├── ssh/sshd_config        # + authorized_keys (gitignored; public key by design)
│   └── tor/torrc
└── ops/              # Mac-side loopback forwarding into the Colima VM
    ├── forward.sh                 # ad-hoc -L 8088/2222
    └── install-forward-agent.sh   # persistent LaunchAgent (calls ./forward.sh)
```

**Security posture:** key-only sshd, no root/password/TCP-forward beyond
`127.0.0.1:8080|80`, IPv6 disabled, bound to loopback. Reachable only via
`ops/` tunnels; never expose publicly. Build: `docker compose build gateway`.
