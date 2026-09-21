# plasma/gateway/ops — Mac→Colima loopback forwards

Operator scripts that reach the gateway container from the Mac. Colima's own
auto-forwarder binds `*:` (LAN), so these do NOT use it: they open an explicit
ssh forward bound to Mac loopback only.

- `forward.sh` — one-shot `ssh -L 127.0.0.1:8088:… -L 127.0.0.1:2222:…`
  (`ControlPath=none`, so Colima's shared master can't hijack the forwards).
  `./forward.sh stop` tears it down.
- `install-forward-agent.sh` — installs a `com.plasma.forward` LaunchAgent that
  keeps the same loopback forwards alive across logins/Colima restarts.
  `./install-forward-agent.sh uninstall` removes it.

Both forward `127.0.0.1:8088` (nginx) and `127.0.0.1:2222` (ssh) only. Never
add a `-L 0.0.0.0:` or `-g` forward — that would republish the VM to the LAN.

## Safety

Only test electronics you own. Authorized systems only. Loopback-bound by
default (`127.0.0.1`/`::1`) — every forward binds Mac loopback, never `0.0.0.0`
or `*:`. No evasion. No arbitrary execution — typed capabilities only. No
secrets in git.
