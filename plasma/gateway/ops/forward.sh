#!/bin/sh
# Mac loopback-only forwards into the Colima VM (Lima's auto-forwarder binds *:, i.e. LAN).
# usage: ./forward.sh [stop]
S="$HOME/.colima/_lima/colima/tor-gw-fwd.sock"
if [ "$1" = stop ]; then ssh -F "$HOME/.colima/ssh_config" -S "$S" -O exit colima; exit; fi
exec ssh -F "$HOME/.colima/ssh_config" -f -N -M -S "$S" -o ExitOnForwardFailure=yes -o ControlPersist=no \
  -L 127.0.0.1:8088:127.0.0.1:8088 -L 127.0.0.1:2222:127.0.0.1:2222 colima
