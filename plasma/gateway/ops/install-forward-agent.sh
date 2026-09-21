#!/bin/sh
# Install a LaunchAgent that keeps Mac loopback forwards 127.0.0.1:8088 / :2222 into Colima alive
# (starts at login, reconnects if Colima restarts). usage: ./install-forward-agent.sh [uninstall]
# ControlPath=none: Colima's ssh_config multiplexes, which would hand the forwards to its master and exit.
set -e
LABEL=com.fleet.forward
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
if [ "$1" = uninstall ]; then rm -f "$PLIST"; echo "removed $LABEL"; exit 0; fi
"$(dirname "$0")/forward.sh" stop 2>/dev/null || true
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/ssh</string>
    <string>-F</string><string>$HOME/.colima/ssh_config</string>
    <string>-N</string>
    <string>-o</string><string>ControlMaster=no</string>
    <string>-o</string><string>ControlPath=none</string>
    <string>-o</string><string>ExitOnForwardFailure=yes</string>
    <string>-o</string><string>ServerAliveInterval=15</string>
    <string>-o</string><string>ServerAliveCountMax=3</string>
    <string>-L</string><string>127.0.0.1:8088:127.0.0.1:8088</string>
    <string>-L</string><string>127.0.0.1:2222:127.0.0.1:2222</string>
    <string>colima</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardErrorPath</key><string>/tmp/$LABEL.log</string>
</dict>
</plist>
PLIST
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed $LABEL"
