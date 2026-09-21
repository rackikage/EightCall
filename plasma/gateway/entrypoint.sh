#!/bin/sh
set -e
chown -R tor /var/lib/tor && chmod 700 /var/lib/tor/hs
/usr/sbin/sshd
nginx
exec tor -f /etc/tor/torrc   # drops to user tor via torrc
