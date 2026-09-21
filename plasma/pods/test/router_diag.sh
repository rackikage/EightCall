#!/usr/bin/env bash
# router_diag.sh — read-only LAN map for the next-phase nat-map path.
#
# Probes owned equipment (the B628 by default) and the local LAN. Does not
# authenticate to anything, does not modify any state, does not probe the
# iCloud Keychain or any iOS IPC surface. All output is JSON-friendly
# key=value so it's grep-able and fits the pods log style.
#
# Run:
#     ./test/router_diag.sh                  # default target = gateway
#     TARGET=192.168.8.1 ./test/router_diag.sh
#     TARGET=loopback ./test/router_diag.sh  # skip external probes
#
# Exits 0 always — diagnostics never fail.

set -eu

TARGET="${TARGET:-}"
ts() { date -u +%FT%TZ; }
note() { printf '%s key=%s value=%s\n' "$(ts)" "$1" "$2"; }

# --- 1. default gateway + local view -------------------------------------

GW="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')"
[ -n "$GW" ] || GW="unknown"
note "gateway" "$GW"
note "iface" "$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
note "host_ip" "$(ifconfig en0 2>/dev/null | awk '/inet /{print $2; exit}')"
note "host_mac" "$(ifconfig en0 2>/dev/null | awk '/ether /{print $2; exit}')"

# --- 2. ARP / L2 neighbors (recently contacted) -------------------------

while IFS='[()]' read -r _ ip _ mac _ rest; do
    [ -n "$ip" ] || continue
    case "$ip" in *.*) ;; *) continue ;; esac
    case "$mac" in *incomplete*|"") ;; *) note "arp" "$ip $mac" ;; esac
done < <(arp -an 2>/dev/null)

# --- 3. DNS resolver ----------------------------------------------------

while read -r line; do
    case "$line" in
        *nameserver*) note "nameserver" "${line##*nameserver* }" ;;
    esac
done < <(scutil --dns 2>/dev/null)

# --- 4. TCP reachability to common router-admin ports -------------------

if [ -z "$TARGET" ] || [ "$TARGET" = "loopback" ]; then
    note "target" "loopback (skipping external probes)"
else
    note "target" "$TARGET"
    for p in 22 53 80 443 8080 8443 37215 161; do
        if nc -z -G 2 "$TARGET" "$p" 2>/dev/null; then
            note "tcp" "$p open"
        else
            note "tcp" "$p closed_or_filtered"
        fi
    done

    # --- 5. HTTP service probe (port 80) --------------------------------

    code=$(curl -s -m 3 -o /dev/null -w "%{http_code}" "http://$TARGET/" 2>/dev/null || echo "000")
    note "http_80" "status=$code"

    # --- 6. HTTPS probe (port 443 — cert subject/issuer) ----------------

    cert=$(echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" \
                 -no_ign_eof 2>/dev/null | awk '
        /^subject=/ { sub(/^subject=/,""); s=$0 }
        /^issuer=/  { sub(/^issuer=/,"");  i=$0 }
        END { printf "%s|%s", s, i }
    ')
    note "https_443_subject" "${cert%|*}"
    note "https_443_issuer"  "${cert##*|}"

    # --- 7. UPnP IGD discovery (SSDP M-SEARCH, then descriptor GET) ------

    if [ -x /usr/local/bin/upnpc ] || command -v upnpc >/dev/null 2>&1; then
        UP="$(command -v upnpc)"
        if "$UP" -s >/dev/null 2>&1; then
            note "upnp_igd" "responsive"
        else
            note "upnp_igd" "advertised_but_unresponsive"
        fi
        # Walk the UPnP device descriptor on the well-known HTTP port
        # if SSDP discovery returned a URL.
        ssdp_url=$("$UP" -s 2>&1 | awk '/Is it an IGD/ { print $NF }' | head -1)
        if [ -n "$ssdp_url" ]; then
            desc=$(echo "$ssdp_url" | sed -E 's#^(http://[^/]+/ctrlu/).+#\1#')
            # The descriptor URL is the SSDP location; fetch and parse.
            location=$(curl -s -m 3 "$ssdp_url" -w '%{url_effective}' -o /dev/null 2>/dev/null || true)
            # If we can't grab it, just record the URL we know.
            note "upnp_control_url" "$ssdp_url"
        fi
    else
        note "upnp_igd" "no_upnpc_binary"
    fi

    # --- 8. UPnP HTTP descriptor (root device XML) -----------------------

    desc=$(curl -s -m 3 "http://$TARGET:37215/rootDesc.xml" 2>/dev/null || true)
    if [ -z "$desc" ]; then
        # Try discovery-broadcast-derived location
        desc=$(curl -s -m 3 "http://$TARGET:37215/" 2>/dev/null | head -200 || true)
    fi
    if [ -n "$desc" ]; then
        while read -r tag; do
            case "$tag" in
                *"<friendlyName>"*) note "upnp_friendlyName" "${tag#*<friendlyName>}" ;;
            esac
        done <<EOF
$desc
EOF
        # Check for the IGD control service type we need.
        if echo "$ess" | grep -q "WANIPConnection"; then
            note "upnp_service" "WANIPConnection present"
        elif echo "$ess" | grep -q "WANPPPConnection"; then
            note "upnp_service" "WANPPPConnection only — miniupnpc cannot add port maps"
        else
            note "upnp_service" "unknown"
        fi
    else
        note "upnp_descriptor" "not_reachable"
    fi
fi

# --- 9. Bonjour browse for known services -------------------------------

browse() {
    local q="$1"
    local out
    out=$(dns-sd -B "$q" local. 2>&1 & sleep 2 ; kill $! 2>/dev/null ; wait $! 2>/dev/null) || true
    printf '%s' "$out" | awk -v q="$q" '
        /^Browsing/ { next }
        /^Timestamp/ { next }
        /^DATE:/ { next }
        /^STARTING/ { next }
        /^[0-9]+:[0-9]+:[0-9]+/ { print "bonjour q=" q " hit=" $0 }
    '
}

browse _http._tcp
browse _apple-mobdev2._tcp
browse _ssh._tcp
browse _companion-link._tcp

note "result" "done"
