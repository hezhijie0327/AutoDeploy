# ============================================================================
# modules/hosts.sh - standard /etc/hosts entries (all platforms, bash 3.2+)
# Pure data table. Debian platforms append platform extras via WriteHostfile
# (modules/debian/system.sh); macOS writes the table with sudo tee directly.
# ============================================================================

# shellcheck disable=SC2034 # consumed by WriteHostfile (debian system.sh) and macOS
HOSTS_BASE_ENTRIES=(
    "127.0.0.1 localhost"
    "255.255.255.255 broadcasthost"
    "::1 ip6-localhost ip6-loopback localhost"
    "fe00::0 ip6-localnet"
    "ff00::0 ip6-mcastprefix"
    "ff02::1 ip6-allnodes"
    "ff02::2 ip6-allrouters"
    "ff02::3 ip6-allhosts"
)
