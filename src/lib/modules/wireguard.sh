# ============================================================================
# modules/wireguard.sh - wg0 client configuration writer
# (all platforms, bash 3.2+)
# Writes /etc/wireguard/wg0.conf. The private key never touches a temp file.
# Platform handles directory ownership and bringing the interface up.
# ============================================================================

GenerateWireGuardConfig() {
    local tunnel_address="10.172.$((RANDOM % 256)).$((RANDOM % 256))/32"
    local private_key public_key preshared_key
    private_key=$(wg genkey)
    public_key=$(printf '%s' "$private_key" | wg pubkey)
    preshared_key=$(wg genpsk)
    local wireguard_list=(
        "[Interface]"
        "Address = ${tunnel_address}"
        "# DNS = 127.0.0.1, ::1"
        "ListenPort = 51820"
        "MTU = 1420"
        "PrivateKey = ${private_key}"
        "# [Peer]"
        "# AllowedIPs = ${tunnel_address}"
        "# Endpoint = 127.0.0.1:51820"
        "# PersistentKeepalive = 5"
        "# PresharedKey = ${preshared_key}"
        "# PublicKey = ${public_key}"
    )
    printf '%s\n' "${wireguard_list[@]}" > "/etc/wireguard/wg0.conf"
    chmod 600 "/etc/wireguard/wg0.conf"
}
