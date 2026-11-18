# ============================================================================
# modules/proxychains.sh - proxychains-ng client configuration
# (all platforms, bash 3.2+)
# Platform must set: PROXYCHAINS_CONF
# ============================================================================

ConfigureProxyChains() {
    local proxy_line="${PROXY_PROTOCOL:-socks5} ${PROXY_IP:-127.0.0.1} ${PROXY_PORT:-7891}"
    # proxychains reads user/pass as a pair; append only when both are set,
    # so an empty password can never leave a trailing space behind.
    if [ -n "${PROXY_USERNAME:-}" ] && [ -n "${PROXY_PASSWORD:-}" ]; then
        proxy_line="${proxy_line} ${PROXY_USERNAME} ${PROXY_PASSWORD}"
    fi
    local proxychains_list=(
        'localnet 127.0.0.0/255.0.0.0'
        'localnet 10.0.0.0/255.0.0.0'
        'localnet 172.16.0.0/255.240.0.0'
        'localnet 192.168.0.0/255.255.0.0'
        'localnet ::1/128'
        'proxy_dns'
        'remote_dns_subnet 224'
        'strict_chain'
        'tcp_connect_time_out 8000'
        'tcp_read_time_out 15000'
        '[ProxyList]'
        "${proxy_line}"
    )
    printf '%s\n' "${proxychains_list[@]}" > "$PROXYCHAINS_CONF"
}
