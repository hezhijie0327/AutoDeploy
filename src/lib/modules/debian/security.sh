# ============================================================================
# modules/debian/security.sh - Fail2Ban, CrowdSec, sshd and SNMPv3
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureFail2Ban must be given FAIL2BAN_JAILS (array) and
# FAIL2BAN_BANACTION (ufw | nftables-multiport | default = keep the distro
# jail.conf values), plus optional FAIL2BAN_FILTER_NAME + FAIL2BAN_FILTER
# (array). ConfigureSNMPBase needs SNMP_USER.
# ============================================================================

ConfigureFail2Ban() {
    HaveCommand fail2ban-client || return 0
    if [ -d /etc/fail2ban/jail.d ]; then
        rm -f /etc/fail2ban/jail.d/*
    else
        mkdir -p /etc/fail2ban/jail.d
    fi
    if [ -f /etc/fail2ban/fail2ban.conf ]; then
        cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
    fi
    if [ -f /etc/fail2ban/jail.conf ]; then
        if [ "${FAIL2BAN_BANACTION}" = "ufw" ]; then
            sed -E \
                -e 's/action = iptables-allports/action = ufw/g' \
                -e 's/banaction = iptables-multiport(-log)?/banaction = ufw/g' \
                -e 's/banaction = ufw-log/banaction = ufw/g' \
                -e 's/banaction_allports = iptables-allports/banaction_allports = ufw/g' \
                /etc/fail2ban/jail.conf > /etc/fail2ban/jail.local
        elif [ "${FAIL2BAN_BANACTION:-default}" != "default" ]; then
            # Rewriting the iptables defaults keeps the %(banaction_allports)s
            # references intact; the allports twin is derived from the suffix
            # (e.g. nftables-multiport -> nftables-allports).
            local allports_action="${FAIL2BAN_BANACTION%-multiport}-allports"
            sed -E \
                -e "s/^banaction = iptables-multiport(-log)?\$/banaction = ${FAIL2BAN_BANACTION}/" \
                -e "s/^banaction_allports = iptables-allports\$/banaction_allports = ${allports_action}/" \
                /etc/fail2ban/jail.conf > /etc/fail2ban/jail.local
        else
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        fi
    fi
    if [ -n "${FAIL2BAN_FILTER_NAME:-}" ]; then
        printf '%s\n' "${FAIL2BAN_FILTER[@]}" > "/etc/fail2ban/filter.d/${FAIL2BAN_FILTER_NAME}.conf"
    fi
    printf '%s\n' "${FAIL2BAN_JAILS[@]}" > /etc/fail2ban/jail.d/fail2ban_default.conf
    systemctl enable fail2ban
    fail2ban-client reload
    sleep 5
    fail2ban-client status
}

ConfigureCrowdSec() {
    HaveCommand cscli || return 0
    local collection
    for collection in "crowdsecurity/iptables" "crowdsecurity/linux-lpe" "crowdsecurity/linux" "crowdsecurity/sshd"; do
        cscli collections install "$collection"
    done
    systemctl restart crowdsec
    cscli hub list
}

InstallCrowdSec() {
    InstallAptRepo "crowdsec" "https://packagecloud.io/crowdsec/crowdsec/gpgkey" \
        "deb [arch=${OS_ARCHITECTURE:-amd64} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main
deb-src [arch=${OS_ARCHITECTURE:-amd64} signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main"
    if HaveCommand cscli; then
        local bouncer
        while IFS= read -r bouncer; do
            cscli bouncers delete "$bouncer"
        done < <(cscli bouncers list | grep 'FirewallBouncer' | awk '{print $1}' || true)
    fi
    InstallAptPackages "crowdsec" "crowdsec-firewall-bouncer-nftables"
}

# Root password login is intentional: the root account gets locked afterwards
# via LOCK_ROOT=TRUE (see ConfigureRootUser). Needs SSH_PORT (defaults to 22,
# e.g. Proxmox VE keeps 22 for cluster-internal SSH).
ConfigureSshd() {
    [ -f /usr/share/openssh/sshd_config ] || return 0
    local port="${SSH_PORT:-22}"
    # Replace the commented Port directive in place (keeps the vendor
    # layout); fall back to an appended line when the file has none.
    sed -E \
        -e "s/^#?[[:space:]]*Port[[:space:]].*/Port ${port}/" \
        -e 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' \
        -e 's/^#?PermitRootLogin .*/PermitRootLogin yes/' \
        -e 's/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
        /usr/share/openssh/sshd_config > /etc/ssh/sshd_config
    grep -qE '^Port[[:space:]]' /etc/ssh/sshd_config || printf 'Port %s\n' "$port" >> /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/*
    # Ubuntu 25.10+/PVE 9: sshd runs behind ssh.socket, and after changing
    # Port the socket configuration must be regenerated and the socket
    # restarted (the notice in the vendor sshd_config documents exactly
    # this); restarting the service alone does not move the port.
    if systemctl is-enabled ssh.socket > /dev/null 2>&1 || systemctl is-active ssh.socket > /dev/null 2>&1; then
        systemctl daemon-reload
        systemctl restart ssh.socket
    fi
}

# Platform wrapper sets SNMP_USER, then calls this.
ConfigureSNMPBase() {
    HaveCommand snmpwalk || return 0
    if [ -z "${SNMP_AUTH_PASS:-}" ]; then
        SNMP_AUTH_PASS="${ROOT_PASSWORD}"
        LogWarn "SNMP_AUTH_PASS defaults to the root password; override it via SNMP_AUTH_PASS."
    fi
    if [ -z "${SNMP_PRIV_PASS:-}" ]; then
        SNMP_PRIV_PASS="${NEW_HOSTNAME}"
        LogWarn "SNMP_PRIV_PASS defaults to the hostname; override it via SNMP_PRIV_PASS."
    fi
    SNMP_SYS_CONTACT="${DEFAULT_FULLNAME}"
    SNMP_SYS_LOCATION="${NEW_HOSTNAME}"
    SNMP_SYS_NAME="${NEW_FULL_DOMAIN}"
    local snmp_list=(
        "agentaddress udp:161,udp6:161"
        "master agentx"
        "rouser ${SNMP_USER}"
        "sysContact ${SNMP_SYS_CONTACT}"
        "sysLocation ${SNMP_SYS_LOCATION}"
        "sysName ${SNMP_SYS_NAME}"
        "sysServices 76"
    )
    systemctl stop snmpd
    pkill -x snmpd > /dev/null 2>&1 || true
    sed -i 's/^mibs :/# mibs :/g' /etc/snmp/snmp.conf
    printf 'createUser %s SHA "%s" AES "%s"\n' "$SNMP_USER" "$SNMP_AUTH_PASS" "$SNMP_PRIV_PASS" > /var/lib/snmp/snmpd.conf
    printf '%s\n' "${snmp_list[@]}" | sort > /etc/snmp/snmpd.conf
    systemctl start snmpd
    # Verification only; head closes the pipe early, so ignore SIGPIPE.
    snmpwalk -v3 -a SHA -A "$SNMP_AUTH_PASS" -x AES -X "$SNMP_PRIV_PASS" -l authPriv -u "$SNMP_USER" 127.0.0.1 | head || true
}
