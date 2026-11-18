# ============================================================================
# modules/debian/security.sh - Fail2Ban, CrowdSec and SNMPv3
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureFail2Ban must be given FAIL2BAN_JAILS (array) and
# FAIL2BAN_BANACTION (ufw | nftables-multiport | default = keep the distro
# jail.conf values), plus optional FAIL2BAN_FILTER_NAME + FAIL2BAN_FILTER
# (array). ConfigureSNMPBase needs SNMP_USER (platform config: ubuntu / proxmox).
# (sshd lives in debian/ssh.sh alongside the OpenSSH key setup.)
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

# SNMP_USER comes from the platform config block (ubuntu / proxmox).
ConfigureSNMPBase() {
    HaveCommand snmpwalk || return 0
    if [ -z "${SNMP_AUTH_PASSWORD:-}" ]; then
        SNMP_AUTH_PASSWORD="${ROOT_PASSWORD}"
        LogWarn "SNMP_AUTH_PASSWORD defaults to the root password; override it via SNMP_AUTH_PASSWORD"
    fi
    if [ -z "${SNMP_PRIV_PASSWORD:-}" ]; then
        SNMP_PRIV_PASSWORD="${NEW_HOSTNAME}"
        LogWarn "SNMP_PRIV_PASSWORD defaults to the hostname; override it via SNMP_PRIV_PASSWORD"
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
    printf 'createUser %s SHA "%s" AES "%s"\n' "$SNMP_USER" "$SNMP_AUTH_PASSWORD" "$SNMP_PRIV_PASSWORD" > /var/lib/snmp/snmpd.conf
    printf '%s\n' "${snmp_list[@]}" | sort > /etc/snmp/snmpd.conf
    systemctl start snmpd
    # Verification only; head closes the pipe early, so ignore SIGPIPE.
    snmpwalk -v3 -a SHA -A "$SNMP_AUTH_PASSWORD" -x AES -X "$SNMP_PRIV_PASSWORD" -l authPriv -u "$SNMP_USER" 127.0.0.1 | head || true
}
