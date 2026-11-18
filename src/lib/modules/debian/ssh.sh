# ============================================================================
# modules/debian/ssh.sh - OpenSSH host keys, user key setup and sshd
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureOpenSSH needs NEW_HOSTNAME + DEFAULT_USERNAME (+DEFAULT_PASSWORD
# for the key ownership) and the ssh.sh key helpers; ConfigureSshd needs
# SSH_PORT (defaults to 22, e.g. Proxmox VE keeps 22 for cluster-internal
# SSH).
# ============================================================================

ConfigureOpenSSH() {
    HaveCommand ssh-keygen || return 0
    if [ -d /etc/ssh ]; then
        GenerateHostSSHKeys /etc/ssh "root@${NEW_HOSTNAME}"
    fi
    InitUserSSHDir /root/.ssh "root@${NEW_HOSTNAME}"
    local user_ssh="/home/${DEFAULT_USERNAME}/.ssh"
    InitUserSSHDir "$user_ssh" "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" "$DEFAULT_USERNAME:$DEFAULT_USERNAME"
    if [ -f "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" ]; then
        mv "/home/${DEFAULT_USERNAME}/.gnupg/authorized_keys" "${user_ssh}/authorized_keys"
        chmod 600 "${user_ssh}/authorized_keys"
    fi
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
