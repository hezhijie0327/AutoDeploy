# ============================================================================
# modules/debian/users.sh - user, root and host identity management
# (Ubuntu / Proxmox VE, bash 4.4+)
# ConfigureDefaultUser needs DEFAULT_USERNAME/FULLNAME/PASSWORD (plus
# DEFAULT_PASSWORD_DEFAULT for the warning) and the PURGE_OTHER_USERS switch;
# the pveum blocks are no-ops on non-PVE hosts (HaveCommand pveum).
# WriteHostfile needs NEW_HOSTNAME and takes extra host entries as arguments.
# ConfigureOpenSSH needs NEW_HOSTNAME + DEFAULT_USERNAME.
# ============================================================================

# Write /etc/hosts plus /etc/hostname and apply it via hostnamectl.
# Extra entries (e.g. the Ubuntu loopback alias or the PVE management IP)
# come first as arguments, above HOSTS_BASE_ENTRIES.
WriteHostfile() {
    local host_list=("$@")
    host_list+=("${HOSTS_BASE_ENTRIES[@]}")
    printf '%s\n' "${host_list[@]}" > "/etc/hosts"
    printf '%s\n' "$NEW_HOSTNAME" > "/etc/hostname"
    hostnamectl set-hostname "$NEW_HOSTNAME"
}

ConfigureDefaultUser() {
    WarnDefaultPassword "DEFAULT_PASSWORD" "$DEFAULT_PASSWORD" "$DEFAULT_PASSWORD_DEFAULT"
    PURGE_OTHER_USERS="${PURGE_OTHER_USERS:-true}"
    if [ "$PURGE_OTHER_USERS" = "true" ]; then
        LogWarn "PURGE_OTHER_USERS=true: removing every other user under /home (set PURGE_OTHER_USERS=false to keep them)"
        local home_dir user
        for home_dir in /home/*; do
            if [ -d "$home_dir" ]; then
                user="${home_dir##*/}"
                if [ "$user" != "$DEFAULT_USERNAME" ]; then
                    userdel -rf "$user" > /dev/null 2>&1 || true
                    if HaveCommand pveum; then
                        pveum userdel "${user}@pam" > /dev/null 2>&1 || true
                    fi
                fi
            fi
        done
    fi
    if id "$DEFAULT_USERNAME" > /dev/null 2>&1; then
        userdel -rf "$DEFAULT_USERNAME" > /dev/null 2>&1 || true
    fi
    useradd -c "$DEFAULT_FULLNAME" -d "/home/${DEFAULT_USERNAME}" -s "/bin/zsh" -m "$DEFAULT_USERNAME"
    printf '%s:%s\n' "$DEFAULT_USERNAME" "$DEFAULT_PASSWORD" | chpasswd
    adduser "$DEFAULT_USERNAME" "docker"
    adduser "$DEFAULT_USERNAME" "sudo"
    # shellcheck disable=SC2034 # consumed by InstallCrontab (modules/crontab.sh)
    CRONTAB_USER="$DEFAULT_USERNAME"
    # shellcheck disable=SC2034 # consumed by InstallCrontab (modules/crontab.sh)
    CRONTAB_ENTRIES=(
        "@reboot rm -rf ~/.*_history ~/.ssh/known_hosts*"
    )
    InstallCrontab
    if HaveCommand pveum; then
        if pveum group list | grep -q 'LADM'; then
            pveum group modify "LADM" -comment "Local Administrators"
        else
            pveum groupadd "LADM" -comment "Local Administrators"
        fi
        pveum aclmod "/" -group "LADM" -role "Administrator"
        if pveum user list | grep -q "${DEFAULT_USERNAME}@pam"; then
            pveum usermod "${DEFAULT_USERNAME}@pam" -comment "$DEFAULT_FULLNAME" -firstname "$DEFAULT_FIRSTNAME" -group "LADM" -lastname "$DEFAULT_LASTNAME"
        else
            pveum useradd "${DEFAULT_USERNAME}@pam" -comment "$DEFAULT_FULLNAME" -firstname "$DEFAULT_FIRSTNAME" -group "LADM" -lastname "$DEFAULT_LASTNAME"
        fi
        pveum usermod "root@pam" -comment "Proxmox Root" -firstname "Root" -group "LADM" -lastname "Proxmox"
    fi
}

# Only the deployment user switches to zsh; system accounts keep their shells.
ConfigureDefaultShell() {
    if HaveCommand zsh && [ -n "${DEFAULT_USERNAME:-}" ]; then
        usermod -s /bin/zsh "$DEFAULT_USERNAME"
    fi
    usermod -s /bin/bash root
}

ConfigureRootUser() {
    LOCK_ROOT="${LOCK_ROOT:-FALSE}"
    ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"
    WarnDefaultPassword "ROOT_PASSWORD" "$ROOT_PASSWORD" 'R00t@123!'
    printf 'root:%s\n' "$ROOT_PASSWORD" | chpasswd
    if [ "$LOCK_ROOT" = "TRUE" ]; then
        passwd -l root
    else
        passwd -u root
    fi
}

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
