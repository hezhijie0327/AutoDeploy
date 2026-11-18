# ============================================================================
# modules/ssh.sh - SSH key pair generation and per-user .ssh initialization
# (all platforms, bash 3.2+)
# ============================================================================

# Generate the user key pairs (ecdsa/ed25519/rsa) inside an existing .ssh dir.
# DSA is intentionally gone: OpenSSH >= 9.8 disables it, 10.x removed it.
GenerateSSHKeys() {
    local ssh_dir="$1" comment="$2"
    ssh-keygen -t ecdsa -b 384 -f "${ssh_dir}/id_ecdsa" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t ed25519 -f "${ssh_dir}/id_ed25519" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t rsa -b 4096 -f "${ssh_dir}/id_rsa" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    chmod 400 "${ssh_dir}"/id_*
    chmod 644 "${ssh_dir}"/id_*.pub
}

GenerateHostSSHKeys() {
    local ssh_dir="$1" comment="$2"
    rm -f "${ssh_dir}"/ssh_host_*
    ssh-keygen -t ecdsa -b 384 -f "${ssh_dir}/ssh_host_ecdsa_key" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t ed25519 -f "${ssh_dir}/ssh_host_ed25519_key" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    ssh-keygen -t rsa -b 4096 -f "${ssh_dir}/ssh_host_rsa_key" -C "$comment" -N "${OPENSSH_PASSWORD:-}"
    chmod 400 "${ssh_dir}"/ssh_host_*
    chmod 644 "${ssh_dir}"/ssh_host_*.pub
}

# Initialize a user .ssh dir: back up any existing one, create the skeleton,
# generate the key pairs, fix permissions. Callers that import authorized_keys
# from GPG_HOME do so afterwards (the mv replaces the placeholder file).
# Pass owner (user:group) when running as root; empty owner = skip chown.
InitUserSSHDir() {
    local ssh_dir="$1" comment="$2" owner="${3:-}"
    BackupPath "$ssh_dir"
    mkdir -p "$ssh_dir"
    touch "${ssh_dir}/authorized_keys" "${ssh_dir}/known_hosts"
    GenerateSSHKeys "$ssh_dir" "$comment"
    chmod 600 "${ssh_dir}/authorized_keys"
    chmod 644 "${ssh_dir}/known_hosts"
    chmod 700 "$ssh_dir"
    if [ -n "$owner" ]; then
        chown -R "$owner" "$ssh_dir"
    fi
}
