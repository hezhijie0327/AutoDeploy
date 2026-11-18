# ============================================================================
# modules/gpg.sh - GPG key setup with SSH authentication support
# (all platforms, bash 3.2+)
# Platform must set: GPG_HOME, GPG_KEYSERVER, GPG_PINENTRY (may be empty),
# and optionally GPG_HOME_OWNER (user:group) when running as root.
# ============================================================================

ConfigureGPG() {
    HaveCommand gpg || return 0
    GPG_PUBKEY="${GPG_PUBKEY:-DD982DAAB9C71C78F9563E5207EB56787030D792}"
    BackupPath "$GPG_HOME"
    mkdir -p "$GPG_HOME"
    export GNUPGHOME="$GPG_HOME"
    gpg --keyserver "$GPG_KEYSERVER" --recv "$GPG_PUBKEY" || Die "failed to receive GPG key ${GPG_PUBKEY}"
    printf '%s:6:\n' "$GPG_PUBKEY" | gpg --import-ownertrust
    GPG_PUBKEY_ID_A=$(gpg --list-keys --keyid-format LONG | awk '/^(pub|sub)/ && /\[A\]/ {split($2, a, "/"); print a[2]}' | head -n 1)
    GPG_PUBKEY_ID_C=$(gpg --list-keys --keyid-format LONG | awk '/^(pub|sub)/ && /\[C\]/ {split($2, a, "/"); print a[2]}' | head -n 1)
    if [ -n "$GPG_PUBKEY_ID_A" ]; then
        {
            printf '%s\n' "enable-ssh-support"
            if [ -n "$GPG_PINENTRY" ]; then
                printf '%s\n' "pinentry-program ${GPG_PINENTRY}"
            fi
        } > "${GPG_HOME}/gpg-agent.conf"
        printf '%s\n' "$GPG_PUBKEY_ID_A" > "${GPG_HOME}/sshcontrol"
    fi
    if [ -n "$GPG_PUBKEY_ID_C" ]; then
        gpg --export-ssh-key "$GPG_PUBKEY_ID_C" > "${GPG_HOME}/authorized_keys"
    fi
    gpgconf --kill gpg-agent > /dev/null 2>&1 || true
    unset GNUPGHOME
    if [ -n "${GPG_HOME_OWNER:-}" ]; then
        chown -R "$GPG_HOME_OWNER" "$GPG_HOME"
    fi
    find "$GPG_HOME" -type d -exec chmod 700 {} +
    find "$GPG_HOME" -type f -exec chmod 600 {} +
}
