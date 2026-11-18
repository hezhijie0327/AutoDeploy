# ============================================================================
# modules/crontab.sh - crontab installation helper (all platforms, bash 3.2+)
# Caller must set: CRONTAB_USER, CRONTAB_ENTRIES (array)
# ============================================================================

InstallCrontab() {
    HaveCommand crontab || return 0
    local sudo_prefix=()
    if [ "$(id -u)" -ne 0 ]; then
        sudo_prefix=(sudo)
    fi
    printf '%s\n' "${CRONTAB_ENTRIES[@]}" | ${sudo_prefix[@]+"${sudo_prefix[@]}"} crontab -u "$CRONTAB_USER" -
    ${sudo_prefix[@]+"${sudo_prefix[@]}"} crontab -lu "$CRONTAB_USER"
}
