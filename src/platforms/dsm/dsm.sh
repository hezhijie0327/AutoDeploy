## Function
# Get System Information
GetSystemInformation() {
    GetCurrentUsername
    HOME_BASE="/var/services/homes/${CURRENT_USERNAME}"
    SetGHProxyDomain
}

# Configure Packages
ConfigurePackages() {
    ConfigureDocker() {
        if HaveCommand synogroup; then
            synogroup --add docker || true
            if [ -S "/var/run/docker.sock" ]; then
                chown root:docker "/var/run/docker.sock"
            fi
            synogroup --member docker "$CURRENT_USERNAME"
        fi
        # Registry mirrors for Container Manager / Docker: only the
        # registry-mirrors value is rewritten in dockerd.json - everything
        # else (data-root, the DSM "db" log-driver, storage-driver) stays as
        # the package shipped it. An empty DOCKER_REGISTRY_MIRRORS keeps the
        # file untouched.
        if [ "${#DOCKER_REGISTRY_MIRRORS[@]}" -eq 0 ]; then
            LogInfo "DOCKER_REGISTRY_MIRRORS empty; dockerd.json left unchanged"
            return 0
        fi
        local dockerd_conf="" conf_candidate pkg_name mirrors_json="[" entry sep=""
        for conf_candidate in \
            "/var/packages/ContainerManager/etc/dockerd.json" \
            "/var/packages/Docker/etc/dockerd.json"; do
            if [ -f "$conf_candidate" ]; then
                dockerd_conf="$conf_candidate"
                break
            fi
        done
        if [ -z "$dockerd_conf" ]; then
            LogInfo "Container Manager not installed; skipping registry mirrors"
            return 0
        fi
        for entry in "${DOCKER_REGISTRY_MIRRORS[@]}"; do
            mirrors_json="${mirrors_json}${sep}\"${entry}\""
            sep=","
        done
        mirrors_json="${mirrors_json}]"
        if grep -q '"registry-mirrors"' "$dockerd_conf"; then
            sed -i -E "s|\"registry-mirrors\"[[:space:]]*:[[:space:]]*\[[^]]*\]|\"registry-mirrors\": ${mirrors_json}|" "$dockerd_conf"
        else
            sed -i "s|^\{|{\"registry-mirrors\": ${mirrors_json}, |" "$dockerd_conf"
        fi
        pkg_name="$(dirname "$(dirname "$dockerd_conf")")"
        pkg_name="${pkg_name##*/}"
        synopkg restart "$pkg_name" > /dev/null 2>&1 || LogWarn "restart ${pkg_name} failed - mirrors apply at the next restart"
        LogInfo "registry mirrors set in ${dockerd_conf}"
    }
    ConfigureOpenSSH() {
        HaveCommand ssh-keygen || return 0
        local user_ssh="${HOME_BASE}/.ssh"
        InitUserSSHDir "$user_ssh" "${CURRENT_USERNAME}@$(hostname)" "${CURRENT_USERNAME}:users"
        if [ -f "${GPG_HOME}/authorized_keys" ]; then
            mv "${GPG_HOME}/authorized_keys" "${user_ssh}/authorized_keys"
            chown "${CURRENT_USERNAME}:users" "${user_ssh}/authorized_keys"
            chmod 600 "${user_ssh}/authorized_keys"
        fi
    }
    ConfigurePing() {
        HaveCommand setcap || return 0
        HaveCommand ping || return 0
        setcap 'cap_net_raw+ep' "$(command -v ping)"
    }

    GPG_HOME="${HOME_BASE}/.gnupg"
    GPG_KEYSERVER="hkp://keyserver.ubuntu.com"
    GPG_PINENTRY=""
    GPG_HOME_OWNER="${CURRENT_USERNAME}:users"
    ZSH_HOME="$HOME_BASE"
    ZSH_OWNER="${CURRENT_USERNAME}:users"
    ZSH_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/usr/syno/bin" "/usr/syno/sbin")
    ZSH_EXTRA_EXPORTS=("export DEBIAN_FRONTEND=\"noninteractive\"")
    ZSH_TRAPEXIT="true"

    RunStep "ConfigureDocker" ConfigureDocker
    RunStep "ConfigureGit" ConfigureGit
    RunStep "ConfigureGPG" ConfigureGPG
    RunStep "ConfigureOpenSSH" ConfigureOpenSSH
    RunStep "ConfigurePing" ConfigurePing
    RunStep "ConfigureZsh" ConfigureZsh
}

# Configure System
ConfigureSystem() {
    ConfigureDefaultShell() {
        HaveCommand zsh || return 0
        local zsh_path
        zsh_path=$(command -v zsh)
        local profile_list=(
            "if [[ -x ${zsh_path} ]]; then"
            "    export SHELL=${zsh_path}"
            "    exec ${zsh_path}"
            "fi"
        )
        printf '%s\n' "${profile_list[@]}" > "${HOME_BASE}/.profile"
    }
    RunStep "ConfigureDefaultShell" ConfigureDefaultShell
}

# Merge PKG_SOURCES into the Package Center feeds file. The file is a flat
# JSON array of {"feed":url,"name":name} objects, so plain string surgery
# with URL dedupe is enough - no JSON tooling required. Existing feeds are
# kept; Package Center picks the file up on its next refresh.
ConfigurePkgSources() {
    HaveCommand synopkg || return 0
    local feeds_file="/usr/syno/etc/packages/feeds"
    mkdir -p "$(dirname "$feeds_file")"
    local existing="" new_entries="" entry name url
    if [ -f "$feeds_file" ]; then
        existing="$(cat "$feeds_file")"
    fi
    for entry in "${PKG_SOURCES[@]}"; do
        name="${entry%%|*}"
        url="${entry#*|}"
        case "$existing" in
            *"$url"*) continue ;; # already configured
        esac
        entry="{\"feed\":\"${url}\",\"name\":\"${name}\"}"
        if [ -n "$new_entries" ]; then
            new_entries="${new_entries},${entry}"
        else
            new_entries="$entry"
        fi
    done
    if [ -z "$new_entries" ]; then
        LogInfo "package sources already configured"
        return 0
    fi
    case "$existing" in
        "") printf '[%s]\n' "$new_entries" > "$feeds_file" ;;
        "["*"]")
            # splice into the existing array: drop the outer brackets, keep
            # whatever is inside, and append after a comma
            existing="${existing#\[}"
            existing="${existing%\]}"
            printf '[%s,%s]\n' "$existing" "$new_entries" > "$feeds_file"
            ;;
        *)
            BackupPath "$feeds_file"
            printf '[%s]\n' "$new_entries" > "$feeds_file"
            LogWarn "unrecognized feeds content - replaced (old file backed up)"
            ;;
    esac
    # Best-effort catalog refresh; otherwise Package Center fetches it on the
    # next open.
    synopkg update > /dev/null 2>&1 || LogWarn "feed refresh deferred - open Package Center once to pick up new sources"
    LogInfo "package sources merged into ${feeds_file}"
}

# Install the PKG_PACKAGES ids from the configured feeds. Packages keep
# their default autostart; there is no synopkg on/off on DSM 7.
InstallPkgPackages() {
    HaveCommand synopkg || return 0
    local pkg
    for pkg in "${PKG_PACKAGES[@]}"; do
        if synopkg install_from_server "$pkg"; then
            LogInfo "package installed: ${pkg}"
        else
            LogWarn "synopkg install_from_server ${pkg} failed - check the feed or the package id"
        fi
    done
}

# Install Custom Packages
InstallCustomPackages() {
    OMZ_HOME="$HOME_BASE"
    OMZ_OWNER="${CURRENT_USERNAME}:users"
    RunStep "ConfigurePkgSources" ConfigurePkgSources
    RunStep "InstallPkgPackages" InstallPkgPackages
    RunStep "InstallOhMyZsh" InstallOhMyZsh
}

## Process
RequireRoot
# Call GetSystemInformation (always runs: later steps need its globals)
GetSystemInformation
InitRun
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
RenderProgress "complete"
