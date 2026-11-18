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
        HaveCommand synogroup || return 0
        synogroup --add docker || true
        if [ -S "/var/run/docker.sock" ]; then
            chown root:docker "/var/run/docker.sock"
        fi
        synogroup --member docker "$CURRENT_USERNAME"
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
    ZSH_PATH_LIST=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/usr/syno/bin" "/usr/syno/sbin")
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

# Install Custom Packages
InstallCustomPackages() {
    OMZ_HOME="$HOME_BASE"
    OMZ_OWNER="${CURRENT_USERNAME}:users"
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
