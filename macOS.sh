#!/bin/bash

# Current Version: 1.6.3

## How to get and use?
# /bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"
# /bin/bash -c "$(wget -qO- 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"

## Function
# Get System Information
function GetSystemInformation() {
    function GetCurrentUsername() {
        CurrentUsername=$(whoami)
    }
    function IsArmArchitecture() {
        if [ "$(uname -m)" == "arm64" ]; then
            softwareupdate --install-rosetta
        else
            if [ "$(uname -m)" != "x86_64" ]; then
                echo "Unsupported architecture."
                exit 1
            fi
        fi
    }
    GetCurrentUsername
    IsArmArchitecture
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureCrontab() {
        crontab_list=(
            "@reboot rm -rf /Users/${CurrentUsername}/.*_history"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && sudo crontab -u "${CurrentUsername}" "/tmp/crontab.autodeploy" && sudo crontab -lu "${CurrentUsername}" && rm -rf "/tmp/crontab.autodeploy"
        fi
    }
    function ConfigureZsh() {
        function GenerateCommandPath() {
            default_path_list=(
                "/bin"
                "/sbin"
                "/usr/bin"
                "/usr/sbin"
                "/usr/local/bin"
                "/usr/local/sbin"
                "/opt/homebrew/bin"
                "/opt/homebrew/sbin"
            )
            for default_path_list_task in "${!default_path_list[@]}"; do
                DEFAULT_PATH="${default_path_list[$default_path_list_task]}:${DEFAULT_PATH}"
                DEFAULT_PATH=$(echo "${DEFAULT_PATH}" | sed "s/\:$//g")
            done
            custom_path_list=(
                "coreutils/libexec/gnubin"
                "curl/bin"
                "findutils/libexec/gnubin"
                "gawk/libexec/gnubin"
                "gnu-indent/libexec/gnubin"
                "gnu-sed/libexec/gnubin"
                "gnu-tar/libexec/gnubin"
                "gnu-time/libexec/gnubin"
                "gnu-units/libexec/gnubin"
                "gnu-which/libexec/gnubin"
                "grep/libexec/gnubin"
                "libtool/libexec/gnubin"
                "whois/bin"
            )
            export PATH="${DEFAULT_PATH}" && BREW_PATH="$(brew --prefix)/opt" && for custom_path_list_task in "${!custom_path_list[@]}"; do
                CUSTOM_PATH="${BREW_PATH}/${custom_path_list[$custom_path_list_task]}:${CUSTOM_PATH}"
                CUSTOM_PATH=$(echo "${CUSTOM_PATH}" | sed "s/\:$//g")
            done
        }
        function GenerateOMZProfile() {
            omz_list=(
                "export EDITOR=\"nano\""
                "export GPG_TTY=\$\(tty\)"
                "export HOMEBREW_BOTTLE_DOMAIN=\"https://mirrors.ustc.edu.cn/homebrew-bottles/bottles\""
                "export HOMEBREW_GITHUB_API_TOKEN=\"your_token_here\""
                "export PATH=\"${CUSTOM_PATH}:${DEFAULT_PATH}\""
                "export ZSH=\"\$HOME/.oh-my-zsh\""
                "plugins=(zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting)"
                "ZSH_CACHE_DIR=\"\$ZSH/cache\""
                "ZSH_CUSTOM=\"\$ZSH/custom\""
                "ZSH_THEME=\"ys\""
                "DISABLE_AUTO_UPDATE=\"false\""
                "DISABLE_UPDATE_PROMPT=\"false\""
                "UPDATE_ZSH_DAYS=\"30\""
                "ZSH_COMPDUMP=\"\$ZSH_CACHE_DIR/.zcompdump\""
                "ZSH_DISABLE_COMPFIX=\"false\""
                "CASE_SENSITIVE=\"true\""
                "COMPLETION_WAITING_DOTS=\"true\""
                "DISABLE_AUTO_TITLE=\"false\""
                "DISABLE_LS_COLORS=\"false\""
                "DISABLE_MAGIC_FUNCTIONS=\"false\""
                "DISABLE_UNTRACKED_FILES_DIRTY=\"false\""
                "ENABLE_CORRECTION=\"true\""
                "HIST_STAMPS=\"yyyy-mm-dd\""
                "HYPHEN_INSENSITIVE=\"false\""
                "ZSH_THEME_RANDOM_QUIET=\"true\""
                "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE=\"bg=250,fg=238,bold,underline\""
                "ZSH_AUTOSUGGEST_STRATEGY=(match_prev_cmd history completion)"
                "ZSH_AUTOSUGGEST_USE_ASYNC=\"true\""
                "source \"\$(brew --repository)/Library/Taps/homebrew/homebrew-command-not-found/handler.sh\""
                "source \"\$ZSH/oh-my-zsh.sh\""
            )
            which "zsh" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ] && [ -d "/Users/${CurrentUsername}/.oh-my-zsh" ]; then
                rm -rf "/tmp/omz.autodeploy" && for omz_list_task in "${!omz_list[@]}"; do
                    echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.autodeploy"
                done && cat "/tmp/omz.autodeploy" > "/Users/${CurrentUsername}/.zshrc" && rm -rf "/tmp/omz.autodeploy"
            fi
        }
        GenerateCommandPath
        GenerateOMZProfile
    }
    ConfigureCrontab
    ConfigureZsh
}
# Configure System
function ConfigureSystem() {
    function ConfigureHostfile() {
        host_list=(
            "127.0.0.1 localhost"
            "255.255.255.255 broadcasthost"
            "::1 ip6-localhost ip6-loopback localhost"
            "fe00::0 ip6-localnet"
            "ff00::0 ip6-mcastprefix"
            "ff02::1 ip6-allnodes"
            "ff02::2 ip6-allrouters"
            "ff02::3 ip6-allhosts"
        )
        rm -rf "/tmp/hosts.autodeploy" && for host_list_task in "${!host_list[@]}"; do
            echo "${host_list[$host_list_task]}" >> "/tmp/hosts.autodeploy"
        done && sudo chmod -R 666 "/etc/hosts" && sudo cat "/tmp/hosts.autodeploy" > "/etc/hosts" && sudo chmod -R 644 "/etc/hosts" && rm -rf "/tmp/hosts.autodeploy"
    }
    ConfigureHostfile
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallAppFromCask() {
        app_list=(
            "betterzip" # BetterZip
            "cleanmymac" # CleanMyMac X
            "cleanshot" # CleanShot X
            "docker" # Docker
            "downie" # Downie 4
            "firefox" # Firefox
            "iina" # IINA
            "logitech-options" # Logi Options
            "parallels" # Parallels Desktop
            "permute" # Permute 3
            "pixelsnap" # PixelSnap 2
            "visual-studio-code" # Visual Studio Code
        )
        which "brew" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for app_list_task in "${!app_list[@]}"; do
                brew info --cask ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    brew install --cask ${app_list[$app_list_task]}
                fi
            done
        fi
    }
    function InstallAppFromMAS() {
        app_list=(
            "1136220934" # Infuse
            "409222199" # Cyberduck
            "419330170" # Moom
            "424389933" # Final Cut Pro
            "424390742" # Compressor
            "430798174" # HazeOver
            "434290957" # Motion
            "451108668" # QQ
            "462054704" # Microsoft Word
            "462058435" # Microsoft Excel
            "462062816" # Microsoft PowerPoint
            "497799835" # Xcode
            "634148309" # Logic Pro
            "634159523" # MainStage
            "823766827" # OneDrive
            "824183456" # Affinity Photo
            "836500024" # Wechat
            "993841014" # CopyLess 2
        )
        which "mas" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for app_list_task in "${!app_list[@]}"; do
                mas info ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    mas install ${app_list[$app_list_task]} && if [ "$?" -eq "1" ]; then
                        mas purchase ${app_list[$app_list_task]}
                    fi
                fi
            done
        fi
    }
    function InstallOhMyZsh() {
        plugin_list=(
            "zsh-autosuggestions"
            "zsh-completions"
            "zsh-history-substring-search"
            "zsh-syntax-highlighting"
        )
        rm -rf "/Users/${CurrentUsername}/.oh-my-zsh" && git clone --depth=1 "https://github.com.cnpmjs.org/ohmyzsh/ohmyzsh.git" "/Users/${CurrentUsername}/.oh-my-zsh" && if [ -d "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://github.com.cnpmjs.org/zsh-users/${plugin_list[$plugin_list_task]}.git" "/Users/${CurrentUsername}/.oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi
    }
    InstallAppFromCask
    InstallAppFromMAS
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    tap_list=(
        "homebrew-aliases"
        "homebrew-autoupdate"
        "homebrew-bundle"
        "homebrew-cask"
        "homebrew-cask-drivers"
        "homebrew-cask-fonts"
        "homebrew-cask-versions"
        "homebrew-command-not-found"
        "homebrew-core"
        "homebrew-formula-analytics"
        "homebrew-json"
        "homebrew-portable-ruby"
        "homebrew-services"
        "homebrew-test-bot"
    )
    export PATH="/opt/homebrew/sbin:/opt/homebrew/bin:${PATH}"
    which "brew" > "/dev/null" 2>&1
    if [ "$?" -eq "1" ]; then
        /bin/bash -c "$(curl -fsSL 'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh' | sed 's/https\:\/\/github\.com/https\:\/\/github\.com\.cnpmjs\.org/g')"
    fi && export HOMEBREW_BOTTLE_DOMAIN="https://mirrors.ustc.edu.cn/homebrew-bottles/bottles"
    if [ -d "$(brew --repo)/Library/Taps/homebrew" ]; then
        app_list=(
            "bash"
            "coreutils"
            "curl"
            "ffmpeg"
            "findutils"
            "gawk"
            "git"
            "git-flow"
            "git-lfs"
            "gnu-apl"
            "gnu-barcode"
            "gnu-chess"
            "gnu-cobol"
            "gnu-complexity"
            "gnu-getopt"
            "gnu-go"
            "gnu-indent"
            "gnu-scientific-library"
            "gnu-sed"
            "gnu-shogi"
            "gnu-tar"
            "gnu-time"
            "gnu-typist"
            "gnu-units"
            "gnu-which"
            "gnupg"
            "gnutls"
            "grep"
            "iperf3"
            "jq"
            "knot"
            "mailutils"
            "mas"
            "mercurial"
            "mtr"
            "nano"
            "neofetch"
            "openssh"
            "p7zip"
            "rar"
            "unzip"
            "vim"
            "wget"
            "whois"
            "wireshark"
            "youtube-dl"
            "zip"
            "zsh"
        )
        for tap_list_task in "${!tap_list[@]}"; do
            rm -rf "$(brew --repo)/Library/Taps/homebrew/${tap_list[$tap_list_task]}" && git clone "https://github.com.cnpmjs.org/Homebrew/${tap_list[$tap_list_task]}.git" "$(brew --repo)/Library/Taps/homebrew/${tap_list[$tap_list_task]}"
        done && brew update && for app_list_task in "${!app_list[@]}"; do
            brew info --formula ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                brew install --formula ${app_list[$app_list_task]}
            else
                brew info --cask ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    brew install --cask ${app_list[$app_list_task]}
                fi
            fi
        done
    fi
}
# Upgrade Packages
function UpgradePackages() {
    brew update && brew upgrade --cask --greedy && brew upgrade --formula && mas upgrade && softwareupdate -ai
}
# Cleanup Temp Files
function CleanupTempFiles() {
    brew cleanup && rm -rf /Users/${CurrentUsername}/.*_history /tmp/*.autodeploy
}

## Process
# Call GetSystemInformation
GetSystemInformation
# Call InstallDependencyPackages
InstallDependencyPackages
# Call UpgradePackages
UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigurePackages
ConfigurePackages
# Call ConfigureSystem
ConfigureSystem
# Call CleanupTempFiles
CleanupTempFiles
