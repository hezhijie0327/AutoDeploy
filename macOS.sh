#!/bin/bash

# Current Version: 1.1.5

## How to get and use?
# /bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"
# /bin/bash -c "$(wget -qO- 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"

## Function
# Get System Information
function GetSystemInformation() {
    function GetCurrentUsername() {
        CurrentUsername=$(whoami)
    }
    GetCurrentUsername
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureCrontab() {
        crontab_list=(
            "0 0 * * 7 brew update && brew upgrade && brew cleanup && mas upgrade && softwareupdate -ai"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.tmp" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.tmp"
            done && sudo crontab -u "${CurrentUsername}" "/tmp/crontab.tmp" && sudo crontab -lu "${CurrentUsername}" && rm -rf "/tmp/crontab.tmp"
        fi
    }
    function ConfigureZsh() {
        omz_list=(
            "export HOMEBREW_BOTTLE_DOMAIN=\"https://mirrors.ustc.edu.cn/homebrew-bottles/bottles\""
            "export PATH=\"/opt/homebrew/bin:/usr/local/sbin:\$PATH\""
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
            "source \"\$ZSH/oh-my-zsh.sh\""
        )
        which "zsh" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ] && [ -d "/Users/${CurrentUsername}/.oh-my-zsh" ]; then
            rm -rf "/tmp/omz.tmp" && for omz_list_task in "${!omz_list[@]}"; do
                echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.tmp"
            done && cat "/tmp/omz.tmp" > "/Users/${CurrentUsername}/.zshrc" && rm -rf "/tmp/omz.tmp"
        fi
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
        rm -rf "/tmp/hosts.tmp" && for host_list_task in "${!host_list[@]}"; do
            echo "${host_list[$host_list_task]}" >> "/tmp/hosts.tmp"
        done && sudo chmod -R 666 "/etc/hosts" && sudo cat "/tmp/hosts.tmp" > "/etc/hosts" && sudo chmod -R 644 "/etc/hosts" && rm -rf "/tmp/hosts.tmp"
    }
    ConfigureHostfile
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallAppFromCask() {
        app_list=(
            "adguard" # AdGuard
            "betterzip" # BetterZip
            "cleanmymac" # CleanMyMac X
            "cleanshot" # CleanShot X
            "docker" # Docker
            "downie" # Downie 4
            "folx" # Folx
            "github" # GitHub Desktop
            "iina" # IINA
            "logitech-options" # Logi Options
            "loopback" # Loopback
            "obs" # OBS
            "parallels" # Parallels Desktop
            "permute" # Permute 3
            "pixelsnap" # PixelSnap 2
            "visual-studio-code" # Visual Studio Code
        )
        which "brew" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for app_list_task in "${!app_list[@]}"; do
                brew search --cask ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
                    brew install --cask ${app_list[$app_list_task]}
                fi
            done
        fi
    }
    function InstallAppFromMAS() {
        app_list=(
            "1176074088" # Termius
            "1289583905" # Pixelmator Pro
            "1333542190" # 1Password 7
            "408981434" # iMovie
            "409183694" # Keynote
            "409201541" # Pages
            "409203825" # Numbers
            "409222199" # Cyberduck
            "424389933" # Final Cut Pro
            "424390742" # Compressor
            "430798174" # HazeOver
            "434290957" # Motion
            "441258766" # Magnet
            "451108668" # QQ
            "462054704" # Microsoft Word
            "462058435" # Microsoft Excel
            "462062816" # Microsoft PowerPoint
            "497799835" # Xcode
            "595615424" # QQ Music
            "634148309" # Logic Pro
            "634159523" # MainStage
            "682658836" # GarageBand
            "789066512" # Maipo
            "824171161" # Affinity Designer
            "824183456" # Affinity Photo
            "836500024" # WeChat
            "881418622" # Affinity Publisher
            "937984704" # Amphetamine
            "967805235" # Paste
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
        "homebrew-cask-versions"
        "homebrew-cask"
        "homebrew-core"
    )
    which "brew" > "/dev/null" 2>&1
    if [ "$?" -eq "1" ]; then
        /bin/bash -c "$(curl -fsSL 'https://cdn.jsdelivr.net/gh/Homebrew/install@master/install.sh' | sed 's/https\:\/\/github\.com\/Homebrew\/brew/https\:\/\/mirrors\.ustc\.edu\.cn\/brew\.git/g;s/https\:\/\/github\.com\/Homebrew\/homebrew\-core/https\:\/\/mirrors\.ustc\.edu\.cn\/homebrew\-core\.git/g')"
    fi && export HOMEBREW_BOTTLE_DOMAIN="https://mirrors.ustc.edu.cn/homebrew-bottles/bottles"
    if [ -d "/usr/local/Homebrew/Library/Taps/homebrew" ]; then
        for tap_list_task in "${!tap_list[@]}"; do
            rm -rf "/usr/local/Homebrew/Library/Taps/homebrew/${tap_list[$tap_list_task]}" && git clone "https://mirrors.ustc.edu.cn/${tap_list[$tap_list_task]}.git" "/usr/local/Homebrew/Library/Taps/homebrew/${tap_list[$tap_list_task]}"
        done && brew update && brew install bash curl git jq knot mas nano neofetch vim wget zsh && brew cleanup && softwareupdate --install-rosetta
    fi
}
# Upgrade Packages
function UpgradePackages() {
    brew update && brew upgrade && brew cleanup && mas upgrade && softwareupdate -ai
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
