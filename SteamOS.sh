#!/bin/bash

# Current Version: 1.0.0

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/SteamOS.sh" | bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/SteamOS.sh" | bash

## Function
function ConfigureDeckUser() {
        if [[ $(passwd -S "deck" | awk -F " " '{print $2}') != "P" ]]; then
            DECK_PASSWORD='*SteamOS123*'
            echo deck:$DECK_PASSWORD | chpasswd
        fi && echo ${DECK_PASSWORD} | sudo -v -S
    }
function ConfigureSystem() {
    function ConfigureSWAP() {
        SWAP_SIZE="1"
        sudo swapoff -a && sudo dd if=/dev/zero of=/home/swapfile bs=1G count=${SWAP_SIZE} && sudo chmod 0600 /home/swapfile && sudo mkswap /home/swapfile && sudo swapon /home/swapfile
    }
    ConfigureSWAP
}
function ConfigurePackages() {
    function ConfigureIOMMU() {
        ENABLE_IOMMU="false"
        if [ -z $(cat "/etc/default/grub" | grep -E -i 'GRUB_CMDLINE_LINUX_DEFAULT=".+(amd_iommu=on iommu=pt).+"') ] || [ "${ENABLE_IOMMU}" == "true" ]; then
            sudo sed -i 's/amd_iommu=off/amd_iommu=on iommu=pt/' '/etc/default/grub'
        else
            sudo sed -i 's/amd_iommu=on iommu=pt/amd_iommu=off/' '/etc/default/grub'
        fi
    }
    function ConfigureSysctl() {
        which "sysctl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ ! -d "/etc/sysctl.d" ]; then
                mkdir "/etc/sysctl.d"
            fi
            sudo echo -e "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" > "/etc/sysctl.d/bbr.conf"
            sudo echo -e "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1" > "/etc/sysctl.d/ip_forward.conf"
            sudo echo -e "net.ipv4.tcp_fastopen = 3" > "/etc/sysctl.d/tcp_fastopen.conf"
            sudo echo -e "vm.swappiness = 10" > "/etc/sysctl.d/swappiness.conf"
        fi && sudo sysctl -p
    }
    ConfigureIOMMU
    ConfigureSysctl
}

## Process
# Call ConfigureDeckUser
ConfigureDeckUser
# Disable Steam OS Protection
sudo steamos-readonly disable
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Enable Steam OS Protection
sudo steamos-readonly enable
