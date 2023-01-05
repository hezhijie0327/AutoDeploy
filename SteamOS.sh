#!/bin/bash

# Current Version: 1.0.4

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/SteamOS.sh" | bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/SteamOS.sh" | bash

## Function
function CheckSteamDeckUser() {
        if [[ $(passwd -S "deck" | awk -F " " '{print $2}') != "P" ]]; then
            echo "deck's password has not been set. Please run <passwd> first!"
            exit 1
        fi
    }
function ConfigureSystem() {
    function ConfigureSWAP() {
        SWAP_SIZE="4"
        sudo swapoff -a && sudo dd if=/dev/zero of=/home/swapfile bs=1G count=${SWAP_SIZE} && sudo chmod 0600 /home/swapfile && sudo mkswap /home/swapfile && sudo swapon /home/swapfile
    }
    ConfigureSWAP
}
function ConfigurePackages() {
    function ConfigureIOMMU() {
        ENABLE_IOMMU="true"
        if [ -z $(cat "/etc/default/grub" | grep "amd_iommu=on iommu=pt") ] || [ "${ENABLE_IOMMU}" == "true" ]; then
            sudo sed -i 's/amd_iommu=off/amd_iommu=on iommu=pt/' '/etc/default/grub'
        else
            sudo sed -i 's/amd_iommu=on iommu=pt/amd_iommu=off/' '/etc/default/grub'
        fi && sudo update-grub
    }
    function ConfigureSysctl() {
        which "sysctl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ ! -d "/etc/sysctl.d" ]; then
                mkdir "/etc/sysctl.d"
            fi
            echo -e "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" | sudo tee "/etc/sysctl.d/bbr.conf"
            echo -e "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1" | sudo tee "/etc/sysctl.d/ip_forward.conf"
            echo -e "net.ipv4.tcp_fastopen = 3" | sudo tee "/etc/sysctl.d/tcp_fastopen.conf"
            echo -e "vm.swappiness = 10" | sudo tee "/etc/sysctl.d/swappiness.conf"
        fi
    }
    ConfigureIOMMU
    ConfigureSysctl
}

## Process
# Call CheckSteamDeckUser
CheckSteamDeckUser
# Disable Steam OS Protection
sudo steamos-readonly disable
# Call ConfigureSystem
ConfigureSystem
# Call ConfigurePackages
ConfigurePackages
# Enable Steam OS Protection
sudo steamos-readonly enable
