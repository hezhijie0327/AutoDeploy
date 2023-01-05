#!/bin/bash

# Current Version: 1.0.6

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
        if [ "${ENABLE_IOMMU}" == "true" ]; then
            sudo sed -i 's/amd_iommu=off/amd_iommu=on iommu=pt/' '/etc/default/grub'
        else
            sudo sed -i 's/amd_iommu=on iommu=pt/amd_iommu=off/' '/etc/default/grub'
        fi && sudo update-grub
    }
    function ConfigureOpenSSH() {
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/etc/ssh" ]; then
                rm -rf /etc/ssh/ssh_host_* && ssh-keygen -t dsa -b 1024 -f "/etc/ssh/ssh_host_dsa_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/etc/ssh/ssh_host_ecdsa_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/etc/ssh/ssh_host_ed25519_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/etc/ssh/ssh_host_rsa_key" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && chmod 400 /etc/ssh/ssh_host_* && chmod 644 /etc/ssh/ssh_host_*.pub
            fi
            rm -rf "/root/.ssh" && mkdir "/root/.ssh" && touch "/root/.ssh/authorized_keys" && touch "/root/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/root/.ssh/id_dsa" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/root/.ssh/id_ecdsa" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/root/.ssh/id_ed25519" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/root/.ssh/id_rsa" -C "root@$(hostname)" -N "${OPENSSH_PASSWORD}" && chmod 400 /root/.ssh/id_* && chmod 600 "/root/.ssh/authorized_keys" && chmod 644 "/root/.ssh/known_hosts" && chmod 644 /root/.ssh/id_*.pub && chmod 700 "/root/.ssh"
            rm -rf "/home/deck/.ssh" && mkdir "/home/deck/.ssh" && touch "/home/deck/.ssh/authorized_keys" && touch "/home/deck/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/home/deck/.ssh/id_dsa" -C "deck@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/home/deck/.ssh/id_ecdsa" -C "deck@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/home/deck/.ssh/id_ed25519" -C "deck@$(hostname)" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/home/deck/.ssh/id_rsa" -C "deck@$(hostname)" -N "${OPENSSH_PASSWORD}" && chown -R deck:deck "/home/deck/.ssh" && chown -R deck:deck /home/deck/.ssh/* && chmod 400 /home/deck/.ssh/id_* && chmod 600 "/home/deck/.ssh/authorized_keys" && chmod 644 "/home/deck/.ssh/known_hosts" && chmod 644 /home/deck/.ssh/id_*.pub && chmod 700 "/home/deck/.ssh" && sudo systemctl enable sshd
        fi
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
    ConfigureOpenSSH
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
