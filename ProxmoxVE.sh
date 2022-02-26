#!/bin/bash

# Current Version: 1.8.6

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash

## Function
# Get System Information
function GetSystemInformation() {
    function CheckHypervisorEnvironment() {
        which "virt-what" > "/dev/null" 2>&1
        if [ "$?" -eq "1" ]; then
            apt update && apt install virt-what -qy
            which "virt-what" > "/dev/null" 2>&1
            if [ "$?" -eq "1" ]; then
                echo "virt-what has not been installed!"
                exit 1
            fi
        fi && hypervisor_environment=$(virt-what) && if [ "${hypervisor_environment}" == "" ]; then
            hypervisor_environment="none"
        elif [ "${hypervisor_environment}" == "kvm" ]; then
            HYPERVISOR_AGENT=("qemu-guest-agent")
        elif [ "${hypervisor_environment}" == "vmware" ]; then
            HYPERVISOR_AGENT=("open-vm-tools")
        elif [ "${hypervisor_environment}" == "virtualbox" ]; then
            HYPERVISOR_AGENT=("virtualbox-guest-dkms")
        fi
    }
    function GenerateDomain() {
        NEW_DOMAIN="localdomain"
    }
    function GenerateHostname() {
        NEW_HOSTNAME="ProxmoxVE-$(date '+%Y%m%d%H%M%S')"
    }
    function GetCPUVendorID() {
        CPU_VENDOR_ID=$(cat '/proc/cpuinfo' | grep 'vendor_id' | uniq | awk -F ':' '{print $2}' | awk -F ' ' '{print $1}')
        if [ "${CPU_VENDOR_ID}" == "AuthenticAMD" ]; then
            CPU_VENDOR_ID="AMD"
            ENABLE_IOMMU=" amd_iommu=on iommu=pt pcie_acs_override=downstream"
        elif [ "${CPU_VENDOR_ID}" == "GenuineIntel" ]; then
            CPU_VENDOR_ID="Intel"
            ENABLE_IOMMU=" intel_iommu=on iommu=pt pcie_acs_override=downstream"
        else
            CPU_VENDOR_ID="Unknown"
            ENABLE_IOMMU=""
        fi
    }
    function GetHostname() {
        OLD_HOSTNAME=$(cat "/etc/hostname")
    }
    function GetLSBCodename() {
        LSBCodename=$(cat "/etc/os-release" | grep "CODENAME" | cut -f 2 -d "=")
    }
    function GetManagementIPAddress() {
        CURRENT_MANAGEMENT_IP=$(ip address show vmbr0 | grep "inet" | awk '{print $2}' | sort | head -n 1 | sed "s/\/.*//")
    }
    function SetGHProxyDomain() {
        export GHPROXY_URL="ghproxy.com"
    }
    CheckHypervisorEnvironment
    GenerateDomain
    GenerateHostname
    GetCPUVendorID
    GetHostname
    GetLSBCodename
    GetManagementIPAddress
    SetGHProxyDomain
}
# Set Repository Mirror
function SetRepositoryMirror() {
    mirror_list=(
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian-security ${LSBCodename}-security main contrib non-free"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename} main contrib non-free"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports main contrib non-free"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-updates main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian-security ${LSBCodename}-security main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename} main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-backports main contrib non-free"
        "deb-src ${transport_protocol}://mirrors.ustc.edu.cn/debian ${LSBCodename}-updates main contrib non-free"
    )
    proxmox_mirror_list=(
        "# deb ${transport_protocol}://enterprise.proxmox.com/debian/pve ${LSBCodename} pve-enterprise"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/proxmox/debian ${LSBCodename} pve-no-subscription"
        "# deb ${transport_protocol}://mirrors.ustc.edu.cn/proxmox/debian ${LSBCodename} pvetest"
        "deb ${transport_protocol}://mirrors.ustc.edu.cn/proxmox/debian/ceph-pacific ${LSBCodename} main"
        "# deb ${transport_protocol}://mirrors.ustc.edu.cn/proxmox/debian/ceph-pacific ${LSBCodename} test"
    )
    if [ ! -d "/etc/apt/sources.list.d" ]; then
        mkdir "/etc/apt/sources.list.d"
    else
        rm -rf /etc/apt/sources.list.d/*.*
    fi
    rm -rf "/tmp/apt.autodeploy" && for mirror_list_task in "${!mirror_list[@]}"; do
        echo "${mirror_list[$mirror_list_task]}" >> "/tmp/apt.autodeploy"
    done && cat "/tmp/apt.autodeploy" > "/etc/apt/sources.list" && rm -rf "/tmp/apt.autodeploy"
    rm -rf "/tmp/apt.autodeploy" && for proxmox_mirror_list_task in "${!proxmox_mirror_list[@]}"; do
        echo "${proxmox_mirror_list[$proxmox_mirror_list_task]}" >> "/tmp/apt.autodeploy"
    done && cat "/tmp/apt.autodeploy" > "/etc/apt/sources.list.d/proxmox.list" && rm -rf "/tmp/apt.autodeploy"
}
# Set Readonly Flag
function SetReadonlyFlag() {
    file_list=(
        "/etc/apt/sources.list"
        "/etc/apt/sources.list.d/proxmox.list"
        "/etc/chrony/chrony.conf"
        "/etc/fail2ban/fail2ban.local"
        "/etc/fail2ban/filter.d/proxmox.conf"
        "/etc/fail2ban/jail.local"
        "/etc/fail2ban/jail.d/fail2ban_default.conf"
        "/etc/hostname"
        "/etc/hosts"
        "/etc/modprobe.d/iommu_unsafe_interrupts.conf"
        "/etc/modules"
        "/etc/sysctl.conf"
        "/etc/zsh/oh-my-zsh.zshrc"
    )
    if [ "${read_only}" == "TRUE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            if [ -d "${file_list[$file_list_task]}" ] || [ -f "${file_list[$file_list_task]}" ]; then
                chattr +i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
            fi
        done
    elif [ "${read_only}" == "FALSE" ]; then
        for file_list_task in "${!file_list[@]}"; do
            if [ -d "${file_list[$file_list_task]}" ] || [ -f "${file_list[$file_list_task]}" ]; then
                chattr -i "${file_list[$file_list_task]}" > "/dev/null" 2>&1
            fi
        done
    fi
}
# Configure Packages
function ConfigurePackages() {
    function ConfigureChrony() {
        chrony_list=(
            "allow"
            "clientloglimit 65536"
            "driftfile /var/lib/chrony/chrony.drift"
            "dumpdir /run/chrony"
            "keyfile /etc/chrony/chrony.keys"
            "leapsectz right/UTC"
            "logdir /var/log/chrony"
            "makestep 1 3"
            "ratelimit burst 8 interval 3 leak 2"
            "rtcsync"
        )
        DHCP_NTP=()
        chrony_ntp_list=(
            "ntp.ntsc.ac.cn"
            "cn.ntp.org.cn"
            "time.apple.com"
            "time.windows.com"
            "time.izatcloud.net"
            "pool.ntp.org"
            "asia.pool.ntp.org"
            "cn.pool.ntp.org"
            "${DHCP_NTP[@]}"
        )
        which "chronyc" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/chrony.autodeploy" && for chrony_list_task in "${!chrony_list[@]}"; do
                echo "${chrony_list[$chrony_list_task]}" >> "/tmp/chrony.autodeploy"
            done && for chrony_ntp_list_task in "${!chrony_ntp_list[@]}"; do
                if [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "ntp.ntsc.ac.cn" ] || [ "${chrony_ntp_list[$chrony_ntp_list_task]}" == "cn.ntp.org.cn" ] || [ "$(echo ${DHCP_NTP[@]} | grep ${chrony_ntp_list[$chrony_ntp_list_task]})" != "" ]; then
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst prefer" >> "/tmp/chrony.autodeploy"
                else
                    echo "server ${chrony_ntp_list[$chrony_ntp_list_task]} iburst" >> "/tmp/chrony.autodeploy"
                fi
            done && cat "/tmp/chrony.autodeploy" > "/etc/chrony/chrony.conf" && rm -rf "/tmp/chrony.autodeploy" && systemctl restart chrony.service && sleep 5s && chronyc activity && chronyc tracking && chronyc clients && hwclock -w
        fi
    }
    function ConfigureCrontab() {
        crontab_list=(
            "0 0 * * 7 sudo apt update && sudo apt dist-upgrade -qy && sudo apt -t ${LSBCodename}-backports dist-upgrade -qy && sudo apt upgrade -qy && sudo apt -t ${LSBCodename}-backports upgrade -qy && sudo apt autoremove -qy"
            "@reboot sudo rm -rf /root/.*_history /root/.ssh/known_hosts*"
        )
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && crontab -u "root" "/tmp/crontab.autodeploy" && crontab -lu "root" && rm -rf "/tmp/crontab.autodeploy"
        fi
    }
    function ConfigureFail2Ban() {
        fail2ban_list=(
            "[proxmox]"
            "bantime = 604800"
            "enabled = true"
            "filter = proxmox"
            "findtime = 60"
            "logpath = /var/log/daemon.log"
            "maxretry = 5"
            "port = 8006"
            "[sshd]"
            "bantime = 604800"
            "enabled = true"
            "filter = sshd"
            "findtime = 60"
            "logpath = /var/log/auth.log"
            "maxretry = 5"
            "port = 22"
        )
        fail2ban_proxmox_list=(
            "[Definition]"
            "failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*"
            "ignoreregex ="
        )
        which "fail2ban-client" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/etc/fail2ban/jail.d" ]; then
                rm -rf /etc/fail2ban/jail.d/*
            else
                mkdir "/etc/fail2ban/jail.d"
            fi
            if [ -f "/etc/fail2ban/fail2ban.conf" ]; then
                cat "/etc/fail2ban/fail2ban.conf" > "/etc/fail2ban/fail2ban.local"
            fi
            if [ -f "/etc/fail2ban/jail.conf" ]; then
                cat "/etc/fail2ban/jail.conf" > "/etc/fail2ban/jail.local"
            fi
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_proxmox_list_task in "${!fail2ban_proxmox_list[@]}"; do
                echo "${fail2ban_proxmox_list[$fail2ban_proxmox_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/filter.d/proxmox.conf" && rm -rf "/tmp/fail2ban.autodeploy"
            rm -rf "/tmp/fail2ban.autodeploy" && for fail2ban_list_task in "${!fail2ban_list[@]}"; do
                echo "${fail2ban_list[$fail2ban_list_task]}" >> "/tmp/fail2ban.autodeploy"
            done && cat "/tmp/fail2ban.autodeploy" > "/etc/fail2ban/jail.d/fail2ban_default.conf" && rm -rf "/tmp/fail2ban.autodeploy" && fail2ban-client reload && sleep 5s && fail2ban-client status
        fi
    }
    function ConfigureGit() {
        gitconfig_key_list=(
            "commit.gpgsign"
            "http.proxy"
            "https.proxy"
            "user.name"
            "user.email"
            "user.signingkey"
            "url.https://${GHPROXY_URL}/https://github.com/.insteadOf"
        )
        gitconfig_value_list=(
            "${GIT_COMMIT_GPGSIGN:-false}"
            "${GIT_HTTP_PROXY}"
            "${GIT_HTTPS_PROXY}"
            "${GIT_USER_NAME}"
            "${GIT_USER_EMAIL}"
            "${GIT_USER_SIGNINGKEY}"
            "https://github.com/"
        )
        which "git" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            for gitconfig_list_task in "${!gitconfig_key_list[@]}"; do
                git config --global --unset ${gitconfig_key_list[$gitconfig_list_task]}
                if [ "${gitconfig_value_list[$gitconfig_list_task]}" != "" ]; then
                    git config --global ${gitconfig_key_list[$gitconfig_list_task]} "${gitconfig_value_list[$gitconfig_list_task]}"
                fi
            done
        fi
    }
    function ConfigureGrub() {
        which "update-grub" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -f "/usr/share/grub/default/grub" ]; then
                rm -rf "/tmp/grub.autodeploy" && cat "/usr/share/grub/default/grub" | sed "s/GRUB\_CMDLINE\_LINUX\_DEFAULT\=\"quiet\"/GRUB\_CMDLINE\_LINUX\_DEFAULT\=\"quiet${ENABLE_IOMMU}\"/g" > "/tmp/grub.autodeploy" && cat "/tmp/grub.autodeploy" > "/etc/default/grub" && update-grub && rm -rf "/tmp/grub.autodeploy"
            fi
        fi
    }
    function ConfigureIOMMU() {
        module_list=(
            "vfio"
            "vfio_iommu_type1"
            "vfio_pci"
            "vfio_virqfd"
        )
        if [ "${ENABLE_IOMMU}" != "" ]; then
            if [ -f "/etc/modules" ]; then
                rm -rf "/etc/modules"
            fi && rm -rf "/tmp/module.autodeploy" && for module_list_task in "${!module_list[@]}"; do
                echo "${module_list[$module_list_task]}" >> "/tmp/module.autodeploy"
            done && cat "/tmp/module.autodeploy" > "/etc/modules" && rm -rf "/tmp/module.autodeploy" && if [ -f "/etc/modprobe.d/iommu_unsafe_interrupts.conf" ]; then
                rm -rf "/etc/modprobe.d/iommu_unsafe_interrupts.conf"
            fi && echo "# options vfio_iommu_type1 allow_unsafe_interrupts=1" > "/etc/modprobe.d/iommu_unsafe_interrupts.conf"
        fi
    }
    function ConfigureOpenSSH() {
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ -d "/etc/ssh" ]; then
                rm -rf /etc/ssh/ssh_host_* && ssh-keygen -t dsa -b 1024 -f "/etc/ssh/ssh_host_dsa_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/etc/ssh/ssh_host_ecdsa_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/etc/ssh/ssh_host_ed25519_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/etc/ssh/ssh_host_rsa_key" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chmod 400 /etc/ssh/ssh_host_* && chmod 644 /etc/ssh/ssh_host_*.pub
            fi
            if [ -d "/etc/pve/priv" ]; then
                rm -rf "/etc/pve/priv/authorized_keys" "/etc/pve/priv/known_hosts" && touch "/etc/pve/priv/authorized_keys" && touch "/etc/pve/priv/known_hosts" && chmod 600 "/etc/pve/priv/authorized_keys" && chmod 600 "/etc/pve/priv/known_hosts"
            fi
            rm -rf "/root/.ssh" && mkdir "/root/.ssh" && touch "/root/.ssh/authorized_keys" && touch "/root/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/root/.ssh/id_dsa" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/root/.ssh/id_ecdsa" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/root/.ssh/id_ed25519" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/root/.ssh/id_rsa" -C "root@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chmod 400 /root/.ssh/id_* && chmod 600 "/root/.ssh/authorized_keys" && chmod 644 "/root/.ssh/known_hosts" && chmod 644 /root/.ssh/id_*.pub && chmod 700 "/root/.ssh"
        fi
    }
    function ConfigurePostfix() {
        if [ -f "/etc/postfix/main.cf" ]; then
            if [ "$(cat '/etc/postfix/main.cf' | grep 'myhostname\=')" != "" ]; then
                CURRENT_HOSTNAME=$(cat "/etc/postfix/main.cf" | grep "myhostname\=" | sed "s/myhostname\=//g")
                cat "/etc/postfix/main.cf" | sed "s/$CURRENT_HOSTNAME/$NEW_HOSTNAME/g" > "/tmp/main.cf.autodeploy" && cat "/tmp/main.cf.autodeploy" > "/etc/postfix/main.cf" && rm -rf "/tmp/main.cf.autodeploy"
            fi
        fi
    }
    function ConfigurePVECeph() {
        ceph_mon_list=($(ls "/etc/systemd/system/ceph-mon.target.wants" | grep "ceph-mon\@"))
        for ceph_mon_list_task in "${!ceph_mon_list[@]}"; do
            systemctl stop ${ceph_mon_list[$ceph_mon_list_task]} && systemctl disable ${ceph_mon_list[$ceph_mon_list_task]}
        done && rm -rf "/etc/ceph" "/etc/pve/ceph.conf" "/var/lib/ceph" && mkdir "/etc/ceph" "/var/lib/ceph" "/var/lib/ceph/mgr" "/var/lib/ceph/mon"
    }
    function ConfigurePVECluster() {
        systemctl stop pve-cluster && systemctl stop corosync && pmxcfs -l && rm -rf "/etc/pve/corosync.conf" && rm -rf /etc/corosync/* /var/log/corosync/* /var/lib/corosync/* && killall pmxcfs && systemctl start pve-cluster
    }
    function ConfigurePVEFirewall() {
        cluster_fw_list=(
            "[OPTIONS]"
            "ebtables: 1"
            "enable: 1"
            "log_ratelimit: burst=5,enable=1,rate=1/second"
            "policy_in: REJECT"
            "policy_out: ACCEPT"
        )
        host_fw_list=(
            "[OPTIONS]"
            "enable: 1"
            "log_level_in: err"
            "log_level_out: err"
            "log_nf_conntrack: 1"
            "ndp: 1"
            "nf_conntrack_allow_invalid: 0"
            "nf_conntrack_max: 262144"
            "nf_conntrack_tcp_timeout_established: 432000"
            "nf_conntrack_tcp_timeout_syn_recv: 60"
            "nosmurfs: 1"
            "protection_synflood: 1"
            "protection_synflood_burst: 1000"
            "protection_synflood_rate: 200"
            "smurf_log_level: err"
            "tcp_flags_log_level: err"
            "tcpflags: 1"
            "[RULES]"
            "IN ACCEPT -p icmp -log err"
            "IN ACCEPT -p udp -dport 111 -log err"
            "IN ACCEPT -p udp -dport 123 -log err"
            "IN ACCEPT -p tcp -dport 22 -log err"
            "IN ACCEPT -p tcp -dport 3128 -log err"
            "IN ACCEPT -p udp -dport 323 -log err"
            "IN ACCEPT -p udp -dport 5404:5405 -log err"
            "IN ACCEPT -p tcp -dport 5900:5999 -log err"
            "IN ACCEPT -p tcp -dport 60000:60050 -log err"
            "IN ACCEPT -p tcp -dport 8006 -log err"
        )
        vm_container_fw_list=(
            "[OPTIONS]"
            "dhcp: 1"
            "enable: 0"
            "ipfilter: 1"
            "log_level_in: err"
            "log_level_out: err"
            "macfilter: 1"
            "ndp: 1"
            "policy_in: ACCEPT"
            "policy_out: REJECT"
            "radv: 1"
        )
        vm_container_list=(
            $(ls "/etc/pve/lxc" | grep "\.conf" | sed "s/\.conf//g" | awk '{print $1}')
            $(ls "/etc/pve/qemu-server" | grep "\.conf" | sed "s/\.conf//g" | awk '{print $1}')
            "template"
        )
        rm -rf "/tmp/pve_firewall.autodeploy" && for cluster_fw_list_task in "${!cluster_fw_list[@]}"; do
            echo "${cluster_fw_list[$cluster_fw_list_task]}" >> "/tmp/pve_firewall.autodeploy"
        done && cat "/tmp/pve_firewall.autodeploy" > "/etc/pve/firewall/cluster.fw" && rm -rf "/tmp/pve_firewall.autodeploy"
        rm -rf "/tmp/pve_firewall.autodeploy" && for host_fw_list_task in "${!host_fw_list[@]}"; do
            echo "${host_fw_list[$host_fw_list_task]}" >> "/tmp/pve_firewall.autodeploy"
        done && cat "/tmp/pve_firewall.autodeploy" > "/etc/pve/nodes/${NEW_HOSTNAME}/host.fw" && rm -rf "/tmp/pve_firewall.autodeploy"
        rm -rf "/tmp/pve_firewall.autodeploy" && for vm_container_fw_list_task in "${!vm_container_fw_list[@]}"; do
            echo "${vm_container_fw_list[$vm_container_fw_list_task]}" >> "/tmp/pve_firewall.autodeploy"
        done && if [ "${#vm_container_list[@]}" -ne 0 ]; then
            for vm_container_list_task in "${!vm_container_list[@]}"; do
                cat "/tmp/pve_firewall.autodeploy" > "/etc/pve/firewall/${vm_container_list[vm_container_list_task]}.fw"
            done
        fi && rm -rf "/tmp/pve_firewall.autodeploy"
    }
    function ConfigurePythonPyPI() {
        which "pip3" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            WHICH_PIP="pip3"
        else
            which "pip" > "/dev/null" 2>&1
            if [ "$?" -eq "0" ]; then
                WHICH_PIP="pip"
            else
                WHICH_PIP="null"
            fi
        fi
        if [ "${WHICH_PIP}" != "null" ]; then
            ${WHICH_PIP} config set global.index-url "https://mirrors.ustc.edu.cn/pypi/web/simple"
        fi
    }
    function ConfigureSysctl() {
        sysctl_list=(
            "net.core.default_qdisc = fq"
            "net.ipv4.ip_forward = 1"
            "net.ipv4.tcp_congestion_control = bbr"
            "net.ipv4.tcp_fastopen = 3"
            "net.ipv6.conf.all.forwarding = 1"
        )
        which "sysctl" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/sysctl.autodeploy" && for sysctl_list_task in "${!sysctl_list[@]}"; do
                sysctl -w "$(echo ${sysctl_list[$sysctl_list_task]} | sed 's/\ //g')" > "/dev/null" 2>&1
                if [ "$?" -eq "0" ]; then
                    echo "${sysctl_list[$sysctl_list_task]}" >> "/tmp/sysctl.autodeploy"
                fi
            done && cat "/tmp/sysctl.autodeploy" > "/etc/sysctl.conf" && sysctl -p && rm -rf "/tmp/sysctl.autodeploy"
        fi
    }
    function ConfigureSshd() {
        if [ -f "/usr/share/openssh/sshd_config" ]; then
            cat "/usr/share/openssh/sshd_config" | sed "s/\#PasswordAuthentication\ yes/PasswordAuthentication\ yes/g;s/\#PermitRootLogin\ prohibit\-password/PermitRootLogin\ yes/g;s/\#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/g" > "/tmp/sshd_config.autodeploy" && cat "/tmp/sshd_config.autodeploy" > "/etc/ssh/sshd_config" && rm -rf "/tmp/sshd_config.autodeploy"
        fi
    }
    function ConfigureZsh() {
        omz_list=(
            "export DEBIAN_FRONTEND=\"noninteractive\""
            "export EDITOR=\"nano\""
            "export GPG_TTY=\$(tty)"
            "export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH\""
            "# export SSH_AUTH_SOCK=\"\$(gpgconf --list-dirs agent-ssh-socket)\" && gpgconf --launch gpg-agent && gpg-connect-agent updatestartuptty /bye > \"/dev/null\" 2>&1"
            "export ZSH=\"\$HOME/.oh-my-zsh\""
            "plugins=(zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting)"
            "ZSH_CACHE_DIR=\"\$ZSH/cache\""
            "ZSH_CUSTOM=\"\$ZSH/custom\""
            "ZSH_THEME=\"ys\""
            "DISABLE_AUTO_UPDATE=\"false\""
            "DISABLE_UPDATE_PROMPT=\"false\""
            "UPDATE_ZSH_DAYS=\"7\""
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
        if [ "$?" -eq "0" ] && [ -d "/etc/zsh/oh-my-zsh" ]; then
            rm -rf "/tmp/omz.autodeploy" && for omz_list_task in "${!omz_list[@]}"; do
                echo "${omz_list[$omz_list_task]}" >> "/tmp/omz.autodeploy"
            done && cat "/tmp/omz.autodeploy" > "/etc/zsh/oh-my-zsh.zshrc" && rm -rf "/tmp/omz.autodeploy" && ln -s "/etc/zsh/oh-my-zsh" "/root/.oh-my-zsh" && ln -s "/etc/zsh/oh-my-zsh.zshrc" "/root/.zshrc"
        fi
    }
    ConfigureChrony
    ConfigureCrontab
    ConfigureFail2Ban
    ConfigureGit
    ConfigureGrub
    ConfigureIOMMU
    ConfigureOpenSSH
    ConfigurePostfix
    ConfigurePVECeph
    ConfigurePVECluster
    ConfigurePVEFirewall
    ConfigurePythonPyPI
    ConfigureSshd
    ConfigureSysctl
    ConfigureZsh
}
# Configure System
function ConfigureSystem() {
    function ConfigureDefaultShell() {
        if [ -f "/etc/passwd" ]; then
            echo "$(cat '/etc/passwd' | sed 's/\/bin\/bash/\/bin\/zsh/g;s/\/bin\/sh/\/bin\/zsh/g')" > "/tmp/shell.autodeploy"
            cat "/tmp/shell.autodeploy" > "/etc/passwd" && rm -rf "/tmp/shell.autodeploy"
        fi
    }
    function ConfigureDefaultUser() {
        DEFAULT_FIRSTNAME="User"
        DEFAULT_LASTNAME="Proxmox"
        DEFAULT_FULLNAME="${DEFAULT_LASTNAME} ${DEFAULT_FIRSTNAME}"
        DEFAULT_USERNAME="proxmox"
        DEFAULT_PASSWORD='*Proxmox123*'
        crontab_list=(
            "@reboot rm -rf /home/${DEFAULT_USERNAME}/.*_history /home/${DEFAULT_FIRSTNAME}/.ssh/known_hosts*"
        )
        userdel -rf "${DEFAULT_USERNAME}" > "/dev/null" 2>&1
        useradd -c "${DEFAULT_FULLNAME}" -d "/home/${DEFAULT_USERNAME}" -s "/bin/zsh" -m "${DEFAULT_USERNAME}" && echo $DEFAULT_USERNAME:$DEFAULT_PASSWORD | chpasswd && adduser "${DEFAULT_USERNAME}" "sudo"
        # Please use "gpg --list-keys --with-keygrip" to get your GPG_AUTH_KEY (A) & GPG_KEY_ID (C).
        GPG_AUTH_KEY=""
        GPG_KEY_ID=""
        if [ "${GPG_AUTH_KEY}" != "" ] && [ -d "/home/${DEFAULT_USERNAME}/.gnupg" ]; then
            gpg_agent_list=(
                "enable-ssh-support"
                "pinentry-program /usr/bin/pinentry-curses"
            )
            rm -rf "/home/${DEFAULT_USERNAME}/.gnupg/gpg-agent.conf" && for gpg_agent_list_task in "${!gpg_agent_list[@]}"; do
                echo "${gpg_agent_list[$gpg_agent_list_task]}" >> "/home/${DEFAULT_USERNAME}/.gnupg/gpg-agent.conf"
            done && echo "${GPG_AUTH_KEY}" > "/home/${DEFAULT_USERNAME}/.gnupg/sshcontrol" && gpg -k && echo "Please use \"gpg --export-ssh-key ${GPG_KEY_ID} > /home/${DEFAULT_USERNAME}/.ssh/authorized_keys\" to export your SSH key."
        fi
        if [ -d "/etc/zsh/oh-my-zsh" ]; then
            cp -rf "/etc/zsh/oh-my-zsh" "/home/${DEFAULT_USERNAME}/.oh-my-zsh" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.oh-my-zsh"
            if [ -f "/etc/zsh/oh-my-zsh.zshrc" ]; then
                cp -rf "/etc/zsh/oh-my-zsh.zshrc" "/home/${DEFAULT_USERNAME}/.zshrc" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.zshrc"
            fi
        fi
        if [ -f "/root/.gitconfig" ]; then
            mv "/root/.gitconfig" "/root/.gitconfig.bak" && GIT_COMMIT_GPGSIGN="" && GIT_HTTP_PROXY="" && GIT_HTTPS_PROXY="" && GIT_USER_NAME="" && GIT_USER_EMAIL="" && GIT_USER_SIGNINGKEY="" && ConfigureGit && mv "/root/.gitconfig" "/home/${DEFAULT_USERNAME}/.gitconfig" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.gitconfig" && mv "/root/.gitconfig.bak" "/root/.gitconfig"
        fi
        if [ -f "/root/.config/pip/pip.conf" ]; then
            if [ ! -d "/home/${DEFAULT_USERNAME}/.config" ]; then
                mkdir "/home/${DEFAULT_USERNAME}/.config"
            fi
            if [ ! -d "/home/${DEFAULT_USERNAME}/.config/pip" ]; then
                mkdir "/home/${DEFAULT_USERNAME}/.config/pip"
            fi
            rm -rf "/home/${DEFAULT_USERNAME}/.config/pip/pip.conf" && cp -rf "/root/.config/pip/pip.conf" "/home/${DEFAULT_USERNAME}/.config/pip/pip.conf" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.config" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.config/pip" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.config/pip/pip.conf"
        fi
        which "crontab" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/tmp/crontab.autodeploy" && for crontab_list_task in "${!crontab_list[@]}"; do
                echo "${crontab_list[$crontab_list_task]}" >> "/tmp/crontab.autodeploy"
            done && crontab -u "${DEFAULT_USERNAME}" "/tmp/crontab.autodeploy" && crontab -lu "${DEFAULT_USERNAME}" && rm -rf "/tmp/crontab.autodeploy"
        fi
        OPENSSH_PASSWORD=""
        which "ssh-keygen" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            rm -rf "/home/${DEFAULT_USERNAME}/.ssh" && mkdir "/home/${DEFAULT_USERNAME}/.ssh" && touch "/home/${DEFAULT_USERNAME}/.ssh/authorized_keys" && touch "/home/${DEFAULT_USERNAME}/.ssh/known_hosts" && ssh-keygen -t dsa -b 1024 -f "/home/${DEFAULT_USERNAME}/.ssh/id_dsa" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ecdsa -b 384 -f "/home/${DEFAULT_USERNAME}/.ssh/id_ecdsa" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t ed25519 -f "/home/${DEFAULT_USERNAME}/.ssh/id_ed25519" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && ssh-keygen -t rsa -b 4096 -f "/home/${DEFAULT_USERNAME}/.ssh/id_rsa" -C "${DEFAULT_USERNAME}@${NEW_HOSTNAME}" -N "${OPENSSH_PASSWORD}" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME "/home/${DEFAULT_USERNAME}/.ssh" && chown -R $DEFAULT_USERNAME:$DEFAULT_USERNAME /home/${DEFAULT_USERNAME}/.ssh/* && chmod 400 /home/${DEFAULT_USERNAME}/.ssh/id_* && chmod 600 "/home/${DEFAULT_USERNAME}/.ssh/authorized_keys" && chmod 644 "/home/${DEFAULT_USERNAME}/.ssh/known_hosts" && chmod 644 /home/${DEFAULT_USERNAME}/.ssh/id_*.pub && chmod 700 "/home/${DEFAULT_USERNAME}/.ssh"
        fi
        which "pveum" > "/dev/null" 2>&1
        if [ "$?" -eq "0" ]; then
            if [ "$(pveum group list | grep 'LADM')" == "" ]; then
                pveum groupadd "LADM" -comment "Local Administrators"
            else
                pveum group modify "LADM" -comment "Local Administrators"
            fi && pveum aclmod "/" -group "LADM" -role "Administrator" && if [ "$(pveum user list | grep ${DEFAULT_USERNAME}@pam)" == "" ]; then
                pveum useradd "${DEFAULT_USERNAME}@pam" -comment "${DEFAULT_FULLNAME}" -firstname "${DEFAULT_FIRSTNAME}" -group "LADM" -lastname "${DEFAULT_LASTNAME}"
            else
                pveum usermod "${DEFAULT_USERNAME}@pam" -comment "${DEFAULT_FULLNAME}" -firstname "${DEFAULT_FIRSTNAME}" -group "LADM" -lastname "${DEFAULT_LASTNAME}"
            fi && pveum usermod "root@pam" -comment "Proxmox Root" -firstname "Root" -group "LADM" -lastname "Proxmox"
        fi
    }
    function ConfigureHostfile() {
        host_list=(
            "${CURRENT_MANAGEMENT_IP} ${NEW_HOSTNAME}.${NEW_DOMAIN} ${NEW_HOSTNAME}"
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
        done && cat "/tmp/hosts.autodeploy" > "/etc/hosts" && rm -rf "/tmp/hosts.autodeploy"
        rm -rf "/tmp/hostname.autodeploy" && echo "${NEW_HOSTNAME}" > "/tmp/hostname.autodeploy" && cat "/tmp/hostname.autodeploy" > "/etc/hostname" && rm -rf "/tmp/hostname.autodeploy"
    }
    function ConfigureProxmoxVENode() {
        if [ "${OLD_HOSTNAME}" != "${NEW_HOSTNAME}" ]; then
            if [ -d "/etc/pve/nodes/${OLD_HOSTNAME}" ]; then
                tar -czvf "/etc/pve/nodes/${OLD_HOSTNAME}.tar.gz" "/etc/pve/nodes/${OLD_HOSTNAME}" && if [ -f "/etc/pve/nodes/${OLD_HOSTNAME}.tar.gz" ]; then
                    rm -rf "/etc/pve/nodes/${OLD_HOSTNAME}"
                fi
            fi
            if [ -f "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}" ]; then
                cp -rf "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}" "/var/lib/rrdcached/db/pve2-node/${NEW_HOSTNAME}" && if [ -f "/var/lib/rrdcached/db/pve2-node/${NEW_HOSTNAME}" ]; then
                    rm -rf "/var/lib/rrdcached/db/pve2-node/${OLD_HOSTNAME}"
                fi
            fi
            if [ -d "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" ]; then
                cp -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}" "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}" && if [ -d "/var/lib/rrdcached/db/pve2-storage/${NEW_HOSTNAME}" ]; then
                    rm -rf "/var/lib/rrdcached/db/pve2-storage/${OLD_HOSTNAME}"
                fi
            fi
        fi
    }
    function ConfigureRootUser() {
        LOCK_ROOT="TRUE"
        ROOT_PASSWORD='R00t@123!'
        echo root:$ROOT_PASSWORD | chpasswd && if [ "${LOCK_ROOT}" == "TRUE" ]; then
            passwd -l "root"
        else
            passwd -u "root"
        fi
    }
    ConfigureDefaultShell
    ConfigureDefaultUser
    ConfigureHostfile
    ConfigureProxmoxVENode
    ConfigureRootUser
}
# Install Custom Packages
function InstallCustomPackages() {
    function InstallOhMyZsh() {
        plugin_list=(
            "zsh-autosuggestions"
            "zsh-completions"
            "zsh-history-substring-search"
            "zsh-syntax-highlighting"
        )
        plugin_upgrade_list=(
            '#!/bin/bash'
            'plugin_list=($(ls "$HOME/.oh-my-zsh/custom/plugins" | grep -v "^example$" | awk "{print $1}"))'
            'for plugin_list_task in "${!plugin_list[@]}"; do'
            "    rm -rf \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\" && git clone --depth=1 \"https://${GHPROXY_URL}/https://github.com/zsh-users/\${plugin_list[\$plugin_list_task]}.git\" \"\$HOME/.oh-my-zsh/custom/plugins/\${plugin_list[\$plugin_list_task]}\""
            'done'
        )
        rm -rf "/etc/zsh/oh-my-zsh" && git clone --depth=1 "https://${GHPROXY_URL}/https://github.com/ohmyzsh/ohmyzsh.git" "/etc/zsh/oh-my-zsh" && if [ -d "/etc/zsh/oh-my-zsh/custom/plugins" ]; then
            for plugin_list_task in "${!plugin_list[@]}"; do
                rm -rf "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}" && git clone --depth=1 "https://${GHPROXY_URL}/https://github.com/zsh-users/${plugin_list[$plugin_list_task]}.git" "/etc/zsh/oh-my-zsh/custom/plugins/${plugin_list[$plugin_list_task]}"
            done
        fi && rm -rf "/etc/zsh/oh-my-zsh/oh-my-zsh-plugin.sh" && for plugin_upgrade_list_task in "${!plugin_upgrade_list[@]}"; do
            echo "${plugin_upgrade_list[$plugin_upgrade_list_task]}" >> "/etc/zsh/oh-my-zsh/oh-my-zsh-plugin.sh"
        done
    }
    InstallOhMyZsh
}
# Install Dependency Packages
function InstallDependencyPackages() {
    app_regular_list=(
        "apt-file"
        "apt-transport-https"
        "ca-certificates"
        "ceph"
        "chrony"
        "curl"
        "dnsutils"
        "fail2ban"
        "git"
        "git-flow"
        "git-lfs"
        "gnupg"
        "iperf3"
        "jq"
        "knot-dnsutils"
        "lsb-release"
        "mailutils"
        "mtr-tiny"
        "nano"
        "neofetch"
        "net-tools"
        "nmap"
        "ntfs-3g"
        "openssh-client"
        "openssh-server"
        "p7zip-full"
        "pinentry-curses"
        "postfix"
        "python3"
        "python3-pip"
        "qrencode"
        "rar"
        "sudo"
        "systemd"
        "tcpdump"
        "tshark"
        "unrar"
        "unzip"
        "vim"
        "virt-what"
        "wget"
        "whois"
        "zip"
        "zsh"
    )
    hypervisor_agent_list=(
        "qemu-guest-agent"
        "open-vm-tools"
        "virtualbox-guest-dkms"
    )
    app_list=(${app_regular_list[*]} ${HYPERVISOR_AGENT[*]})
    apt update && for app_list_task in "${!app_list[@]}"; do
        apt-cache show ${app_list[$app_list_task]} && if [ "$?" -eq "0" ]; then
            apt install -qy ${app_list[$app_list_task]}
        fi
    done && for hypervisor_agent_list_task in "${!hypervisor_agent_list[@]}"; do
        if [ "${hypervisor_agent_list[$hypervisor_agent_list_task]}" != "${HYPERVISOR_AGENT[*]}" ]; then
            if [ "$(apt list --installed | grep ${hypervisor_agent_list[$hypervisor_agent_list_task]})" != "" ]; then
                apt purge -yq ${hypervisor_agent_list[$hypervisor_agent_list_task]} && apt autoremove -yq
            fi
        fi
    done
}
# Upgrade Packages
function UpgradePackages() {
    apt update && apt dist-upgrade -qy && apt -t ${LSBCodename}-backports dist-upgrade -qy && apt upgrade -qy && apt -t ${LSBCodename}-backports upgrade -qy && apt autoremove -qy
}
# Cleanup Temp Files
function CleanupTempFiles() {
    apt clean && rm -rf /root/.*_history /tmp/*
}

## Process
# Set DEBIAN_FRONTEND to "noninteractive"
export DEBIAN_FRONTEND="noninteractive"
# Set read_only="FALSE"; Call SetReadonlyFlag
read_only="FALSE" && SetReadonlyFlag
# Call GetSystemInformation
GetSystemInformation
# Set transport_protocol="http"; Call SetRepositoryMirror
transport_protocol="http" && SetRepositoryMirror
# Call InstallDependencyPackages
InstallDependencyPackages
# Set transport_protocol="https"; Call SetRepositoryMirror
transport_protocol="https" && SetRepositoryMirror
# Call UpgradePackages
UpgradePackages
# Call InstallCustomPackages
InstallCustomPackages
# Call ConfigurePackages
ConfigurePackages
# Call ConfigureSystem
ConfigureSystem
# Set read_only="TRUE"; Call SetReadonlyFlag
read_only="TRUE" && SetReadonlyFlag
# Call CleanupTempFiles
CleanupTempFiles
