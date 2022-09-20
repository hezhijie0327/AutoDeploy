#!/bin/sh

# Current Version: 1.0.0

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo sh
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/OpenWrt.sh" | sudo sh

## How to install OpenWrt on Ubuntu?
# dd if=openwrt-*-x86-64-combined-ext4.img of=/dev/sda bs=4M; sync;
# parted /dev/sda print
# parted /dev/sda resizepart 2 <MAX SIZE>G
# resize2fs /dev/sda2

## Function
# Set Repository Mirror
function SetRepositoryMirror() {
    sed -i 's/downloads.openwrt.org/mirrors.ustc.edu.cn\/openwrt/g' "/etc/opkg/distfeeds.conf"
}
# Upgrade Packages
function UpgradePackages() {
    opkg update && opkg list-upgradable | cut -f 1 -d ' ' | xargs opkg upgrade
}
# Cleanup Temp Files
function CleanupTempFiles() {
    rm -rf /root/.*_history /tmp/*
}

## Process
# Call SetRepositoryMirror
SetRepositoryMirror
# Call UpgradePackages
UpgradePackages
# Call CleanupTempFiles
CleanupTempFiles
