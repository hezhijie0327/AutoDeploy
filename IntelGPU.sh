#!/bin/bash

# Current Version: 1.0.0

## How to get and use?
# curl "https://source.zhijie.online/AutoDeploy/main/IntelGPU.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/IntelGPU.sh" | sudo bash

GHPROXY_URL=""
DOWNLOAD_DIR="/tmp"

URL=(
    $(cURL -s "https://api.github.com/repos/intel/compute-runtime/releases/latest" | grep -o '"browser_download_URL": *"[^"]*"' | awk -F '"' '{print $4}')
    $(cURL -s "https://api.github.com/repos/intel/intel-graphics-compiler/releases/latest" | grep -o '"browser_download_URL": *"[^"]*"' | awk -F '"' '{print $4}')
)

for i in "${URL[@]}"; do
    if [ -n "$GHPROXY_URL" ]; then
        i=$(echo $i | sed "s|https://github.com|https://${GHPROXY_URL}/https://github.com|g")
    fi && wget -P $DOWNLOAD_DIR $i
done

if [ -f $DOWNLOAD_DIR/*.deb ]; then
    dpkg -i $DOWNLOAD_DIR/*.deb && rm -rf $DOWNLOAD_DIR/*.deb
fi
if [ -f $DOWNLOAD_DIR/*.ddeb ]; then
    dpkg -i $DOWNLOAD_DIR/*.ddeb && rm -rf $DOWNLOAD_DIR/*.ddeb
fi
