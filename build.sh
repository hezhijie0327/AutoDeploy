#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# Assemble the single-file distribution scripts from src/ into dist/.
# The generated dist/ scripts are what `curl | bash` fetches; commit them
# together with any src/ change (lint.sh verifies they stay in sync).
# Module composition per platform is explicit below: config layer first,
# then the core library, then the selected lib modules, then the platform
# orchestration file.

set -Eeuo pipefail
cd "$(dirname "$0")" || exit 1

mkdir -p dist

BuildScript() {
    local output="$1" usage="$2"
    shift 2
    {
        printf '%s\n' \
            '#!/bin/bash' \
            '# Copyright 2026 Zhijie He' \
            '# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.' \
            '#' \
            '# GENERATED FILE - edit src/ and run ./build.sh to regenerate.' \
            '# For a one-off tweak you may edit the Configuration block below.' \
            '#' \
            '## How to get and use?'
        printf '%s\n' "$usage"
        cat "$@"
    } > "$output"
    chmod +x "$output"
    printf 'built %s\n' "$output"
}

BuildScript "dist/DSM.sh" \
    '# curl "https://source.zhijie.online/AutoDeploy/main/dist/DSM.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/dist/DSM.sh" | sudo bash' \
    src/config/common.sh src/platforms/dsm/config.sh \
    src/lib/core.sh \
    src/lib/modules/git.sh src/lib/modules/gpg.sh src/lib/modules/ssh.sh src/lib/modules/zsh.sh \
    src/platforms/dsm/dsm.sh

BuildScript "dist/macOS.sh" \
    "# /bin/bash -c \"\$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/dist/macOS.sh')\"
# /bin/bash -c \"\$(wget -qO- 'https://source.zhijie.online/AutoDeploy/main/dist/macOS.sh')\"" \
    src/config/common.sh src/platforms/macos/config.sh \
    src/lib/core.sh \
    src/lib/modules/crontab.sh src/lib/modules/git.sh src/lib/modules/gpg.sh src/lib/modules/hosts.sh \
    src/lib/modules/proxychains.sh src/lib/modules/pypi.sh src/lib/modules/ssh.sh \
    src/lib/modules/wireguard.sh src/lib/modules/zsh.sh \
    src/platforms/macos/macos.sh

BuildScript "dist/Ubuntu.sh" \
    '# curl "https://source.zhijie.online/AutoDeploy/main/dist/Ubuntu.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/dist/Ubuntu.sh" | sudo bash' \
    src/config/common.sh src/config/debian.sh src/platforms/ubuntu/config.sh \
    src/lib/core.sh \
    src/lib/modules/crontab.sh src/lib/modules/git.sh src/lib/modules/gpg.sh src/lib/modules/hosts.sh \
    src/lib/modules/proxychains.sh src/lib/modules/pypi.sh src/lib/modules/ssh.sh \
    src/lib/modules/wireguard.sh src/lib/modules/zsh.sh \
    src/lib/modules/debian/apt.sh src/lib/modules/debian/daemons.sh src/lib/modules/debian/kernel.sh \
    src/lib/modules/debian/security.sh src/lib/modules/debian/storage.sh \
    src/lib/modules/debian/system.sh src/lib/modules/debian/users.sh \
    src/platforms/ubuntu/ubuntu.sh

BuildScript "dist/ProxmoxVE.sh" \
    '# curl "https://source.zhijie.online/AutoDeploy/main/dist/ProxmoxVE.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/dist/ProxmoxVE.sh" | sudo bash' \
    src/config/common.sh src/config/debian.sh src/platforms/proxmoxve/config.sh \
    src/lib/core.sh \
    src/lib/modules/crontab.sh src/lib/modules/git.sh src/lib/modules/gpg.sh src/lib/modules/hosts.sh \
    src/lib/modules/proxychains.sh src/lib/modules/pypi.sh src/lib/modules/ssh.sh \
    src/lib/modules/zsh.sh \
    src/lib/modules/debian/apt.sh src/lib/modules/debian/daemons.sh src/lib/modules/debian/kernel.sh \
    src/lib/modules/debian/security.sh src/lib/modules/debian/storage.sh \
    src/lib/modules/debian/system.sh src/lib/modules/debian/users.sh \
    src/platforms/proxmoxve/proxmoxve.sh
