#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# Assemble the single-file distribution scripts from src/.
# The generated root scripts are what `curl | bash` fetches; commit them
# together with any src/ change (lint.sh verifies they stay in sync).

set -Eeuo pipefail
cd "$(dirname "$0")" || exit 1

BuildScript() {
    local output="$1" usage="$2"
    shift 2
    {
        printf '%s\n' \
            '#!/bin/bash' \
            '# Copyright 2026 Zhijie He' \
            '# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.' \
            '#' \
            '# GENERATED FILE - do not edit directly. Edit src/ and run ./build.sh.' \
            '#' \
            '## How to get and use?'
        printf '%s\n' "$usage"
        cat "$@"
    } > "$output"
    chmod +x "$output"
    printf 'built %s\n' "$output"
}

BuildScript "DSM.sh" \
    '# curl "https://source.zhijie.online/AutoDeploy/main/DSM.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/DSM.sh" | sudo bash' \
    src/lib/common.sh src/DSM.sh

BuildScript "macOS.sh" \
    "# /bin/bash -c \"\$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')\"
# /bin/bash -c \"\$(wget -qO- 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')\"" \
    src/lib/common.sh src/macOS.sh

BuildScript "Ubuntu.sh" \
    '# curl "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" | sudo bash' \
    src/lib/common.sh src/lib/debian.sh src/Ubuntu.sh

BuildScript "ProxmoxVE.sh" \
    '# curl "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash
# wget -qO- "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash' \
    src/lib/common.sh src/lib/debian.sh src/ProxmoxVE.sh
