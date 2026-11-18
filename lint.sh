#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# Validate sources and generated scripts:
#   1. bash -n syntax check on every shell file
#   2. shellcheck on the generated single-file scripts (if installed)
#   3. generated dist/ scripts match a fresh build (no forgotten rebuilds)

set -Eeuo pipefail
cd "$(dirname "$0")" || exit 1

status=0

printf '== bash -n ==\n'
while IFS= read -r file; do
    if bash -n "$file"; then
        printf 'ok   %s\n' "$file"
    else
        printf 'FAIL %s\n' "$file"
        status=1
    fi
done < <(find src dist -name '*.sh' -not -path '*/.git/*' | sort)

if command -v shellcheck > /dev/null 2>&1; then
    printf '\n== shellcheck ==\n'
    while IFS= read -r file; do
        if shellcheck --shell=bash --severity=warning "$file"; then
            printf 'ok   %s\n' "$file"
        else
            printf 'FAIL %s\n' "$file"
            status=1
        fi
    done < <(find src/lib -name '*.sh' | sort; printf '%s\n' dist/DSM.sh dist/macOS.sh dist/Ubuntu.sh dist/ProxmoxVE.sh dist/Reinstall.sh)
else
    printf '\n== shellcheck ==\nskipped (not installed)\n'
fi

printf '\n== step count ==\n'
for file in dist/DSM.sh dist/macOS.sh dist/Ubuntu.sh dist/ProxmoxVE.sh dist/Reinstall.sh; do
    count=$(grep -cE '^[[:space:]]*RunStep "' "$file" || true)
    total=$(sed -n 's/^AUTODEPLOY_STEP_TOTAL=\([0-9][0-9]*\).*/\1/p' "$file")
    if [ "$count" = "$total" ]; then
        printf 'ok   %s (%s steps)\n' "$file" "$total"
    else
        printf 'FAIL %s: %s RunStep calls but AUTODEPLOY_STEP_TOTAL=%s\n' "$file" "$count" "$total"
        status=1
    fi
done

printf '\n== build freshness ==\n'
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
cp -R src build.sh "$tmpdir/"
(cd "$tmpdir" && ./build.sh > /dev/null)
for file in dist/DSM.sh dist/macOS.sh dist/Ubuntu.sh dist/ProxmoxVE.sh dist/Reinstall.sh; do
    if diff -q "$file" "$tmpdir/$file" > /dev/null 2>&1; then
        printf 'ok   %s\n' "$file"
    else
        printf 'FAIL %s is stale - run ./build.sh\n' "$file"
        status=1
    fi
done

exit "$status"
