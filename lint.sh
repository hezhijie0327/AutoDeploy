#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# Validate sources and generated scripts:
#   1. bash -n syntax check on every shell file
#   2. shellcheck on the generated single-file scripts (if installed)
#   3. generated root scripts match a fresh build (no forgotten rebuilds)

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
done < <(find src . -maxdepth 2 -name '*.sh' -not -path './.git/*' | sort)

if command -v shellcheck > /dev/null 2>&1; then
    printf '\n== shellcheck ==\n'
    for file in DSM.sh macOS.sh Ubuntu.sh ProxmoxVE.sh; do
        if shellcheck --shell=bash --severity=warning "$file"; then
            printf 'ok   %s\n' "$file"
        else
            printf 'FAIL %s\n' "$file"
            status=1
        fi
    done
else
    printf '\n== shellcheck ==\nskipped (not installed)\n'
fi

printf '\n== build freshness ==\n'
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
cp -R src build.sh "$tmpdir/"
(cd "$tmpdir" && ./build.sh > /dev/null)
for file in DSM.sh macOS.sh Ubuntu.sh ProxmoxVE.sh; do
    if diff -q "$file" "$tmpdir/$file" > /dev/null 2>&1; then
        printf 'ok   %s\n' "$file"
    else
        printf 'FAIL %s is stale - run ./build.sh\n' "$file"
        status=1
    fi
done

exit "$status"
