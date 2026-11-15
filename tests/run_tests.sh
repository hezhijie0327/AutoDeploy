#!/bin/bash
# Copyright 2026 Zhijie He
# Licensed under Apache-2.0 WITH Commons-Clause-1.0. See LICENSE.
#
# Unit tests for the pure functions in src/lib/. These cover the logic that
# silently misbehaved in the original scripts (domain/hostname fallbacks,
# DNS exclusion, swap sizing, PATH construction). Runs on bash 3.2+.
#
# Usage: bash tests/run_tests.sh

set -Eeuo pipefail
cd "$(dirname "$0")/.." || exit 1

# shellcheck source=../src/lib/common.sh
source src/lib/common.sh
# shellcheck source=../src/lib/debian.sh
source src/lib/debian.sh

FAILURES=0
TMPDIR_TESTS=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TESTS"' EXIT

AssertEq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        printf 'ok   %s\n' "$desc"
    else
        printf 'FAIL %s\n     expected: [%s]\n     actual:   [%s]\n' "$desc" "$expected" "$actual"
        FAILURES=$((FAILURES + 1))
    fi
}

printf '== GenerateDomain ==\n'
RESOLV_CONF="${TMPDIR_TESTS}/resolv.conf"
printf 'nameserver 1.1.1.1\nsearch example.com corp.example.com\n' > "$RESOLV_CONF"
GenerateDomain
AssertEq "parses all search domains" "example.com corp.example.com" "${NEW_DOMAIN[*]}"

printf 'nameserver 1.1.1.1\n' > "$RESOLV_CONF"
GenerateDomain
AssertEq "falls back to localdomain without search line" "localdomain" "${NEW_DOMAIN[*]}"

: > "$RESOLV_CONF"
GenerateDomain
AssertEq "falls back to localdomain on empty resolv.conf" "localdomain" "${NEW_DOMAIN[*]}"

printf 'search example.com\n' > "$RESOLV_CONF"
RESET_DOMAIN="true" GenerateDomain
AssertEq "RESET_DOMAIN forces localdomain" "localdomain" "${NEW_DOMAIN[*]}"
unset RESET_DOMAIN

printf '== GenerateHostname ==\n'
HOSTNAME_FILE="${TMPDIR_TESTS}/hostname"
printf 'myhost\n' > "$HOSTNAME_FILE"
HOSTNAME_PREFIX="Test" GenerateHostname
AssertEq "reads hostname file" "myhost" "$NEW_HOSTNAME"

printf 'myhost extra\n' > "$HOSTNAME_FILE"
HOSTNAME_PREFIX="Test" GenerateHostname
AssertEq "takes first field only" "myhost" "$NEW_HOSTNAME"

HOSTNAME_FILE="${TMPDIR_TESTS}/missing"
RESET_HOSTNAME="true" HOSTNAME_PREFIX="Test" GenerateHostname
case "$NEW_HOSTNAME" in
    Test-[0-9]*) printf 'ok   RESET_HOSTNAME generates prefixed timestamp\n' ;;
    *) printf 'FAIL RESET_HOSTNAME generates prefixed timestamp, got [%s]\n' "$NEW_HOSTNAME"; FAILURES=$((FAILURES + 1)) ;;
esac
unset RESET_HOSTNAME

printf '== Custom hostname / domain ==\n'
CUSTOM_HOSTNAME="myhost"
HOSTNAME_PREFIX="Test" GenerateHostname
AssertEq "CUSTOM_HOSTNAME overrides detection" "myhost" "$NEW_HOSTNAME"
RESET_HOSTNAME="true" HOSTNAME_PREFIX="Test" GenerateHostname
AssertEq "CUSTOM_HOSTNAME wins over RESET_HOSTNAME" "myhost" "$NEW_HOSTNAME"
unset CUSTOM_HOSTNAME RESET_HOSTNAME
CUSTOM_DOMAIN="example.com corp.example.com"
GenerateDomain
AssertEq "CUSTOM_DOMAIN sets search domains" "example.com corp.example.com" "${NEW_DOMAIN[*]}"
RESET_DOMAIN="true" GenerateDomain
AssertEq "CUSTOM_DOMAIN wins over RESET_DOMAIN" "example.com corp.example.com" "${NEW_DOMAIN[*]}"
unset CUSTOM_DOMAIN RESET_DOMAIN

printf '== CollectDNS ==\n'
# Normally provided by the Configuration block; set them here for the unit test.
CUSTOM_DNS_CN=("223.5.5.5" "223.6.6.6" "2400:3200::1" "2400:3200:baba::1")
CUSTOM_DNS_GLOBAL=("8.8.4.4" "8.8.8.8" "2001:4860:4860::8844" "2001:4860:4860::8888")
RESOLV_CONF="${TMPDIR_TESTS}/resolv.conf"
printf 'nameserver 1.1.1.1\nnameserver 223.5.5.5\nnameserver 127.0.0.53\nnameserver 9.9.9.9\n' > "$RESOLV_CONF"
CollectDNS
AssertEq "excludes custom and stub resolvers" "1.1.1.1 9.9.9.9" "${CURRENT_DNS[*]}"
AssertEq "DNS_LINE keeps first three" "1.1.1.1 9.9.9.9 223.5.5.5" "$DNS_LINE"
AssertEq "default DNS is AliDNS" "223.5.5.5" "${CUSTOM_DNS[0]}"

USE_GLOBAL_DNS="true" CollectDNS
AssertEq "USE_GLOBAL_DNS switches to Google" "8.8.4.4" "${CUSTOM_DNS[0]}"
unset USE_GLOBAL_DNS

printf '== ComputeSwapSize ==\n'
AssertEq "1 GiB RAM -> 2 GiB swap" "2048" "$(ComputeSwapSize 1024)"
AssertEq "2 GiB RAM -> 4 GiB swap" "4096" "$(ComputeSwapSize 2048)"
AssertEq "4 GiB RAM -> 4 GiB swap" "4096" "$(ComputeSwapSize 4096)"
AssertEq "8 GiB RAM -> 8 GiB swap" "8192" "$(ComputeSwapSize 8192)"
AssertEq "16 GiB RAM -> 4 GiB swap" "4096" "$(ComputeSwapSize 16384)"
AssertEq "64 GiB RAM -> 4 GiB swap" "4096" "$(ComputeSwapSize 65536)"
AssertEq "128 GiB RAM -> 8 GiB swap" "8192" "$(ComputeSwapSize 131072)"
AssertEq "3000 MiB rounds down (frac .5)" "4096" "$(ComputeSwapSize 3000)"
AssertEq "3500 MiB rounds up (frac .7)" "4096" "$(ComputeSwapSize 3500)"

printf '== GenerateCommandPath ==\n'
ZSH_PATH_LIST=("/bin" "/usr/bin" "/usr/local/bin")
GenerateCommandPath
AssertEq "reverses list, no trailing colon" "/usr/local/bin:/usr/bin:/bin" "$DEFAULT_PATH"

printf '== ComputeFullDomain ==\n'
NEW_DOMAIN=("a.com" "b.com")
NEW_HOSTNAME="host"
ComputeFullDomain
AssertEq "joins FQDNs with spaces" "host.a.com host.b.com" "$NEW_FULL_DOMAIN"

printf '== ConfigureZsh / GenerateOMZProfile ==\n'
ZSH_HOME="${TMPDIR_TESTS}/zsh"
ZSH_OWNER=""
ZSH_PATH_LIST=("/bin" "/usr/bin" "/opt/homebrew/bin")
ZSH_BUILD_IN_PLUGINS="aliases brew git"
ZSH_EXTRA_EXPORTS=("export HOMEBREW_NO_AUTO_UPDATE=\"1\"")
ZSH_TRAPEXIT="true"
mkdir -p "${ZSH_HOME}/.oh-my-zsh"
ConfigureZsh
AssertEq "zshrc PATH order" 'export PATH="/opt/homebrew/bin:/usr/bin:/bin:$PATH"' "$(grep 'export PATH=' "${ZSH_HOME}/.zshrc")"
AssertEq "zshrc platform extras" 'export HOMEBREW_NO_AUTO_UPDATE="1"' "$(grep HOMEBREW_NO_AUTO_UPDATE "${ZSH_HOME}/.zshrc")"
AssertEq "zshrc plugins line" "plugins=(aliases brew git zsh-autosuggestions zsh-completions zsh-history-substring-search zsh-syntax-highlighting)" "$(grep '^plugins=' "${ZSH_HOME}/.zshrc")"
AssertEq "zshrc TRAPEXIT present" "1" "$(grep -c 'TRAPEXIT()' "${ZSH_HOME}/.zshrc" || true)"
ZSH_TRAPEXIT="false"
ConfigureZsh
AssertEq "zshrc TRAPEXIT absent when disabled" "0" "$(grep -c 'TRAPEXIT()' "${ZSH_HOME}/.zshrc" || true)"

printf '== ConfigureProxyChains ==\n'
PROXYCHAINS_CONF="${TMPDIR_TESTS}/proxychains.conf"
PROXY_PROTOCOL=""; PROXY_IP=""; PROXY_PORT=""; PROXY_USERNAME=""; PROXY_PASSWORD=""
ConfigureProxyChains
AssertEq "default proxy line" "socks5 127.0.0.1 7891" "$(tail -n 1 "$PROXYCHAINS_CONF")"
PROXY_USERNAME="user"; PROXY_PASSWORD="pass"
ConfigureProxyChains
AssertEq "proxy line with credentials" "socks5 127.0.0.1 7891 user pass" "$(tail -n 1 "$PROXYCHAINS_CONF")"

printf '== BackupPath ==\n'
mkdir -p "${TMPDIR_TESTS}/backup-target"
touch "${TMPDIR_TESTS}/backup-target/file"
BackupPath "${TMPDIR_TESTS}/backup-target" > /dev/null
if [ ! -e "${TMPDIR_TESTS}/backup-target" ] && ls -d "${TMPDIR_TESTS}/backup-target.bak."* > /dev/null 2>&1; then
    printf 'ok   moves target aside with timestamp\n'
else
    printf 'FAIL moves target aside with timestamp\n'
    FAILURES=$((FAILURES + 1))
fi
BackupPath "${TMPDIR_TESTS}/never-existed" > /dev/null
printf 'ok   no-op on missing target\n'

printf '== Resume / progress ==\n'
AUTODEPLOY_STATE_DIR="${TMPDIR_TESTS}/state"
AUTODEPLOY_STEP_TOTAL=3
AUTODEPLOY_FORCE="false"
STEP_RUN_COUNT=0
DummyStep() { STEP_RUN_COUNT=$((STEP_RUN_COUNT + 1)); }

RunStep "s1" DummyStep > /dev/null
AssertEq "first run executes step" "1" "$STEP_RUN_COUNT"
RunStep "s1" DummyStep > /dev/null
AssertEq "completed step is skipped" "1" "$STEP_RUN_COUNT"
if StepDone "s1"; then printf 'ok   StepDone true for finished step\n'; else printf 'FAIL StepDone true for finished step\n'; FAILURES=$((FAILURES + 1)); fi
if StepDone "s2"; then printf 'FAIL StepDone false for pending step\n'; FAILURES=$((FAILURES + 1)); else printf 'ok   StepDone false for pending step\n'; fi
AssertEq "StepsCompleted counts state lines" "1" "$(StepsCompleted)"

out=$(RenderProgress "test")
case "$out" in
    *"1/3 (33%)"*) printf 'ok   progress renders completed/total\n' ;;
    *) printf 'FAIL progress renders completed/total, got [%s]\n' "$out"; FAILURES=$((FAILURES + 1)) ;;
esac

# A failing step must not be recorded. Run it in a separate bash process so
# errexit is fully active (a `|| true` subshell would suppress it).
cat > "${TMPDIR_TESTS}/failrun.sh" <<'EOS'
source src/lib/common.sh
AUTODEPLOY_STATE_DIR="$1"
AUTODEPLOY_STEP_TOTAL=3
AUTODEPLOY_FORCE="false"
FailStep() { return 1; }
RunStep "failstep" FailStep
EOS
bash "${TMPDIR_TESTS}/failrun.sh" "${TMPDIR_TESTS}/state-fail" > /dev/null 2>&1 || true
if [ -f "${TMPDIR_TESTS}/state-fail/state" ] && grep -qxF "failstep" "${TMPDIR_TESTS}/state-fail/state"; then
    printf 'FAIL failing step is not recorded\n'
    FAILURES=$((FAILURES + 1))
else
    printf 'ok   failing step is not recorded\n'
fi

AUTODEPLOY_FORCE="true" InitRun > /dev/null
AssertEq "AUTODEPLOY_FORCE clears state" "0" "$(StepsCompleted)"
AUTODEPLOY_FORCE="false"

printf '== SetGHProxyDomain normalization ==\n'
GHPROXY_URL="proxy.example.com"; SetGHProxyDomain
AssertEq "bare domain gets https and slash" "https://proxy.example.com/" "$GHPROXY_URL"
GHPROXY_URL="https://proxy.example.com"; SetGHProxyDomain
AssertEq "https without trailing slash" "https://proxy.example.com/" "$GHPROXY_URL"
GHPROXY_URL="https://proxy.example.com/"; SetGHProxyDomain
AssertEq "https with slash unchanged" "https://proxy.example.com/" "$GHPROXY_URL"
GHPROXY_URL="http://proxy.example.com"; SetGHProxyDomain
AssertEq "http scheme preserved" "http://proxy.example.com/" "$GHPROXY_URL"
GHPROXY_URL="https://proxy.example.com//"; SetGHProxyDomain
AssertEq "extra trailing slashes collapsed" "https://proxy.example.com/" "$GHPROXY_URL"
GHPROXY_URL=""; SetGHProxyDomain
AssertEq "empty stays empty" "" "$GHPROXY_URL"

printf '== InstallAptPackages batching ==\n'
# Mock apt tools so this runs without a real apt (e.g. on macOS).
MOCK_APT_LOG="${TMPDIR_TESTS}/apt.log"
: > "$MOCK_APT_LOG"
apt() { printf 'apt %s\n' "$*" >> "$MOCK_APT_LOG"; }
apt-cache() { [ "$2" != "bad" ]; }
InstallAptPackages good1 good2 bad good3 > /dev/null 2>&1
AssertEq "single batched install of available packages" "apt install -qy good1 good2 good3" "$(grep '^apt install' "$MOCK_APT_LOG")"
AssertEq "unavailable package skipped" "0" "$(grep -c 'bad' "$MOCK_APT_LOG" || true)"
unset -f apt apt-cache

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
    printf 'all tests passed\n'
    exit 0
else
    printf '%s test(s) failed\n' "$FAILURES"
    exit 1
fi
