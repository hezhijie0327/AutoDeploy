# AGENTS.md

ZJDeploy is a collection of shell scripts for automated system deployment across Synology DSM, macOS, Proxmox VE, and Ubuntu, plus a network reinstall entry for Ubuntu hosts. See [README.md](README.md) for the Chinese overview.

## HANDOVER.md

When a multi-step task is interrupted, write progress to `HANDOVER.md` so the next session can pick up where you left off. Include: what was done, what remains, key decisions made, and the next concrete step. Delete the file when the task is complete.

## Behavioral Guidelines

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

**Additional rules:**
- Be concise in output but thorough in reasoning.
- Do not re-read files you have already read.
- User instructions always override this file.
- Don't wrestle with indentation in the Edit tool — focus on logic, let the project's formatter fix formatting. Use `sed` or `python3` freely when the Edit tool struggles with whitespace.

## Git commit convention

Every commit subject starts with a type prefix — `feat` / `fix` / `chore` / `docs` / `revert` / `refactor` / `perf` / `test` / `build` — optionally scoped: `fix(toolbar): ...`. Subject: imperative, lowercase start, no trailing period, aim ≤ 72 chars; detail goes in the body after a blank line (why, not what); breaking changes take `!` before the colon or a `BREAKING CHANGE:` body footer. Never rewrite pushed history.

- Commit incrementally — one logical change per commit, after lint and tests pass. Present changes for review before committing.
- **Never commit a `src/` change without its regenerated `dist/` artifacts**: run `./build.sh` first and `git add` the dist files in the SAME commit. A src commit without dist leaves the tree stale (lint.sh fails on a fresh clone) and forces history rewrites to fix.
- PRs: link the issue, summarize the change and verification (tests/benchmarks), and include config/log/pprof evidence for bug fixes.
- Commit tested changes only
- Use descriptive commit messages
- Tag releases for stable versions
- Include license header in all scripts

### Co-Author Format

- Always add co-author information. If closing an issue in commit text, verify against `main` first: `gh issue view <issue-id>`.
- Only ONE co-author line is allowed. If multiple agents contributed, aggregate into ONE entry.

Format: `Co-authored-by: <AgentName> <Email>`

Valid examples (choose EXACTLY ONE):

```
Co-authored-by: ZCode <noreply@z.ai>
```

## Documentation format

Family-wide Markdown rules, shared verbatim across all ZJ projects:

- **Language**: AGENTS.md, AUDIT.md, DESIGN.md and other agent-facing docs are English; README.md is Chinese (human-facing). Keep literal UI strings and code identifiers verbatim.
- **AGENTS.md skeleton** — generic sections first, then project; omit sections that don't apply, keep the order:
  `# AGENTS.md` → 1–2 sentence intro (what the project is + key doc links) → Behavioral Guidelines → Git commit convention → Documentation format → Project → Commands → Architecture → Conventions (Gotchas as a subsection) → project-specific sections → Key Docs.
- **README.md skeleton**: `# <project>` → badge block → one-line positioning + stack + key links → 特性 → 快速开始 → 配置 / 用法 → 文档 → License (omit as needed).
- **README badges** (shields.io, after the title, in order): Version (only where a real version exists, linked to the repo's GitHub releases), License (Apache 2.0 with Commons Clause — every project), primary-language badge (Go / TypeScript / Bash / Python / Docker), Biome for TypeScript projects; pure data/config repos get License only. Version links use the real GitHub repo name.
- **Formatting**: ATX headings (`#`), never skip a level; code fences always carry a language tag (`bash`, `go`, `json`, `text` for trees); tables for structured reference; no decorative emoji in headings or bullets; bold for key terms only.

## Project

Five generated scripts: platform deployments (`DSM.sh`, `macOS.sh`, `ProxmoxVE.sh`, `Ubuntu.sh`) plus the Ubuntu network reinstall (`Reinstall.sh`).

The `dist/*.sh` files are **generated distribution artifacts** — they are what `curl | bash` fetches. Edit the sources under `src/`, then run `./build.sh` to regenerate them. Never hand-edit the dist scripts; `lint.sh` fails if they are stale.

Deployment scripts share the same phases: system information gathering → repository mirrors → dependency packages → custom packages → system configuration → package configuration → cleanup. `Reinstall.sh` has its own two-phase flow: host-side preparation (facts, credentials, Alpine netboot initramfs, one-time GRUB entry), then the actual install runs after reboot inside an Alpine RAM system (`src/platforms/reinstall/trans.sh`).

## Commands

```bash
# Regenerate dist/ scripts from src/ (run after every source change)
./build.sh

# Full validation: bash -n + shellcheck + step-count + build freshness
./lint.sh

# Unit tests for pure functions (runs on bash 3.2 and 5.x)
bash tests/run_tests.sh

# Syntax check one script
bash -n dist/Ubuntu.sh

# Static analysis (warning severity must stay clean)
shellcheck --shell=bash --severity=warning dist/Ubuntu.sh
```

There is no dry-run mode. The scripts modify the live system; test in a VM or spare machine, never on a host you care about.

## Architecture

```text
src/
├── config/
│   ├── common.sh       # knobs shared by every platform (credentials, git, proxy, zsh)
│   └── debian.sh       # knobs shared by Ubuntu + Proxmox VE (+ DEPENDENCY_PACKAGES_BASE)
├── lib/
│   ├── core.sh                 # logging, traps, resume/progress (bash 3.2)
│   └── modules/                # reusable topic modules, selected per platform in build.sh
│       ├── crontab.sh          #   cross-platform modules (bash 3.2)
│       ├── git.sh
│       ├── gpg.sh
│       ├── hosts.sh
│       ├── proxychains.sh
│       ├── pypi.sh
│       ├── ssh.sh
│       ├── wireguard.sh
│       ├── zsh.sh
│       └── debian/             # Debian-family modules (bash 4.4+)
│           ├── apt.sh          #   APT config, batch installs, upgrades, cleanup
│           ├── daemons.sh      #   chrony, docker, frr, lldpd, nut, postfix
│           ├── kernel.sh       #   modules, sysctl, tuned, gai
│           ├── security.sh     #   fail2ban, crowdsec, snmp
│           ├── ssh.sh          #   host/user SSH keys wiring, sshd config
│           ├── storage.sh      #   swap sizing, swap clear, zram
│           ├── system.sh       #   domain/hostname/DNS/CPU/arch facts, hosts file, SetDebianGlobals
│           └── users.sh        #   default user, root
└── platforms/          # one directory per platform: config.sh + <name>.sh
    ├── dsm/            #   config.sh + dsm.sh
    ├── macos/          #   config.sh + macos.sh
    ├── ubuntu/         #   config.sh + ubuntu.sh
    ├── proxmoxve/      #   config.sh + proxmoxve.sh
    └── reinstall/      #   config.sh + reinstall.sh (phase 1) + trans.sh (phase 2, busybox ash)
build.sh                # assembles each dist/<Script>.sh from an explicit module list
lint.sh                 # bash -n, shellcheck, step-count, build-freshness checks
tests/run_tests.sh      # unit tests for the pure functions
```

`build.sh` assembles each dist script as: license/usage header → config files (common → shared family → `src/platforms/<name>/config.sh`) → `lib/core.sh` → selected `lib/modules/*.sh` (+ `lib/modules/debian/*.sh` for Ubuntu/PVE) → `src/platforms/<name>/<name>.sh`. The Configuration block lands at the very top of the generated script so operators can tune a deployment in one place. Modules carry shared functions; platform files set the structural globals a module needs (documented above each function, e.g. `FAIL2BAN_JAILS`, `DOCKER_APT_DISTRO`, `FRR_APT_LINE`) and keep only platform-specific logic plus the `## Process` orchestration.

All scripts run under `set -Eeuo pipefail` with an `ERR` trap that reports the failing line and command. Commands whose failure is expected (e.g. `git config --unset` on a missing key, `chattr` on unsupported filesystems) carry an explicit `|| true`.

### Configuration block

`src/config/` holds the shared layers (`common.sh` → `debian.sh`, Ubuntu + PVE only); each platform keeps its deltas in `src/platforms/<name>/config.sh`. The platform file keeps the deltas only: step totals, platform credentials, platform switches, platform package additions (`DEPENDENCY_PACKAGES=("${DEPENDENCY_PACKAGES_BASE[@]}" ...)`) and arch-conditional picks (PVE swaps `grub-efi-amd64-signed` for `grub-efi-arm64-signed`). Every knob is env-overridable (`VAR="${VAR:-default}"`). Functions reference these globals; the `:-` fallbacks kept inside a few shared functions are only a safety net, not a second place to edit. Structural arrays that operators rarely touch (firewall rules, sysctl values, chrony servers) stay in the functions.

### Resume and progress

Each orchestration leaf runs through `RunStep "<id>" <function>`. A step is appended to the state file (`$ZJDEPLOY_STATE_DIR/state`, default `~/.zjdeploy`) only after it succeeds, so an interrupted run resumes at the first unfinished step. Container functions (`ConfigurePackages`, `ConfigureSystem`, `InstallCustomPackages`) always run — they set globals and dispatch their children, which skip individually if already done. `GetSystemInformation` always runs because later steps depend on the globals it sets. `ZJDEPLOY_FORCE=true` clears the state and re-runs everything. `RenderProgress` prints a `[####----] done/total (pct%)` line per step; `ZJDEPLOY_STEP_TOTAL` must equal the number of `RunStep` calls (lint.sh enforces this). `Reinstall.sh` uses the same machinery; its state only helps re-running a failed preparation, since the reboot wipes the host.

## Conventions

### General Principles
- `#!/bin/bash` shebang for built scripts; license header is emitted by `build.sh`
- dist scripts are executable (`build.sh` sets the bit)
- Source files are lowercase (`src/platforms/ubuntu/config.sh`, `src/platforms/ubuntu/ubuntu.sh`); generated dist scripts keep their published names (`dist/Ubuntu.sh`)
- No `function` keyword; PascalCase verb-noun function names: `GetSystemInformation()`, `InstallCustomPackages()`
- Platform-specific helpers are nested inside their parent function; shared helpers live in `src/lib/modules/`
- Modules are selected per platform by the explicit file lists in `build.sh`; a module a platform uses must be listed there
- `lib/core.sh` and `lib/modules/*.sh` must stay bash 3.2-compatible (macOS); `lib/modules/debian/*` targets bash 4.4+
- `src/platforms/reinstall/trans.sh` runs under busybox ash in the Alpine installer: no arrays, no `[[ ]]`, no process substitution

### Variable Naming
- UPPERCASE_SNAKE_CASE for globals: `NEW_HOSTNAME`, `GHPROXY_URL`, `DEFAULT_USERNAME`
- lowercase_snake_case for locals, declared with `local`
- Every tunable is an env-overridable global: `ROOT_PASSWORD="${ROOT_PASSWORD:-R00t@123!}"`
- Loop variables are short (`i`, `entry`, `pkg`); always quote expansions

### Error Handling
- Check commands with `HaveCommand` (wraps `command -v`), never `which`
- `RequireRoot` guards the Linux/DSM scripts; macOS runs as the operator and uses `sudo` per command
- `Die` for fatal errors, `LogWarn` for degraded-but-continuing, `LogInfo` for progress
- `BackupPath` moves an existing file/dir to `*.bak.<timestamp>` instead of deleting — re-runs must not destroy keys or configs

### File Operations
- Write config files with `printf '%s\n' "${array[@]}" > "$target"` — no temp-file round-trips
- `rm -f` for files; `rm -rf` only for directories
- Cleanup removes only `*.zjdeploy` temp files, never all of `/tmp`
- Sensitive files 600, SSH dirs 700, private keys 400

### Gotchas
- **macOS ships bash 3.2**: `lib/core.sh` and `lib/modules/*.sh` must stay 3.2-compatible — no associative arrays, no namerefs, guard empty-array expansions with `${arr[@]+"${arr[@]}"}`. `lib/modules/debian/*` targets bash 4.4+ only; `src/platforms/reinstall/trans.sh` is busybox ash only.
- **Module composition lives in build.sh**: adding a shared function to a new platform means adding its module file to that platform's build list — lint.sh does not verify module selection, only freshness.
- **Generated files**: commit the regenerated `dist/` scripts together with the `src/` change; `lint.sh` enforces freshness.
- **Step total**: when adding/removing a `RunStep` call, update `ZJDEPLOY_STEP_TOTAL` in the platform's `src/platforms/<name>/config.sh`; `lint.sh` fails on a mismatch.
- **Configuration is authoritative**: edit tunable defaults in `src/config/`, not inside functions. Keep new knobs env-overridable. Structural globals a module needs (e.g. `DOCKER_APT_DISTRO`, `FRR_APT_LINE`) are documented above that function and set by the dispatcher that runs it - install-time globals at the top of InstallCustomPackages/ConfigureSystem, configure-time ones in ConfigurePackages.
- **Release pinning is intentional**: `LSB_CODENAME`/`LSB_VERSION` (Ubuntu) and `LSB_CODENAME`/`CEPH_CODENAME` (PVE) are hardcoded to the latest release by design. `REINSTALL_RELEASE` (Reinstall) pins the latest LTS but stays env-overridable to the other LTS releases. Bump them each release in the config block; do not switch to auto-detection. PVE package picks are arch-aware: the `grub-efi-*-signed` swap happens in `src/platforms/proxmoxve/config.sh`.
- **Internal `*.zhijie.online` names resolve to `127.0.0.1` on public DNS** (split-horizon): only the LAN DNS serves real addresses, so referencing them in public config defaults and docs (e.g. the `PROXY_URL` default) is inert off-site by design.
- **Single quotes in generated snippets** (e.g. `plugin_upgrade_list`) are deliberate — they must not expand at generation time.
- `pcie_acs_override` is a patched-kernel parameter; mainline kernels ignore it. Kept intentionally for homelab IOMMU grouping.
- macOS has no `shuf`; use `$((RANDOM % 256))` for random octets.

## Platform-Specific Considerations

### DSM.sh
- Runs as root via `sudo bash`; the operator account is taken from `SUDO_USER` (not `whoami`, which is root under sudo)
- Synology commands: `synogroup`, `chown root:docker`; homes under `/var/services/homes/`
- Package Center: PKG_SOURCES are merged into `/usr/syno/etc/packages/feeds`
  (flat JSON array, URL-deduped in bash); PKG_PACKAGES install via
  `synopkg install_from_server` (the server-feed subcommand - plain
  `synopkg install` is for local .spk files). Package auto-update is
  deliberately left to the DSM Task Scheduler UI - crontab surgery is
  avoided on purpose
- Docker registry mirrors: only the `registry-mirrors` value in
  `/var/packages/{ContainerManager,Docker}/etc/dockerd.json` is rewritten;
  never touch the DSM `db` log-driver, and keep PKG_PACKAGES ids matching
  the feed package ids (`synopkg list`)
- Default shell switches via `~/.profile` exec (DSM has no `usermod`)

### macOS.sh
- Runs as the operator, no root requirement; `BREW_PREFIX` detects `/opt/homebrew` (ARM) vs `/usr/local` (Intel)
- Homebrew openssh: host keys and sshd_config under `${BREW_PREFIX}/etc/ssh`, `/etc/ssh` symlinked to it
- MAS (Mac App Store) integration via `mas`

### ProxmoxVE.sh
- APT-based; `proxmox-boot-tool` for ZFS bootloader config
- Node rename (ConfigureProxmoxVENode): guest configs (qemu-server/lxc
  .conf) are copied into the new node folder before the old directory is
  archived - pmxcfs cannot rename non-empty folders; the rrd files are
  copied with -f checks (they are files, not directories)
- `ConfigurePVECluster` resets corosync state — gated by `RESET_CLUSTER` (default `true`; set `false` on clustered nodes)
- Subscription-nag and CT-template mirror patches are fragile across PVE upgrades; re-run after updating

### Ubuntu.sh
- APT with CERNET mirrors; Netplan for network; systemd-resolved for DNS
- XanMod kernel selection respects CPU psABI level (`PSABI_LEVEL`); amd64-only (other arches fall back to `linux-generic`), psABI v1 CPUs are forced to the `lts` branch (the only one shipping x64v1), the xanmod apt repo is only added when a xanmod kernel will actually be installed, and the default branch is `main` (edge packages have been version-identical to main since 7.3)
- UFW firewall; `ufw --force reset/enable` to stay non-interactive

### Reinstall.sh
- Ubuntu-only source host (needs apt + GRUB); the target disk is located by partition-table UUID and wiped on the next reboot
- Target releases are LTS-only (20.04 / 22.04 / 24.04 / 26.04), mapped to codenames in `GetUbuntuCodename`
- Boot mode (`REINSTALL_BOOT_MODE`) defaults to following the running host; forcing `efi` from a CSM-booted host skips NVRAM registration (no efivarfs) and needs the firmware switched to UEFI by hand afterwards; the EFI bootloader is always also installed to the removable fallback path (`\EFI\BOOT\BOOTX64.EFI`) so it survives NVRAM wipes
- Phase 2 (`src/platforms/reinstall/trans.sh`) partitions the disk (ESP/bios_grub + root + trailing installer staging partition), copies the Ubuntu cloud image out of a qemu-nbd-attached qcow2 (never dd — 24.04+ images carry a separate /boot partition), and preserves the root UUID/label so baked-in grub references stay valid
- The target root filesystem is ext4 only: the image content is copied onto a freshly formatted partition that preserves the image's UUID/label, and the ESP carries the image's own signed shim+grub (copied from the image's ESP, partition 15 on ubuntu cloud images) with a matching efibootmgr entry - mirroring the upstream reinstall project
- All installer-phase mirrors use http, not https: the Alpine RAM system may boot with an unsynced clock, which breaks TLS certificate validation
- The netplan written into the new system matches the NIC by MAC address and re-applies the previous IPv4/IPv6 addressing
- The installer starts dropbear (same credentials as the final system, from the baked-in /configs) and tees its log to /zjdeploy.log (/zjdeploy.fail marks a failed run) so the install can be watched or repaired over ssh; the CANCEL abort stays console-only
- Cloud-init is disabled (`/etc/cloud/cloud-init.disabled`); run the matching deployment script after the first boot for full ZJDeploy configuration
- Requires a real-machine test round before trusting: GRUB one-time entry, initramfs init injection, and netplan replay are environment-sensitive

## Common Patterns

### Proxy Configuration
`GHPROXY_URL` is env-overridable; it accepts a bare domain or a full URL (scheme optional) and normalizes to `scheme://host/`:
```bash
SetGHProxyDomain() {
    GHPROXY_URL="${GHPROXY_URL:-}"
    if [ -n "$GHPROXY_URL" ]; then
        # Accept a bare domain (proxy.example.com) or a full URL
        # (https://proxy.example.com[/]); keep any given scheme.
        case "$GHPROXY_URL" in
            *://*) ;;
            *) GHPROXY_URL="https://${GHPROXY_URL}" ;;
        esac
        # Normalize to exactly one trailing slash.
        while [ "$GHPROXY_URL" != "${GHPROXY_URL%/}" ]; do
            GHPROXY_URL="${GHPROXY_URL%/}"
        done
        export GHPROXY_URL="${GHPROXY_URL}/"
    fi
}
```

### SSH Key Generation
ecdsa-384 / ed25519 / rsa-4096 only. DSA was removed: OpenSSH ≥ 9.8 disables it and 10.x removed it, which broke the whole `&&` chain on modern systems.

### Credentials
`ROOT_PASSWORD` and `DEFAULT_PASSWORD` default to empty and are generated randomly at run time (printed to the log); operators can override them via environment variable. The remaining literal defaults (NUT) trigger a `WarnDefaultPassword`/`LogWarn` notice. SSH root password login is intentional; the root account is locked afterwards with `LOCK_ROOT=true`.

## Security Considerations

- SSH keys: 400 private, 644 public; `.ssh` 700; `authorized_keys` 600
- GPG home: directories 700, files 600 (never chmod a directory 600 — it breaks key access)
- WireGuard private keys are generated in memory, never written to temp files
- Destructive operations are gated and warn: `PURGE_OTHER_USERS` (default `true`), `RESET_CLUSTER` (default `true`)
- Firewall rules are restrictive by default; Fail2Ban + CrowdSec where applicable

## Deployment Guidelines

1. Review the script and override credentials/knobs via environment variables
2. Back up critical configuration; test in a non-production environment first
3. Run:
```bash
curl "https://source.zhijie.online/ZJDeploy/main/dist/SCRIPT.sh" | sudo bash
```

`Reinstall.sh` additionally accepts `REINSTALL_RELEASE` and `REINSTALL_PASSWORD` and wipes the machine on the next reboot — read the Platform-Specific Considerations first.

`REINSTALL_*` knobs must be passed as `sudo VAR=value bash Reinstall.sh` (or `curl ... | sudo VAR=value bash`): sudo strips exported environment variables, so `export VAR && sudo bash` silently runs with defaults.

## Key Docs

- [README.md](README.md) - Chinese user-facing overview and configuration reference
- [LICENSE](LICENSE) - Apache 2.0 with Commons Clause v1.0
