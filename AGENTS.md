# AGENTS.md

AutoDeploy is a collection of shell scripts for automated system deployment across Synology DSM, macOS, Proxmox VE, and Ubuntu. See [README.md](README.md) for the Chinese overview.

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

Four deployment scripts, one per platform:

- `DSM.sh` - Synology DSM deployment script
- `macOS.sh` - macOS deployment script
- `ProxmoxVE.sh` - Proxmox VE deployment script
- `Ubuntu.sh` - Ubuntu deployment script

The root `*.sh` files are **generated distribution artifacts** — they are what `curl | bash` fetches. Edit the sources under `src/`, then run `./build.sh` to regenerate them. Never hand-edit the root scripts; `lint.sh` fails if they are stale.

Each script follows the same phases: system information gathering → repository mirrors → dependency packages → custom packages → system configuration → package configuration → cleanup.

## Commands

```bash
# Regenerate root scripts from src/ (run after every source change)
./build.sh

# Full validation: bash -n + shellcheck + build freshness
./lint.sh

# Unit tests for pure functions (runs on bash 3.2 and 5.x)
bash tests/run_tests.sh

# Syntax check one script
bash -n Ubuntu.sh

# Static analysis (warning severity must stay clean)
shellcheck --shell=bash --severity=warning Ubuntu.sh
```

There is no dry-run mode. The scripts modify the live system; test in a VM or spare machine, never on a host you care about.

## Architecture

```text
src/
├── lib/
│   ├── common.sh    # shared by all four platforms (bash 3.2 compatible)
│   └── debian.sh    # shared by Ubuntu + Proxmox VE (bash 4.4+)
├── DSM.sh           # platform-specific functions + orchestration
├── macOS.sh
├── Ubuntu.sh
└── ProxmoxVE.sh
build.sh             # concatenates header + libs + platform file → root script
lint.sh              # bash -n, shellcheck, build-freshness check
tests/run_tests.sh   # unit tests for the pure functions
```

`build.sh` assembles each root script as: license/usage header → `lib/common.sh` → (`lib/debian.sh` for Ubuntu/PVE) → platform file. Shared functions live in the libs; platform files set the globals a shared function needs (documented above each function, e.g. `GPG_HOME`, `ZSH_PATH_LIST`, `FAIL2BAN_JAILS`) and keep only platform-specific logic plus the `## Process` orchestration.

All scripts run under `set -Eeuo pipefail` with an `ERR` trap that reports the failing line and command. Commands whose failure is expected (e.g. `git config --unset` on a missing key, `chattr` on unsupported filesystems) carry an explicit `|| true`.

## Conventions

### General Principles
- `#!/bin/bash` shebang; license header is emitted by `build.sh`
- Root scripts are executable (`build.sh` sets the bit)
- PascalCase verb-noun function names: `GetSystemInformation()`, `InstallCustomPackages()`
- Platform-specific helpers are nested inside their parent function; shared helpers live in `src/lib/`

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
- Cleanup removes only `*.autodeploy` temp files, never all of `/tmp`
- Sensitive files 600, SSH dirs 700, private keys 400

### Gotchas
- **macOS ships bash 3.2**: `lib/common.sh` must stay 3.2-compatible — no associative arrays, no namerefs, guard empty-array expansions with `${arr[@]+"${arr[@]}"}`. `lib/debian.sh` targets bash 4.4+ only.
- **Generated files**: commit the regenerated root scripts together with the `src/` change; `lint.sh` enforces freshness.
- **Release pinning is intentional**: `LSB_CODENAME`/`LSB_VERSION` (Ubuntu) and `LSB_CODENAME`/`CEPH_CODENAME` (PVE) are hardcoded to the latest release by design. Bump them each release; do not switch to auto-detection.
- **Single quotes in generated snippets** (e.g. `plugin_upgrade_list`) are deliberate — they must not expand at generation time.
- `pcie_acs_override` is a patched-kernel parameter; mainline kernels ignore it. Kept intentionally for homelab IOMMU grouping.
- macOS has no `shuf`; use `$((RANDOM % 256))` for random octets.

## Platform-Specific Considerations

### DSM.sh
- Runs as root via `sudo bash`; the operator account is taken from `SUDO_USER` (not `whoami`, which is root under sudo)
- Synology commands: `synogroup`, `chown root:docker`; homes under `/var/services/homes/`
- Default shell switches via `~/.profile` exec (DSM has no `usermod`)

### macOS.sh
- Runs as the operator, no root requirement; `BREW_PREFIX` detects `/opt/homebrew` (ARM) vs `/usr/local` (Intel)
- Homebrew openssh: host keys and sshd_config under `${BREW_PREFIX}/etc/ssh`, `/etc/ssh` symlinked to it
- MAS (Mac App Store) integration via `mas`

### ProxmoxVE.sh
- APT-based; `proxmox-boot-tool` for ZFS bootloader config
- `ConfigurePVECluster` resets corosync state — gated by `RESET_CLUSTER` (default `true`; set `false` on clustered nodes)
- Subscription-nag and CT-template mirror patches are fragile across PVE upgrades; re-run after updating

### Ubuntu.sh
- APT with CERNET mirrors; Netplan for network; systemd-resolved for DNS
- XanMod kernel selection respects CPU psABI level (`PSABI_LEVEL`); v1 CPUs fall back to the main branch
- UFW firewall; `ufw --force reset/enable` to stay non-interactive

## Common Patterns

### Proxy Configuration
`GHPROXY_URL` is env-overridable (bare domain, no scheme):
```bash
SetGHProxyDomain() {
    GHPROXY_URL="${GHPROXY_URL:-}"
    if [ -n "$GHPROXY_URL" ]; then
        export GHPROXY_URL="https://${GHPROXY_URL}/"
    fi
}
```

### SSH Key Generation
ecdsa-384 / ed25519 / rsa-4096 only. DSA was removed: OpenSSH ≥ 9.8 disables it and 10.x removed it, which broke the whole `&&` chain on modern systems.

### Credentials
Default passwords are kept on purpose (operators change them after deployment). Every default in use triggers a `WarnDefaultPassword`/`LogWarn` notice and can be overridden via environment variable before running. SSH root password login is intentional; the root account is locked afterwards with `LOCK_ROOT=TRUE`.

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
curl "https://source.zhijie.online/AutoDeploy/main/SCRIPT.sh" | sudo bash
```

## Key Docs

- [README.md](README.md) - Chinese user-facing overview and configuration reference
- [LICENSE](LICENSE) - Apache 2.0 with Commons Clause v1.0
