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
- **README.md skeleton**: `# <project>` → one-line positioning + stack + key links → 特性 → 快速开始 → 配置 / 用法 → 文档 → License (omit as needed).
- **Formatting**: ATX headings (`#`), never skip a level; code fences always carry a language tag (`bash`, `go`, `json`, `text` for trees); tables for structured reference; no decorative emoji in headings or bullets; bold for key terms only.

## Project

This project consists of 4 main deployment scripts:
- `DSM.sh` - Synology DSM deployment script
- `macOS.sh` - macOS deployment script  
- `ProxmoxVE.sh` - Proxmox VE deployment script
- `Ubuntu.sh` - Ubuntu deployment script

All scripts follow a similar structure with functions for:
1. System information gathering
2. Repository mirror configuration
3. Package installation and configuration
4. System configuration

## Commands

### Testing Single Scripts
Each script is standalone and can be tested with:
```bash
# Test with dry run (comment out actual modifications)
sudo bash DSM.sh
sudo bash macOS.sh  
sudo bash ProxmoxVE.sh
sudo bash Ubuntu.sh
```

### Validation Commands
```bash
# Check script syntax
bash -n SCRIPT_NAME.sh

# Check script execution trace (debug)
bash -x SCRIPT_NAME.sh

# Verify executable permissions
ls -la *.sh
```

### Testing Individual Functions
Add test calls at the end of scripts:
```bash
# Test individual function
GetSystemInformation
echo "Hostname: $NEW_HOSTNAME"
exit 0
```

## Conventions

### General Principles
- Use `#!/bin/bash` shebang
- All scripts should be executable with `chmod +x`
- Use functions to organize code logically
- Follow consistent naming patterns across scripts

### Function Naming
- Use PascalCase for function names: `GetSystemInformation()`, `ConfigurePackages()`
- Group related functions under parent functions with descriptive names
- Use verb-noun pattern: `InstallCustomPackages()`, `GenerateHostname()`

### Variable Naming
- Use UPPERCASE_SNAKE_CASE for global variables: `NEW_HOSTNAME`, `GHPROXY_URL`
- Use lowercase_snake_case for local variables
- Export environment variables when needed: `export GHPROXY_URL`

### Code Organization
```bash
function ParentFunction() {
    function NestedFunction() {
        # Implementation
    }
    # Call nested functions
    NestedFunction
}
```

### Error Handling
- Check command existence before execution:
```bash
which "git" > "/dev/null" 2>&1
if [ "$?" -eq "0" ]; then
    # Command exists, proceed
fi
```
- Use proper exit codes for error conditions
- Handle architecture differences with conditional logic

### String Manipulation
- Use `sed` for text replacement with proper escaping
- Use `awk` for text processing
- Quote variables properly: `"$VARIABLE"` not `$VARIABLE`

### File Operations
- Create temporary files with `.autodeploy` suffix
- Always clean up temporary files: `rm -rf "/tmp/file.autodeploy"`
- Use proper permissions for sensitive files (600, 700, 400)
- Check file existence before operations

### Array Usage
```bash
array_name=(
    "item1"
    "item2"
    "item3"
)
for task in "${!array_name[@]}"; do
    echo "${array_name[$task]}"
done
```

## Platform-Specific Considerations

### DSM.sh
- Uses Synology-specific commands: `synogroup`, `chown root:docker`
- Paths: `/var/services/homes/` instead of `/home/`
- Package management via opkg

### macOS.sh
- Architecture detection (ARM vs x86_64)
- Homebrew paths: `/opt/homebrew/` (ARM) vs `/usr/local/` (Intel)
- LaunchDaemons for service management
- MAS (Mac App Store) integration

### ProxmoxVE.sh
- APT-based package management
- Kernel module loading and configuration
- Virtualization-specific optimizations
- Uses `proxmox-boot-tool` for bootloader config

### Ubuntu.sh
- APT package management with USTC mirrors
- Netplan for network configuration
- systemd for service management
- UFW firewall configuration

## Common Patterns

### Proxy Configuration
All scripts support GitHub proxy via `GHPROXY_URL` variable:
```bash
SetGHProxyDomain() {
    GHPROXY_URL="proxy.example.com"
    if [ "${GHPROXY_URL}" != "" ]; then
        export GHPROXY_URL="https://${GHPROXY_URL}/"
    fi
}
```

### Git Configuration
Standardized across all platforms:
```bash
function ConfigureGit() {
    gitconfig_key_list=(
        "commit.gpgsign"
        "gpg.program"
        "user.name"
        "user.email"
        # ... more configs
    )
    # Configure git settings
}
```

### SSH Key Generation
Consistent key generation across all scripts:
```bash
ssh-keygen -t ecdsa -b 384 -f "path/to/key" -C "comment" -N ""
ssh-keygen -t ed25519 -f "path/to/key" -C "comment" -N ""
ssh-keygen -t rsa -b 4096 -f "path/to/key" -C "comment" -N ""
```

## Security Considerations

### File Permissions
- SSH keys: 400 for private, 644 for public
- Config files: 600 or 644 depending on sensitivity
- Directories: 700 for SSH, 755 for general

### Secret Management
- Avoid hardcoding passwords in scripts
- Use variables for default passwords that should be changed
- GPG key import and trust configuration

### Service Security
- Firewall rules are restrictive by default
- SSH configuration hardening
- Fail2Ban integration where applicable

## Deployment Guidelines

### Before Running Scripts
1. Review script contents for site-specific customizations
2. Ensure proper backup of critical configuration
3. Test in non-production environment first

### Customization Points
- Proxy settings: `GHPROXY_URL`, proxy configurations
- DNS settings: Custom DNS servers in `CUSTOM_DNS` arrays
- Package lists: Modify `app_list` arrays as needed
- User accounts: Default usernames and passwords should be changed

### Script Execution
All scripts can be executed via:
```bash
# Direct execution
curl "https://source.zhijie.online/AutoDeploy/main/SCRIPT.sh" | sudo bash

# Or download first
wget -qO- "https://source.zhijie.online/AutoDeploy/main/SCRIPT.sh" | sudo bash
```

## Repository Structure Best Practices

### File Organization
- Keep scripts in root directory
- Use consistent naming: PlatformName.sh
- Maintain same function structure across scripts
- Document platform-specific differences

### Documentation Updates
- Update AGENTS.md when adding new functions
- Document breaking changes
- Maintain platform-specific considerations
- Update usage examples

## Common Debugging Techniques

### Enable Debug Mode
Add to script beginning:
```bash
set -x  # Enable debug
set -e  # Exit on error
```

### Check Variables
```bash
# Debug variable values
echo "DEBUG: Variable = $VARIABLE" >&2
```

### Test Command Execution
```bash
# Dry run with echo
echo "Would run: command with options"

# Test with redirection
command > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Command succeeded"
fi
```
