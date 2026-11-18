# AutoDeploy

[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Bash](https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)

跨平台自动化系统部署脚本集合，一条命令完成系统初始化、镜像源配置、软件安装与安全加固。编码代理指南见 [AGENTS.md](AGENTS.md)。

## 支持的平台

- **DSM.sh** - 群晖 NAS (Synology DSM)
- **macOS.sh** - macOS（自动识别 ARM / Intel）
- **ProxmoxVE.sh** - Proxmox VE 虚拟化平台（amd64 / arm64）
- **Ubuntu.sh** - Ubuntu
- **Reinstall.sh** - Ubuntu 网络重装（重启后自动完成，仅限 Ubuntu 源系统）

## 特性

- **单文件分发**：`curl | bash` 直接执行，无需克隆仓库
- **模块化构建**：`src/lib/modules/` 按主题拆分（git / gpg / ssh / zsh / apt / security…），`build.sh` 按平台显式挑选模块拼装
- **国内镜像加速**：CERNET 镜像源（APT / Homebrew / PyPI / Docker CE / Alpine / Ubuntu Cloud Images），可选 GitHub 代理
- **开发环境**：oh-my-zsh + 常用插件、Git、GPG（SSH 认证支持）
- **安全加固**：UFW / PVE 防火墙、Fail2Ban、CrowdSec、SSH 密钥自动生成（ecdsa / ed25519 / rsa）
- **系统优化**：BBR、sysctl 调优、ZRAM swap、chrony 时间同步、XanMod 内核（按 CPU psABI 级别选择）
- **一键重装**：`Reinstall.sh` 备好 Alpine 安装环境与一次性 GRUB 引导项，重启即重装为全新 Ubuntu（云镜像复制安装，保留原网络配置）
- **可重复执行**：已有密钥和配置自动备份为 `*.bak.<时间戳>`，不会直接覆盖
- **断点续跑**：每个步骤成功后记录到 `~/.autodeploy/state`，中断后重跑自动跳过已完成步骤；`AUTODEPLOY_FORCE=true` 全部重来
- **进度可视**：每步打印 `[####----------------] 8/48 (16%) ConfigureChrony` 进度条
- **顶部集中配置**：每个脚本开头是 Configuration 块，凭据 / 开关 / 网络 / 软件包列表一处可调
- **批量装包**：依赖一次性批量安装（apt / brew），省去逐包重复解析，装机与重跑更快
- **失败即停**：`set -Eeuo pipefail` + 行号报错，不再静默跑完一半

## 快速开始

```bash
# DSM 群晖
curl "https://source.zhijie.online/AutoDeploy/main/dist/DSM.sh" | sudo bash

# macOS（普通用户执行，内部按需 sudo）
/bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/dist/macOS.sh')"

# Proxmox VE
curl "https://source.zhijie.online/AutoDeploy/main/dist/ProxmoxVE.sh" | sudo bash

# Ubuntu
curl "https://source.zhijie.online/AutoDeploy/main/dist/Ubuntu.sh" | sudo bash

# Ubuntu 网络重装（危险：下次重启清盘重装，默认生成随机 root 密码并打印）
curl "https://source.zhijie.online/AutoDeploy/main/dist/Reinstall.sh" | sudo bash
# 指定版本与密码：
REINSTALL_RELEASE='24.04' REINSTALL_PASSWORD='MyS3cure!Pass' \
  curl "https://source.zhijie.online/AutoDeploy/main/dist/Reinstall.sh" | sudo bash
```

## 配置

每个脚本顶部都有一个 **Configuration 块**，集中了全部可调默认值（凭据、身份、行为开关、网络/DNS、发行版代号、代理、zsh、软件包列表），微调时直接编辑那一处即可。

所有开关也支持**环境变量**覆盖（优先级高于配置块默认值），在执行前 export 即可。使用内置默认密码时脚本会打印 WARNING，部署后请及时修改。

### 凭据

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ROOT_PASSWORD` | `R00t@123!` | root 密码（Ubuntu / PVE） |
| `DEFAULT_PASSWORD` | `*Ubuntu123*` / `*Proxmox123*` | 默认用户密码 |
| `LOCK_ROOT` | `FALSE` | 设为 `TRUE` 部署后锁定 root 账户 |
| `NUT_ADMIN_PASSWORD` / `NUT_MON_PASSWORD` | `123456` / `secret` | NUT UPS 用户密码 |
| `SNMP_AUTH_PASS` / `SNMP_PRIV_PASS` | root 密码 / 主机名 | SNMPv3 凭据（建议显式设置） |
| `OPENSSH_PASSWORD` | 空 | SSH 私钥口令 |

### 行为开关

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PURGE_OTHER_USERS` | `true` | 删除 `/home` 下其他用户（Ubuntu / PVE，全新装机假设；保留请设 `false`） |
| `RESET_CLUSTER` | `true` | 重置 corosync 集群状态（PVE；**已入集群的节点务必设 `false`**） |
| `REINSTALL_BREW` | `false` | 重装 Homebrew（macOS） |
| `DISABLE_SWAP` | `false` | 不创建 swapfile（Ubuntu） |
| `AUTODEPLOY_FORCE` | `false` | 忽略断点记录，强制重跑所有步骤 |
| `AUTODEPLOY_STATE_DIR` | `~/.autodeploy` | 断点续跑状态文件目录 |
| `XANMOD_BRANCH` | `edge` | XanMod 内核分支：`disable` / `main` / `edge` / `lts` / `rt` |
| `GHPROXY_URL` | 空 | GitHub 代理地址，可带或不带 `https://`（自动补全 scheme 与末尾斜杠） |

### 网络与身份

| 变量 | 说明 |
|------|------|
| `NIC_NAME` / `STATIC_IPV4_CONFIG` / `STATIC_IPV6_CONFIG` | Netplan 静态网络，格式 `地址/掩码,网关`（Ubuntu） |
| `GIT_USER_NAME` / `GIT_USER_EMAIL` / `GIT_USER_SIGNINGKEY` | root 的 Git 身份 |
| `PROXY_PROTOCOL` / `PROXY_IP` / `PROXY_PORT` / `PROXY_USERNAME` / `PROXY_PASSWORD` | proxychains 上游代理 |
| `CUSTOM_HOSTNAME` / `CUSTOM_DOMAIN` | 自定义主机名 / 搜索域（Ubuntu / PVE），优先于自动检测与 `RESET_*` |
| `CUSTOM_DNS` | `223.5.5.5 223.6.6.6 2400:3200::1 2400:3200:baba::1` | 解析器列表（空格分隔，默认 AliDNS，env 可覆盖） |
| `DEFAULT_USERNAME` | 默认用户名（`ubuntu` / `proxmox`） |

示例：

```bash
export ROOT_PASSWORD='MyS3cure!Pass'
export DEFAULT_PASSWORD='MyUser!Pass'
export PURGE_OTHER_USERS=false
curl "https://source.zhijie.online/AutoDeploy/main/dist/Ubuntu.sh" | sudo bash
```

### 重装（Reinstall.sh）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `REINSTALL_RELEASE` | `26.04` | 目标 Ubuntu **LTS** 版本（`20.04` / `22.04` / `24.04` / `26.04`） |
| `REINSTALL_PASSWORD` | 随机生成并打印 | 新系统 root 密码；留空时若检测到本机 SSH 公钥则同时安装密钥 |
| `REINSTALL_SSH_KEYS` | 复用本机 root 公钥 | authorized_keys 内容或文件路径 |
| `REINSTALL_ALPINE_VERSION` | `auto` | 固定 Alpine 版本（如 `3.22`） |
| `REINSTALL_INSTALLER_PART_SIZE_MB` | `2048` | 安装暂存分区大小 |

流程：脚本在本机备好 Alpine netboot 内核与安装器（写入 initramfs），注册一次性 GRUB 引导项；重启后自动分区、下载 Ubuntu 云镜像并复制安装、按原网卡 MAC 还原网络配置、写入密码 / 密钥并禁用 cloud-init。**目标磁盘会被清空**，仅支持 Ubuntu 源系统、GRUB 引导。重装完成后建议再跑一次 `dist/Ubuntu.sh` 完成完整配置。

## 开发

`dist/` 下的 `*.sh` 是**构建产物**（`curl | bash` 直接拉取），源码在 `src/`：共享配置在 `src/config/`（`common.sh` 全平台共享、`debian.sh` Ubuntu / PVE 共享），每个平台一个目录 `src/platforms/<平台>/`（`config.sh` 增量配置 + 同名编排脚本）；共享函数按主题拆成 `src/lib/modules/*.sh`（跨平台，bash 3.2 兼容）与 `src/lib/modules/debian/*.sh`（Ubuntu / PVE，bash 4.4+）。`build.sh` 按平台显式列出模块清单，按「头部 → 配置 → 核心 → 模块 → 平台」拼装进 `dist/` 单文件。

```bash
./build.sh              # 修改 src/ 后重新生成 dist/ 脚本（需一并提交）
./lint.sh               # bash -n + shellcheck + 构建一致性检查
bash tests/run_tests.sh # 纯函数单元测试
```

发行版代号（Ubuntu `resolute/26.04`、PVE `trixie/tentacle`）**有意硬编码到最新版本**，每个发行版周期手动更新。

## 注意事项

- 脚本会修改系统配置（用户、网络、防火墙、SSH），**请先在测试环境验证**
- 默认密码仅为装机便利，生产环境必须修改；SSH root 密码登录是有意保留的，部署完成后建议 `LOCK_ROOT=TRUE`
- `PURGE_OTHER_USERS` 与 `RESET_CLUSTER` 默认为破坏性行为，仅适用于全新装机
- 建议执行前备份重要数据

## 文档

- [AGENTS.md](AGENTS.md) - 架构、约定与编码代理指南（英文）

## License

[Apache License 2.0 with Commons Clause v1.0](LICENSE)

---

**免责声明**：本脚本仅供学习和测试使用，在生产环境使用前请充分测试并评估风险。
