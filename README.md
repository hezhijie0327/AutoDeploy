# ZJDeploy

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
- **断点续跑**：每个步骤成功后记录到 `~/.zjdeploy/state`，中断后重跑自动跳过已完成步骤；`ZJDEPLOY_FORCE=true` 全部重来
- **进度可视**：每步打印 `[####----------------] 8/48 (16%) ConfigureChrony` 进度条
- **顶部集中配置**：每个脚本开头是 Configuration 块，凭据 / 开关 / 网络 / 软件包列表一处可调
- **批量装包**：依赖一次性批量安装（apt / brew），省去逐包重复解析，装机与重跑更快
- **失败即停**：`set -Eeuo pipefail` + 行号报错，不再静默跑完一半

## 快速开始

| 平台 | 脚本 | 运行方式 |
|------|------|----------|
| DSM 群晖 | [DSM.sh](https://source.zhijie.online/ZJDeploy/main/dist/DSM.sh) | root 执行 |
| macOS | [macOS.sh](https://source.zhijie.online/ZJDeploy/main/dist/macOS.sh) | 普通用户执行，内部按需 `sudo` |
| Proxmox VE | [ProxmoxVE.sh](https://source.zhijie.online/ZJDeploy/main/dist/ProxmoxVE.sh) | root 执行 |
| Ubuntu | [Ubuntu.sh](https://source.zhijie.online/ZJDeploy/main/dist/Ubuntu.sh) | root 执行 |
| Ubuntu 网络重装 | [Reinstall.sh](https://source.zhijie.online/ZJDeploy/main/dist/Reinstall.sh) | root 执行；**危险：下次重启清盘重装** |

```bash
# Linux / DSM / PVE（<脚本名> 换成上表任意一个）
curl "https://source.zhijie.online/ZJDeploy/main/dist/<脚本名>.sh" | sudo bash

# macOS（普通用户执行）
/bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/ZJDeploy/main/dist/macOS.sh')"
```

网络重装指定版本与密码（默认生成随机 root 密码并打印）：

```bash
REINSTALL_RELEASE='26.04' REINSTALL_PASSWORD='MyS3cure!Pass' \
  curl "https://source.zhijie.online/ZJDeploy/main/dist/Reinstall.sh" | sudo bash
```

## 配置

每个脚本顶部都有一个 **Configuration 块**，集中了全部可调默认值（凭据、身份、行为开关、网络/DNS、发行版代号、代理、zsh、软件包列表），微调时直接编辑那一处即可。

所有开关也支持**环境变量**覆盖（优先级高于配置块默认值），在执行前 export 即可。使用内置默认密码时脚本会打印 WARNING，部署后请及时修改。

### 凭据

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ROOT_PASSWORD` | 留空随机生成并打印 | root 密码（Ubuntu / PVE） |
| `DEFAULT_PASSWORD` | 留空随机生成并打印 | 默认用户密码（Ubuntu / PVE） |
| `LOCK_ROOT` | `false` | 设为 `true` 部署后锁定 root 账户 |
| `NUT_ADMIN_PASSWORD` / `NUT_MON_PASSWORD` | `123456` / `secret` | NUT UPS 用户密码；`secret` 刻意固定——群晖 DSM 的 UPS 客户端只会尝试 monuser/secret 这组凭据，改了 DSM 就连不上 |
| `SNMP_AUTH_PASSWORD` / `SNMP_PRIV_PASSWORD` | root 密码 / 主机名 | SNMPv3 凭据（建议显式设置） |
| `SNMP_USER` | `ubuntu` / `proxmox` | SNMPv3 只读用户名（Ubuntu / PVE） |
| `OPENSSH_PASSWORD` | 空 | SSH 私钥口令 |
| `GPG_PUBKEY` | `DD982DAAB9C71C78F9563E5207EB56787030D792` | 导入的 GPG 公钥（SSH 认证支持） |

### 行为开关

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PURGE_OTHER_USERS` | `true` | 删除 `/home` 下其他用户（Ubuntu / PVE，全新装机假设；保留请设 `false`） |
| `RESET_CLUSTER` | `true` | 重置 corosync 集群状态（PVE；**已入集群的节点务必设 `false`**） |
| `RESET_BREW` | `false` | 重装 Homebrew（macOS） |
| `DISABLE_SWAP` | `false` | 不创建 swapfile（Ubuntu） |
| `ZJDEPLOY_FORCE` | `false` | 忽略断点记录，强制重跑所有步骤 |
| `ZJDEPLOY_STATE_DIR` | `~/.zjdeploy` | 断点续跑状态文件目录 |
| `XANMOD_BRANCH` | `main` | XanMod 内核分支（仅 amd64，arm64 回退 `linux-generic`）：`disable` / `main` / `edge` / `lts` / `rt`；psABI v1 老 CPU 自动引导到 `lts`（唯一提供 x64v1 的分支）。`edge` 自 7.3 起与 `main` 版本完全一致 |
| `GHPROXY_URL` | 空 | GitHub 代理地址，可带或不带 `https://`（自动补全 scheme 与末尾斜杠） |
| `RESET_DOMAIN` / `RESET_HOSTNAME` | `false` | 忽略检测到的搜索域 / 主机名；主机名重置后生成 12 位随机 hash（同 docker 容器 ID 风格） |
| `DISABLE_ICMP_ECHO` | `false` | `true` 时忽略全部 ICMP echo（Ubuntu / PVE） |
| `PREFER_IPV4` | `true` | gai.conf 地址选择优先 IPv4 |
| `DISABLE_DISPLAY` | `false` | 关闭 efifb/vesafb（PVE，GPU 直通场景） |
| `PATCH_INTEL_82599_SFP` | `false` | 放行 ixgbe 不受支持的 SFP 模块（PVE） |
| `ZFS_ARC_MAX` | `1` | ZFS ARC 上限，GiB（PVE） |
| `I915_GUC_OPTION` | `3` | i915 GuC/HuC 加载策略：0 关闭 / 1 GuC / 2 HuC / 3 GuC+HuC |
| `NUT_MODE` / `NUT_HOST` / `UPS_NAME` | `none` / `localhost` / `ups` | NUT UPS 模式、服务端地址（netclient 模式）、设备名 |
| `INSTALL_CLOUDFLARE_WARP` / `INSTALL_TOR` | `false` | 安装 cloudflare-warp / tor（Ubuntu，env 置 `true` 启用） |
| `INSTALL_APP_FROM_CASK` / `INSTALL_APP_FROM_MAS` | `false` | 安装 CASK_APPS / MAS_APPS 应用列表（macOS；MAS 需先登录 App Store） |
| `SSH_PORT` | `9022`（Ubuntu）/ `22`（PVE） | sshd 监听端口，fail2ban jail 与 ufw 规则联动（PVE 保持 22 以兼容集群内部 SSH） |
| `COCKPIT_PORT` | `9090` | Cockpit Web UI 端口（Ubuntu，自动生成 cockpit.socket 覆盖） |

### 网络与身份

| 变量 | 说明 |
|------|------|
| `NIC_NAME` / `STATIC_IPV4_CONFIG` / `STATIC_IPV6_CONFIG` | Netplan 静态网络，格式 `地址/掩码,网关`（Ubuntu） |
| `GIT_USER_NAME` / `GIT_USER_EMAIL` / `GIT_USER_SIGNINGKEY` | root 的 Git 身份 |
| `GIT_COMMIT_GPGSIGN` / `GIT_GPG_PROGRAM` | Git 提交 GPG 签名开关与 gpg 程序路径 |
| `GIT_HTTP_PROXY` / `GIT_HTTPS_PROXY` | git 的 HTTP(S) 代理（独立于全局代理） |
| `PROXY_PROTOCOL` / `PROXY_IP` / `PROXY_PORT` / `PROXY_USERNAME` / `PROXY_PASSWORD` | proxychains 上游代理 |
| `PROXY_URL` | `http://vpn.zhijie.online:7890` | zsh `proxy_on` 便捷代理 |
| `DEFAULT_FIRSTNAME` / `DEFAULT_LASTNAME` | `User` / `Default` | 默认用户姓名（`DEFAULT_FULLNAME` = 姓名） |
| `CUSTOM_HOSTNAME` / `CUSTOM_DOMAIN` | 自定义主机名 / 搜索域（Ubuntu / PVE），优先于自动检测与 `RESET_*`；检测不到主机名时自动生成 12 位随机 hash（如 `a3f19c02b7d4`） |
| `ZSH_THEME` | `ys` | oh-my-zsh 主题 |
| `CUSTOM_DNS` | 默认 `223.5.5.5 223.6.6.6 2400:3200::1 2400:3200:baba::1`（AliDNS），空格分隔，env 可覆盖 |
| `DEFAULT_USERNAME` | `default` | 默认用户名（Ubuntu / PVE） |

### 软件包与内置常量（编辑配置块，非环境变量）

以下为数组或常量，环境变量无法覆盖，直接编辑对应配置文件后随脚本部署即可：

| 变量 | 所在文件 | 说明 |
|------|----------|------|
| `DEPENDENCY_PACKAGES_BASE` / `DEPENDENCY_PACKAGES` | `config/debian.sh` + 平台配置 | Debian 系基础包 + 平台增量 |
| `DOCKER_REGISTRY_MIRRORS` | `config/debian.sh` + `platforms/dsm/config.sh` | Docker registry 镜像列表；Ubuntu/PVE 写入 daemon.json，DSM 写入 Container Manager dockerd.json（DSM 默认空 = 不动已有配置） |
| `PKG_SOURCES` / `PKG_PACKAGES` | `platforms/dsm/config.sh` | DSM 套件源（合并进 `/usr/syno/etc/packages/feeds`）与 `synopkg install_from_server` 套件列表；包自动更新建议在 DSM 任务计划 UI 手动添加（用户定义的脚本：`synopkg upgradeall`） |
| `ZSH_BUILD_IN_PLUGINS` | 平台配置 | oh-my-zsh 内置插件列表 |
| `BREW_PACKAGES` / `CASK_APPS` / `MAS_APPS` | `platforms/macos/config.sh` | Homebrew formulae / cask / Mac App Store 应用 |
| `LSB_CODENAME` / `LSB_VERSION` / `CEPH_CODENAME` | 平台配置 | 发行版代号（**有意 pin 到最新**，随发行版周期手动更新） |
| `GRUB_SIGNED_PACKAGE` | `platforms/proxmoxve/config.sh` | 按架构自动选择 amd64 / arm64 签名 GRUB |
| `ZJDEPLOY_STEP_TOTAL` | 平台配置 | 步骤总数（须与 RunStep 数一致，lint.sh 校验） |

示例：

```bash
export ROOT_PASSWORD='MyS3cure!Pass'
export DEFAULT_PASSWORD='MyUser!Pass'
export PURGE_OTHER_USERS=false
curl "https://source.zhijie.online/ZJDeploy/main/dist/Ubuntu.sh" | sudo bash
```

### 重装（Reinstall.sh）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `REINSTALL_RELEASE` | `26.04` | 目标 Ubuntu **LTS** 版本（`20.04` / `22.04` / `24.04` / `26.04`） |
| `REINSTALL_PASSWORD` | 随机生成并打印 | 新系统 root 密码；留空时若检测到本机 SSH 公钥则同时安装密钥 |
| `REINSTALL_SSH_KEYS` | 复用本机 root 公钥 | authorized_keys 内容或文件路径 |
| `REINSTALL_INSTALLER_PART_SIZE_MB` | `2048` | 安装暂存分区大小 |
| `REINSTALL_CANCEL` | `false` | `true` 时撤销已 staged 的重装：清除一次性 GRUB 引导项、删除安装文件并重置状态，然后退出 |
| `REINSTALL_BOOT_MODE` | `auto` | 目标系统引导方式：`auto` 跟随源系统；`efi` / `bios` 强制指定。**BIOS 转 EFI 需固件支持 UEFI**，且 CSM 启动下安装器写不了 NVRAM，重装后需手动进固件切换 UEFI 启动 |

流程：脚本在本机备好 Alpine netboot 内核与安装器（写入 initramfs），注册一次性 GRUB 引导项；重启后自动分区、下载 Ubuntu 云镜像并复制安装、按原网卡 MAC 还原网络配置、写入密码 / 密钥并禁用 cloud-init。**目标磁盘会被清空**，仅支持 Ubuntu 源系统、GRUB 引导。重装完成后建议再跑一次 `dist/Ubuntu.sh` 完成完整配置。

取消：重启前任何时刻跑 `REINSTALL_CANCEL=true ... Reinstall.sh` 即可撤销（清除一次性引导项与安装文件）；重启进安装器后的最初 10 秒内在**控制台**输入 `CANCEL` 也会中止并回退到原系统（此时尚未动盘），无人值守超时后自动继续。

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
- 凭据留空时随机生成并在运行日志打印（生产环境改掉或显式传入）；SSH root 密码登录是有意保留的，部署完成后建议 `LOCK_ROOT=true`
- `PURGE_OTHER_USERS` 与 `RESET_CLUSTER` 默认为破坏性行为，仅适用于全新装机
- 建议执行前备份重要数据

## 文档

- [AGENTS.md](AGENTS.md) - 架构、约定与编码代理指南（英文）

## License

[Apache License 2.0 with Commons Clause v1.0](LICENSE)

---

**免责声明**：本脚本仅供学习和测试使用，在生产环境使用前请充分测试并评估风险。
