# AutoDeploy

这是一个跨平台自动化系统部署脚本集合，支持多种操作系统的快速配置和部署。

## 支持的平台

- **DSM.sh** - 群晖 NAS (Synology DSM) 部署脚本
- **macOS.sh** - macOS 系统部署脚本
- **ProxmoxVE.sh** - Proxmox VE 虚拟化平台部署脚本
- **Ubuntu.sh** - Ubuntu 系统部署脚本

## 功能特性

所有脚本都包含以下功能模块：

### 1. 系统信息获取

- 自动检测当前用户和系统架构
- 设置代理和镜像源
- 获取硬件信息（CPU供应商等）

### 2. 仓库镜像配置

- 配置国内镜像源（中科大等）
- 优化软件包下载速度
- 支持自定义代理设置

### 3. 软件包安装配置

- 安装必要工具和依赖
- 配置开发环境
- 安装系统安全增强工具

### 4. 系统配置

- SSH 密钥生成和配置
- Git 环境配置
- GPG 密钥配置
- 防火墙和安全设置
- 网络和系统优化

## 快速使用

### 直接执行

```bash
# DSM 群晖
curl "https://source.zhijie.online/AutoDeploy/main/DSM.sh" | sudo bash

# macOS
/bin/bash -c "$(curl -fsSL 'https://source.zhijie.online/AutoDeploy/main/macOS.sh')"

# Proxmox VE
curl "https://source.zhijie.online/AutoDeploy/main/ProxmoxVE.sh" | sudo bash

# Ubuntu
curl "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" | sudo bash
```

### 下载后执行

```bash
# 下载脚本
wget -qO- "https://source.zhijie.online/AutoDeploy/main/Ubuntu.sh" > Ubuntu.sh

# 赋予执行权限
chmod +x Ubuntu.sh

# 执行脚本
sudo bash Ubuntu.sh
```

## 自定义配置

### 代理设置

```bash
# 在脚本执行前设置代理环境变量
export GHPROXY_URL="proxy.example.com"
```

### DNS 自定义

修改脚本中的 `CUSTOM_DNS` 数组：

```bash
CUSTOM_DNS=(
    "223.5.5.5"
    "223.6.6.6"
    "8.8.8.8"
)
```

### 软件包定制

编辑对应脚本中的 `app_list` 数组来添加或删除需要安装的软件包。

## 注意事项

⚠️ **重要提醒**：

- 脚本会修改系统配置，请在测试环境先行验证
- 部分操作需要 root 权限
- 建议在执行前备份重要数据
- 默认密码应在生产环境中修改

## 故障排除

### 调试模式

在脚本开头添加以下行启用调试：

```bash
set -x  # 启用调试输出
set -e  # 遇到错误立即退出
```

### 常见问题

1. **权限错误**：确保使用 sudo 执行脚本
2. **网络问题**：检查 DNS 和代理设置
3. **架构不兼容**：脚本会自动检测并提示不支持的架构

## 贡献指南

欢迎提交 Issue 和 Pull Request 来改进这些脚本！

### 代码规范

- 使用 PascalCase 命名函数
- 使用 UPPERCASE_SNAKE_CASE 命名全局变量
- 保持各平台脚本结构一致
- 添加适当的注释和文档

## 许可证

本项目采用 Apache License 2.0 with Commons Clause v1.0 许可证。详见 [LICENSE](LICENSE) 文件。

---

**免责声明**：本脚本仅供学习和测试使用，在生产环境使用前请充分测试并评估风险。
