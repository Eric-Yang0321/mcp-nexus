# MCP Nexus

> 让 ChatGPT 网页端获得 Codex 级别的服务器 + 桌面管理能力

通过 MCP (Model Context Protocol) 协议，ChatGPT 网页端可以自动审批并执行服务器运维、Git 操作、代码搜索、数据库查询、Windows 远程管理等 **64 个工具**。零弹框——SAFE/MUTATING 操作自动批，DESTRUCTIVE 操作才需要确认。

## ✨ 核心特性

| 特性 | 说明 |
|------|------|
| 🤖 **智能自动审批** | Chrome 扩展实现分级审批：🟢SAFE 自动批 / 🟡MUTATING 自动批+审计 / 🔴DESTRUCTIVE 弹框确认 |
| 🖥️ **服务器全栈管理** | Docker 容器、systemd 服务、进程、磁盘、网络、日志 |
| 📝 **Codex 级代码能力** | Git 操作、代码搜索(grep)、diff 编辑、数据库查询 |
| 💻 **双端统一管理** | 一套 MCP 同时管理 Linux 服务器和 Windows 电脑（通过 SSH 隧道） |
| ⚡ **工作流引擎** | 可复用的多步骤自动化流程 |
| 🏥 **健康监控** | 容器/端口/磁盘/HTTP 状态检查 + 自动修复 |
| ⏰ **定时任务** | crontab 管理，定时巡检/备份 |
| 📋 **任务系统** | 断点续接的长时间任务 |
| 🧠 **知识库** | 跨会话记忆，重启不丢失 |
| 📬 **通知推送** | Webhook 通知（Telegram/Slack/Discord） |
| 🔒 **OAuth 2.1** | PKCE + DCR，持久化存储 |

## 🏗️ 架构

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ ChatGPT 网页 │ ──→ │ MCP Nexus    │ ──→ │ Linux 服务器 │
│ + Chrome扩展 │     │ (FastMCP)    │     │ (57 tools)  │
└─────────────┘     │              │     └─────────────┘
       │            │ 审批代理      │
  自动点击           │ 标注改写      │     ┌─────────────┐
  Approve           └──────┬───────┘ ──→ │ Windows 电脑 │
                           │ SSH 隧道     │ (7 tools)   │
                           └─────────────┘──────────────┘
```

## 🚀 快速开始

### 1. 服务器部署

```bash
# 安装 Python 3.12 + FastMCP
uv python install 3.12
uv venv && source .venv/bin/activate
uv pip install fastmcp uvicorn starlette pyyaml

# 配置环境变量
cp .env.example .env
# 编辑 .env，设置 MCP_BASE_URL=https://your-domain.com

# 启动
python server.py
```

### 2. Cloudflare Tunnel（可选，用于公网访问）

```yaml
# /etc/cloudflared/config.yml
ingress:
  - hostname: mcp.your-domain.com
    service: http://localhost:8766
```

### 3. ChatGPT 连接

1. ChatGPT → Settings → Developer Mode → 新建 Connector
2. URL: `https://mcp.your-domain.com/mcp`
3. Authentication: OAuth
4. 授权通过即可使用

### 4. Chrome 扩展（自动审批）

```bash
chrome://extensions → 开发者模式 → 加载已解压 → chrome-extension/
```

### 5. Windows 远程管理（可选）

在 Windows 上安装 OpenSSH Server，建立反向隧道：

```powershell
# Windows 端
ssh -R 2223:localhost:22 root@your-server-ip
```

## 📊 工具清单

### 🖥️ 服务器管理 (57 tools)
`get_server_status` `get_docker_containers` `get_docker_logs` `restart_docker_container`
`get_systemd_services` `restart_systemd_service` `get_processes` `get_disk_usage`
`get_network_info` `read_logs` `write_file` `append_file` `edit_file` `rollback_file`
`run_allowed_command` `read_config` `write_config` ...

### 📝 Git & 代码 (8 tools)
`git_status` `git_diff` `git_log` `git_blame` `git_branch_list` `git_checkout` `git_commit`
`search_code` `search_files`

### 🗄️ 数据库 (1 tool)
`db_query`

### 🐳 Docker Compose (3 tools)
`docker_compose_ps` `docker_compose_logs` `docker_compose_restart`

### 💾 备份 (3 tools)
`backup_create` `backup_list` `backup_restore`

### ⚡ 工作流 (4 tools)
`workflow_create` `workflow_list` `workflow_run` `workflow_status`

### 🏥 健康监控 (4 tools)
`health_check_add` `health_check_list` `health_check_run` `health_remediate`

### ⏰ 定时任务 (4 tools)
`cron_add` `cron_list` `cron_remove` `cron_log`

### 📋 任务系统 (5 tools)
`task_start` `task_update` `task_status` `task_list` `task_cancel`

### 🧠 知识库 (4 tools)
`kb_save` `kb_search` `kb_list` `kb_summary`

### 📬 通知 (3 tools)
`notify_config` `notify_send` `notify_log`

### 💻 Windows 管理 (7 tools)
`win_read_file` `win_write_file` `win_list_dir` `win_get_processes` `win_get_system_info` `win_run_command`

## 🤝 对比

| | MCP Nexus | Codex Desktop | Claude Code |
|---|---|---|---|
| 网页端使用 | ✅ | ❌ (桌面端) | ❌ (终端) |
| 自动审批 | ✅ 分级 | ✅ | ✅ |
| 双端管理 | ✅ Linux+Win | ❌ | ❌ |
| 工作流引擎 | ✅ | ❌ | ❌ |
| 健康监控 | ✅ | ❌ | ❌ |
| 知识库 | ✅ | ⚠️ | ✅ |

## 📄 许可证

MIT License
