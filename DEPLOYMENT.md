# MCP Server 部署信息

## 访问地址
- URL: https://mcp.eric-ai-lab.top/mcp
- 认证: OAuth 2.1 (自动 DCR + PKCE)

## 服务状态
- 服务: mcp-server (systemd)
- 状态: ✅ 运行中
- 开机自启: ✅ 已启用
- 端口: 127.0.0.1:8765
- 传输: Streamable HTTP (MCP 2026 推荐)
- 认证: OAuth 2.1 (Authorization Code + PKCE + DCR)

## ChatGPT 网页端连接步骤

### 前提条件
- ChatGPT Pro 会员 ✅
- Developer Mode 已启用

### 配置
1. 打开 https://chatgpt.com
2. 进入 Settings → Apps → Advanced Settings → Developer Mode
3. 创建新的 Connector
4. 配置如下:
   - **URL**: https://mcp.eric-ai-lab.top/mcp
   - **Authentication**: OAuth
5. 点击 Connect，会弹出授权页面
6. 在授权页面点击 "Authorize" 允许 ChatGPT 访问
7. 完成后返回 ChatGPT，Connector 应该显示为已连接

## OAuth 端点

| 端点 | 用途 |
|------|------|
| /.well-known/oauth-authorization-server | OAuth 元数据发现 |
| /.well-known/oauth-protected-resource/mcp | 受保护资源元数据 |
| /authorize | 用户授权页面 |
| /token | Token 签发/刷新 |
| /register | 动态客户端注册 (DCR) |

## 可用工具 (全部只读)

| 工具 | 功能 |
|------|------|
| get_server_status | CPU、内存、磁盘、系统信息 |
| get_docker_containers | Docker 容器状态和资源使用 |
| read_logs(path, lines, filter) | 读取日志文件 |
| get_processes(sort_by, count) | 进程列表 |
| get_disk_usage(directory) | 磁盘使用情况 |
| get_network_info | 网络状态和监听端口 |
| get_systemd_services(filter) | systemd 服务状态 |
| get_docker_logs(container, lines) | Docker 容器日志 |

## 管理命令

```bash
# 查看服务状态
systemctl status mcp-server

# 重启服务
systemctl restart mcp-server

# 查看日志
journalctl -u mcp-server -f

# 停止服务
systemctl stop mcp-server
```

## 安全说明
- 所有工具为只读操作
- OAuth 2.1 (Authorization Code + PKCE) 认证
- DCR (动态客户端注册) 为每个客户端生成唯一凭证
- 授权码和 Token 均为短期有效
- 路径访问有限制（白名单+黑名单）
- systemd 服务使用最小权限原则
- HTTPS via Cloudflare TLS

## ⚠️ 注意事项
- OAuth 客户端和 Token 存储在内存中，服务重启后需要重新授权
- ChatGPT 的 OAuth 回调地址: https://chatgpt.com/connector_platform_oauth_redirect
- 如果 ChatGPT 报 "OAuth state not found"，这是 ChatGPT 端已知 Bug，重新连接通常可解决

## 文件位置
- 代码: /opt/mcp-server/server.py
- 配置: /opt/mcp-server/.env
- 服务: /etc/systemd/system/mcp-server.service
- 隧道: /etc/cloudflared/config.yml
