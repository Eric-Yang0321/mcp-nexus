---
name: daily-inspect
description: "每日服务器巡检并生成报告"
triggers: [巡检,检查,health check,服务器状态]
created: 2026-05-31T04:03:17.651257
---

# 每日服务器巡检

## 步骤
1. get_server_status() — 获取服务器状态
2. get_docker_containers() — 获取容器状态
3. health_check_run() — 运行所有健康检查
4. 如果有异常: health_remediate(检查名, "restart_container") 或 notify_send("⚠️ 发现异常", "test")
5. write_file("/tmp/daily-inspect-{{date}}.txt", 报告内容)
6. kb_save("每日巡检 {{date}}", "结果摘要", "inspection,daily")
