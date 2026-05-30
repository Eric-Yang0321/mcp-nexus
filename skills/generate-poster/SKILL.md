---
name: generate-poster
description: "生成海报图片并传到Windows桌面"
triggers: [海报,poster,生成图,做图,生成图片,画图]
created: 2026-05-31T04:03:17.642939
---

# 生成海报并传到桌面

## 步骤
1. 用 AI 能力生成一张 {{topic}} 风格的高清海报图片
2. 将图片保存到服务器: write_file("/tmp/poster-output.png", ...)
3. 用 win_transfer_file 传到 Windows 桌面: win_transfer_file("/tmp/poster-output.png", "D:\360MoveData\Users\Eric\Desktop\{{filename}}.png")
4. 清理服务器临时文件: run_allowed_command(["rm", "/tmp/poster-output.png"])
5. 告知用户: "海报已保存到桌面: {{filename}}.png"

## 变量
- topic: 海报主题，默认 "落霞与孤鹜齐飞"
- filename: 文件名，默认 "海报"
