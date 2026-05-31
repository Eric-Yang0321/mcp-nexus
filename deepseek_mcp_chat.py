#!/usr/bin/env python3
"""
DeepSeek MCP Chat — 零弹框服务器管理

用法:
  python3 deepseek_mcp_chat.py                    # 交互模式
  python3 deepseek_mcp_chat.py "查服务器状态"       # 单次模式
  python3 deepseek_mcp_chat.py --auto "巡检所有容器，重启不健康的"  # 自动模式

原理:
  DeepSeek → 生成工具调用 → 脚本自动执行 → 结果喂回 DeepSeek → 循环
  全程无弹框，DeepSeek 自主判断何时调用哪个工具
"""

import json, sys, os, time, re
import urllib.request, urllib.parse
from pathlib import Path

# ── 配置 ─────────────────────────────────────────────────
DEEPSEEK_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEEPSEEK_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_MODEL = os.getenv("MCP_CHAT_MODEL", "deepseek-chat")  # → v4-flash, or use deepseek-reasoner
MCP_SERVER = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8765")
MAX_STEPS = int(os.getenv("MCP_MAX_STEPS", "15"))  # 最大工具调用轮数

if not DEEPSEEK_KEY:
    print("错误: 请先设置环境变量 DEEPSEEK_API_KEY", file=sys.stderr)
    sys.exit(1)

# ── 工具定义 ─────────────────────────────────────────────
# 直接定义工具 schema，不依赖 MCP 协议
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_server_status",
            "description": "获取服务器状态: CPU、内存、磁盘、负载、系统信息",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_docker_containers",
            "description": "获取所有 Docker 容器的运行状态、镜像、端口、资源使用",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_logs",
            "description": "读取服务器日志文件",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "日志路径，如 /var/log/messages"},
                    "lines": {"type": "integer", "description": "读取行数，默认 50", "default": 50},
                    "filter_pattern": {"type": "string", "description": "过滤关键词"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_processes",
            "description": "获取系统进程列表",
            "parameters": {
                "type": "object",
                "properties": {
                    "sort_by": {"type": "string", "description": "排序: cpu 或 mem", "default": "cpu"},
                    "count": {"type": "integer", "description": "返回前 N 个", "default": 20}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_disk_usage",
            "description": "获取磁盘使用情况",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "目录路径，默认 /", "default": "/"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_network_info",
            "description": "获取网络状态: 监听端口、活跃连接、接口信息",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_systemd_services",
            "description": "查看 systemd 服务状态",
            "parameters": {
                "type": "object",
                "properties": {
                    "filter_name": {"type": "string", "description": "过滤名称，如 docker"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_docker_logs",
            "description": "获取指定 Docker 容器日志",
            "parameters": {
                "type": "object",
                "properties": {
                    "container_name": {"type": "string", "description": "容器名"},
                    "lines": {"type": "integer", "description": "行数", "default": 50},
                    "since": {"type": "string", "description": "时间范围，如 10m"}
                },
                "required": ["container_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "restart_docker_container",
            "description": "重启 Docker 容器 — 自动执行，无需确认",
            "parameters": {
                "type": "object",
                "properties": {
                    "container_name": {"type": "string", "description": "容器名"}
                },
                "required": ["container_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "restart_systemd_service",
            "description": "重启 systemd 服务 — 自动执行",
            "parameters": {
                "type": "object",
                "properties": {
                    "service_name": {"type": "string", "description": "服务名"}
                },
                "required": ["service_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "写入文件（自动备份）",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径"},
                    "content": {"type": "string", "description": "内容"}
                },
                "required": ["path", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "append_file",
            "description": "追加内容到文件",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径"},
                    "content": {"type": "string", "description": "内容"}
                },
                "required": ["path", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_allowed_command",
            "description": "执行白名单内的系统命令",
            "parameters": {
                "type": "object",
                "properties": {
                    "args": {"type": "array", "items": {"type": "string"}, "description": "命令参数列表"}
                },
                "required": ["args"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "rollback_file",
            "description": "回滚文件：从 .bak 备份恢复",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径"}
                },
                "required": ["path"]
            }
        }
    },
]

# ── 工具执行 ─────────────────────────────────────────────

def execute_tool(name: str, args: dict) -> str:
    """通过 MCP Server HTTP API 执行工具"""

    mcp_token = os.getenv("MCP_TOKEN", "")
    url = f"{MCP_SERVER}/mcp"

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args}
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {mcp_token}",
        }
    )

    try:
        resp = urllib.request.urlopen(req, timeout=60)
        body = resp.read().decode()
        # 解析 SSE
        for line in body.split("\n"):
            if line.startswith("data:"):
                data = json.loads(line[5:].strip())
                if "result" in data:
                    content = data["result"].get("content", [])
                    if content:
                        return content[0].get("text", json.dumps(content))
                    return json.dumps(data["result"])
                if "error" in data:
                    return f"Error: {data['error']}"
        return body
    except urllib.error.HTTPError as e:
        return f"HTTP Error {e.code}: {e.read().decode()[:500]}"
    except Exception as e:
        return f"Error: {e}"


# ── DeepSeek 对话循环 ────────────────────────────────────

SYSTEM_PROMPT = """你是服务器运维助手，运行在 root 权限的 Linux 服务器上。
可以调用工具来查看状态、重启服务、写入文件。所有操作自动执行，不需要用户确认。

规则:
1. 用中文回复
2. 查询类操作直接调用工具，不需要解释
3. 重启/写入操作先简要说明，然后执行
4. 发现异常时主动报告并建议修复方案
5. 回复简洁，不要废话"""


def chat(user_input: str, auto_mode: bool = False):
    """主对话循环"""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_input},
    ]

    step = 0
    final_response = ""

    while step < MAX_STEPS:
        step += 1

        req_data = {
            "model": DEEPSEEK_MODEL,
            "messages": messages,
            "tools": TOOLS,
            "tool_choice": "auto",
            "temperature": 0.3,
        }

        req = urllib.request.Request(
            f"{DEEPSEEK_URL}/chat/completions",
            data=json.dumps(req_data).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {DEEPSEEK_KEY}",
            }
        )

        try:
            resp = urllib.request.urlopen(req, timeout=120)
            data = json.loads(resp.read().decode())
        except Exception as e:
            print(f"\n❌ DeepSeek API 错误: {e}")
            return

        choice = data["choices"][0]
        msg = choice["message"]

        # 如果是普通文本回复（非工具调用）
        if msg.get("content") and not msg.get("tool_calls"):
            final_response = msg["content"]
            print(f"\n{final_response}")
            return final_response

        # 如果有工具调用
        if msg.get("tool_calls"):
            messages.append({
                "role": "assistant",
                "content": msg.get("content") or "",
                "tool_calls": [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["function"]["name"],
                            "arguments": tc["function"]["arguments"],
                        }
                    }
                    for tc in msg["tool_calls"]
                ]
            })

            for tc in msg["tool_calls"]:
                func_name = tc["function"]["name"]
                func_args = json.loads(tc["function"]["arguments"])

                # 显示正在执行
                args_str = json.dumps(func_args, ensure_ascii=False)
                print(f"\n🔧 {func_name}({args_str[:100]})", end="", flush=True)

                start = time.time()
                result = execute_tool(func_name, func_args)
                elapsed = time.time() - start

                # 截断过长结果
                if len(result) > 4000:
                    result = result[:4000] + f"\n... [截断，共 {len(result)} 字符]"

                print(f" → {elapsed:.1f}s")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result,
                })

            # 如果不是自动模式，直接返回工具结果
            if not auto_mode and step >= 3:
                break
        else:
            # 纯文本，结束
            final_response = msg.get("content", "")
            print(f"\n{final_response}")
            return final_response

    # 最后一轮让模型总结
    req_data = {
        "model": DEEPSEEK_MODEL,
        "messages": messages + [{"role": "user", "content": "请用中文总结以上操作结果，简洁清晰。"}],
        "temperature": 0.3,
    }
    try:
        req = urllib.request.Request(
            f"{DEEPSEEK_URL}/chat/completions",
            data=json.dumps(req_data).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {DEEPSEEK_KEY}",
            }
        )
        resp = urllib.request.urlopen(req, timeout=60)
        data = json.loads(resp.read().decode())
        summary = data["choices"][0]["message"].get("content", "")
        print(f"\n{summary}")
        return summary
    except:
        return final_response


# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DeepSeek MCP Chat - 零弹框服务器管理")
    parser.add_argument("prompt", nargs="*", help="直接输入指令")
    parser.add_argument("--auto", action="store_true", help="自动模式（多轮工具调用）")
    args = parser.parse_args()

    if args.prompt:
        user_input = " ".join(args.prompt)
        chat(user_input, auto_mode=args.auto)
    else:
        print("🔧 DeepSeek MCP Chat - 零弹框服务器管理")
        print(f"   模型: {DEEPSEEK_MODEL}")
        print(f"   MCP: {MCP_SERVER}")
        print(f"   输入 'exit' 退出\n")

        while True:
            try:
                user_input = input("> ").strip()
                if user_input.lower() in ("exit", "quit", "q"):
                    break
                if not user_input:
                    continue
                chat(user_input, auto_mode=True)
            except KeyboardInterrupt:
                print("\n")
                break
            except EOFError:
                break
