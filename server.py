"""
MCP Server — 服务器监控与运维工具
通过 Streamable HTTP 提供，支持 OAuth 2.1 认证 + 风险分级自动审批

ChatGPT 网页端连接:
  URL: https://mcp.eric-ai-lab.top/mcp
  Authentication: OAuth
"""

import os, re, sys, time, json, socket, logging, secrets, subprocess, urllib.request
from pathlib import Path
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

HOST = os.getenv("MCP_HOST", "127.0.0.1")
PORT = int(os.getenv("MCP_PORT", "8765"))
LOG_LEVEL = os.getenv("MCP_LOG_LEVEL", "info").upper()
BASE_URL = os.getenv("MCP_BASE_URL", "https://mcp.eric-ai-lab.top")
LOCAL_API_KEY = os.getenv("MCP_LOCAL_API_KEY", secrets.token_hex(32))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
log = logging.getLogger("mcp-server")

# ── 路径安全 ────────────────────────────────────────────
ALLOWED_READ_PATHS = [
    "/var/log", "/opt", "/root", "/etc", "/tmp",
    "/proc/cpuinfo", "/proc/meminfo", "/proc/loadavg",
    "/proc/uptime", "/proc/diskstats", "/proc/net/dev", "/proc/version",
]

BLOCKED_PATTERNS = [
    r".*\.pem$", r".*\.key$", r".*\.secret$", r".*\.env$",
    r".*/\.ssh/.*", r".*/\.gnupg/.*", r".*/\.aws/.*",
    r".*/shadow$", r".*id_rsa.*", r".*id_ed25519.*",
]

def is_path_allowed(path_str: str) -> tuple[bool, str]:
    try:
        resolved = str(Path(path_str).resolve())
    except (OSError, RuntimeError):
        return False, "无法解析路径"
    for pattern in BLOCKED_PATTERNS:
        if re.match(pattern, resolved, re.IGNORECASE):
            return False, f"路径被安全策略阻止: {pattern}"
    for allowed in ALLOWED_READ_PATHS:
        ar = str(Path(allowed).resolve())
        if resolved == ar or resolved.startswith(ar + "/"):
            return True, resolved
    return False, f"路径不在允许范围: {resolved}"

# ── 写操作安全 ──────────────────────────────────────────
WRITE_ALLOWED_PATHS = ["/opt", "/root", "/tmp", "/var/log", "/etc/cloudflared", "/etc/systemd/system"]
WRITE_BLOCKED = [r".*\.pem$", r".*\.key$", r".*\.secret$", r".*\.env$", r".*/\.ssh/.*", r".*\.venv/.*", r".*server\.py$"]
ALLOWED_COMMANDS = {
    "docker": ("mutating", 60), "systemctl": ("mutating", 30), "cat": ("safe", 5), "grep": ("safe", 10), "find": ("safe", 15), "echo": ("safe", 5),
    "touch": ("safe", 5), "mkdir": ("mutating", 10), "cp": ("mutating", 30),
    "mv": ("destructive", 20), "rm": ("destructive", 10), "git": ("mutating", 60),
    "chown": ("destructive", 10), "chmod": ("destructive", 10),
}
BLOCKED_CMD_ARGS = [r"rm\s+-rf\s+/", r"mkfs\.", r"dd\s+if=", r">\s*/dev/", r"shutdown", r"reboot", r":\(\)\s*\{"]
ALLOWED_SERVICES = ["mcp-server", "cloudflared", "openresty", "docker", "nginx", "1panel"]
AUDIT_LOG_PATH = Path(__file__).parent / "audit.log"

def audit_log(action: str, tool: str, params: dict, result: str, risk: str):
    try:
        entry = {"timestamp": datetime.now().isoformat(), "action": action, "tool": tool, "risk_level": risk, "parameters": params, "result_summary": result[:500]}
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

def is_write_path_allowed(path_str: str) -> tuple[bool, str]:
    try:
        resolved = str(Path(path_str).resolve())
    except (OSError, RuntimeError):
        return False, "无法解析路径"
    for p in WRITE_BLOCKED:
        if re.match(p, resolved, re.IGNORECASE):
            return False, f"写入被阻止: {p}"
    for a in WRITE_ALLOWED_PATHS:
        ar = str(Path(a).resolve())
        if resolved == ar or resolved.startswith(ar + "/"):
            return True, resolved
    return False, f"写入路径不在允许范围: {resolved}"

# ── OAuth 2.1 + 持久化 ──────────────────────────────────
from fastmcp.server.auth import OAuthProvider
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.server.auth.provider import (
    AuthorizationCode as AuthCode, AuthorizationParams,
    OAuthClientInformationFull, OAuthToken, AccessToken as MCPAccessToken,
)

OAUTH_STORE_FILE = Path(__file__).parent / "oauth_store.json"

class InMemoryOAuthProvider(OAuthProvider):
    """OAuth Provider with JSON persistence (survives restarts)"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, AuthCode] = {}
        self._access_tokens: dict[str, MCPAccessToken] = {}
        self._refresh_tokens: dict[str, tuple[str, OAuthClientInformationFull]] = {}
        self._load_from_disk()

    def _save_to_disk(self):
        try:
            data = {
                "clients": {cid: json.loads(c.model_dump_json()) for cid, c in self._clients.items()},
                "access_tokens": {at: json.loads(t.model_dump_json()) for at, t in self._access_tokens.items()},
                "refresh_tokens": {rt: {"access_token": at, "client_id": c.client_id}
                                  for rt, (at, c) in self._refresh_tokens.items()},
            }
            OAUTH_STORE_FILE.write_text(json.dumps(data))
        except Exception as e:
            log.error(f"💾 持久化失败: {e}")

    def _load_from_disk(self):
        try:
            if not OAUTH_STORE_FILE.exists():
                return
            data = json.loads(OAUTH_STORE_FILE.read_text())
            for cid, cdata in data.get("clients", {}).items():
                for field in ["redirect_uris", "jwks_uri", "client_uri", "logo_uri",
                              "policy_uri", "tos_uri", "initiate_login_uri"]:
                    if field in cdata and cdata[field] is not None:
                        cdata[field] = [str(u) for u in cdata[field]] if isinstance(cdata[field], list) else str(cdata[field])
                self._clients[cid] = OAuthClientInformationFull(**cdata)
            for at, tdata in data.get("access_tokens", {}).items():
                self._access_tokens[at] = MCPAccessToken(**tdata)
            for rt, rdata in data.get("refresh_tokens", {}).items():
                if rdata["client_id"] in self._clients:
                    self._refresh_tokens[rt] = (rdata["access_token"], self._clients[rdata["client_id"]])
            if self._clients:
                log.info(f"💾 从磁盘恢复了 {len(self._clients)} 个 OAuth 客户端")
        except Exception as e:
            log.warning(f"⚠️ 加载持久化数据失败: {e}")

    async def register_client(self, ci: OAuthClientInformationFull) -> None:
        self._clients[ci.client_id] = ci; self._save_to_disk()
        log.info(f"📝 DCR: {ci.client_id[:12]}...")

    async def get_client(self, cid: str) -> OAuthClientInformationFull | None:
        return self._clients.get(cid)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        code = secrets.token_urlsafe(32)
        self._auth_codes[code] = AuthCode(
            code=code, client_id=client.client_id, redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=True, code_challenge=params.code_challenge,
            resource=params.resource, scopes=params.scopes or [], expires_at=time.time() + 600,
        )
        sep = "&" if "?" in str(params.redirect_uri) else "?"
        return f"{params.redirect_uri}{sep}code={code}&state={params.state}&iss={params.resource or ''}"

    async def load_authorization_code(self, client, auth_code: str) -> AuthCode | None:
        ac = self._auth_codes.pop(auth_code, None)
        return None if (ac and ac.expires_at < time.time()) else ac

    async def exchange_authorization_code(self, client, ac: AuthCode) -> OAuthToken:
        at, rt = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._access_tokens[at] = MCPAccessToken(token=at, client_id=client.client_id, scopes=ac.scopes or [], expires_at=int(time.time()) + 3600, resource=ac.resource)
        self._refresh_tokens[rt] = (at, client); self._save_to_disk()
        return OAuthToken(access_token=at, token_type="Bearer", expires_in=3600, refresh_token=rt, scope=" ".join(ac.scopes) if ac.scopes else None)

    async def load_access_token(self, token: str) -> MCPAccessToken | None:
        at = self._access_tokens.get(token)
        if at and at.expires_at and at.expires_at < time.time():
            del self._access_tokens[token]; return None
        return at

    async def load_refresh_token(self, client, rt: str):
        entry = self._refresh_tokens.pop(rt, None)
        if not entry: return None
        self._access_tokens.pop(entry[0], None)
        na, nr = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        nt = MCPAccessToken(token=na, client_id=client.client_id, scopes=[], expires_at=int(time.time()) + 3600)
        self._access_tokens[na] = nt; self._refresh_tokens[nr] = (na, client); self._save_to_disk()
        return nt

oauth = InMemoryOAuthProvider(
    base_url=BASE_URL,
    client_registration_options=ClientRegistrationOptions(enabled=True),
)

# ── FastMCP + 风险分级 ──────────────────────────────────
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

RISK = {
    "safe": ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    "mutating": ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True),
    "destructive": ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True),
}

mcp = FastMCP(
    name="Server Monitor",
    instructions="""服务器监控运维 + Git + 代码搜索 MCP Server — 30 tools with risk-tiered auto-approval:

🟢 SAFE (auto-approve, no prompt):
  get_server_status, get_docker_containers, read_logs, get_processes,
  get_disk_usage, get_network_info, get_systemd_services, get_docker_logs,
  git_status, git_diff, git_log, git_blame, git_branch_list,
  search_code, search_files, get_tool_risk_levels

🟡 MUTATING (auto-approve with audit log):
  restart_docker_container, restart_systemd_service, append_file, git_checkout

🔴 DESTRUCTIVE (prompt user for confirmation):
  write_file, run_allowed_command, rollback_file, git_commit, edit_file

Use get_tool_risk_levels() to see the full risk classification.""",
    version="2.0.0",
    auth=oauth,
)

# ═══════════════════════════════════════════════════════════
# 🟢 SAFE 工具 (自动放行)
# ═══════════════════════════════════════════════════════════

@mcp.tool(annotations=RISK["safe"])
def get_server_status() -> dict:
    """[SAFE] 服务器状态: CPU/内存/磁盘/系统信息"""
    try:
        with open("/proc/loadavg") as f: loadavg = f.read().strip().split()
        with open("/proc/cpuinfo") as f: cpu_count = len([l for l in f if l.startswith("processor")])
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                if ":" in line: k, v = line.split(":", 1); mem[k.strip()] = v.strip()
        total_mem = int(mem.get("MemTotal", "0 kB").split()[0])
        avail_mem = int(mem.get("MemAvailable", "0 kB").split()[0])
        used_mem = total_mem - avail_mem
        mem_pct = round(used_mem / total_mem * 100, 1) if total_mem > 0 else 0
        disk_info = []
        for part in Path("/proc/mounts").read_text().strip().split("\n"):
            if not part: continue
            parts = part.split()
            if len(parts) < 2 or not parts[1].startswith("/"): continue
            try:
                stat = os.statvfs(parts[1])
                total = stat.f_blocks * stat.f_frsize
                free = stat.f_bavail * stat.f_frsize
                used = total - free
                pct = round(used / total * 100, 1) if total > 0 else 0
                disk_info.append({"mount": parts[1], "total_gb": round(total / 1024**3, 1), "used_gb": round(used / 1024**3, 1), "free_gb": round(free / 1024**3, 1), "used_pct": pct})
            except OSError: pass
        with open("/proc/uptime") as f: uptime_sec = float(f.read().split()[0])
        uptime_str = f"{int(uptime_sec // 86400)}d {int((uptime_sec % 86400) // 3600)}h {int((uptime_sec % 3600) // 60)}m"
        with open("/proc/version") as f: kernel = f.read().strip()
        return {
            "hostname": socket.gethostname(), "kernel": kernel[:120], "uptime": uptime_str,
            "cpu": {"cores": cpu_count, "load_1min": float(loadavg[0]), "load_5min": float(loadavg[1]), "load_15min": float(loadavg[2])},
            "memory": {"total_gb": round(total_mem / 1024**2, 1), "used_gb": round(used_mem / 1024**2, 1), "available_gb": round(avail_mem / 1024**2, 1), "used_pct": mem_pct},
            "disks": disk_info, "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool(annotations=RISK["safe"])
def get_docker_containers() -> dict:
    """[SAFE] Docker 容器状态和资源使用"""
    try:
        fmt = '{"names":"{{.Names}}","image":"{{.Image}}","state":"{{.State}}","status":"{{.Status}}","ports":"{{.Ports}}","running_for":"{{.RunningFor}}","created":"{{.CreatedAt}}"}'
        r = subprocess.run(["docker", "ps", "-a", "--format", fmt], capture_output=True, text=True, timeout=30)
        if r.returncode != 0: return {"error": r.stderr.strip()}
        containers = []
        for line in r.stdout.strip().split("\n"):
            if line:
                try: containers.append(json.loads(line))
                except json.JSONDecodeError: pass
        sr = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], capture_output=True, text=True, timeout=30)
        stats = {}
        for line in sr.stdout.strip().split("\n"):
            if line:
                try:
                    s = json.loads(line)
                    stats[s.get("Name", "")] = {"cpu_pct": s.get("CPUPerc", "N/A"), "mem_usage": s.get("MemUsage", "N/A"), "net_io": s.get("NetIO", "N/A")}
                except json.JSONDecodeError: pass
        running_count = sum(1 for c in containers if c.get("state") == "running")
        for c in containers: c["resources"] = stats.get(c.get("names", ""), {})
        return {"total": len(containers), "running": running_count, "containers": containers, "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": "docker ps timed out"}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["safe"])
def read_logs(path: str, lines: int = 50, filter_pattern: Optional[str] = None) -> dict:
    """[SAFE] 读取日志文件（路径受安全策略限制）

    Args:
        path: 日志文件路径，如 /var/log/messages
        lines: 读取最后 N 行，默认 50，最大 500
        filter_pattern: 可选过滤关键词
    """
    try:
        allowed, resolved = is_path_allowed(path)
        if not allowed: return {"error": resolved}
        p = Path(resolved)
        if not p.exists(): return {"error": f"文件不存在: {resolved}"}
        if not p.is_file(): return {"error": f"不是文件: {resolved}"}
        lines = max(1, min(lines, 500))
        content = p.read_text(errors="replace")
        all_lines = content.split("\n")
        last_lines = [l for l in all_lines[-lines:] if l.strip()]
        if filter_pattern:
            pl = filter_pattern.lower()
            last_lines = [l for l in last_lines if pl in l.lower()]
        max_ll = 2000
        truncated = [(l[:max_ll] + f"... [截断 {len(l) - max_ll} 字符]") if len(l) > max_ll else l for l in last_lines]
        return {"path": resolved, "file_size_bytes": p.stat().st_size, "total_lines": len(all_lines), "returned_lines": len(truncated), "requested_lines": lines, "filter": filter_pattern, "content": truncated[-lines:], "timestamp": datetime.now().isoformat()}
    except PermissionError: return {"error": f"无权限: {path}"}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["safe"])
def get_processes(sort_by: str = "cpu", count: int = 20) -> dict:
    """[SAFE] 系统进程列表（只读 ps）

    Args:
        sort_by: cpu 或 mem
        count: 前 N 个进程，最大 50
    """
    try:
        count = max(1, min(count, 50))
        sf = "-%cpu" if sort_by == "cpu" else "-%mem"
        r = subprocess.run(["ps", "aux", "--sort", sf, "--no-headers"], capture_output=True, text=True, timeout=10)
        if r.returncode != 0: return {"error": r.stderr.strip()}
        headers = ["user", "pid", "cpu_pct", "mem_pct", "vsz", "rss", "tty", "stat", "start", "time", "command"]
        procs = []
        for line in r.stdout.strip().split("\n")[:count]:
            if not line: continue
            fields = line.split(None, 10)
            if len(fields) >= 11: procs.append(dict(zip(headers, fields)))
        total = len(r.stdout.strip().split("\n")) if r.stdout.strip() else 0
        return {"total_processes": total, "shown": len(procs), "sort_by": sort_by, "processes": procs, "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": "ps timeout"}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["safe"])
def get_disk_usage(directory: str = "/") -> dict:
    """[SAFE] 磁盘使用情况（只读 du）

    Args:
        directory: 目标目录，默认 /
    """
    try:
        allowed, resolved = is_path_allowed(directory)
        if not allowed: return {"error": resolved}
        p = Path(resolved)
        if not p.exists(): return {"error": f"目录不存在: {resolved}"}
        if not p.is_dir(): return {"error": f"不是目录: {resolved}"}
        r = subprocess.run(["du", "-sh", "--max-depth=1", resolved], capture_output=True, text=True, timeout=30)
        if r.returncode != 0: return {"error": r.stderr.strip()}
        entries = []
        for line in r.stdout.strip().split("\n"):
            if not line: continue
            parts = line.split("\t", 1)
            if len(parts) == 2: entries.append({"size": parts[0].strip(), "path": parts[1].strip()})
        return {"directory": resolved, "entries": entries, "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": "du timeout"}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["safe"])
def get_network_info() -> dict:
    """[SAFE] 网络状态：监听端口、活跃连接、接口"""
    try:
        sr = subprocess.run(["ss", "-tlnp", "--no-header"], capture_output=True, text=True, timeout=10)
        ports = []
        for line in sr.stdout.strip().split("\n"):
            if not line: continue
            parts = line.split()
            if len(parts) >= 5: ports.append({"listen": parts[4], "process": " ".join(parts[5:]) if len(parts) > 5 else ""})
        cr = subprocess.run(["ss", "-s"], capture_output=True, text=True, timeout=10)
        conn_summary = cr.stdout.strip()[:500] if cr.returncode == 0 else "N/A"
        ir = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True, timeout=10)
        interfaces = [l.strip() for l in ir.stdout.strip().split("\n") if l]
        return {"listening_ports": ports, "connection_summary": conn_summary, "interfaces": interfaces, "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["safe"])
def get_systemd_services(filter_name: str = "") -> dict:
    """[SAFE] systemd 服务状态（只读）

    Args:
        filter_name: 可选过滤器，如 docker 或 mcp
    """
    try:
        cmd = ["systemctl", "list-units", "--type=service", "--no-legend", "--no-pager"]
        if filter_name: cmd.append(f"*{filter_name}*")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        services = []
        for line in r.stdout.strip().split("\n"):
            if not line.strip(): continue
            parts = line.split(None, 4)
            if len(parts) >= 4: services.append({"unit": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3], "description": parts[4] if len(parts) > 4 else ""})
        return {"total": len(services), "filter": filter_name or "all", "services": services, "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["safe"])
def get_docker_logs(container_name: str, lines: int = 50, since: str = "") -> dict:
    """[SAFE] Docker 容器日志（只读）

    Args:
        container_name: 容器名
        lines: 最后 N 行，最大 200
        since: 时间范围，如 10m 或 1h
    """
    try:
        lines = max(1, min(lines, 200))
        cmd = ["docker", "logs", "--tail", str(lines)]
        if since: cmd.extend(["--since", since])
        cmd.append(container_name)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode != 0: return {"error": r.stderr.strip()}
        log_lines = r.stdout.strip().split("\n") if r.stdout.strip() else []
        max_ll = 3000
        truncated = [(l[:max_ll] + "... [截断]") if len(l) > max_ll else l for l in log_lines[-lines:]]
        return {"container": container_name, "lines_returned": len(truncated), "since": since or "default", "content": truncated, "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": f"docker logs timeout: {container_name}"}
    except Exception as e: return {"error": str(e)}

# ═══════════════════════════════════════════════════════════
# 🟡 MUTATING 工具 (自动放行 + 审计日志)
# ═══════════════════════════════════════════════════════════

@mcp.tool(annotations=RISK["mutating"])
def restart_docker_container(container_name: str) -> dict:
    """[MUTATING] 重启 Docker 容器

    Args:
        container_name: 容器名称
    """
    try:
        check = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={container_name}"], capture_output=True, text=True, timeout=10)
        if container_name not in check.stdout.strip().split("\n"): return {"error": f"容器不存在: {container_name}"}
        before = subprocess.run(["docker", "inspect", "--format", "{{.State.Status}}", container_name], capture_output=True, text=True, timeout=10)
        r = subprocess.run(["docker", "restart", container_name], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            audit_log("FAIL", "restart_docker_container", {"container": container_name}, r.stderr.strip(), "mutating")
            return {"error": r.stderr.strip()}
        time.sleep(2)
        after = subprocess.run(["docker", "inspect", "--format", "{{.State.Status}}", container_name], capture_output=True, text=True, timeout=10)
        audit_log("SUCCESS", "restart_docker_container", {"container": container_name}, f"{before.stdout.strip()} → {after.stdout.strip()}", "mutating")
        return {"container": container_name, "before": before.stdout.strip(), "after": after.stdout.strip(), "message": f"容器 {container_name} 已重启", "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": f"超时: {container_name}"}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["mutating"])
def restart_systemd_service(service_name: str) -> dict:
    """[MUTATING] 重启 systemd 服务（白名单限制）

    Args:
        service_name: 服务名，如 mcp-server, docker, nginx
    """
    try:
        if service_name not in ALLOWED_SERVICES: return {"error": f"服务不在白名单: {ALLOWED_SERVICES}"}
        before = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True, timeout=10)
        r = subprocess.run(["systemctl", "restart", service_name], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            audit_log("FAIL", "restart_systemd_service", {"service": service_name}, r.stderr.strip(), "mutating")
            return {"error": r.stderr.strip()}
        time.sleep(2)
        after = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True, timeout=10)
        audit_log("SUCCESS", "restart_systemd_service", {"service": service_name}, f"{before.stdout.strip()} → {after.stdout.strip()}", "mutating")
        return {"service": service_name, "before": before.stdout.strip(), "after": after.stdout.strip(), "message": f"服务 {service_name} 已重启", "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["mutating"])
def append_file(path: str, content: str) -> dict:
    """[MUTATING] 追加内容到文件末尾

    Args:
        path: 目标文件路径
        content: 要追加的文本
    """
    try:
        allowed, resolved = is_write_path_allowed(path)
        if not allowed: return {"error": resolved}
        p = Path(resolved)
        p.parent.mkdir(parents=True, exist_ok=True)
        was_new = not p.exists()
        with open(p, "a", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"): f.write("\n")
        audit_log("SUCCESS", "append_file", {"path": resolved, "size": len(content), "new": was_new}, f"追加 {len(content)} 字节", "mutating")
        return {"path": resolved, "bytes_appended": len(content), "new_file": was_new, "message": f"已追加 {len(content)} 字节到 {resolved}", "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}

# ═══════════════════════════════════════════════════════════
# 🔴 DESTRUCTIVE 工具 (需用户确认)
# ═══════════════════════════════════════════════════════════

@mcp.tool(annotations=RISK["destructive"])
def write_file(path: str, content: str) -> dict:
    """[DESTRUCTIVE] 写入文件（自动备份 .bak）

    Args:
        path: 目标文件路径
        content: 要写入的文本
    """
    try:
        allowed, resolved = is_write_path_allowed(path)
        if not allowed: return {"error": resolved}
        p = Path(resolved)
        backup = None
        if p.exists():
            backup = str(p) + ".bak"
            try: p.rename(backup)
            except OSError as e: return {"error": f"无法创建备份: {e}"}
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        audit_log("SUCCESS", "write_file", {"path": resolved, "backup": backup, "size": len(content)}, f"写入 {len(content)} 字节", "destructive")
        return {"path": resolved, "bytes_written": len(content), "backup_created": backup, "message": f"写入 {resolved} ({len(content)} 字节)" + (f", 备份: {backup}" if backup else ""), "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["destructive"])
def run_allowed_command(args: list[str]) -> dict:
    """[DESTRUCTIVE] 执行白名单命令（严格安全控制）

    Args:
        args: 命令参数列表，如 ["docker", "ps"] 或 ["systemctl", "status", "nginx"]
    """
    try:
        if not args: return {"error": "参数不能为空"}
        cmd = args[0]
        if cmd not in ALLOWED_COMMANDS: return {"error": f"命令 '{cmd}' 不在白名单: {list(ALLOWED_COMMANDS.keys())}"}
        risk_level, timeout_sec = ALLOWED_COMMANDS[cmd]
        full_cmd = " ".join(args)
        for pattern in BLOCKED_CMD_ARGS:
            if re.match(pattern, full_cmd, re.IGNORECASE):
                audit_log("BLOCKED", "run_allowed_command", {"args": args}, f"匹配黑名单: {pattern}", risk_level)
                return {"error": f"命令被安全策略拒绝: 匹配危险模式"}
        for i, arg in enumerate(args):
            if i == 0: continue
            if re.search(r'[;&|`$(){}\[\]<>!\\]', arg): return {"error": f"参数含 shell 字符: '{arg}'"}
        r = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout_sec)
        stdout = r.stdout[:10000] if r.stdout else ""
        stderr = r.stderr[:10000] if r.stderr else ""
        audit_log("SUCCESS" if r.returncode == 0 else "FAIL", "run_allowed_command", {"args": args, "risk": risk_level}, f"exit={r.returncode}", risk_level)
        return {"command": full_cmd, "risk_level": risk_level, "exit_code": r.returncode, "stdout": stdout, "stderr": stderr, "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": f"命令超时"}
    except Exception as e: return {"error": str(e)}

@mcp.tool(annotations=RISK["destructive"])
def rollback_file(path: str) -> dict:
    """[DESTRUCTIVE] 回滚文件：用 .bak 备份恢复

    Args:
        path: 被修改的文件路径
    """
    try:
        allowed, resolved = is_write_path_allowed(path)
        if not allowed: return {"error": resolved}
        bp = Path(str(resolved) + ".bak")
        if not bp.exists(): return {"error": f"未找到备份: {bp}"}
        orig = Path(resolved).read_text(errors="replace") if Path(resolved).exists() else "(不存在)"
        bc = bp.read_text(errors="replace")
        bp.rename(resolved)
        audit_log("SUCCESS", "rollback_file", {"path": resolved}, f"从备份恢复 {len(bc)} 字节", "destructive")
        return {"path": resolved, "restored_bytes": len(bc), "previous_content_preview": orig[:200], "message": f"已从备份恢复 {resolved}", "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}

# ═══════════════════════════════════════════════════════════
# 📋 风险分级元工具
# ═══════════════════════════════════════════════════════════

@mcp.tool(annotations=RISK["safe"])
def get_tool_risk_levels() -> dict:
    """[SAFE] 查看所有工具的风险等级和自动审批策略

    Returns:
        工具风险分级表，包含每类工具的审批策略说明
    """
    return {
        "auto_approve_policy": {
            "safe": "🟢 自动放行 — 不弹确认框，直接执行",
            "mutating": "🟡 自动放行 + 审计日志 — 不弹框但记录所有操作",
            "destructive": "🔴 需用户确认 — 弹框确认后才执行",
            "blocked": "⛔ 直接拒绝 — 危险操作永不执行",
        },
        "tools": {
            "safe": [
                {"name": "get_server_status", "description": "服务器状态"},
                {"name": "get_docker_containers", "description": "容器状态"},
                {"name": "read_logs", "description": "读取日志"},
                {"name": "get_processes", "description": "进程列表"},
                {"name": "get_disk_usage", "description": "磁盘使用"},
                {"name": "get_network_info", "description": "网络状态"},
                {"name": "get_systemd_services", "description": "服务状态"},
                {"name": "get_docker_logs", "description": "容器日志"},
                {"name": "git_status", "description": "Git 状态"},
                {"name": "git_diff", "description": "Git 差异"},
                {"name": "git_log", "description": "Git 提交历史"},
                {"name": "git_blame", "description": "Git blame"},
                {"name": "git_branch_list", "description": "Git 分支列表"},
                {"name": "search_code", "description": "代码搜索 (grep)"},
                {"name": "search_files", "description": "文件搜索 (find)"},
                {"name": "get_tool_risk_levels", "description": "风险分级表"},
            ],
            "mutating": [
                {"name": "restart_docker_container", "description": "重启容器"},
                {"name": "restart_systemd_service", "description": "重启服务"},
                {"name": "append_file", "description": "追加文件"},
                {"name": "git_checkout", "description": "切换/创建分支"},
            ],
            "destructive": [
                {"name": "write_file", "description": "写入文件"},
                {"name": "run_allowed_command", "description": "执行白名单命令"},
                {"name": "rollback_file", "description": "回滚文件"},
                {"name": "git_commit", "description": "Git 提交"},
                {"name": "edit_file", "description": "精确文本替换"},
            ],
        },
        "timestamp": datetime.now().isoformat(),
    }

# ═══════════════════════════════════════════════════════════
# 🟢 Git 工具
# ═══════════════════════════════════════════════════════════

VALID_GIT_REPOS = ["/opt", "/root", "/home"]

def is_git_repo(path: str) -> tuple[bool, str]:
    allowed, resolved = is_path_allowed(path)
    if not allowed: return False, resolved
    if not (Path(resolved) / ".git").exists():
        return False, f"不是 Git 仓库: {resolved}"
    return True, resolved

def run_git(repo: str, args: list[str], timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(["git", "-C", repo] + args, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout[:20000], r.stderr[:5000]


@mcp.tool(annotations=RISK["safe"])
def git_status(repo_path: str = "/root") -> dict:
    """[SAFE] 查看 Git 仓库状态

    Args:
        repo_path: Git 仓库路径，默认 /root
    """
    ok, msg = is_git_repo(repo_path)
    if not ok: return {"error": msg}
    code, stdout, stderr = run_git(msg, ["status", "--short"])
    return {"repo": msg, "files": [l for l in stdout.split("\n") if l.strip()], "total": len([l for l in stdout.split("\n") if l.strip()]), "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def git_diff(repo_path: str = "/root", staged: bool = False, file_path: str = "") -> dict:
    """[SAFE] 查看 Git 工作区差异

    Args:
        repo_path: Git 仓库路径
        staged: True 查看暂存区差异，False 查看工作区差异
        file_path: 可选，只查看指定文件的差异
    """
    ok, msg = is_git_repo(repo_path)
    if not ok: return {"error": msg}
    args = ["diff"]
    if staged: args.append("--staged")
    if file_path:
        p = Path(file_path)
        args.append(str(p))
    code, stdout, stderr = run_git(msg, args, timeout=30)
    lines = stdout.split("\n")
    return {"repo": msg, "staged": staged, "file": file_path or "all", "diff_lines": len(lines), "diff": stdout[:15000], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def git_log(repo_path: str = "/root", count: int = 20, file_path: str = "") -> dict:
    """[SAFE] 查看 Git 提交历史

    Args:
        repo_path: Git 仓库路径
        count: 返回最近 N 条记录，默认 20
        file_path: 可选，只看某文件的历史
    """
    ok, msg = is_git_repo(repo_path)
    if not ok: return {"error": msg}
    args = ["log", f"-{count}", "--oneline", "--decorate"]
    if file_path:
        p = Path(file_path)
        args.append("--")
        args.append(str(p))
    code, stdout, stderr = run_git(msg, args)
    commits = [l for l in stdout.split("\n") if l.strip()]
    return {"repo": msg, "count": len(commits), "commits": commits, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def git_blame(repo_path: str, file_path: str, start_line: int = 1, end_line: int = 0) -> dict:
    """[SAFE] 查看文件每行的最后修改者 (git blame)

    Args:
        repo_path: Git 仓库路径
        file_path: 要查看的文件（相对于仓库根目录）
        start_line: 起始行号
        end_line: 结束行号，0 表示到文件末尾
    """
    ok, msg = is_git_repo(repo_path)
    if not ok: return {"error": msg}
    line_range = f"{start_line}" if end_line == 0 else f"{start_line},{end_line}"
    args = ["blame", "-L", line_range, file_path]
    code, stdout, stderr = run_git(msg, args, timeout=20)
    lines = [l for l in stdout.split("\n") if l.strip()]
    return {"repo": msg, "file": file_path, "lines": len(lines), "blame": lines[:200], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def git_branch_list(repo_path: str = "/root") -> dict:
    """[SAFE] 列出 Git 分支"""
    ok, msg = is_git_repo(repo_path)
    if not ok: return {"error": msg}
    code, stdout, stderr = run_git(msg, ["branch", "-a"])
    branches = [l.strip() for l in stdout.split("\n") if l.strip()]
    current = [l[2:] for l in branches if l.startswith("* ")]
    return {"repo": msg, "current": current[0] if current else "unknown", "branches": branches, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def git_checkout(repo_path: str, branch: str, create: bool = False) -> dict:
    """[MUTATING] 切换/创建 Git 分支

    Args:
        repo_path: Git 仓库路径
        branch: 分支名
        create: True 创建新分支并切换
    """
    ok, msg = is_git_repo(repo_path)
    if not ok: return {"error": msg}
    args = ["checkout"]
    if create: args.append("-b")
    args.append(branch)
    code, stdout, stderr = run_git(msg, args, timeout=20)
    audit_log("SUCCESS" if code == 0 else "FAIL", "git_checkout", {"repo": msg, "branch": branch, "create": create}, stdout[:200] if code == 0 else stderr[:200], "mutating")
    return {"repo": msg, "branch": branch, "created": create, "success": code == 0, "output": stdout[:500] if code == 0 else stderr[:500], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["destructive"])
def git_commit(repo_path: str, message: str, files: list[str] = None) -> dict:
    """[DESTRUCTIVE] 提交 Git 更改

    Args:
        repo_path: Git 仓库路径
        message: 提交信息
        files: 可选，只提交指定文件列表
    """
    ok, msg = is_git_repo(repo_path)
    if not ok: return {"error": msg}
    if files:
        code_add, _, _ = run_git(msg, ["add"] + files)
        if code_add != 0: return {"error": f"git add 失败"}
    else:
        run_git(msg, ["add", "-A"])
    code, stdout, stderr = run_git(msg, ["commit", "-m", message], timeout=30)
    audit_log("SUCCESS" if code == 0 else "FAIL", "git_commit", {"repo": msg, "message": message, "files": files}, stdout[:200] if code == 0 else stderr[:200], "destructive")
    return {"repo": msg, "message": message, "success": code == 0, "output": stdout[:500] if code == 0 else stderr[:500], "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# 🟢 代码搜索工具
# ═══════════════════════════════════════════════════════════

@mcp.tool(annotations=RISK["safe"])
def search_code(directory: str, pattern: str, file_types: str = "", max_results: int = 50) -> dict:
    """[SAFE] 在代码目录中搜索文本模式 (基于 grep -r)

    Args:
        directory: 搜索目录，如 /opt/wepost
        pattern: 搜索的正则表达式
        file_types: 可选，限制文件类型如 "*.py,*.js"
        max_results: 最大结果数，默认 50
    """
    try:
        allowed, resolved = is_path_allowed(directory)
        if not allowed: return {"error": resolved}
        if not Path(resolved).is_dir(): return {"error": f"不是目录: {resolved}"}

        args = ["grep", "-rn", "--color=never", "-I"]
        if file_types:
            for ft in file_types.split(","):
                args.extend(["--include", ft.strip()])
        args.extend([pattern, resolved])

        r = subprocess.run(args, capture_output=True, text=True, timeout=30)

        lines = r.stdout.strip().split("\n") if r.stdout.strip() else []
        # rc=1 means no matches (not an error)
        results = []
        for line in lines[:max_results]:
            parts = line.split(":", 2)
            if len(parts) >= 3:
                results.append({"file": parts[0], "line": int(parts[1]) if parts[1].isdigit() else parts[1], "content": parts[2][:500]})

        return {
            "directory": resolved, "pattern": pattern, "file_types": file_types or "all",
            "total_matches": len(lines), "results": results, "truncated": len(lines) > max_results,
            "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired: return {"error": "搜索超时 (>30s)"}
    except Exception as e: return {"error": str(e)}


@mcp.tool(annotations=RISK["safe"])
def search_files(directory: str, name_pattern: str, max_depth: int = 4) -> dict:
    """[SAFE] 按文件名搜索文件 (基于 find)

    Args:
        directory: 搜索根目录
        name_pattern: 文件名模式，如 "*.py" 或 "config*"
        max_depth: 最大搜索深度，默认 4
    """
    try:
        allowed, resolved = is_path_allowed(directory)
        if not allowed: return {"error": resolved}
        if not Path(resolved).is_dir(): return {"error": f"不是目录: {resolved}"}

        args = ["find", resolved, "-maxdepth", str(max_depth), "-name", name_pattern, "-type", "f"]
        r = subprocess.run(args, capture_output=True, text=True, timeout=20)

        files = [l for l in r.stdout.strip().split("\n") if l]
        return {"directory": resolved, "pattern": name_pattern, "max_depth": max_depth, "count": len(files), "files": files[:100], "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": "搜索超时"}
    except Exception as e: return {"error": str(e)}


@mcp.tool(annotations=RISK["destructive"])
def edit_file(path: str, old_string: str, new_string: str) -> dict:
    """[DESTRUCTIVE] 在文件中精确替换文本（仿 Codex apply_patch）

    查找 old_string 并替换为 new_string。old_string 必须在文件中唯一出现一次。

    Args:
        path: 要编辑的文件路径
        old_string: 要替换的原文本（必须精确匹配）
        new_string: 替换后的新文本
    """
    try:
        allowed, resolved = is_write_path_allowed(path)
        if not allowed: return {"error": resolved}
        p = Path(resolved)
        if not p.exists(): return {"error": f"文件不存在: {resolved}"}
        content = p.read_text(errors="replace")
        count = content.count(old_string)
        if count == 0: return {"error": "old_string 在文件中未找到"}
        if count > 1: return {"error": f"old_string 出现了 {count} 次，必须唯一。"}

        # 备份
        backup = str(p) + ".bak"
        p.rename(backup)

        # 替换
        new_content = content.replace(old_string, new_string, 1)
        p.write_text(new_content, encoding="utf-8")

        audit_log("SUCCESS", "edit_file", {"path": resolved, "old": old_string[:100], "new": new_string[:100]}, f"替换 {len(old_string)}→{len(new_string)} 字节", "destructive")

        return {
            "path": resolved, "replaced": True, "backup": backup,
            "old_bytes": len(old_string), "new_bytes": len(new_string),
            "message": f"已替换 {resolved} 中的文本 ({len(old_string)}→{len(new_string)} 字节)",
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e: return {"error": str(e)}


# ═══════════════════════════════════════════════════════════
# 🟢 数据库查询 (只读)
# ═══════════════════════════════════════════════════════════

KNOWN_DBS = {
    "media-os":   {"container": "media-os-db-1",   "user": "mediaos", "db": "mediaos"},
    "wepost":     {"container": "wepost-db-1",     "user": "postgres", "db": "postgres"},
    "throughline": {"container": "throughline-postgres", "user": "postgres", "db": "postgres"},
    "dify":       {"container": "dify-api",        "docker_exec": True},
}

@mcp.tool(annotations=RISK["safe"])
def db_query(database: str, sql: str, limit: int = 50) -> dict:
    """[SAFE] 执行只读 SQL 查询

    Args:
        database: 数据库名 (media-os / wepost / throughline)
        sql: SELECT 查询语句（只允许 SELECT，自动加 LIMIT）
        limit: 最大返回行数，默认 50

    Examples:
        db_query("media-os", "SELECT tablename FROM pg_tables WHERE schemaname='public'")
        db_query("wepost", "SELECT count(*) FROM pg_stat_activity")
    """
    try:
        if database not in KNOWN_DBS:
            return {"error": f"未知数据库: {database}，可用: {list(KNOWN_DBS.keys())}"}

        # 安全检查：只允许 SELECT
        sql_upper = sql.strip().upper()
        if not sql_upper.startswith("SELECT"):
            return {"error": f"只允许 SELECT 查询，收到: {sql[:50]}..."}
        if any(kw in sql_upper for kw in ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE", "TRUNCATE"]):
            return {"error": "DML/DDL 语句被禁止"}

        db_conf = KNOWN_DBS[database]
        sql_safe = sql.strip().rstrip(";")

        # 自动加 LIMIT（如果不存在）
        if "LIMIT" not in sql_upper:
            sql_safe += f" LIMIT {limit}"

        # 通过 docker exec 执行
        if "container" in db_conf:
            user = db_conf["user"]
            dbname = db_conf["db"]
            r = subprocess.run(
                ["docker", "exec", db_conf["container"],
                 "psql", "-U", user, "-d", dbname,
                 "-t", "-A", "-c", sql_safe],
                capture_output=True, text=True, timeout=30,
            )
        else:
            return {"error": "不支持的数据库类型"}

        if r.returncode != 0:
            return {"error": r.stderr.strip()[:500]}

        rows = [row for row in r.stdout.strip().split("\n") if row.strip() and row.strip() != "--"]
        return {
            "database": database, "sql": sql_safe, "rows": len(rows),
            "data": rows[:limit], "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired: return {"error": "查询超时 (>30s)"}
    except Exception as e: return {"error": str(e)}


# ═══════════════════════════════════════════════════════════
# 🟡 Docker Compose 管理
# ═══════════════════════════════════════════════════════════

KNOWN_COMPOSE_PROJECTS = {
    "media-os":    "/root/media-os",
    "wepost":      "/opt/wepost",
    "throughline": "/opt/throughline",
    "dify":        "/opt/dify",
    "video-reader": "/opt/video-reader",
}

@mcp.tool(annotations=RISK["safe"])
def docker_compose_ps(project: str) -> dict:
    """[SAFE] 查看 Docker Compose 项目状态

    Args:
        project: 项目名 (media-os / wepost / throughline / dify / video-reader)
    """
    try:
        if project not in KNOWN_COMPOSE_PROJECTS:
            return {"error": f"未知项目: {project}，可用: {list(KNOWN_COMPOSE_PROJECTS.keys())}"}
        path = KNOWN_COMPOSE_PROJECTS[project]
        if not (Path(path) / "docker-compose.yml").exists():
            return {"error": f"找不到 docker-compose.yml: {path}"}
        r = subprocess.run(["docker", "compose", "-f", f"{path}/docker-compose.yml", "ps", "--format", "json"],
                          capture_output=True, text=True, timeout=20)
        if r.returncode != 0: return {"error": r.stderr.strip()[:500]}
        try:
            data = json.loads(r.stdout) if r.stdout.strip() else []
        except json.JSONDecodeError:
            data = [l for l in r.stdout.strip().split("\n") if l]
        return {"project": project, "path": path, "services": len(data) if isinstance(data, list) else 0, "containers": data if isinstance(data, list) else str(data)[:3000], "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}


@mcp.tool(annotations=RISK["safe"])
def docker_compose_logs(project: str, service: str = "", lines: int = 50) -> dict:
    """[SAFE] 查看 Docker Compose 服务日志

    Args:
        project: 项目名
        service: 服务名（可选，空=所有）
        lines: 行数，默认 50
    """
    try:
        if project not in KNOWN_COMPOSE_PROJECTS:
            return {"error": f"未知项目: {project}"}
        path = KNOWN_COMPOSE_PROJECTS[project]
        args = ["docker", "compose", "-f", f"{path}/docker-compose.yml", "logs", "--tail", str(lines)]
        if service: args.append(service)
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        log_lines = [l for l in r.stdout.strip().split("\n") if l.strip()][-lines:]
        return {"project": project, "service": service or "all", "lines": len(log_lines), "logs": log_lines, "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}


@mcp.tool(annotations=RISK["mutating"])
def docker_compose_restart(project: str, service: str = "") -> dict:
    """[MUTATING] 重启 Docker Compose 服务

    Args:
        project: 项目名
        service: 服务名（空=全部）
    """
    try:
        if project not in KNOWN_COMPOSE_PROJECTS:
            return {"error": f"未知项目: {project}"}
        path = KNOWN_COMPOSE_PROJECTS[project]
        args = ["docker", "compose", "-f", f"{path}/docker-compose.yml", "restart"]
        if service: args.append(service)
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
        audit_log("SUCCESS" if r.returncode == 0 else "FAIL", "docker_compose_restart",
                  {"project": project, "service": service}, r.stdout[:200] if r.returncode == 0 else r.stderr[:200], "mutating")
        return {"project": project, "service": service or "all", "success": r.returncode == 0, "output": r.stdout[:500] if r.returncode == 0 else r.stderr[:500], "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}


# ═══════════════════════════════════════════════════════════
# 🟡 备份快照
# ═══════════════════════════════════════════════════════════

BACKUP_DIR = Path("/opt/mcp-server/backups")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

@mcp.tool(annotations=RISK["mutating"])
def backup_create(source: str, name: str = "") -> dict:
    """[MUTATING] 创建目录/文件备份快照 (tar.gz)

    Args:
        source: 要备份的目录或文件路径
        name: 备份名称（可选，默认自动生成时间戳名）
    """
    try:
        allowed, resolved = is_path_allowed(source)
        if not allowed: return {"error": resolved}
        if not Path(resolved).exists(): return {"error": f"不存在: {resolved}"}

        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_name = name or f"{Path(resolved).name}-{ts}"
        backup_path = BACKUP_DIR / f"{backup_name}.tar.gz"

        r = subprocess.run(["tar", "-czf", str(backup_path), "-C", str(Path(resolved).parent), Path(resolved).name],
                          capture_output=True, text=True, timeout=120)
        if r.returncode != 0: return {"error": r.stderr.strip()[:500]}

        size = backup_path.stat().st_size
        audit_log("SUCCESS", "backup_create", {"source": resolved, "name": backup_name}, f"创建备份 {size} 字节", "mutating")
        return {"name": backup_name, "path": str(backup_path), "source": resolved, "size_bytes": size, "message": f"备份已创建: {backup_name} ({round(size/1024,1)}KB)", "timestamp": datetime.now().isoformat()}
    except subprocess.TimeoutExpired: return {"error": "备份超时 (>120s)"}
    except Exception as e: return {"error": str(e)}


@mcp.tool(annotations=RISK["safe"])
def backup_list() -> dict:
    """[SAFE] 列出所有备份快照"""
    try:
        backups = []
        for f in sorted(BACKUP_DIR.glob("*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True)[:50]:
            backups.append({"name": f.stem, "size_bytes": f.stat().st_size, "created": datetime.fromtimestamp(f.stat().st_mtime).isoformat()})
        return {"total": len(backups), "backups": backups, "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}


@mcp.tool(annotations=RISK["destructive"])
def backup_restore(name: str, target: str) -> dict:
    """[DESTRUCTIVE] 从备份快照恢复

    Args:
        name: 备份名称 (不含 .tar.gz)
        target: 恢复目标目录
    """
    try:
        allowed, resolved = is_write_path_allowed(target)
        if not allowed: return {"error": resolved}

        backup_path = BACKUP_DIR / f"{name}.tar.gz"
        if not backup_path.exists(): return {"error": f"备份不存在: {backup_path}"}

        # 恢复前先备份当前状态
        if Path(resolved).exists():
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            pre_restore = BACKUP_DIR / f"pre-restore-{Path(resolved).name}-{ts}.tar.gz"
            subprocess.run(["tar", "-czf", str(pre_restore), "-C", str(Path(resolved).parent), Path(resolved).name],
                          capture_output=True, timeout=60)

        r = subprocess.run(["tar", "-xzf", str(backup_path), "-C", str(Path(resolved).parent)],
                          capture_output=True, text=True, timeout=120)
        if r.returncode != 0: return {"error": r.stderr.strip()[:500]}

        audit_log("SUCCESS", "backup_restore", {"backup": name, "target": resolved}, "恢复成功", "destructive")
        return {"name": name, "target": resolved, "message": f"已从备份恢复: {name} → {resolved}", "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}


# ═══════════════════════════════════════════════════════════
# 🟢/🔴 配置管理
# ═══════════════════════════════════════════════════════════

import yaml as _yaml
try:
    import tomllib as _toml
except ImportError:
    import tomli as _toml

def _parse_config(path: str) -> dict:
    """解析 JSON/YAML/TOML 配置"""
    p = Path(path)
    content = p.read_text(errors="replace")
    suffix = p.suffix.lower()
    if suffix in (".json",): return json.loads(content)
    if suffix in (".yaml", ".yml"): return _yaml.safe_load(content) or {}
    if suffix in (".toml",): return _toml.loads(content)
    return {"_raw": content, "_error": f"不支持的文件类型: {suffix}"}


@mcp.tool(annotations=RISK["safe"])
def read_config(path: str) -> dict:
    """[SAFE] 读取并解析配置文件 (JSON/YAML/TOML)

    Args:
        path: 配置文件路径
    """
    try:
        allowed, resolved = is_path_allowed(path)
        if not allowed: return {"error": resolved}
        p = Path(resolved)
        if not p.exists(): return {"error": f"文件不存在: {resolved}"}
        config = _parse_config(resolved)
        # 序列化回 JSON 以确保 MCP 兼容
        return {"path": resolved, "type": p.suffix, "size_bytes": p.stat().st_size, "config": json.loads(json.dumps(config, default=str)), "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}


@mcp.tool(annotations=RISK["destructive"])
def write_config(path: str, updates: dict) -> dict:
    """[DESTRUCTIVE] 修改配置文件 (保留格式，仅支持 JSON/YAML)

    将 updates 合并到现有配置中（浅合并）

    Args:
        path: 配置文件路径
        updates: 要更新的键值对
    """
    try:
        allowed, resolved = is_write_path_allowed(path)
        if not allowed: return {"error": resolved}
        p = Path(resolved)
        if not p.exists(): return {"error": f"文件不存在: {resolved}"}
        suffix = p.suffix.lower()
        if suffix not in (".json", ".yaml", ".yml"): return {"error": f"只支持 JSON/YAML，收到: {suffix}"}

        # 备份
        backup = str(p) + ".bak"
        p.rename(backup)

        # 读取并合并
        config = _parse_config(backup)
        if isinstance(config, dict):
            config.update(updates)
        else:
            return {"error": "配置文件不是字典结构，无法合并"}

        # 写回
        if suffix == ".json":
            p.write_text(json.dumps(config, indent=2, ensure_ascii=False))
        else:
            p.write_text(_yaml.dump(config, allow_unicode=True, default_flow_style=False))

        audit_log("SUCCESS", "write_config", {"path": resolved, "updates": json.dumps(updates)}, f"已更新配置", "destructive")
        return {"path": resolved, "backup": backup, "updates": updates, "message": f"已更新: {resolved}", "timestamp": datetime.now().isoformat()}
    except Exception as e: return {"error": str(e)}


# ═══════════════════════════════════════════════════════════
# Phase 1: 🧠 跨会话知识库
# ═══════════════════════════════════════════════════════════

KB_PATH = Path(__file__).parent / "knowledge_base.jsonl"

def _kb_load() -> list[dict]:
    if not KB_PATH.exists(): return []
    return [json.loads(l) for l in KB_PATH.read_text().strip().split("\n") if l.strip()]

def _kb_save_entry(entry: dict):
    with open(KB_PATH, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


@mcp.tool(annotations=RISK["safe"])
def kb_save(topic: str, content: str, tags: str = "") -> dict:
    """[SAFE] 保存知识条目到跨会话知识库

    知识库在服务器重启后仍然保留，ChatGPT 可在后续对话中搜索使用。

    Args:
        topic: 主题标题
        content: 内容（支持多行文本）
        tags: 逗号分隔的标签，如 "nginx,config,fix"
    """
    entry = {
        "id": secrets.token_hex(6),
        "topic": topic, "content": content,
        "tags": [t.strip() for t in tags.split(",") if t.strip()],
        "created": datetime.now().isoformat(),
    }
    _kb_save_entry(entry)
    return {"id": entry["id"], "topic": topic, "tags": entry["tags"], "message": f"已保存: {topic}", "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def kb_search(query: str, max_results: int = 20) -> dict:
    """[SAFE] 搜索知识库（全文本匹配 topic + content + tags）

    Args:
        query: 搜索关键词（空格分隔多关键词用 OR 逻辑）
        max_results: 最大返回数，默认 20
    """
    entries = _kb_load()
    keywords = query.lower().split()
    results = []
    for e in reversed(entries):
        text = (e.get("topic","") + " " + e.get("content","") + " " + " ".join(e.get("tags",[]))).lower()
        if any(kw in text for kw in keywords):
            results.append({"id": e["id"], "topic": e["topic"], "tags": e["tags"], "created": e["created"], "preview": e["content"][:300]})
    results = results[:max_results]
    return {"query": query, "found": len(results), "results": results, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def kb_list(tags: str = "", max_results: int = 30) -> dict:
    """[SAFE] 列出知识库条目

    Args:
        tags: 按标签过滤，如 "fix,nginx"
        max_results: 最大返回数
    """
    entries = _kb_load()
    filter_tags = [t.strip() for t in tags.split(",") if t.strip()]
    results = []
    for e in reversed(entries):
        if filter_tags and not any(ft in e.get("tags",[]) for ft in filter_tags):
            continue
        results.append({"id": e["id"], "topic": e["topic"], "tags": e["tags"], "created": e["created"][:19], "preview": e["content"][:200]})
    results = results[:max_results]
    return {"total": len(results), "filter_tags": filter_tags, "entries": results, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def kb_summary(days: int = 7) -> dict:
    """[SAFE] 获取过去 N 天的知识库操作摘要

    Args:
        days: 天数，默认 7
    """
    entries = _kb_load()
    cutoff = datetime.now().timestamp() - days * 86400
    recent = [e for e in entries if datetime.fromisoformat(e["created"]).timestamp() > cutoff]
    tags = {}
    for e in recent:
        for t in e.get("tags",[]):
            tags[t] = tags.get(t, 0) + 1
    return {
        "period": f"{days} 天", "total_entries": len(recent),
        "topics": [{"topic": e["topic"], "created": e["created"][:19]} for e in recent[-20:]],
        "top_tags": sorted(tags.items(), key=lambda x: x[1], reverse=True)[:15],
        "timestamp": datetime.now().isoformat(),
    }


# ═══════════════════════════════════════════════════════════
# Phase 2: 📋 长时间任务系统
# ═══════════════════════════════════════════════════════════

TASK_PATH = Path(__file__).parent / "tasks.jsonl"

def _task_load() -> list[dict]:
    if not TASK_PATH.exists(): return []
    return [json.loads(l) for l in TASK_PATH.read_text().strip().split("\n") if l.strip()]

def _task_save(tasks: list[dict]):
    TASK_PATH.write_text("\n".join(json.dumps(t, ensure_ascii=False) for t in tasks) + "\n")

def _task_find(task_id: str) -> tuple[list[dict], dict | None]:
    tasks = _task_load()
    for i, t in enumerate(tasks):
        if t["id"] == task_id:
            return tasks, i, t
    return tasks, -1, None


@mcp.tool(annotations=RISK["safe"])
def task_start(name: str, steps: list[str], description: str = "", tags: str = "") -> dict:
    """[SAFE] 创建长时间任务，支持断点续接

    任务持久化到磁盘，即使 ChatGPT 会话结束，下次也能通过 task_list / task_continue 续接。

    Args:
        name: 任务名称，如 "巡检所有容器"
        steps: 步骤列表，如 ["检查容器状态", "分析日志", "写报告"]
        description: 详细描述
        tags: 标签
    """
    tid = secrets.token_hex(6)
    task = {
        "id": tid, "name": name, "description": description,
        "steps": [{"name": s, "status": "pending", "note": ""} for s in steps],
        "current_step": 0, "status": "running",
        "tags": [t.strip() for t in tags.split(",") if t.strip()],
        "created": datetime.now().isoformat(), "updated": datetime.now().isoformat(),
        "log": [{"time": datetime.now().isoformat(), "msg": "任务创建"}],
    }
    tasks = _task_load()
    tasks.append(task)
    _task_save(tasks)
    _kb_save_entry({"id": tid, "topic": f"Task: {name}", "content": json.dumps(task, ensure_ascii=False), "tags": task["tags"] + ["task"], "created": datetime.now().isoformat()})
    return {"task_id": tid, "name": name, "total_steps": len(steps), "message": f"任务已创建: {name} ({len(steps)} 步骤)", "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def task_status(task_id: str) -> dict:
    """[SAFE] 查看任务进度

    Args:
        task_id: 任务 ID
    """
    tasks, idx, task = _task_find(task_id)
    if not task: return {"error": f"任务不存在: {task_id}"}
    done = sum(1 for s in task["steps"] if s["status"] == "done")
    return {
        "task_id": task_id, "name": task["name"], "status": task["status"],
        "progress": f"{done}/{len(task['steps'])}", "current_step": task["current_step"],
        "steps": task["steps"], "log": task["log"][-10:], "timestamp": datetime.now().isoformat(),
    }


@mcp.tool(annotations=RISK["safe"])
def task_update(task_id: str, step_index: int, status: str = "done", note: str = "") -> dict:
    """[SAFE] 更新任务步骤状态

    Args:
        task_id: 任务 ID
        step_index: 步骤索引 (0-based)
        status: done / failed / skipped / running
        note: 备注
    """
    tasks, idx, task = _task_find(task_id)
    if not task: return {"error": f"任务不存在: {task_id}"}
    if step_index >= len(task["steps"]): return {"error": f"步骤索引超出范围: {step_index}"}

    task["steps"][step_index]["status"] = status
    task["steps"][step_index]["note"] = note
    task["updated"] = datetime.now().isoformat()
    task["current_step"] = step_index + 1 if status == "done" else step_index
    task["log"].append({"time": datetime.now().isoformat(), "msg": f"步骤 {step_index}: {status} — {note[:100]}"})

    all_done = all(s["status"] == "done" for s in task["steps"])
    if all_done:
        task["status"] = "completed"
        task["log"].append({"time": datetime.now().isoformat(), "msg": "任务完成"})

    tasks[idx] = task
    _task_save(tasks)
    return {"task_id": task_id, "step": step_index, "status": status, "task_status": task["status"], "message": f"步骤 {step_index} → {status}", "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def task_list(status_filter: str = "", max_results: int = 20) -> dict:
    """[SAFE] 列出所有任务

    Args:
        status_filter: 过滤 running / completed / failed / 空=全部
        max_results: 最大返回数
    """
    tasks = _task_load()
    if status_filter:
        tasks = [t for t in tasks if t["status"] == status_filter]
    results = []
    for t in reversed(tasks[-max_results:]):
        done = sum(1 for s in t["steps"] if s["status"] == "done")
        results.append({"id": t["id"], "name": t["name"], "status": t["status"], "progress": f"{done}/{len(t['steps'])}", "created": t["created"][:19]})
    return {"total": len(results), "filter": status_filter or "all", "tasks": results, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def task_cancel(task_id: str) -> dict:
    """[MUTATING] 取消/标记任务为失败

    Args:
        task_id: 任务 ID
    """
    tasks, idx, task = _task_find(task_id)
    if not task: return {"error": f"任务不存在: {task_id}"}
    task["status"] = "cancelled"
    task["updated"] = datetime.now().isoformat()
    task["log"].append({"time": datetime.now().isoformat(), "msg": "任务取消"})
    tasks[idx] = task
    _task_save(tasks)
    return {"task_id": task_id, "status": "cancelled", "message": f"任务已取消: {task['name']}", "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# Phase 3: 📬 通知系统
# ═══════════════════════════════════════════════════════════

NOTIFY_PATH = Path(__file__).parent / "notify_config.json"
NOTIFY_LOG = Path(__file__).parent / "notify_log.jsonl"

def _notify_config() -> dict:
    if NOTIFY_PATH.exists():
        return json.loads(NOTIFY_PATH.read_text())
    return {"channels": {}}

def _notify_save_config(cfg: dict):
    NOTIFY_PATH.write_text(json.dumps(cfg, indent=2))


@mcp.tool(annotations=RISK["safe"])
def notify_config(action: str, channel: str = "", url: str = "") -> dict:
    """[SAFE] 管理通知渠道

    Args:
        action: add / remove / list
        channel: 渠道名 (telegram / slack / discord / custom)
        url: Webhook URL
    """
    cfg = _notify_config()
    if action == "add":
        cfg["channels"][channel] = {"url": url, "added": datetime.now().isoformat()}
        _notify_save_config(cfg)
        return {"message": f"已添加渠道: {channel}", "channels": list(cfg["channels"].keys()), "timestamp": datetime.now().isoformat()}
    elif action == "remove":
        cfg["channels"].pop(channel, None)
        _notify_save_config(cfg)
        return {"message": f"已移除渠道: {channel}", "channels": list(cfg["channels"].keys()), "timestamp": datetime.now().isoformat()}
    else:
        return {"channels": list(cfg["channels"].keys()), "total": len(cfg["channels"]), "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def notify_send(message: str, channel: str = "", title: str = "") -> dict:
    """[MUTATING] 发送通知到已配置的渠道

    Args:
        message: 通知内容
        channel: 渠道名（空=发送到所有渠道）
        title: 通知标题（可选）
    """
    cfg = _notify_config()
    targets = {channel: cfg["channels"][channel]} if channel and channel in cfg["channels"] else cfg["channels"]
    if not targets:
        return {"error": "未配置通知渠道。请先用 notify_config('add', 'telegram', 'https://...') 添加"}

    results = {}
    for ch_name, ch_cfg in targets.items():
        try:
            payload = json.dumps({"text": f"*{title or 'MCP 通知'}*\n{message}" if title else message, "parse_mode": "Markdown"}).encode()
            req = urllib.request.Request(ch_cfg["url"], data=payload, headers={"Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=10)
            results[ch_name] = f"OK ({resp.status})"
        except Exception as e:
            results[ch_name] = f"FAIL: {str(e)[:100]}"

    # 记录通知日志
    entry = {"timestamp": datetime.now().isoformat(), "title": title, "message": message[:500], "channels": results}
    with open(NOTIFY_LOG, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return {"sent_to": results, "message": message[:200], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def notify_log(max_results: int = 20) -> dict:
    """[SAFE] 查看通知发送历史

    Args:
        max_results: 最大返回数
    """
    if not NOTIFY_LOG.exists():
        return {"total": 0, "entries": [], "timestamp": datetime.now().isoformat()}
    entries = [json.loads(l) for l in NOTIFY_LOG.read_text().strip().split("\n") if l.strip()]
    recent = entries[-max_results:]
    return {"total": len(entries), "entries": [{"time": e["timestamp"][:19], "title": e.get("title",""), "msg": e["message"][:100]} for e in reversed(recent)], "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# Phase 4: ⏰ 定时任务
# ═══════════════════════════════════════════════════════════

CRON_LOG_PATH = Path("/opt/mcp-server/cron_execution.log")

def _cron_current() -> str:
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""

def _cron_write(content: str):
    r = subprocess.run(["crontab", "-"], input=content, text=True, capture_output=True)
    if r.returncode != 0:
        log.error(f"crontab write failed: {r.stderr[:200]}")


@mcp.tool(annotations=RISK["safe"])
def cron_list() -> dict:
    """[SAFE] 列出所有 MCP 定时任务"""
    content = _cron_current()
    all_lines = content.split("\n")
    tasks = []
    for i, line in enumerate(all_lines):
        if line.startswith("#MCP_TASK:"):
            parts = line[10:].split("|")
            cron_expr = ""
            for j in range(i+1, min(i+3, len(all_lines))):
                if not all_lines[j].startswith("#"):
                    cron_expr = all_lines[j].split("#")[0].strip()
                    break
            tasks.append({
                "id": parts[0], "name": parts[1] if len(parts) > 1 else "?",
                "cron": cron_expr or "?", "created": parts[2] if len(parts) > 2 else "?",
                "last_run": parts[3] if len(parts) > 3 else "never",
                "enabled": "DISABLED" not in line,
            })
    return {"total": len(tasks), "tasks": tasks, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def cron_add(schedule: str, name: str, command: str = "", description: str = "") -> dict:
    """[MUTATING] 添加定时任务（Linux crontab）

    Args:
        schedule: Cron 表达式，如 "0 3 * * *" (每天凌晨3点) 或 "*/30 * * * *" (每30分钟)
        name: 任务名称
        command: 要执行的命令（或留空由 ChatGPT 通过 MCP 触发）
        description: 描述

    Examples:
        cron_add("0 3 * * *", "每日巡检", "echo 'inspection started'")
        cron_add("*/10 * * * *", "健康检查")
    """
    if not re.match(r'^[\d*,/\-]+\s+[\d*,/\-]+\s+[\d*,/\-]+\s+[\d*,/\-]+\s+[\d*,/\-]+$', schedule.strip()):
        return {"error": f"无效的 cron 表达式: {schedule}。格式: 分 时 日 月 周"}

    tid = secrets.token_hex(4)
    content = _cron_current().strip()
    header = f"#MCP_TASK:{tid}|{name}|{datetime.now().isoformat()[:19]}|never|{description}"
    cmd = command or f"echo '[MCP-CRON] {name} triggered at \$(date)' >> /opt/mcp-server/cron_execution.log"

    cron_entry = f"{header}\n{schedule} {cmd} #MCP:{tid}\n"
    new_content = content + "\n" + cron_entry if content else cron_entry
    _cron_write(new_content)

    audit_log("SUCCESS", "cron_add", {"schedule": schedule, "name": name}, f"已添加定时任务", "mutating")
    return {"id": tid, "name": name, "schedule": schedule, "message": f"定时任务已添加: {name} ({schedule})", "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def cron_remove(task_id: str) -> dict:
    """[MUTATING] 删除定时任务

    Args:
        task_id: 任务 ID (从 cron_list 获取)
    """
    content = _cron_current()
    lines = content.split("\n")
    new_lines = []
    skip_count = 0
    removed = False
    for line in lines:
        if f"MCP_TASK:{task_id}" in line:
            skip_count = 2  # skip header + next line (cron entry)
            removed = True
            continue
        if skip_count > 0:
            skip_count -= 1
            continue
        new_lines.append(line)
    if removed:
        _cron_write("\n".join(new_lines))
        audit_log("SUCCESS", "cron_remove", {"task_id": task_id}, "已删除定时任务", "mutating")
        return {"task_id": task_id, "message": "定时任务已删除", "timestamp": datetime.now().isoformat()}
    return {"error": f"任务不存在: {task_id}"}


@mcp.tool(annotations=RISK["safe"])
def cron_log(max_results: int = 30) -> dict:
    """[SAFE] 查看定时任务执行日志"""
    if not CRON_LOG_PATH.exists():
        return {"total": 0, "entries": [], "timestamp": datetime.now().isoformat()}
    lines = [l.strip() for l in CRON_LOG_PATH.read_text().strip().split("\n") if l.strip()]
    return {"total": len(lines), "entries": lines[-max_results:], "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# Phase 5: 🏥 健康监控 + 自动修复
# ═══════════════════════════════════════════════════════════

HEALTH_PATH = Path(__file__).parent / "health_checks.json"
HEALTH_LOG = Path(__file__).parent / "health_log.jsonl"

def _health_load() -> list[dict]:
    if not HEALTH_PATH.exists(): return []
    return json.loads(HEALTH_PATH.read_text())

def _health_save(checks: list[dict]):
    HEALTH_PATH.write_text(json.dumps(checks, indent=2, ensure_ascii=False))

def _health_log(entry: dict):
    with open(HEALTH_LOG, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


@mcp.tool(annotations=RISK["mutating"])
def health_check_add(name: str, check_type: str, target: str, threshold: str = "", auto_fix: bool = False) -> dict:
    """[MUTATING] 添加健康检查

    Args:
        name: 检查名称
        check_type: container_running / port_open / disk_usage / service_active / http_status
        target: 检查目标 (容器名 / 端口号 / 路径 / 服务名 / URL)
        threshold: 阈值 (如磁盘 >80% 告警时填 "80"; HTTP 期望状态码填 "200")
        auto_fix: 是否自动修复
    """
    valid_types = ["container_running", "port_open", "disk_usage", "service_active", "http_status"]
    if check_type not in valid_types:
        return {"error": f"无效类型: {check_type}，可选: {valid_types}"}

    checks = _health_load()
    checks.append({
        "name": name, "type": check_type, "target": target,
        "threshold": threshold, "auto_fix": auto_fix,
        "enabled": True, "created": datetime.now().isoformat(),
        "last_status": "unknown", "last_check": None,
    })
    _health_save(checks)
    return {"name": name, "type": check_type, "auto_fix": auto_fix, "total_checks": len(checks), "message": f"健康检查已添加: {name}", "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def health_check_list() -> dict:
    """[SAFE] 列出所有健康检查"""
    checks = _health_load()
    return {"total": len(checks), "checks": [{"name": c["name"], "type": c["type"], "target": c["target"], "last_status": c.get("last_status","?"), "auto_fix": c.get("auto_fix",False), "enabled": c.get("enabled",True)} for c in checks], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def health_check_run(name: str = "") -> dict:
    """[MUTATING] 运行健康检查（name 为空则运行全部）

    Args:
        name: 检查名称，空=全部
    """
    checks = _health_load()
    if name:
        checks = [c for c in checks if c["name"] == name]
        if not checks: return {"error": f"未找到: {name}"}

    results = []
    issues = []

    for c in checks:
        if not c.get("enabled", True): continue
        status = "ok"
        detail = ""
        try:
            if c["type"] == "container_running":
                r = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", c["target"]], capture_output=True, text=True, timeout=10)
                status = "ok" if r.stdout.strip() == "running" else "down"
                detail = r.stdout.strip()
            elif c["type"] == "port_open":
                r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=10)
                status = "ok" if f":{c['target']} " in r.stdout else "down"
            elif c["type"] == "disk_usage":
                usage = subprocess.run(["df", c["target"]], capture_output=True, text=True, timeout=10)
                lines = usage.stdout.strip().split("\n")
                if len(lines) >= 2:
                    pct = int(lines[1].split()[-2].rstrip("%"))
                    threshold = int(c["threshold"]) if c["threshold"] else 80
                    status = "ok" if pct < threshold else "warning"
                    detail = f"{pct}% (阈值: {threshold}%)"
            elif c["type"] == "service_active":
                r = subprocess.run(["systemctl", "is-active", c["target"]], capture_output=True, text=True, timeout=10)
                status = "ok" if r.stdout.strip() == "active" else "down"
                detail = r.stdout.strip()
            elif c["type"] == "http_status":
                req = urllib.request.Request(c["target"], method="HEAD")
                try:
                    resp = urllib.request.urlopen(req, timeout=10)
                    expected = c["threshold"] or "200"
                    status = "ok" if str(resp.status) == expected else "mismatch"
                    detail = f"HTTP {resp.status}"
                except Exception as e:
                    status = "down"; detail = str(e)[:100]
        except Exception as e:
            status = "error"; detail = str(e)[:100]

        c["last_status"] = status
        c["last_check"] = datetime.now().isoformat()
        results.append({"name": c["name"], "status": status, "detail": detail})
        if status != "ok":
            issues.append({"name": c["name"], "status": status, "detail": detail, "auto_fix": c.get("auto_fix", False)})

    _health_save(checks)
    _health_log({"timestamp": datetime.now().isoformat(), "results": results, "issues": len(issues)})

    return {
        "checked": len(results), "healthy": sum(1 for r in results if r["status"] == "ok"),
        "issues": issues,
        "results": results,
        "timestamp": datetime.now().isoformat(),
    }


@mcp.tool(annotations=RISK["destructive"])
def health_remediate(check_name: str, action: str) -> dict:
    """[DESTRUCTIVE] 对异常健康检查执行自动修复

    Args:
        check_name: 健康检查名称
        action: restart_container / restart_service / send_notification / manual
    """
    checks = _health_load()
    match = [c for c in checks if c["name"] == check_name]
    if not match: return {"error": f"未找到: {check_name}"}
    check = match[0]

    msg = ""
    try:
        if action == "restart_container":
            r = subprocess.run(["docker", "restart", check["target"]], capture_output=True, text=True, timeout=60)
            msg = f"重启容器 {check['target']}: {'成功' if r.returncode == 0 else '失败'}"
        elif action == "restart_service":
            r = subprocess.run(["systemctl", "restart", check["target"]], capture_output=True, text=True, timeout=60)
            msg = f"重启服务 {check['target']}: {'成功' if r.returncode == 0 else '失败'}"
        elif action == "send_notification":
            cfg = _notify_config()
            for ch, cc in cfg.get("channels", {}).items():
                urllib.request.urlopen(urllib.request.Request(cc["url"],
                    data=json.dumps({"text": f"⚠️ 健康检查异常: {check_name} — {check.get('last_status','unknown')}"}).encode(),
                    headers={"Content-Type": "application/json"}), timeout=10)
            msg = f"已发送通知: {check_name}"
        else:
            msg = f"手动处理: {check_name}"
    except Exception as e:
        msg = f"修复失败: {e}"

    audit_log("SUCCESS", "health_remediate", {"check": check_name, "action": action}, msg, "destructive")
    _health_log({"timestamp": datetime.now().isoformat(), "action": "remediate", "check": check_name, "method": action, "result": msg})
    return {"check": check_name, "action": action, "result": msg, "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# Phase 6: ⚡ 工作流编排
# ═══════════════════════════════════════════════════════════

WORKFLOW_PATH = Path(__file__).parent / "workflows"

@mcp.tool(annotations=RISK["safe"])
def workflow_create(name: str, steps: list[dict], on_failure: str = "stop", description: str = "") -> dict:
    """[SAFE] 创建工作流（可复用的多步骤自动化流程）

    Args:
        name: 工作流名称
        steps: 步骤列表，每步格式 {"tool": "工具名", "args": {...}, "description": "说明"}
        on_failure: stop(遇错停止) / continue(继续) / rollback(回滚)
        description: 描述

    Example:
        workflow_create("每日巡检", [
            {"tool": "get_server_status", "args": {}, "description": "查状态"},
            {"tool": "get_docker_containers", "args": {}, "description": "查容器"},
            {"tool": "health_check_run", "args": {}, "description": "健康检查"},
        ])
    """
    WORKFLOW_PATH.mkdir(exist_ok=True)
    wf_id = secrets.token_hex(4)
    workflow = {"id": wf_id, "name": name, "steps": steps, "on_failure": on_failure, "description": description, "created": datetime.now().isoformat(), "run_count": 0, "last_run": None}
    (WORKFLOW_PATH / f"{wf_id}.json").write_text(json.dumps(workflow, indent=2, ensure_ascii=False))
    return {"id": wf_id, "name": name, "steps": len(steps), "message": f"工作流已创建: {name} ({len(steps)} 步骤)", "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def workflow_list() -> dict:
    """[SAFE] 列出所有工作流"""
    WORKFLOW_PATH.mkdir(exist_ok=True)
    workflows = []
    for f in sorted(WORKFLOW_PATH.glob("*.json")):
        try:
            wf = json.loads(f.read_text())
            workflows.append({"id": wf["id"], "name": wf["name"], "steps": len(wf["steps"]), "run_count": wf.get("run_count",0), "last_run": wf.get("last_run","never")})
        except: pass
    return {"total": len(workflows), "workflows": workflows, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def workflow_run(name_or_id: str, params: dict = {}) -> dict:
    """[MUTATING] 执行工作流，返回每步结果

    Args:
        name_or_id: 工作流名称或 ID
        params: 可选的参数替换（{{name}} → value）
    """
    WORKFLOW_PATH.mkdir(exist_ok=True)
    # Find workflow
    wf = None
    for f in WORKFLOW_PATH.glob("*.json"):
        try:
            w = json.loads(f.read_text())
            if w["id"] == name_or_id or w["name"] == name_or_id:
                wf = w; break
        except: pass
    if not wf: return {"error": f"工作流不存在: {name_or_id}"}

    # Resolve params
    def resolve(v):
        if isinstance(v, str):
            for k, pv in params.items():
                v = v.replace(f"{{{{{k}}}}}", str(pv))
        return v

    results = []
    for i, step in enumerate(wf["steps"]):
        tool_name = resolve(step["tool"])
        args = {k: resolve(v) for k, v in step.get("args", {}).items()}
        desc = step.get("description", f"Step {i+1}")

        # 从环境变量或 params 获取 token
        auth_token = params.get("_token", "") or os.getenv("MCP_TOKEN", "")
        if not auth_token:
            # fallback: read from .env.chat
            try:
                for line in Path(__file__).parent.joinpath(".env.chat").read_text().split("\n"):
                    if line.startswith("MCP_TOKEN="):
                        auth_token = line.split("=", 1)[1].strip()
                        break
            except: pass
        try:
            # Call via curl with auth
            cmd = ["curl", "-s", "-X", "POST", "http://127.0.0.1:8765/mcp",
                "-H", "Content-Type: application/json",
                "-H", "Accept: application/json, text/event-stream"]
            if auth_token:
                cmd.extend(["-H", f"Authorization: Bearer {auth_token}"])
            cmd.extend(["-d", json.dumps({"jsonrpc":"2.0","id":i+1,"method":"tools/call","params":{"name":tool_name,"arguments":args}})])
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            # Parse SSE
            result_text = r.stdout
            for line in result_text.split("\n"):
                if line.startswith("data:"):
                    try:
                        result_text = json.loads(line[5:]).get("result",{}).get("structuredContent",{}).get("message", json.loads(line[5:]).get("result",{}).get("structuredContent", r.stdout[:200]))
                    except: pass
            status = "done"
        except Exception as e:
            result_text = str(e); status = "failed"

        results.append({"step": i+1, "tool": tool_name, "description": desc, "status": status, "result": str(result_text)[:500]})

        if status == "failed" and wf["on_failure"] == "stop":
            results.append({"message": f"工作流在第 {i+1} 步失败，已停止"})
            break

    # Update run stats
    wf["run_count"] = wf.get("run_count", 0) + 1
    wf["last_run"] = datetime.now().isoformat()
    (WORKFLOW_PATH / f"{wf['id']}.json").write_text(json.dumps(wf, indent=2, ensure_ascii=False))

    _kb_save_entry({"id": wf["id"], "topic": f"Workflow Run: {wf['name']}", "content": json.dumps(results, ensure_ascii=False), "tags": ["workflow_run"], "created": datetime.now().isoformat()})

    done = sum(1 for r in results if r.get("status") == "done")
    return {"workflow": wf["name"], "run": wf["run_count"], "completed": f"{done}/{len(wf['steps'])}", "steps": results, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def workflow_status(name_or_id: str) -> dict:
    """[SAFE] 查看工作流定义和最近运行结果"""
    WORKFLOW_PATH.mkdir(exist_ok=True)
    for f in WORKFLOW_PATH.glob("*.json"):
        try:
            wf = json.loads(f.read_text())
            if wf["id"] == name_or_id or wf["name"] == name_or_id:
                return {"id": wf["id"], "name": wf["name"], "steps": [{"tool": s["tool"], "desc": s.get("description","")} for s in wf["steps"]], "run_count": wf.get("run_count",0), "last_run": wf.get("last_run"), "timestamp": datetime.now().isoformat()}
        except: pass
    return {"error": f"未找到: {name_or_id}"}


# ═══════════════════════════════════════════════════════════
# 🖥️ Windows 电脑管理 (通过反向 SSH 隧道)
# ═══════════════════════════════════════════════════════════

WIN_SSH_PORT = "2223"
WIN_SSH_USER = "Eric"
WIN_SSH_HOST = "localhost"

def _win_ssh(cmd: str, timeout: int = 20) -> tuple[int, str, str]:
    """通过反向 SSH 隧道在 Windows 上执行命令 (UTF-8 编码)"""
    r = subprocess.run(
        ["ssh", "-p", WIN_SSH_PORT, "-o", "ConnectTimeout=10",
         "-o", "StrictHostKeyChecking=no", f"{WIN_SSH_USER}@{WIN_SSH_HOST}",
         f"chcp 65001 >nul 2>&1 && {cmd}"],
        capture_output=True, timeout=timeout,
    )
    # 手动解码，处理 Windows GBK 编码
    try:
        stdout = r.stdout.decode("utf-8", errors="replace")[:20000]
    except:
        stdout = r.stdout.decode("gbk", errors="replace")[:20000]
    try:
        stderr = r.stderr.decode("utf-8", errors="replace")[:5000]
    except:
        stderr = r.stderr.decode("gbk", errors="replace")[:5000]
    return r.returncode, stdout, stderr

WIN_ALLOWED_PATHS = ["C:/Users/Eric", "D:/", "E:/", "C:/temp", "C:/tmp", "D:/360MoveData/Users/Eric"]

def _win_path_ok(path: str) -> tuple[bool, str]:
    p = path.replace("\\", "/")
    for allowed in WIN_ALLOWED_PATHS:
        a = allowed.replace("\\", "/")
        if p.lower().startswith(a.lower()):
            return True, p
    return False, f"路径不在允许范围: {path}"


@mcp.tool(annotations=RISK["safe"])
def win_read_file(path: str, lines: int = 50) -> dict:
    """[SAFE] 读取 Windows 电脑上的文件 (通过 SSH 隧道)

    Args:
        path: Windows 文件路径，如 C:\\Users\\Eric\\Desktop\\test.txt
        lines: 读取最后 N 行，默认 50
    """
    ok, msg = _win_path_ok(path)
    if not ok: return {"error": msg}
    lines = min(lines, 500)
    code, stdout, stderr = _win_ssh(f'type "{msg}"', timeout=15)
    if code != 0: return {"error": stderr[:500]}
    content = stdout.split("\n")
    last = [l for l in content[-lines:] if l.strip()]
    return {"path": msg, "lines": len(last), "content": last, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def win_list_dir(path: str = "C:\\Users\\Eric\\Desktop") -> dict:
    """[SAFE] 列出 Windows 电脑上的目录内容

    Args:
        path: 目录路径
    """
    ok, msg = _win_path_ok(path)
    if not ok: return {"error": msg}
    code, stdout, stderr = _win_ssh(f'dir "{msg}"', timeout=15)
    if code != 0: return {"error": stderr[:500]}
    lines = [l.strip() for l in stdout.split("\n") if l.strip()]
    return {"path": msg, "entries": len(lines), "output": lines[:60], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["destructive"])
def win_write_file(path: str, content: str) -> dict:
    """[DESTRUCTIVE] 写入文件到 Windows 电脑

    Args:
        path: 文件路径，如 C:\\Users\\Eric\\Desktop\\notes.txt
        content: 文件内容
    """
    ok, msg = _win_path_ok(path)
    if not ok: return {"error": msg}
    # 创建父目录
    parent = "\\".join(msg.replace("/", "\\").split("\\")[:-1])
    _win_ssh(f'if not exist "{parent}" mkdir "{parent}"', timeout=10)
    # 写入文件（base64 避免转义问题）
    import base64
    b64 = base64.b64encode(content.encode("utf-8")).decode()
    cmd = f'powershell -Command "[IO.File]::WriteAllBytes(\\"{msg}\\", [Convert]::FromBase64String(\\"{b64}\\"))"'
    code, stdout, stderr = _win_ssh(cmd, timeout=20)
    audit_log("SUCCESS" if code == 0 else "FAIL", "win_write_file", {"path": msg, "size": len(content)}, f"写入 {len(content)} 字节", "destructive")
    return {"path": msg, "bytes": len(content), "success": code == 0, "message": f"已写入 {msg} ({len(content)} 字节)" if code == 0 else stderr[:200], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def win_get_processes(count: int = 20, sort_by: str = "cpu") -> dict:
    """[SAFE] 查看 Windows 进程列表

    Args:
        count: 前 N 个，默认 20
        sort_by: cpu 或 mem
    """
    sort_arg = "CPU" if sort_by == "cpu" else "WorkingSet64"
    code, stdout, stderr = _win_ssh(
        f'powershell -Command "Get-Process | Sort-Object {sort_arg} -Descending | Select-Object -First {count} Name,Id,CPU,WorkingSet64 | Format-Table -AutoSize"',
        timeout=20
    )
    lines = [l.strip() for l in stdout.split("\n") if l.strip()]
    return {"count": min(count, len(lines)), "sort_by": sort_by, "processes": lines[:count+3], "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["mutating"])
def win_transfer_file(source_path: str, dest_path: str) -> dict:
    """[MUTATING] 将服务器上的文件通过 SCP 传输到 Windows 电脑

    配合 write_file 两步完成大文件传输:
      1. write_file → 把内容写到服务器的 /tmp/xxx
      2. win_transfer_file → SCP 传到 Windows 桌面

    Args:
        source_path: 服务器上的源文件路径，如 /tmp/poster.jpg
        dest_path: Windows 目标路径，如 D:\\Users\\Eric\\Desktop\\poster.jpg
    """
    ok, msg = _win_path_ok(dest_path)
    if not ok: return {"error": msg}

    src = Path(source_path)
    if not src.exists():
        return {"error": f"服务器文件不存在: {source_path}"}
    if not src.is_file():
        return {"error": f"不是文件: {source_path}"}

    size = src.stat().st_size
    win_path = msg.replace("/", "\\")

    r = subprocess.run(
        ["scp", "-P", WIN_SSH_PORT, "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
         str(src), f"{WIN_SSH_USER}@{WIN_SSH_HOST}:{win_path}"],
        capture_output=True, text=True, timeout=120,
    )

    audit_log("SUCCESS" if r.returncode == 0 else "FAIL", "win_transfer_file",
              {"source": source_path, "dest": msg, "size": size},
              f"{'已传输' if r.returncode == 0 else '失败'} {size} 字节",
              "mutating")

    if r.returncode == 0:
        return {"source": source_path, "dest": msg, "bytes": size, "message": f"已传输 {source_path} → {msg} ({size} 字节)", "timestamp": datetime.now().isoformat()}
    else:
        return {"error": r.stderr[:500]}


@mcp.tool(annotations=RISK["destructive"])
def win_write_binary(path: str, content_b64: str) -> dict:
    """[DESTRUCTIVE] 写入大文件到 Windows（通过 SCP，支持图片等二进制文件）

    对于小文本文件请用 win_write_file，大文件（图片/压缩包等）用此工具。

    Args:
        path: 目标路径，如 D:\\Users\\Eric\\Desktop\\poster.png
        content_b64: 文件的 base64 编码内容
    """
    import base64, tempfile
    ok, msg = _win_path_ok(path)
    if not ok: return {"error": msg}

    try:
        raw = base64.b64decode(content_b64)
    except Exception as e:
        return {"error": f"Base64 解码失败: {e}"}

    # 写到服务器临时文件
    tmp = Path("/tmp") / f"mcp-win-transfer-{secrets.token_hex(4)}"
    tmp.write_bytes(raw)

    # SCP 到 Windows
    win_path = msg.replace("/", "\\")
    r = subprocess.run(
        ["scp", "-P", WIN_SSH_PORT, "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
         str(tmp), f"{WIN_SSH_USER}@{WIN_SSH_HOST}:{win_path}"],
        capture_output=True, text=True, timeout=60,
    )

    # 清理
    tmp.unlink(missing_ok=True)

    audit_log("SUCCESS" if r.returncode == 0 else "FAIL", "win_write_binary",
              {"path": msg, "size": len(raw)}, f"{'写入' if r.returncode == 0 else '失败'} {len(raw)} 字节",
              "destructive")

    if r.returncode == 0:
        return {"path": msg, "bytes": len(raw), "message": f"已写入 {msg} ({len(raw)} 字节)", "timestamp": datetime.now().isoformat()}
    else:
        return {"error": r.stderr[:500]}


@mcp.tool(annotations=RISK["safe"])
def win_get_system_info() -> dict:
    """[SAFE] 查看 Windows 系统信息 (OS版本/内存/磁盘/网络)"""
    info = {}
    # OS
    code, stdout, _ = _win_ssh('systeminfo 2>&1 | findstr /C:"OS" /C:"System" /C:"Memory"', timeout=20)
    info["os"] = [l.strip() for l in stdout.split("\n") if l.strip()][:5]
    # Disk
    code, stdout, _ = _win_ssh('wmic logicaldisk get size,freespace,caption 2>&1', timeout=15)
    info["disks"] = [l.strip() for l in stdout.split("\n") if l.strip()][:10]
    # IP
    code, stdout, _ = _win_ssh('ipconfig 2>&1 | findstr /C:"IPv4"', timeout=10)
    info["ip"] = [l.strip() for l in stdout.split("\n") if l.strip()][:5]
    return {"system": info, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["destructive"])
def win_run_command(args: list[str]) -> dict:
    """[DESTRUCTIVE] 在 Windows 上执行命令 (白名单: tasklist/dir/type/echo/systeminfo/ipconfig/whoami/ping)

    Args:
        args: 命令参数列表，如 ["dir", "C:\\Users\\Eric\\Desktop"]
    """
    allowed = ["tasklist", "dir", "type", "echo", "systeminfo", "ipconfig", "whoami", "ping", "netstat", "findstr", "where", "powershell"]
    if not args: return {"error": "参数不能为空"}
    if args[0] not in allowed:
        return {"error": f"命令 '{args[0]}' 不在白名单: {allowed}"}
    cmd = " ".join(args)
    code, stdout, stderr = _win_ssh(cmd, timeout=30)
    audit_log("SUCCESS" if code == 0 else "FAIL", "win_run_command", {"args": args}, f"exit={code}", "destructive")
    return {"command": cmd, "exit_code": code, "stdout": stdout[:5000], "stderr": stderr[:2000], "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# 🎯 Skill 系统 (仿 Claude Code SKILL.md + 渐进加载)
# ═══════════════════════════════════════════════════════════

SKILLS_PATH = Path(__file__).parent / "skills"
SKILLS_PATH.mkdir(exist_ok=True)


@mcp.tool(annotations=RISK["safe"])
def skill_create(name: str, description: str, instructions: str, triggers: str = "") -> dict:
    """[SAFE] 创建可复用的 Skill（技能）

    Skill 定义了完成特定任务的完整流程。当用户请求匹配触发词时，ChatGPT 自动加载并执行。

    Args:
        name: 技能名称，如 generate-poster
        description: 一句话描述，如 "生成海报图片并保存到桌面"
        instructions: 逐步操作说明，包含要调用的工具和参数模板。支持 {{variable}} 占位符
        triggers: 逗号分隔的触发词，如 "海报,生成图,poster,做图"

    Example:
        skill_create("generate-poster",
            "生成海报并保存到桌面",
            "1. 用 AI 生成图片\n2. write_file 保存到 /tmp/poster.png\n3. win_transfer_file 传到桌面",
            "海报,poster,生成图")
    """
    skill_dir = SKILLS_PATH / name
    skill_dir.mkdir(exist_ok=True)

    frontmatter = f"""---
name: {name}
description: "{description}"
triggers: [{triggers}]
created: {datetime.now().isoformat()}
---

"""
    skill_md = frontmatter + instructions
    (skill_dir / "SKILL.md").write_text(skill_md, encoding="utf-8")

    return {"name": name, "description": description, "triggers": [t.strip() for t in triggers.split(",") if t.strip()], "message": f"Skill 已创建: {name}", "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def skill_list() -> dict:
    """[SAFE] 列出所有可用 Skill"""
    skills = []
    for d in sorted(SKILLS_PATH.iterdir()):
        if d.is_dir() and (d / "SKILL.md").exists():
            content = (d / "SKILL.md").read_text(encoding="utf-8", errors="replace")
            # Parse YAML frontmatter
            name = d.name
            desc = ""
            triggers = []
            if content.startswith("---"):
                end = content.find("---", 3)
                if end > 0:
                    for line in content[3:end].strip().split("\n"):
                        line = line.strip()
                        if line.startswith("name:"): name = line.split(":",1)[1].strip()
                        elif line.startswith("description:"): desc = line.split(":",1)[1].strip().strip('"')
                        elif line.startswith("triggers:"):
                            triggers = [t.strip() for t in line.split("[",1)[1].rstrip("]").split(",") if t.strip()]
            skills.append({"name": name, "description": desc, "triggers": triggers})
    return {"total": len(skills), "skills": skills, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def skill_search(query: str) -> dict:
    """[SAFE] 按关键词搜索 Skill（匹配名称、描述、触发词）

    Args:
        query: 搜索关键词，如 "海报" 或 "备份"
    """
    all_skills = skill_list()
    q = query.lower()
    results = []
    for s in all_skills["skills"]:
        text = s["name"] + " " + s["description"] + " " + " ".join(s["triggers"])
        if q in text.lower():
            results.append(s)
    return {"query": query, "found": len(results), "skills": results, "timestamp": datetime.now().isoformat()}


@mcp.tool(annotations=RISK["safe"])
def skill_run(name: str, params: dict = None) -> dict:
    """[SAFE] 加载并返回 Skill 的执行指令

    返回完整的分步指令。ChatGPT 应严格按照步骤顺序执行，使用已有的 MCP 工具。
    步骤中的 {{variable}} 会被 params 中的值替换。

    Args:
        name: Skill 名称
        params: 可选参数，如 {"topic": "落霞与孤鹜", "style": "水墨画"}
    """
    skill_dir = SKILLS_PATH / name
    if not skill_dir.is_dir() or not (skill_dir / "SKILL.md").exists():
        return {"error": f"Skill 不存在: {name}。用 skill_list 查看可用列表。"}

    content = (skill_dir / "SKILL.md").read_text(encoding="utf-8", errors="replace")

    # Extract body (after frontmatter)
    body = content
    if content.startswith("---"):
        end = content.find("---", 3)
        if end > 0:
            body = content[end+3:].strip()

    # Variable substitution
    if params:
        for k, v in params.items():
            body = body.replace(f"{{{{{k}}}}}", str(v))

    return {
        "skill": name,
        "instructions": body,
        "message": f"请严格按照以下步骤执行。完成后报告结果。",
        "timestamp": datetime.now().isoformat(),
    }


@mcp.tool(annotations=RISK["safe"])
def skill_delete(name: str) -> dict:
    """[SAFE] 删除一个 Skill

    Args:
        name: Skill 名称
    """
    skill_dir = SKILLS_PATH / name
    if not skill_dir.is_dir():
        return {"error": f"Skill 不存在: {name}"}
    import shutil
    shutil.rmtree(skill_dir)
    return {"name": name, "message": f"Skill 已删除: {name}", "timestamp": datetime.now().isoformat()}


# ═══════════════════════════════════════════════════════════
# 🚀 启动
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    log.info(f"🔐 OAuth 2.1 已启用 (issuer: {BASE_URL})")
    log.info(f"🚀 MCP Server v4.0: {BASE_URL}/mcp")
    log.info("📋 30 tools with risk-tiered auto-approval:")
    log.info("   🟢 SAFE (21) — auto-approve, no prompt")
    log.info("   🟡 MUTATING (7) — auto-approve + audit log")
    log.info("   🔴 DESTRUCTIVE (4) — prompt for confirmation")

    app = mcp.http_app(path="/mcp", stateless_http=True, transport="streamable-http")

    # ChatGPT OAuth 发现路径兼容
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    _pm = {"resource": f"{BASE_URL}/mcp", "authorization_servers": [f"{BASE_URL}/"], "scopes_supported": ["mcp:read"], "bearer_methods_supported": ["header"]}
    async def root_protected(request): return JSONResponse(_pm)
    app.routes.insert(0, Route("/.well-known/oauth-protected-resource", endpoint=root_protected, methods=["GET", "OPTIONS"]))

    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level=LOG_LEVEL.lower(), access_log=True)
