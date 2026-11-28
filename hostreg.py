# /// script
# requires-python = ">=3.11"
# ///
"""hostreg —— 主机清单的读写与校验，凭据文件只有这一个写入口。

供这些调用方共用：
  - `hosts_web.py`（本地 Web 界面，用户本人跑）
  - `gen_hosts.py`（命令行薄壳）
  - `ssh_marshal.py`（只调用 Web 界面的拉起/判活，不读写凭据）

设计约束：
  - **纯 stdlib**，不 import paramiko / mcp，方便离线测。
  - 保存是原子的：先写同目录临时文件再 `os.replace`，服务端按 mtime 热加载，
    不会读到半截 JSON；保存不生成备份。
  - `_` 开头的注释键原样保留；条目里服务端不认识的键也原样保留（GUI 只改它认识的字段）。
  - password 留空 = 沿用旧口令（GUI 不回填明文，避免出现在截图里）。

本模块注意：**服务进程（ssh_marshal.py）只读凭据文件**，写只在用户自己的工具里发生。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_NAME = "ssh_marshal_hosts.json"
SKIP_HOSTS = {"github.com"}  # 没有 shell 可 exec 的目标

# 服务端 HostCred 认识的字段；GUI 表单按这张表生成
FIELDS = (
    "address", "port", "username", "auth", "password", "key_path", "hostKey", "purpose",
    "elevate", "elevate_user", "elevate_password", "shell_init",
    "disabled", "critical", "xfer",
)
FLAG_FIELDS = ("elevate", "disabled", "critical", "xfer")
ALIAS_RE = re.compile(r"^[A-Za-z0-9._:@+-]+$")
HOSTKEY_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]+$")

# 与 paramiko Transport._preferred_keys 前几档一致（本机实测 paramiko 5.0.0）
KEY_RANK = {
    "ssh-ed25519": 0,
    "ecdsa-sha2-nistp256": 1,
    "ecdsa-sha2-nistp384": 2,
    "ecdsa-sha2-nistp521": 3,
    "rsa-sha2-512": 4,
    "rsa-sha2-256": 4,
    "ssh-rsa": 4,
}


class HostregError(ValueError):
    """凭据文件本身不可用（JSON 坏了、顶层不是对象）：拒绝写入，别覆盖用户数据。"""


def hosts_path() -> Path:
    if raw := os.environ.get("SSHMARSHAL_HOSTS"):
        return Path(raw).expanduser()
    base = Path(os.environ["SSHMARSHAL_HOME"]).expanduser() if os.environ.get("SSHMARSHAL_HOME") else HERE
    return base / DEFAULT_NAME


def is_entry(value) -> bool:
    return isinstance(value, dict)


def hosts(raw: dict) -> dict[str, dict]:
    """只取真正的条目：跳过 `_` 注释键与非对象值。"""
    return {k: v for k, v in (raw or {}).items() if not str(k).startswith("_") and is_entry(v)}


def normalize(entry: dict) -> dict:
    """把值收敛成服务端能直接吃的形态；未知键原样保留。"""
    out = dict(entry)
    for key in ("port",):
        if key in out:
            try:
                out[key] = int(out[key])
            except (TypeError, ValueError):
                pass
    for key in FLAG_FIELDS:
        if key in out:
            out[key] = bool(out[key])
    for key in ("address", "username", "auth", "password", "key_path", "hostKey", "purpose",
                "elevate_user", "elevate_password", "shell_init"):
        if key in out and out[key] is None:
            out[key] = ""
    return out


def validate(alias: str, entry: dict, existing_aliases: set[str] | None = None,
             is_new: bool = True) -> tuple[list[str], list[str]]:
    """返回 (errors, warnings)。errors 非空时不该保存；warnings 只是提示。"""
    errors: list[str] = []
    warnings: list[str] = []
    if not alias:
        errors.append("别名不能为空")
    elif alias.startswith("_"):
        errors.append("别名不能以 _ 开头（服务端会当成注释跳过）")
    elif not ALIAS_RE.match(alias):
        errors.append("别名只能含字母、数字与 . _ : @ + -")
    elif existing_aliases and is_new and alias in existing_aliases:
        errors.append(f"别名 {alias} 已存在")

    address = str(entry.get("address") or "").strip()
    if not address:
        errors.append("address 不能为空")
    elif any(c.isspace() for c in address):
        errors.append("address 不能含空白")

    port_raw = entry.get("port", 22)
    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            errors.append("port 必须在 1–65535")
    except (TypeError, ValueError):
        errors.append("port 不是整数")

    if not str(entry.get("username") or "").strip():
        warnings.append("username 为空：连不上，保存后记得补")

    auth = str(entry.get("auth") or "password")
    if auth not in ("password", "key"):
        errors.append("auth 只能是 password 或 key")
    if auth == "password":
        keep_existing = not is_new and not str(entry.get("password") or "")
        if not str(entry.get("password") or "") and not keep_existing:
            warnings.append("auth=password 但口令为空：exec 会失败")
    else:
        key_path = str(entry.get("key_path") or "").strip()
        if key_path and not Path(key_path).expanduser().is_file():
            warnings.append(f"key_path 指向的文件不存在：{key_path}（运行时还会再找 ssh-agent）")

    host_key = str(entry.get("hostKey") or "").strip()
    if host_key and not HOSTKEY_RE.match(host_key):
        errors.append("hostKey 形如 SHA256:xxxx（不带末尾 =）")
    if not host_key:
        warnings.append("hostKey 为空：先探测指纹并确认，否则 exec 会被拒")
    return errors, warnings


@dataclass
class Candidate:
    alias: str
    entry: dict
    notes: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)  # 不可导入的原因，非空时 GUI 置灰

    @property
    def importable(self) -> bool:
        return not self.reasons


class Registry:
    """一个凭据文件的读写句柄。每次写都会重新读盘，避免覆盖别人期间的改动。"""

    def __init__(self, path: Path | None = None):
        self.path = Path(path or hosts_path()).expanduser()
        self.raw: dict = {}
        self.error: str = ""
        self.reload()

    def reload(self) -> None:
        self.error = ""
        if not self.path.exists():
            self.raw = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.raw = {}
            self.error = f"{self.path.name} 无法解析：{exc}"
            return
        if not isinstance(raw, dict):
            self.raw = {}
            self.error = f"{self.path.name} 顶层不是对象"
            return
        self.raw = raw

    @property
    def writable(self) -> bool:
        return not self.error

    def entries(self) -> dict[str, dict]:
        return hosts(self.raw)

    def aliases(self) -> set[str]:
        return set(self.entries())

    def get(self, alias: str) -> dict:
        return dict(self.entries().get(alias) or {})

    def save(self) -> None:
        """原子写，不生成备份；失败抛 HostregError/OSError。"""
        if not self.writable:
            raise HostregError(self.error)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f"{self.path.name}.tmp")
        payload = json.dumps(self.raw, indent=2, ensure_ascii=False) + "\n"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def upsert(self, alias: str, entry: dict, keep_password_if_empty: bool = True) -> dict:
        """新增或更新一条；保留旧条目里的未知键，password 留空时沿用旧口令。

        注意：空字符串不会清掉旧值（这是「留空即不改」的实现），布尔与数字照常覆盖。
        """
        merged = dict(self.entries().get(alias) or {})
        merged.update({k: v for k, v in normalize(entry).items() if v != "" or k not in merged})
        if keep_password_if_empty and not merged.get("password"):
            old = self.entries().get(alias) or {}
            if old.get("password"):
                merged["password"] = old["password"]
        self.raw[alias] = merged
        return merged

    def rename(self, old: str, new: str, entry: dict, keep_password_if_empty: bool = True) -> dict:
        """把 old 整条挪到 new；未知键与「口令留空＝沿用」语义和 upsert 一致。"""
        self.raw[new] = self.raw.pop(old)
        return self.upsert(new, entry, keep_password_if_empty=keep_password_if_empty)

    def remove(self, alias: str) -> bool:
        if alias in self.entries():
            self.raw.pop(alias, None)
            return True
        return False

    def set_flag(self, alias: str, field_name: str, value: bool) -> bool:
        if field_name not in FLAG_FIELDS or alias not in self.entries():
            return False
        self.raw[alias][field_name] = bool(value)
        return True


# --------------------------------------------------------------------------------------
# 从本机 ~/.ssh 扫描候选（gen_hosts 与 GUI 共用）
# --------------------------------------------------------------------------------------


def fingerprint(blob_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def read_known_hosts(path: Path | None = None) -> tuple[dict[tuple[str, int], dict[str, str]], int]:
    path = path or (Path.home() / ".ssh" / "known_hosts")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return {}, 0
    found: dict[tuple[str, int], dict[str, str]] = {}
    hashed = 0
    for line in lines:
        line = line.strip()
        if not line or line[0] in "#@":
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        names, keytype, blob = parts[0], parts[1], parts[2]
        if names.startswith("|"):  # HashKnownHosts 过的行反查不出主机名
            hashed += 1
            continue
        try:
            fp = fingerprint(blob)
        except ValueError:
            continue
        for name in names.split(","):
            if name.startswith("["):
                body, _, port_s = name[1:].partition("]:")
                if not port_s.isdigit():
                    continue
                addr, port = body, int(port_s)
            else:
                addr, port = name, 22
            found.setdefault((addr, port), {})[keytype] = fp
    return found, hashed


def read_ssh_config(path: Path | None = None) -> dict[str, dict[str, str]]:
    path = path or (Path.home() / ".ssh" / "config")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return {}
    out: dict[str, dict[str, str]] = {}
    tokens: list[str] = []
    opts: dict[str, str] = {}

    def flush() -> None:
        if tokens and not any("*" in t or "?" in t or t.startswith("!") for t in tokens):
            for token in tokens:
                out.setdefault(token, dict(opts))

    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        chunks = re.split(r"[=\s]+", line, maxsplit=1)
        key = chunks[0].lower()
        value = chunks[1] if len(chunks) > 1 else ""
        if key == "host":
            flush()
            tokens, opts = value.split(), {}
        elif tokens:
            opts[key] = value
    flush()
    return out


def build_candidates(raw: dict, connected: dict[tuple[str, int], dict[str, str]],
                     config: dict[str, dict[str, str]]) -> list[Candidate]:
    """按地址去重，生成候选清单；已有的地址与别名标成不可导入。"""
    existing = hosts(raw)
    existing_by_addr: dict[tuple[str, int], str] = {}
    for alias, entry in existing.items():
        addr = str(entry.get("address") or "")
        port_raw = entry.get("port", 22)
        if addr:
            existing_by_addr[(addr, int(port_raw) if str(port_raw).isdigit() else 22)] = alias

    entries: dict[tuple[str, int], dict] = {}
    for token, opts in config.items():
        addr = opts.get("hostname") or token
        port_raw = opts.get("port", "")
        port = int(port_raw) if port_raw.isdigit() else 22
        entries.setdefault((addr, port), {}).setdefault("username", opts.get("user", ""))
    for key, types in connected.items():
        entries.setdefault(key, {})["types"] = types

    tails: dict[str, int] = {}
    for addr, _ in entries:
        tails[addr.rsplit(".", 1)[-1]] = tails.get(addr.rsplit(".", 1)[-1], 0) + 1

    out: list[Candidate] = []
    for (addr, port), info in sorted(entries.items()):
        tail = addr.rsplit(".", 1)[-1]
        alias = tail if tails[tail] == 1 and tail not in existing else addr
        if port != 22:
            alias = f"{alias}:{port}"
        types: dict[str, str] = info.get("types", {})
        host_key = types[min(types, key=lambda t: KEY_RANK.get(t, 9))] if types else ""
        cand = Candidate(alias=alias, entry={
            "address": addr, "port": port,
            "username": info.get("username", ""),
            "auth": "password", "password": "", "hostKey": host_key,
        })
        if addr in SKIP_HOSTS:
            cand.reasons.append("不是可 exec 的机器")
        if (addr, port) in existing_by_addr:
            cand.reasons.append(f"已在清单里：{existing_by_addr[(addr, port)]}")
        if alias in existing:
            cand.reasons.append(f"别名冲突：{alias}")
        if not host_key:
            cand.notes.append("known_hosts 里没有它的指纹，需要探测")
        if not cand.entry["username"]:
            cand.notes.append("ssh config 没给 username，需要手填")
        cand.notes.append("password 需要手填")
        out.append(cand)
    return out


# --------------------------------------------------------------------------------------
# Web 界面（hosts_web.py）的拉起与判活（给 ssh_marshal.py 的 hosts_gui 工具用）
#
# 服务拉起是 detached 的；一个凭据文件同时只认一个 Web 服务。
# 判活靠临时状态文件里的端口 + /api/health，不靠进程名或窗口句柄。
# --------------------------------------------------------------------------------------

WEB_STATUS_DIR = Path(tempfile.gettempdir()) / "sshmarshal-web"
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def web_ui_script() -> Path:
    return HERE / "hosts_web.py"


def web_ui_status_path(path: Path | None = None) -> Path:
    target = Path(path or hosts_path()).expanduser().resolve()
    key = hashlib.sha1(str(target).lower().encode("utf-8")).hexdigest()[:16]
    return WEB_STATUS_DIR / f"{key}.json"


def write_web_ui_status(path: Path, port: int, control: str, opened: bool | None = None) -> Path:
    dest = web_ui_status_path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "pid": os.getpid(),
        "port": int(port),
        "hosts": str(Path(path).expanduser().resolve()),
        "control": control,
        "opened": opened,
        "started": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, dest)
    return dest


def clear_web_ui_status(path: Path) -> None:
    dest = web_ui_status_path(path)
    try:
        data = json.loads(dest.read_text(encoding="utf-8"))
        if int(data.get("pid") or 0) == os.getpid():
            dest.unlink(missing_ok=True)
    except (OSError, ValueError, TypeError):
        pass


def read_web_ui_status(path: Path | None = None) -> dict:
    try:
        data = json.loads(web_ui_status_path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def web_ui_running(path: Path | None = None, timeout: float = 0.7) -> dict:
    """返回 {running, pid, port, control}；control 只给启动器内部用，不对外输出。"""
    target = Path(path or hosts_path()).expanduser().resolve()
    status = read_web_ui_status(target)
    port = status.get("port")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return {"running": False, "pid": status.get("pid"), "port": None, "control": ""}
    try:
        with _LOCAL_OPENER.open(f"http://127.0.0.1:{port}/api/health", timeout=timeout) as resp:
            payload = json.loads(resp.read(512).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - 服务没起来/端口被占都按未运行处理
        return {"running": False, "pid": status.get("pid"), "port": port, "control": ""}
    running = bool(payload.get("ok")) and str(payload.get("hosts") or "").lower() == str(target).lower()
    return {
        "running": running,
        "pid": payload.get("pid") or status.get("pid"),
        "port": port,
        "control": status.get("control") or "",
    }


def reopen_web_ui(path: Path | None = None) -> bool:
    """让已运行的 Web 服务再打开一个浏览器页面；control 只在本机状态文件里。"""
    status = web_ui_running(path)
    control = status.get("control") or ""
    if not status.get("running") or not control:
        return False
    req = urllib.request.Request(
        f"http://127.0.0.1:{status['port']}/api/reopen",
        data=b"{}", method="POST",
        headers={"X-Control": control, "Content-Type": "application/json"},
    )
    try:
        with _LOCAL_OPENER.open(req, timeout=2.0) as resp:
            payload = json.loads(resp.read(512).decode("utf-8", "replace"))
            return bool(payload.get("ok")) and bool(payload.get("opened", False))
    except Exception:  # noqa: BLE001
        return False


def launch_web_ui(path: Path | None = None) -> dict:
    """detached 拉起 hosts_web.py；已有服务则复用它并重新打开页面。"""
    target = Path(path or hosts_path()).expanduser()
    status = web_ui_running(target)
    if status["running"]:
        return {
            "ok": True, "running": True, "reused": True,
            "pid": status.get("pid"), "port": status.get("port"),
            "opened": reopen_web_ui(target),
        }
    script = web_ui_script()
    if not script.exists():
        return {"ok": False, "reason": "script_missing", "hint": f"找不到 {script}"}
    env = dict(os.environ)
    env["SSHMARSHAL_HOSTS"] = str(target)  # 页面必须编辑服务正在读的那份清单
    args = [sys.executable, str(script), "--port", "0"]
    kwargs = dict(cwd=str(HERE), env=env, stdin=subprocess.DEVNULL,
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    if os.name == "nt":
        base = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            # 连同 Job 一起脱出，否则客户端重启/命令结束时服务会被回收
            proc = subprocess.Popen(args, creationflags=base | 0x01000000, **kwargs)  # CREATE_BREAKAWAY_FROM_JOB
        except OSError:
            proc = subprocess.Popen(args, creationflags=base, **kwargs)
    else:
        proc = subprocess.Popen(args, **kwargs)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        check = web_ui_running(target)
        if check["running"]:
            current = read_web_ui_status(target)
            return {"ok": True, "running": True, "reused": False,
                    "pid": check.get("pid") or proc.pid, "port": check.get("port"),
                    "opened": bool(current.get("opened"))}
        if proc.poll() is not None:
            return {"ok": False, "reason": "exited", "pid": proc.pid, "exit_code": proc.returncode,
                    "hint": "Web 服务立刻退出了，请用 uv run hosts_web.py 看报错"}
        time.sleep(0.1)
    return {"ok": False, "reason": "timeout", "pid": proc.pid,
            "hint": "Web 服务启动超时；可稍后重试，或直接用 uv run hosts_web.py 打开"}


def file_digest(path: Path) -> dict:
    """内容哈希，用来判断「用户改过没有」；不看 mtime，临时写不会误报。"""
    try:
        data = path.read_bytes()
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        return {"exists": False, "sha256": None, "mtime": None, "size": 0}
    return {
        "exists": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "mtime": datetime.fromtimestamp(mtime).astimezone().isoformat(timespec="seconds"),
        "size": len(data),
    }
