# /// script
# requires-python = ">=3.11"
# dependencies = ["paramiko>=3.4"]
# ///
"""hosts_web.py —— ssh-marshal 主机清单的本地 Web 界面。

    uv run hosts_web.py              # 启动服务并打开浏览器
    uv run hosts_web.py --no-open    # 只启动，打印带 token 的地址

只监听 127.0.0.1，所有 /api 请求都要带启动时生成的 X-Token。
凭据文件仍由 hostreg 唯一写入：原子写（Web 端不生成备份）；页面永远拿不到明文口令。
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import hostreg as R
import ssh_probe as P

HERE = Path(__file__).resolve().parent
WEB_ROOT = (HERE / "web").resolve()
TOKEN = secrets.token_urlsafe(24)
WRITE_LOCK = threading.Lock()
MAX_BODY = 1_000_000

SAFE_FIELDS = tuple(f for f in R.FIELDS if f not in ("password", "elevate_password"))


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def public_entry(entry: dict) -> dict:
    out = {k: entry[k] for k in SAFE_FIELDS if k in entry}
    out["port"] = int(entry.get("port") or 22)
    out["flags"] = {
        "disabled": bool(entry.get("disabled")),
        "critical": bool(entry.get("critical")),
        "xfer": entry.get("xfer") is not False,
        "elevate": bool(entry.get("elevate")),
    }
    out["has_password"] = bool(entry.get("password"))
    out["has_elevate_password"] = bool(entry.get("elevate_password"))
    return out


class App:
    def __init__(self, hosts_path: Path | None = None):
        self.hosts_path = hosts_path

    def registry(self) -> R.Registry:
        return R.Registry(self.hosts_path)

    def state(self) -> dict:
        reg = self.registry()
        hosts = [
            {"alias": alias, **public_entry(entry)}
            for alias, entry in sorted(reg.entries().items())
        ]
        return {
            "ok": True,
            "path": str(reg.path),
            "error": reg.error,
            "writable": reg.writable,
            "file": R.file_digest(reg.path),
            "hosts": hosts,
        }

    def save_host(self, body: dict) -> dict:
        alias = str(body.get("alias") or "").strip()
        entry = body.get("entry") or {}
        is_new = bool(body.get("is_new"))
        if not isinstance(entry, dict):
            raise ApiError(400, "entry 必须是对象")
        with WRITE_LOCK:
            reg = self.registry()
            if not reg.writable:
                raise ApiError(400, reg.error)
            if is_new and alias in reg.aliases():
                raise ApiError(400, f"别名 {alias} 已存在")
            if not is_new and alias not in reg.aliases():
                raise ApiError(400, f"要编辑的主机 {alias} 不存在")
            errors, warnings = R.validate(alias, entry, reg.aliases(), is_new=is_new)
            if errors:
                raise ApiError(400, "；".join(errors))
            reg.upsert(alias, entry)
            reg.save()
        return {"ok": True, "warnings": warnings, "state": self.state()}

    def delete_host(self, body: dict) -> dict:
        alias = str(body.get("alias") or "").strip()
        with WRITE_LOCK:
            reg = self.registry()
            if not reg.writable:
                raise ApiError(400, reg.error)
            if not reg.remove(alias):
                raise ApiError(404, f"清单里没有 {alias}")
            reg.save()
        return {"ok": True, "state": self.state()}

    def probe(self, body: dict) -> dict:
        address = str(body.get("address") or "").strip()
        try:
            port = int(body.get("port") or 22)
        except (TypeError, ValueError):
            raise ApiError(400, "port 不是整数")
        if not address:
            raise ApiError(400, "地址不能为空")
        if not (1 <= port <= 65535):
            raise ApiError(400, "port 必须在 1–65535")
        started = time.monotonic()
        try:
            fingerprint, key_type = P.probe_hostkey(address, port, timeout=10.0)
        except Exception as exc:  # noqa: BLE001 - 网络错误形态太多，原样回给页面
            raise ApiError(400, f"{type(exc).__name__}: {exc}")
        return {
            "ok": True,
            "fingerprint": fingerprint,
            "key_type": key_type,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }

    def test_connection(self, body: dict) -> dict:
        entry = body.get("entry") or {}
        if not isinstance(entry, dict):
            raise ApiError(400, "entry 必须是对象")
        alias = str(body.get("alias") or "").strip()
        reg = self.registry()
        stored = reg.get(alias) if alias else {}
        address = str(entry.get("address") or stored.get("address") or "").strip()
        if not address:
            raise ApiError(400, "地址不能为空")
        try:
            port = int(entry.get("port") or stored.get("port") or 22)
        except (TypeError, ValueError):
            raise ApiError(400, "port 不是整数")
        password = str(entry.get("password") or stored.get("password") or "")
        key_path = str(entry.get("key_path") or stored.get("key_path") or "")
        auth = str(entry.get("auth") or stored.get("auth") or "password")
        username = str(entry.get("username") or stored.get("username") or "")
        pin = str(body.get("hostKey") or entry.get("hostKey") or stored.get("hostKey") or "").strip()
        if not pin:
            raise ApiError(400, "hostKey 为空：先探测指纹并确认，再连测")
        cred = P.ProbeCred(
            address=address, port=port, username=username,
            auth=auth, password=password, key_path=key_path, alias=alias or "probe",
        )
        try:
            result = P.test_connection(cred, pin)
        except Exception as exc:  # noqa: BLE001 - 私钥加载等配置错误也回给页面，不冒成 500
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "reason": "client_error"}
        return {"ok": True, "result": result}

    def candidates(self) -> dict:
        reg = self.registry()
        connected, hashed = R.read_known_hosts()
        config = R.read_ssh_config()
        cands = R.build_candidates(reg.raw, connected, config)
        return {
            "ok": True,
            "known_hosts": len(connected),
            "ssh_config": len(config),
            "hashed": hashed,
            "candidates": [
                {
                    "alias": c.alias,
                    "entry": public_entry(c.entry),
                    "notes": c.notes,
                    "reasons": c.reasons,
                    "importable": c.importable,
                }
                for c in cands
            ],
        }

    def import_candidates(self, body: dict) -> dict:
        wanted = [str(a) for a in (body.get("aliases") or [])]
        with WRITE_LOCK:
            reg = self.registry()
            if not reg.writable:
                raise ApiError(400, reg.error)
            connected, _ = R.read_known_hosts()
            config = R.read_ssh_config()
            by_alias = {
                c.alias: c for c in R.build_candidates(reg.raw, connected, config) if c.importable
            }
            added: list[str] = []
            skipped: list[str] = []
            for alias in dict.fromkeys(wanted):
                cand = by_alias.get(alias)
                if cand is None:
                    skipped.append(alias)
                    continue
                reg.upsert(cand.alias, cand.entry, keep_password_if_empty=False)
                added.append(alias)
            if added:
                reg.save()
        return {
            "ok": True,
            "added": added,
            "skipped": skipped,
            "state": self.state(),
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "ssh-marshal-web"
    protocol_version = "HTTP/1.1"

    # ---------------------------------------------------------------- plumbing
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - 保持控制台安静
        pass

    def _json(self, status: int, obj: dict) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"ok": False, "error": message})

    def _authorized(self) -> bool:
        got = self.headers.get("X-Token", "")
        return bool(got) and secrets.compare_digest(got, self.server.token)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "Content-Length 不合法")
        if length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "请求体过大")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "请求体不是合法 JSON")
        if not isinstance(data, dict):
            raise ApiError(400, "请求体必须是对象")
        return data

    def _serve_static(self) -> None:
        path = urlparse(self.path).path
        if path in ("", "/"):
            path = "/index.html"
        target = (WEB_ROOT / path.lstrip("/")).resolve()
        if target != WEB_ROOT and not target.is_relative_to(WEB_ROOT):
            self._error(403, "forbidden")
            return
        if not target.is_file():
            self._error(404, "not found")
            return
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if target.suffix == ".woff2":
            ctype = "font/woff2"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8" if ctype.startswith("text/") else ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    # ---------------------------------------------------------------- routes
    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if not route.startswith("/api/"):
            self._serve_static()
            return
        if not self._authorized():
            self._error(401, "unauthorized")
            return
        try:
            if route == "/api/state":
                self._json(200, self.server.app.state())
            elif route == "/api/candidates":
                self._json(200, self.server.app.candidates())
            else:
                self._error(404, "unknown endpoint")
        except Exception as exc:  # noqa: BLE001
            self._error(500, f"{type(exc).__name__}: {exc}")

    def do_POST(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if not route.startswith("/api/"):
            self.close_connection = True
            self._error(404, "not found")
            return
        try:
            # 先读完请求体再判令牌：401 时若留下未读 body，HTTP/1.1 keep-alive
            # 会把这段字节拼到下一条请求行上，服务端就会看到 "GET" 前面多出一段 JSON。
            body = self._body()
            if not self._authorized():
                self._error(401, "unauthorized")
                return
            if route == "/api/hosts":
                self._json(200, self.server.app.save_host(body))
            elif route == "/api/delete":
                self._json(200, self.server.app.delete_host(body))
            elif route == "/api/probe":
                self._json(200, self.server.app.probe(body))
            elif route == "/api/test":
                self._json(200, self.server.app.test_connection(body))
            elif route == "/api/import":
                self._json(200, self.server.app.import_candidates(body))
            elif route == "/api/shutdown":
                self._json(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self._error(404, "unknown endpoint")
        except ApiError as exc:
            self._error(exc.status, str(exc))
        except R.HostregError as exc:
            self._error(400, f"保存失败：{exc}")
        except Exception as exc:  # noqa: BLE001 - 回给页面，避免整页 500 无提示
            self._error(500, f"{type(exc).__name__}: {exc}")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.close_connection = True
        self._error(403, "forbidden")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, app: App, token: str):
        super().__init__(address, handler)
        self.app = app
        self.token = token


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="hosts_web.py",
        description="ssh-marshal 主机清单的本地 Web 界面（仅 127.0.0.1）",
    )
    ap.add_argument("--hosts", default="", help="凭据文件路径；默认取 SSHMARSHAL_HOSTS 或脚本目录")
    ap.add_argument("--port", type=int, default=0, help="监听端口；默认自动选一个空闲端口")
    ap.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    app = App(Path(args.hosts).expanduser() if args.hosts else None)
    httpd = Server(("127.0.0.1", args.port), Handler, app, TOKEN)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/#token={TOKEN}"
    reg = app.registry()
    print("ssh-marshal 主机清单", flush=True)
    print(f"  地址：{url}", flush=True)
    print(f"  凭据：{reg.path}" + (f"（{reg.error}）" if reg.error else ""), flush=True)
    print("  按 Ctrl+C 或页面右上角「关闭服务」结束。", flush=True)
    if not args.no_open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    print("已关闭。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
