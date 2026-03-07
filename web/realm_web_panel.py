#!/usr/bin/env python3
import argparse
import html
import http.server
import os
import secrets
import socketserver
import sys
from urllib.parse import parse_qs, urlparse


def read_manager_conf(path: str):
    data = {}
    if not os.path.exists(path):
        return data
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"')
    return data


class PanelHandler(http.server.BaseHTTPRequestHandler):
    sessions = {}
    conf_path = "/etc/realm/manager.conf"

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._home()
        elif path == "/logout":
            self._logout()
        elif path == "/healthz":
            self._text(200, "ok")
        else:
            self._text(404, "Not Found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/login":
            self._login()
        else:
            self._text(404, "Not Found")

    def _form(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        body = self.rfile.read(n).decode("utf-8", errors="ignore")
        return {k: v[0] for k, v in parse_qs(body).items()}

    def _cookie(self, name: str):
        raw = self.headers.get("Cookie", "")
        for kv in raw.split(";"):
            kv = kv.strip()
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if k.strip() == name:
                return v.strip()
        return ""

    def _authed(self):
        sid = self._cookie("xwpf_session")
        return bool(sid and sid in self.sessions)

    def _html(self, code: int, body: str, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _text(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _shell(self, title: str, content: str):
        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>
    :root {{ --bg:#0b1020; --card:rgba(255,255,255,.08); --text:#e8eefc; --muted:#a4b1d6; --line:rgba(255,255,255,.14); --brand:#5b8cff; --brand2:#7a5cff; --ok:#24d07a; --warn:#f8c14f; --danger:#ff6b6b; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; padding:24px; min-height:100vh; color:var(--text); font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif; background:radial-gradient(1200px 600px at 80% -10%,#2f3a80 0%,transparent 50%), radial-gradient(1000px 500px at 0% 100%,#1f7a6f 0%,transparent 50%), var(--bg); }}
    .wrap {{ max-width:860px; margin:0 auto; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:16px; padding:20px; backdrop-filter:blur(8px); box-shadow:0 10px 30px rgba(0,0,0,.25); }}
    .title {{ font-size:24px; margin:0 0 8px; }}
    .desc {{ color:var(--muted); margin:0 0 18px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; }}
    .item {{ border:1px solid var(--line); border-radius:12px; padding:12px; background:rgba(255,255,255,.03); }}
    .k {{ color:var(--muted); font-size:12px; }}
    .v {{ font-weight:600; margin-top:6px; word-break:break-all; }}
    .dot {{ width:8px; height:8px; border-radius:99px; display:inline-block; margin-right:8px; }}
    .ok {{ background:var(--ok); }}
    .btn {{ appearance:none; border:0; cursor:pointer; border-radius:10px; padding:10px 14px; color:#fff; background:linear-gradient(135deg,var(--brand),var(--brand2)); font-weight:600; }}
    .btn-secondary {{ background:rgba(255,255,255,.1); border:1px solid var(--line); }}
    .row {{ display:flex; gap:10px; align-items:center; margin-top:16px; flex-wrap:wrap; }}
    .input {{ width:100%; border:1px solid var(--line); border-radius:10px; padding:10px 12px; background:rgba(255,255,255,.05); color:var(--text); outline:none; }}
    .label {{ font-size:13px; color:var(--muted); margin:10px 0 6px; display:block; }}
    .warn {{ color:var(--warn); font-size:13px; margin-top:12px; }}
    .err {{ color:var(--danger); font-size:13px; margin-top:8px; }}
    footer {{ color:var(--muted); font-size:12px; margin-top:14px; }}
  </style>
</head>
<body><div class="wrap">{content}</div></body>
</html>"""

    def _home(self):
        conf = read_manager_conf(self.conf_path)
        if not self._authed():
            msg = getattr(self.server, "last_error", "")
            err_html = f'<div class="err">{html.escape(msg)}</div>' if msg else ""
            content = f"""
            <div class="card" style="max-width:420px;margin:40px auto;">
              <h1 class="title">xwPF Web 管理登录</h1>
              <p class="desc">简约控制台 · 认证保护</p>
              <form method="post" action="/login">
                <label class="label">账号</label>
                <input class="input" name="username" autocomplete="username" required />
                <label class="label">密码</label>
                <input class="input" type="password" name="password" autocomplete="current-password" required />
                <div class="row"><button class="btn" type="submit">登录</button></div>
              </form>
              {err_html}
              <div class="warn">请安装后尽快在 pf 菜单中重置账号密码。</div>
            </div>
            """
            self.server.last_error = ""
            self._html(200, self._shell("xwPF 登录", content))
            return

        web_port = conf.get("WEB_PORT", str(getattr(self.server, "server_port", 8080)))
        content = f"""
        <div class="card">
          <h1 class="title">xwPF Web 管理面板</h1>
          <p class="desc">简约可视化页面（当前为基础版）</p>
          <div class="grid">
            <div class="item"><div class="k">状态</div><div class="v"><span class="dot ok"></span>在线运行</div></div>
            <div class="item"><div class="k">访问端口</div><div class="v">{html.escape(str(web_port))}</div></div>
            <div class="item"><div class="k">配置文件</div><div class="v">/etc/realm/manager.conf</div></div>
            <div class="item"><div class="k">Realm 配置目录</div><div class="v">/etc/realm</div></div>
          </div>
          <div class="row"><a href="/logout"><button class="btn btn-secondary">退出登录</button></a></div>
          <footer>后续可继续扩展：规则管理、日志查看、启停控制、导入导出等。</footer>
        </div>
        """
        self._html(200, self._shell("xwPF Web 面板", content))

    def _login(self):
        form = self._form()
        username = form.get("username", "")
        password = form.get("password", "")
        conf = read_manager_conf(self.conf_path)
        if username == conf.get("WEB_USERNAME", "") and password == conf.get("WEB_PASSWORD", ""):
            sid = secrets.token_urlsafe(24)
            self.sessions[sid] = username
            self._html(302, "", headers=[
                ("Location", "/"),
                ("Set-Cookie", f"xwpf_session={sid}; Path=/; HttpOnly; SameSite=Lax"),
            ])
            return
        self.server.last_error = "账号或密码错误"
        self._html(302, "", headers=[("Location", "/")])

    def _logout(self):
        sid = self._cookie("xwpf_session")
        if sid in self.sessions:
            del self.sessions[sid]
        self._html(302, "", headers=[
            ("Location", "/"),
            ("Set-Cookie", "xwpf_session=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
        ])

    def log_message(self, fmt, *args):
        sys.stderr.write("[realm-web] %s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))


def run(host: str, port: int, conf_path: str):
    PanelHandler.conf_path = conf_path
    with socketserver.ThreadingTCPServer((host, port), PanelHandler) as httpd:
        httpd.last_error = ""
        print(f"realm-web-panel listening on http://{host}:{port}")
        httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="xwPF realm web panel")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--config", default="/etc/realm/manager.conf")
    args = parser.parse_args()
    run(args.host, args.port, args.config)
