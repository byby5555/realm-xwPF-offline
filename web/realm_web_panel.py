#!/usr/bin/env python3
import argparse
import glob
import html
import json
import os
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlparse
import http.server
import socketserver

MANAGER_CONF = "/etc/realm/manager.conf"
RULES_DIR = "/etc/realm/rules"
DOG_CONFIG = "/etc/port-traffic-dog/config.json"


def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def read_kv_file(path):
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


def write_kv_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = []
    for k, v in data.items():
        sv = str(v).replace('"', '')
        lines.append(f'{k}="{sv}"')
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def parse_rule_file(path):
    d = read_kv_file(path)
    if "RULE_ID" not in d:
        m = re.search(r"rule-(\d+)\.conf$", path)
        if m:
            d["RULE_ID"] = m.group(1)
    return d


def list_rules():
    os.makedirs(RULES_DIR, exist_ok=True)
    rules = []
    for fp in sorted(glob.glob(os.path.join(RULES_DIR, "rule-*.conf")), key=lambda p: int(re.search(r"rule-(\d+)\.conf$", p).group(1)) if re.search(r"rule-(\d+)\.conf$", p) else 0):
        try:
            r = parse_rule_file(fp)
            r["__file"] = fp
            rules.append(r)
        except Exception:
            continue
    return rules


def next_rule_id():
    ids = []
    for r in list_rules():
        try:
            ids.append(int(r.get("RULE_ID", "0")))
        except ValueError:
            pass
    return str(max(ids) + 1 if ids else 1)


def default_rule(rule_id, role):
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    base = {
        "RULE_ID": rule_id,
        "RULE_NAME": "中转" if role == "1" else "服务端",
        "RULE_ROLE": role,
        "SECURITY_LEVEL": "off",
        "LISTEN_PORT": "",
        "LISTEN_IP": "::",
        "THROUGH_IP": "::",
        "REMOTE_HOST": "",
        "REMOTE_PORT": "",
        "FORWARD_TARGET": "",
        "TLS_SERVER_NAME": "",
        "TLS_CERT_PATH": "",
        "TLS_KEY_PATH": "",
        "WS_PATH": "",
        "WS_HOST": "",
        "RULE_NOTE": "",
        "ENABLED": "true",
        "CREATED_TIME": now,
        "BALANCE_MODE": "off",
        "TARGET_STATES": "",
        "WEIGHTS": "",
        "FAILOVER_ENABLED": "false",
        "HEALTH_CHECK_INTERVAL": "4",
        "FAILURE_THRESHOLD": "2",
        "SUCCESS_THRESHOLD": "2",
        "CONNECTION_TIMEOUT": "3",
        "RECOVERY_COOLDOWN": "120",
        "MPTCP_MODE": "off",
        "PROXY_MODE": "off",
    }
    if role == "2":
        base.pop("LISTEN_IP", None)
        base.pop("THROUGH_IP", None)
        base.pop("REMOTE_HOST", None)
        base.pop("REMOTE_PORT", None)
    return base


def save_rule(rule):
    os.makedirs(RULES_DIR, exist_ok=True)
    rid = str(rule.get("RULE_ID", "")).strip()
    if not rid.isdigit():
        raise ValueError("invalid rule id")
    path = os.path.join(RULES_DIR, f"rule-{rid}.conf")
    keys_order = [
        "RULE_ID", "RULE_NAME", "RULE_ROLE", "SECURITY_LEVEL",
        "LISTEN_PORT", "LISTEN_IP", "THROUGH_IP", "REMOTE_HOST", "REMOTE_PORT", "FORWARD_TARGET",
        "TLS_SERVER_NAME", "TLS_CERT_PATH", "TLS_KEY_PATH", "WS_PATH", "WS_HOST",
        "RULE_NOTE", "ENABLED", "CREATED_TIME",
        "BALANCE_MODE", "TARGET_STATES", "WEIGHTS",
        "FAILOVER_ENABLED", "HEALTH_CHECK_INTERVAL", "FAILURE_THRESHOLD", "SUCCESS_THRESHOLD",
        "CONNECTION_TIMEOUT", "RECOVERY_COOLDOWN",
        "MPTCP_MODE", "PROXY_MODE",
    ]
    lines = []
    for k in keys_order:
        if k in rule:
            v = str(rule[k]).replace('"', '')
            if k == "RULE_ID":
                lines.append(f"{k}={v}")
            else:
                lines.append(f'{k}="{v}"')
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def regenerate_and_restart_realm():
    run_cmd("bash /usr/local/bin/xwPF.sh --generate-config-only >/dev/null 2>&1")
    run_cmd("bash /usr/local/bin/xwPF.sh --restart-service >/dev/null 2>&1")


def ensure_dog_config():
    if os.path.exists(DOG_CONFIG):
        return
    os.makedirs(os.path.dirname(DOG_CONFIG), exist_ok=True)
    data = {
        "global": {"billing_mode": "double"},
        "ports": {},
        "nftables": {"table_name": "port_traffic_monitor", "family": "inet"},
    }
    with open(DOG_CONFIG, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def read_dog_config():
    ensure_dog_config()
    with open(DOG_CONFIG, "r", encoding="utf-8") as f:
        return json.load(f)


def write_dog_config(data):
    os.makedirs(os.path.dirname(DOG_CONFIG), exist_ok=True)
    with open(DOG_CONFIG, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class Handler(http.server.BaseHTTPRequestHandler):
    sessions = {}

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/healthz":
            self._text(200, "ok")
            return
        if p.path == "/logout":
            self._logout()
            return
        if p.path == "/":
            self._home(p)
            return
        self._text(404, "Not Found")

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/login":
            self._login()
            return
        if not self._authed():
            self._redirect("/")
            return
        try:
            if p.path == "/rule/new":
                self._rule_new()
            elif p.path == "/rule/save":
                self._rule_save()
            elif p.path == "/rule/delete":
                self._rule_delete()
            elif p.path == "/rule/toggle":
                self._rule_toggle()
            elif p.path == "/realm/restart":
                regenerate_and_restart_realm(); self._redirect("/?msg=服务已重启")
            elif p.path == "/lb/set":
                self._lb_set()
            elif p.path == "/dog/add":
                self._dog_add()
            elif p.path == "/dog/remove":
                self._dog_remove()
            elif p.path == "/dog/update":
                self._dog_update()
            else:
                self._text(404, "Not Found")
        except Exception as e:
            self._redirect(f"/?err={html.escape(str(e))}")

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        return self.rfile.read(n).decode("utf-8", errors="ignore")

    def _form(self):
        return {k: v[0] for k, v in parse_qs(self._body()).items()}

    def _cookie(self, k):
        raw = self.headers.get("Cookie", "")
        for kv in raw.split(";"):
            kv = kv.strip()
            if "=" not in kv:
                continue
            a, b = kv.split("=", 1)
            if a.strip() == k:
                return b.strip()
        return ""

    def _authed(self):
        sid = self._cookie("xwpf_session")
        return sid in self.sessions

    def _redirect(self, loc):
        self.send_response(302)
        self.send_header("Location", loc)
        self.end_headers()

    def _html(self, code, body, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _text(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _shell(self, title, content):
        return f"""<!doctype html><html lang='zh-CN'><head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{html.escape(title)}</title>
<style>
:root{{--bg:#0b1020;--card:rgba(255,255,255,.08);--line:rgba(255,255,255,.14);--text:#eaf0ff;--muted:#9fb0d8;--brand:#5b8cff;--ok:#24d07a;--warn:#f8c14f;--danger:#ff6b6b}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#2f3a80 0,transparent 50%),radial-gradient(1000px 500px at 0 100%,#1f7a6f 0,transparent 50%),var(--bg);color:var(--text);font-family:Inter,Segoe UI,Roboto,sans-serif;padding:20px}}
.wrap{{max-width:1200px;margin:0 auto}}.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;backdrop-filter:blur(8px);margin-bottom:14px}}
h1{{margin:0 0 8px}}h2{{margin:0 0 10px;font-size:18px}}.muted{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}}.item{{border:1px solid var(--line);border-radius:10px;padding:10px;background:rgba(255,255,255,.03)}}
input,select,textarea{{width:100%;background:rgba(255,255,255,.06);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px}}
label{{font-size:12px;color:var(--muted);display:block;margin:8px 0 4px}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid var(--line);padding:8px;font-size:13px;text-align:left;vertical-align:top}}
.btn{{border:0;border-radius:8px;padding:8px 12px;color:#fff;background:linear-gradient(135deg,var(--brand),#7a5cff);cursor:pointer}}
.btn2{{background:rgba(255,255,255,.08);border:1px solid var(--line)}}.danger{{background:#a33b4a}}.ok{{color:var(--ok)}}.warn{{color:var(--warn)}}.row{{display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
small{{color:var(--muted)}}details{{border:1px solid var(--line);border-radius:10px;padding:8px;margin:8px 0;background:rgba(255,255,255,.03)}}
</style></head><body><div class='wrap'>{content}</div></body></html>"""

    def _login(self):
        conf = read_kv_file(MANAGER_CONF)
        f = self._form()
        if f.get("username", "") == conf.get("WEB_USERNAME", "") and f.get("password", "") == conf.get("WEB_PASSWORD", ""):
            sid = secrets.token_urlsafe(24)
            self.sessions[sid] = time.time()
            self._html(302, "", headers=[("Location", "/"), ("Set-Cookie", f"xwpf_session={sid}; Path=/; HttpOnly; SameSite=Lax")])
            return
        self._redirect("/?err=账号或密码错误")

    def _logout(self):
        sid = self._cookie("xwpf_session")
        self.sessions.pop(sid, None)
        self._html(302, "", headers=[("Location", "/"), ("Set-Cookie", "xwpf_session=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")])

    def _rule_new(self):
        f = self._form()
        role = f.get("RULE_ROLE", "1")
        rid = next_rule_id()
        r = default_rule(rid, role)
        for k in r.keys():
            if k in f:
                r[k] = f[k].strip()
        if role == "1" and (not r.get("REMOTE_HOST") or not r.get("REMOTE_PORT")):
            raise ValueError("中转规则需要 REMOTE_HOST 和 REMOTE_PORT")
        if role == "2" and not r.get("FORWARD_TARGET"):
            raise ValueError("服务端规则需要 FORWARD_TARGET")
        save_rule(r)
        regenerate_and_restart_realm()
        self._redirect("/?msg=规则已新增")

    def _rule_save(self):
        f = self._form()
        rid = f.get("RULE_ID", "")
        path = os.path.join(RULES_DIR, f"rule-{rid}.conf")
        if not (rid.isdigit() and os.path.exists(path)):
            raise ValueError("规则不存在")
        r = parse_rule_file(path)
        for k in list(r.keys()):
            if k in f:
                r[k] = f[k].strip()
        save_rule(r)
        regenerate_and_restart_realm()
        self._redirect("/?msg=规则已更新")

    def _rule_delete(self):
        rid = self._form().get("RULE_ID", "")
        path = os.path.join(RULES_DIR, f"rule-{rid}.conf")
        if rid.isdigit() and os.path.exists(path):
            os.remove(path)
            regenerate_and_restart_realm()
        self._redirect("/?msg=规则已删除")

    def _rule_toggle(self):
        rid = self._form().get("RULE_ID", "")
        path = os.path.join(RULES_DIR, f"rule-{rid}.conf")
        if not (rid.isdigit() and os.path.exists(path)):
            raise ValueError("规则不存在")
        r = parse_rule_file(path)
        r["ENABLED"] = "false" if r.get("ENABLED", "true") == "true" else "true"
        save_rule(r)
        regenerate_and_restart_realm()
        self._redirect("/?msg=规则状态已切换")

    def _lb_set(self):
        f = self._form()
        port = f.get("LISTEN_PORT", "").strip()
        mode = f.get("BALANCE_MODE", "off").strip()
        weights = f.get("WEIGHTS", "").strip()
        if not port.isdigit():
            raise ValueError("端口无效")
        changed = 0
        for r in list_rules():
            if r.get("RULE_ROLE") == "1" and r.get("LISTEN_PORT") == port:
                r["BALANCE_MODE"] = mode
                r["WEIGHTS"] = weights
                save_rule(r)
                changed += 1
        if changed == 0:
            raise ValueError("未找到该端口的中转规则")
        regenerate_and_restart_realm()
        self._redirect("/?msg=负载均衡设置已应用")

    def _dog_add(self):
        f = self._form()
        port = f.get("port", "").strip()
        if not port.isdigit():
            raise ValueError("端口无效")
        cfg = read_dog_config()
        ports = cfg.setdefault("ports", {})
        if port not in ports:
            ports[port] = {
                "name": f"端口{port}",
                "enabled": True,
                "billing_mode": "double",
                "bandwidth_limit": {"enabled": False, "rate": "unlimited"},
                "quota": {"enabled": True, "monthly_limit": "unlimited"},
                "remark": "",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
            }
            write_dog_config(cfg)
        self._redirect("/?msg=流量狗端口已添加")

    def _dog_remove(self):
        port = self._form().get("port", "").strip()
        cfg = read_dog_config()
        cfg.setdefault("ports", {}).pop(port, None)
        write_dog_config(cfg)
        self._redirect("/?msg=流量狗端口已移除")

    def _dog_update(self):
        f = self._form()
        port = f.get("port", "").strip()
        cfg = read_dog_config()
        p = cfg.setdefault("ports", {}).setdefault(port, {
            "name": f"端口{port}", "enabled": True, "billing_mode": "double",
            "bandwidth_limit": {"enabled": False, "rate": "unlimited"},
            "quota": {"enabled": True, "monthly_limit": "unlimited"}, "remark": "",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
        })
        bw = f.get("bandwidth", "unlimited").strip() or "unlimited"
        quota = f.get("quota", "unlimited").strip() or "unlimited"
        p.setdefault("bandwidth_limit", {})["enabled"] = bw != "unlimited"
        p.setdefault("bandwidth_limit", {})["rate"] = bw
        p.setdefault("quota", {})["enabled"] = True
        p.setdefault("quota", {})["monthly_limit"] = quota
        p["remark"] = f.get("remark", "").strip()
        write_dog_config(cfg)
        self._redirect("/?msg=流量狗端口配置已更新")

    def _home(self, parsed):
        q = parse_qs(parsed.query)
        msg = html.escape(q.get("msg", [""])[0])
        err = html.escape(q.get("err", [""])[0])

        if not self._authed():
            login = f"""
            <div class='card' style='max-width:420px;margin:40px auto'>
              <h1>xwPF Web 控制台</h1><div class='muted'>可视化管理规则、负载均衡、流量狗端口</div>
              {f"<div class='warn'>{msg}</div>" if msg else ''}{f"<div class='warn' style='color:var(--danger)'>{err}</div>" if err else ''}
              <form method='post' action='/login'>
                <label>账号</label><input name='username' required>
                <label>密码</label><input type='password' name='password' required>
                <div class='row' style='margin-top:10px'><button class='btn' type='submit'>登录</button></div>
              </form>
            </div>
            """
            self._html(200, self._shell("xwPF 登录", login))
            return

        conf = read_kv_file(MANAGER_CONF)
        rules = list_rules()
        relay = [r for r in rules if r.get("RULE_ROLE") == "1"]
        exits = [r for r in rules if r.get("RULE_ROLE") == "2"]
        dog = read_dog_config()
        dog_ports = dog.get("ports", {})

        rows = []
        for r in rules:
            rid = html.escape(r.get("RULE_ID", ""))
            role = "中转" if r.get("RULE_ROLE") == "1" else "服务端"
            target = f"{r.get('REMOTE_HOST','')}:{r.get('REMOTE_PORT','')}" if r.get("RULE_ROLE") == "1" else r.get("FORWARD_TARGET", "")
            rows.append(f"""
            <tr>
              <td>#{rid}</td><td>{html.escape(role)}</td>
              <td>{html.escape(r.get('RULE_NAME',''))}</td>
              <td>{html.escape(r.get('LISTEN_IP','::'))}:{html.escape(r.get('LISTEN_PORT',''))}</td>
              <td>{html.escape(target)}</td>
              <td>{html.escape(r.get('BALANCE_MODE','off'))}</td>
              <td>{'启用' if r.get('ENABLED','true')=='true' else '禁用'}</td>
              <td>
                <div class='row'>
                  <form method='post' action='/rule/toggle'><input type='hidden' name='RULE_ID' value='{rid}'><button class='btn btn2' type='submit'>启停</button></form>
                  <form method='post' action='/rule/delete' onsubmit='return confirm("确认删除规则 {rid}?")'><input type='hidden' name='RULE_ID' value='{rid}'><button class='btn danger' type='submit'>删除</button></form>
                </div>
                <details><summary>编辑</summary>
                  <form method='post' action='/rule/save'>
                    <input type='hidden' name='RULE_ID' value='{rid}'>
                    <label>规则名</label><input name='RULE_NAME' value='{html.escape(r.get('RULE_NAME',''))}'>
                    <label>监听端口</label><input name='LISTEN_PORT' value='{html.escape(r.get('LISTEN_PORT',''))}'>
                    <label>监听IP(中转)</label><input name='LISTEN_IP' value='{html.escape(r.get('LISTEN_IP','::'))}'>
                    <label>中转出口IP</label><input name='THROUGH_IP' value='{html.escape(r.get('THROUGH_IP','::'))}'>
                    <label>目标主机(中转)</label><input name='REMOTE_HOST' value='{html.escape(r.get('REMOTE_HOST',''))}'>
                    <label>目标端口(中转)</label><input name='REMOTE_PORT' value='{html.escape(r.get('REMOTE_PORT',''))}'>
                    <label>FORWARD_TARGET(服务端)</label><input name='FORWARD_TARGET' value='{html.escape(r.get('FORWARD_TARGET',''))}'>
                    <label>安全模式</label><input name='SECURITY_LEVEL' value='{html.escape(r.get('SECURITY_LEVEL','off'))}'>
                    <label>备注</label><input name='RULE_NOTE' value='{html.escape(r.get('RULE_NOTE',''))}'>
                    <label>负载模式</label><select name='BALANCE_MODE'>
                      <option value='off' {'selected' if r.get('BALANCE_MODE')=='off' else ''}>off</option>
                      <option value='roundrobin' {'selected' if r.get('BALANCE_MODE')=='roundrobin' else ''}>roundrobin</option>
                      <option value='iphash' {'selected' if r.get('BALANCE_MODE')=='iphash' else ''}>iphash</option>
                    </select>
                    <label>权重(逗号分隔)</label><input name='WEIGHTS' value='{html.escape(r.get('WEIGHTS',''))}'>
                    <button class='btn' type='submit'>保存修改</button>
                  </form>
                </details>
              </td>
            </tr>
            """)

        lb_ports = sorted({r.get("LISTEN_PORT", "") for r in relay if r.get("LISTEN_PORT", "").isdigit()}, key=lambda x: int(x))
        lb_items = []
        for p in lb_ports:
            members = [r for r in relay if r.get("LISTEN_PORT") == p]
            mode = members[0].get("BALANCE_MODE", "off") if members else "off"
            weights = members[0].get("WEIGHTS", "") if members else ""
            lb_items.append(f"""
            <div class='item'>
              <div><b>监听端口 {html.escape(p)}</b>（{len(members)} 条规则）</div>
              <small>成员ID: {', '.join('#'+m.get('RULE_ID','') for m in members)}</small>
              <form method='post' action='/lb/set'>
                <input type='hidden' name='LISTEN_PORT' value='{html.escape(p)}'>
                <label>负载模式</label>
                <select name='BALANCE_MODE'>
                  <option value='off' {'selected' if mode=='off' else ''}>off</option>
                  <option value='roundrobin' {'selected' if mode=='roundrobin' else ''}>roundrobin</option>
                  <option value='iphash' {'selected' if mode=='iphash' else ''}>iphash</option>
                </select>
                <label>权重（按成员顺序，逗号分隔）</label>
                <input name='WEIGHTS' value='{html.escape(weights)}' placeholder='如: 5,3,2'>
                <div class='row'><button class='btn' type='submit'>应用到该端口组</button></div>
              </form>
            </div>
            """)

        dog_rows = []
        for p, cfg in sorted(dog_ports.items(), key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 999999):
            bw = cfg.get("bandwidth_limit", {}).get("rate", "unlimited")
            quota = cfg.get("quota", {}).get("monthly_limit", "unlimited")
            remark = cfg.get("remark", "")
            dog_rows.append(f"""
            <tr>
              <td>{html.escape(str(p))}</td>
              <td>{html.escape(str(bw))}</td>
              <td>{html.escape(str(quota))}</td>
              <td>{html.escape(str(remark))}</td>
              <td>
                <form method='post' action='/dog/update'>
                  <input type='hidden' name='port' value='{html.escape(str(p))}'>
                  <label>带宽</label><input name='bandwidth' value='{html.escape(str(bw))}' placeholder='如 100mbit 或 unlimited'>
                  <label>月配额</label><input name='quota' value='{html.escape(str(quota))}' placeholder='如 1TB 或 unlimited'>
                  <label>备注</label><input name='remark' value='{html.escape(str(remark))}'>
                  <div class='row'><button class='btn btn2' type='submit'>更新</button></div>
                </form>
                <form method='post' action='/dog/remove' onsubmit='return confirm("确认移除端口 {html.escape(str(p))}?")'>
                  <input type='hidden' name='port' value='{html.escape(str(p))}'>
                  <button class='btn danger' type='submit'>移除</button>
                </form>
              </td>
            </tr>
            """)

        content = f"""
        <div class='card'>
          <div class='row' style='justify-content:space-between'>
            <div>
              <h1>xwPF 全功能 Web 控制台</h1>
              <div class='muted'>按脚本逻辑设计：规则管理 / 负载均衡 / 流量狗端口管理（鼠标+少量参数输入）</div>
            </div>
            <div class='row'>
              <form method='post' action='/realm/restart'><button class='btn' type='submit'>重载并重启 Realm</button></form>
              <a href='/logout'><button class='btn btn2'>退出</button></a>
            </div>
          </div>
          {f"<div class='ok'>{msg}</div>" if msg else ""}
          {f"<div class='warn' style='color:var(--danger)'>{err}</div>" if err else ""}
          <div class='grid'>
            <div class='item'><div class='muted'>Web 地址</div><div><b>http://{html.escape(conf.get('WEB_BIND_IP','0.0.0.0'))}:{html.escape(conf.get('WEB_PORT','8080'))}</b></div></div>
            <div class='item'><div class='muted'>规则总数</div><div><b>{len(rules)}</b>（中转 {len(relay)} / 服务端 {len(exits)}）</div></div>
            <div class='item'><div class='muted'>流量狗端口</div><div><b>{len(dog_ports)}</b></div></div>
          </div>
        </div>

        <div class='card'>
          <h2>添加新规则（中转 / 服务端）</h2>
          <form method='post' action='/rule/new'>
            <div class='grid'>
              <div><label>规则角色</label><select name='RULE_ROLE'><option value='1'>1 中转</option><option value='2'>2 服务端</option></select></div>
              <div><label>规则名称</label><input name='RULE_NAME' placeholder='如 香港中转-A'></div>
              <div><label>监听端口</label><input name='LISTEN_PORT' placeholder='如 443'></div>
              <div><label>监听IP(中转)</label><input name='LISTEN_IP' value='::'></div>
              <div><label>THROUGH_IP(中转)</label><input name='THROUGH_IP' value='::'></div>
              <div><label>REMOTE_HOST(中转)</label><input name='REMOTE_HOST' placeholder='如 1.2.3.4'></div>
              <div><label>REMOTE_PORT(中转)</label><input name='REMOTE_PORT' placeholder='如 8443'></div>
              <div><label>FORWARD_TARGET(服务端)</label><input name='FORWARD_TARGET' placeholder='如 127.0.0.1:20000'></div>
              <div><label>SECURITY_LEVEL</label><input name='SECURITY_LEVEL' value='off'></div>
              <div><label>RULE_NOTE</label><input name='RULE_NOTE' placeholder='可选'></div>
            </div>
            <div class='row' style='margin-top:8px'><button class='btn' type='submit'>新增并生效</button></div>
          </form>
        </div>

        <div class='card'>
          <h2>规则列表（编辑 / 启停 / 删除）</h2>
          <table>
            <thead><tr><th>ID</th><th>角色</th><th>名称</th><th>监听</th><th>目标</th><th>负载</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>{''.join(rows) if rows else '<tr><td colspan="8" class="muted">暂无规则</td></tr>'}</tbody>
          </table>
        </div>

        <div class='card'>
          <h2>负载均衡管理（按监听端口组）</h2>
          <div class='grid'>{''.join(lb_items) if lb_items else '<div class="muted">暂无可配置的中转端口组</div>'}</div>
        </div>

        <div class='card'>
          <h2>端口流量狗（Web 配置）</h2>
          <div class='row muted'>
            说明：此处可在 Web 中管理端口、带宽、月配额与备注。保存后写入 <code>{DOG_CONFIG}</code>。
          </div>
          <form method='post' action='/dog/add' class='row'>
            <input name='port' placeholder='新增监控端口，例如 443' style='max-width:260px'>
            <button class='btn' type='submit'>添加流量狗端口</button>
          </form>
          <table>
            <thead><tr><th>端口</th><th>带宽限制</th><th>月配额</th><th>备注</th><th>操作</th></tr></thead>
            <tbody>{''.join(dog_rows) if dog_rows else '<tr><td colspan="5" class="muted">暂无流量狗端口</td></tr>'}</tbody>
          </table>
        </div>
        """
        self._html(200, self._shell("xwPF 全功能 Web 控制台", content))

    def log_message(self, fmt, *args):
        sys.stderr.write("[realm-web] %s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))


def run(host, port):
    with socketserver.ThreadingTCPServer((host, port), Handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--config", default=MANAGER_CONF)
    args = ap.parse_args()
    MANAGER_CONF = args.config
    run(args.host, args.port)
