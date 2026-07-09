#!/bin/bash
#
# Active/Passive failover helper library for xwPF
#
# Real primary/backup, separate from realm's LB modes.
# Backed by /usr/local/bin/xwpf-failover (Python, see cmd/).
#

# Filesystem layout
XWPF_FAILOVER_BIN="/usr/local/bin/xwpf-failover"
XWPF_FAILOVER_SERVICE="xwpf-failover"
XWPF_FAILOVER_UNIT="/etc/systemd/system/xwpf-failover.service"
XWPF_FAILOVER_CONF_DIR="/etc/xwpf"
XWPF_FAILOVER_CONF="${XWPF_FAILOVER_CONF_DIR}/failover.json"

# Loopback port range used by realm listeners backing each failover pool.
XWPF_FAILOVER_PORT_BASE=10443
XWPF_FAILOVER_PORT_LAST=11442

#
# File operations on /etc/xwpf/failover.json — done ENTIRELY in Python via a
# runner helper below. This avoids having to construct JSON inside bash.
#

failover_json_run() {
    # $1 is the python heredoc body
    XWPF_FAILOVER_CONF="${XWPF_FAILOVER_CONF}" python3 <<'PYEOF'
import json, os, sys, pathlib
p = os.environ["XWPF_FAILOVER_CONF"]
PYEOF
    # concatenate caller body after the imports/prelude
    bash -c "$1" <<< "# caller body follows"
}

# The above function is too clever. Let me use a different approach: a python
# caller function that imports the rest from a python-side helper module.

failover_py_helper() {
    # Generate a temporary Python helper script and run it.
    # Body is passed verbatim to python.
    local body="$1"
    python3 -c "$body"
}

# === Validate addr ===
# Allow "host:port" or bare "port".
failover_validate_addr() {
    local addr="$1"
    if [[ "$addr" =~ ^([0-9]+)$ ]]; then
        is_valid_port "$addr" || return 1
        return 0
    fi
    if [[ "$addr" =~ ^([^:]+):([0-9]+)$ ]]; then
        is_valid_port "${BASH_REMATCH[2]}" || return 1
        return 0
    fi
    return 1
}

# === Normalize listen addr ===
# Bare port -> 0.0.0.0:port
failover_normalize_listen() {
    local addr="$1"
    if [[ "$addr" =~ ^([0-9]+)$ ]]; then
        echo "0.0.0.0:$addr"
    else
        echo "$addr"
    fi
}

# === Used ports (filesystem) ===
# Reads LISTEN_PORT= directly from each rule-N.conf (avoids read_rule_file
# dependency on lib/rules.sh). Prints one port per line.
failover_used_ports_from_rules() {
    local f p
    if [ -d "${RULES_DIR:-/etc/realm/rules}" ]; then
        for f in "${RULES_DIR}"/rule-*.conf; do
            [ -f "$f" ] || continue
            # Strip trailing CR + filter only LISTEN_PORT="N" lines
            p=$(grep -E '^LISTEN_PORT="([0-9]+)"' "$f" 2>/dev/null \
                | sed -E 's/.*"([0-9]+)".*/\1/' | head -1)
            if [[ "$p" =~ ^[0-9]+$ ]]; then
                echo "$p"
            fi
        done
    fi
}

# === Used ports (from /etc/xwpf/failover.json) ===
# Extracts loopback ports previously committed to the failover config so that
# adding a new pool never reuses one. Prints one port per line.
failover_used_ports_from_failover_json() {
    XWPF_FAILOVER_CONF_PATH="${XWPF_FAILOVER_CONF}" python3 <<'PYEOF'
import json, os, re, sys
path = os.environ.get("XWPF_FAILOVER_CONF_PATH", "")
try:
    with open(path) as f:
        txt = f.read()
    # Only consider loopback addresses — non-loopback (public) addresses
    # don't collide with our internal 127.0.0.1 listeners.
    for m in re.finditer(r'127\.0\.0\.1:(\d+)', txt):
        print(m.group(1))
except Exception:
    pass
PYEOF
}

# === Combined used ports ===
failover_used_ports() {
    {
        failover_used_ports_from_rules
        failover_used_ports_from_failover_json
    } | sort -un
}

# === Allocate one free port ===
# Args are ports already allocated WITHIN THIS SESSION that must be excluded
# (the regex-based rules-dir scan can't see ports we haven't written yet).
failover_alloc_port() {
    local reserved=("$@")
    local used
    used="$(failover_used_ports)"
    local p r skip
    for ((p = XWPF_FAILOVER_PORT_BASE; p <= XWPF_FAILOVER_PORT_LAST; p++)); do
        skip=0
        if printf '%s\n' "$used" | grep -qx "$p"; then
            skip=1
        else
            for r in "${reserved[@]}"; do
                if [ "$r" = "$p" ]; then
                    skip=1
                    break
                fi
            done
        fi
        if [ $skip -eq 0 ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# === Create a server-side rule-N.conf (loopback listener) ===
# args: rule_id  listen_port  remote_addr  tls_sni
failover_create_server_rule() {
    local rule_id="$1" listen_port="$2" remote_addr="$3" tls_sni="${4:-}"
    local r_host r_port
    if [[ "$remote_addr" =~ ^([^:]+):([0-9]+)$ ]]; then
        r_host="${BASH_REMATCH[1]}"
        r_port="${BASH_REMATCH[2]}"
    else
        r_host="$remote_addr"
        r_port="443"
    fi
    local outfile="${RULES_DIR}/rule-${rule_id}.conf"
    cat > "$outfile" <<EOF
RULE_ID="${rule_id}"
RULE_NAME="failover-backend-${rule_id}"
RULE_ROLE="2"
SECURITY_LEVEL="off"
LISTEN_PORT="${listen_port}"
LISTEN_IP="127.0.0.1"
THROUGH_IP="127.0.0.1"
FORWARD_TARGET="${r_host}:${r_port}"
TLS_SERVER_NAME="${tls_sni}"
TLS_CERT_PATH=""
TLS_KEY_PATH=""
WS_PATH=""
WS_HOST=""
RULE_NOTE="xwPF failover pool backend"
ENABLED="true"
CREATED_TIME="$(date '+%Y-%m-%d %H:%M:%S')"
BALANCE_MODE="off"
TARGET_STATES=""
WEIGHTS=""
FAILOVER_ENABLED="false"
HEALTH_CHECK_INTERVAL="4"
FAILURE_THRESHOLD="2"
SUCCESS_THRESHOLD="2"
CONNECTION_TIMEOUT="3"
RECOVERY_COOLDOWN="120"
MPTCP_MODE="off"
PROXY_MODE="off"
EOF
}

# === Helper: write pool into failover.json via python helper script ===
# This is invoked from failover_pool_create and works without heredoc weirdness
# by using env vars.
failover_pool_write_json() {
    # Args:
    # $1 = name  $2 = listen  $3 = primary_port  $4 = primary_rule_id
    # $5 = backup_ports_csv  $6 = backups_csv  $7 = backup_rules_csv
    local name="$1" listen="$2" primary_port="$3" primary_rule_id="$4"
    local backup_ports_csv="$5" backups_csv="$6" backup_rules_csv="$7"
    mkdir -p "${XWPF_FAILOVER_CONF_DIR}"
    primary_args=(--name "$name" --listen "$listen" --primary "127.0.0.1:$primary_port")
    # Build backup args + rule_ids list (passed in via --primary/--backup as values)
    backup_args=()
    IFS=',' read -ra bps <<< "$backup_ports_csv"
    IFS=',' read -ra bas <<< "$backups_csv"
    IFS=',' read -ra brs <<< "$backup_rules_csv"
    local i=0
    for bp in "${bps[@]}"; do
        if [ "${#brs[@]}" -gt "$i" ]; then
            backup_args+=(--backup "127.0.0.1:$bp|${bas[$i]}|${brs[$i]}")
        else
            backup_args+=(--backup "127.0.0.1:$bp|${bas[$i]}")
        fi
        i=$((i+1))
    done

    XWPF_FAILOVER_RULES_DIR="${RULES_DIR:-/etc/realm/rules}" \
    python3 - "$XWPF_FAILOVER_CONF" --primary-rule "$primary_rule_id" "${primary_args[@]}" "${backup_args[@]}" <<'PY'
import json, os, sys
conf = sys.argv[1]
args = {a:v for a,v in zip(sys.argv[2::2], sys.argv[3::2])}
try:
    with open(conf) as f:
        cur = json.load(f)
    if not isinstance(cur, list):
        cur = []
except Exception:
    cur = []
backups_raw = [v for k,v in zip(sys.argv[2::2], sys.argv[3::2]) if k == "--backup"]
backups = []
backup_rule_ids = []
for b in backups_raw:
    parts = b.rsplit("|", 1) if "|" in b else [b, ""]
    if len(parts) == 2 and parts[1].isdigit():
        backups.append(parts[0])
        backup_rule_ids.append(int(parts[1]))
    else:
        backups.append(b)
        backup_rule_ids.append(None)
primary_rule_id = int(args.get("--primary-rule", "0")) if args.get("--primary-rule","").isdigit() else None
pool = {
    "name": args.get("--name",""),
    "listen": args.get("--listen",""),
    "primary": args.get("--primary",""),
    "primary_rule_id": primary_rule_id,
    "backups": backups,
    "backup_rule_ids": backup_rule_ids,
    "probe": {
        "interval_sec": 4,
        "timeout_sec": 3,
        "fail_threshold": 2,
        "success_threshold": 2,
        "cooldown_sec": 120,
    },
}
cur.append(pool)
with open(conf,"w") as f:
    json.dump(cur, f, indent=2, ensure_ascii=False)
print(json.dumps(pool, ensure_ascii=False))
PY
}

# === Create a failover pool (interactive caller) ===
failover_pool_create() {
    local name="$1" public_listen="$2" primary_addr="$3" backup_csv="$4"

    failover_validate_addr "$public_listen" || {
        echo -e "${RED}公开监听地址不合法: $public_listen${NC}"
        return 1
    }
    public_listen="$(failover_normalize_listen "$public_listen")"

    failover_validate_addr "$primary_addr" || {
        echo -e "${RED}主后端不合法: $primary_addr${NC}"
        return 1
    }

    local backups=()
    if [ -n "$backup_csv" ]; then
        IFS=',' read -ra backups <<< "$backup_csv"
        for b in "${backups[@]}"; do
            failover_validate_addr "$b" || {
                echo -e "${RED}备后端不合法: $b${NC}"
                return 1
            }
        done
    fi

    # Allocate ports and rule IDs together by INTERLEAVING the writes:
    # each rule file must exist on disk before generate_rule_id() is called
    # for the next one, so we can't pre-allocate everything in batch.
    local primary_rule_id
    primary_rule_id="$(generate_rule_id)"
    local primary_internal_port
    primary_internal_port="$(failover_alloc_port)"
    if [ -z "$primary_internal_port" ]; then
        echo -e "${RED}无可用 loopback 端口 - 请调整 XWPF_FAILOVER_PORT_BASE/LAST${NC}"
        return 1
    fi
    failover_create_server_rule "${primary_rule_id}" "${primary_internal_port}" "${primary_addr}" ""

    local backup_rule_ids=()
    local backup_internal_ports=()
    local bp rid j
    for ((j=0; j<${#backups[@]}; j++)); do
        # Pass primary + any already-allocated+written backup ports as
        # in-session exclusions.
        local -a reservations=("$primary_internal_port")
        if [ ${#backup_internal_ports[@]} -gt 0 ]; then
            reservations+=("${backup_internal_ports[@]}")
        fi
        bp="$(failover_alloc_port "${reservations[@]}")"
        if [ -z "$bp" ]; then
            echo -e "${RED}分配端口耗尽${NC}"
            return 1
        fi
        # Now that the previous rule file (primary, or earlier backup) is on
        # disk, generate_rule_id() returns the next sequential ID.
        rid="$(generate_rule_id)"
        failover_create_server_rule "$rid" "$bp" "${backups[$j]}" ""
        backup_internal_ports+=("$bp")
        backup_rule_ids+=("$rid")
    done

    # Build CSV strings for python helper
    local bps_csv bas_csv brs_csv
    bps_csv="$(IFS=,; echo "${backup_internal_ports[*]}")"
    bas_csv="$(IFS=,; echo "${backups[*]}")"
    brs_csv="$(IFS=,; echo "${backup_rule_ids[*]}")"

    failover_pool_write_json "${name}" "${public_listen}" "${primary_internal_port}" "${primary_rule_id}" "${bps_csv}" "${bas_csv}" "${brs_csv}"

    echo -e "${GREEN}已创建主备池 '${name}'${NC}"
    echo -e "  公开监听: ${YELLOW}${public_listen}${NC}"
    echo -e "  ${BLUE}主${NC}  → ${primary_addr}  (loopback :${primary_internal_port}, rule-${primary_rule_id}.conf)"
    local i=1
    for b in "${backups[@]}"; do
        echo -e "  ${BLUE}备${i}${NC}  → ${b}  (loopback :${backup_internal_ports[$((i-1))]}, rule-${backup_rule_ids[$((i-1))]}.conf)"
        i=$((i+1))
    done
    echo
    echo -e "${YELLOW}下一步: 在 [3] 启停守护 中启动 xwpf-failover 并重启 realm${NC}"
}

# === List pools ===
failover_pool_list() {
    if [ ! -f "${XWPF_FAILOVER_CONF}" ]; then
        echo "  (暂无主备池)"
        return 0
    fi
    XWPF_FAILOVER_CONF_PATH="${XWPF_FAILOVER_CONF}" python3 <<'PYEOF'
import json, os
try:
    with open(os.environ["XWPF_FAILOVER_CONF_PATH"]) as f:
        pools = json.load(f) or []
except Exception:
    pools = []
if not pools:
    print("  (暂无主备池)")
else:
    for i,p in enumerate(pools,1):
        print(f"  [{i}] {p.get('name','?')}")
        print(f"      listen  : {p.get('listen','?')}")
        print(f"      primary : {p.get('primary','?')}")
        for j,b in enumerate(p.get('backups',[]) or [],1):
            print(f"      backup{j}: {b}")
        pr = p.get('probe') or {}
        print(f"      probe   : iv={pr.get('interval_sec')}s, fail>={pr.get('fail_threshold')}, succ>={pr.get('success_threshold')}, cd={pr.get('cooldown_sec')}s")
PYEOF
}

# === Delete pool by index ===
failover_pool_delete() {
    local idx="$1"
    if [ ! -f "${XWPF_FAILOVER_CONF}" ]; then
        echo "无配置"
        return 1
    fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}索引必须是数字${NC}"
        return 1
    fi
    XWPF_FAILOVER_CONF_PATH="${XWPF_FAILOVER_CONF}" \
    XWPF_FAILOVER_RULES_DIR="${RULES_DIR:-/etc/realm/rules}" \
    XWPF_FAILOVER_IDX="$idx" python3 <<'PYEOF'
import json, os, sys
path = os.environ.get("XWPF_FAILOVER_CONF_PATH", "")
rules_dir = os.environ.get("XWPF_FAILOVER_RULES_DIR", "/etc/realm/rules")
idx_s = os.environ.get("XWPF_FAILOVER_IDX", "")
try:
    with open(path) as f:
        pools = json.load(f) or []
except Exception as e:
    print(f"读配置失败: {e}")
    sys.exit(1)
if not pools:
    print("无配置")
    sys.exit(1)
idx = int(idx_s) - 1
if idx < 0 or idx >= len(pools):
    print(f"索引超出范围 (1..{len(pools)})")
    sys.exit(1)
removed = pools.pop(idx)
deleted_files = []
for rid_key in ("primary_rule_id",):
    rid = removed.get(rid_key)
    if isinstance(rid, int):
        f = os.path.join(rules_dir, f"rule-{rid}.conf")
        if os.path.exists(f):
            os.remove(f)
            deleted_files.append(os.path.basename(f))
for rid in (removed.get("backup_rule_ids") or []):
    if isinstance(rid, int):
        f = os.path.join(rules_dir, f"rule-{rid}.conf")
        if os.path.exists(f):
            os.remove(f)
            deleted_files.append(os.path.basename(f))
with open(path, "w") as f:
    json.dump(pools, f, indent=2, ensure_ascii=False)
print(f"已删除池 #{int(idx_s)}: {removed.get('name','?')}")
if deleted_files:
    print(f"  同时清理: {', '.join(deleted_files)}")
print(f"剩余 {len(pools)} 个池")
PYEOF
}

# === Delete ALL pools ===
failover_pool_delete_all() {
    rm -f "${XWPF_FAILOVER_CONF}"
    echo -e "${GREEN}已清空${XWPF_FAILOVER_CONF}${NC}"
}

# === Install/uninstall daemon ===
failover_install_check() {
    if [ ! -x "${XWPF_FAILOVER_BIN}" ] || [ ! -f "${XWPF_FAILOVER_UNIT}" ]; then
        echo -e "${YELLOW}未检测到 xwpf-failover, 正在安装...${NC}"
        failover_install_files
    fi
}

failover_install_files() {
    mkdir -p "${XWPF_FAILOVER_CONF_DIR}"
    local src_dir
    src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/cmd"
    if [ -f "${src_dir}/xwpf-failover.py" ]; then
        install -m 0755 "${src_dir}/xwpf-failover.py" "${XWPF_FAILOVER_BIN}"
    else
        echo -e "${RED}未找到源文件: ${src_dir}/xwpf-failover.py${NC}"
        return 1
    fi
    if [ -f "${src_dir}/xwpf-failover.service" ]; then
        install -m 0644 "${src_dir}/xwpf-failover.service" "${XWPF_FAILOVER_UNIT}"
    fi
    systemctl daemon-reload
    echo -e "${GREEN}已安装${NC}"
}

failover_service_enable() {
    systemctl enable --now "${XWPF_FAILOVER_SERVICE}" 2>/dev/null         || (systemctl daemon-reload && systemctl enable --now "${XWPF_FAILOVER_SERVICE}")
}

failover_service_restart() {
    systemctl restart "${XWPF_FAILOVER_SERVICE}"
}

failover_service_stop() {
    systemctl stop "${XWPF_FAILOVER_SERVICE}" 2>/dev/null || true
    systemctl disable "${XWPF_FAILOVER_SERVICE}" 2>/dev/null || true
}

failover_status_header() {
    echo -e "${BLUE}=== xwpf-failover ===${NC}"
    if systemctl is-active "${XWPF_FAILOVER_SERVICE}" >/dev/null 2>&1; then
        echo -e "  ${GREEN}● ACTIVE${NC}"
    else
        echo -e "  ${RED}● INACTIVE${NC}"
    fi
}

failover_log_follow() {
    journalctl -fu "${XWPF_FAILOVER_SERVICE}"
}

failover_log_tail() {
    journalctl -u "${XWPF_FAILOVER_SERVICE}" -n 50 --no-pager
}
