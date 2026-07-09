# Active/Passive Failover (xwpf-failover)

This is **real primary/backup**, not load balancing:

- While primary is reachable → all new connections go to primary
- After N consecutive probe failures → switch to backup
- After primary recovers (and cooldown elapsed) → switch back

The proxy is a small Python 3 daemon (Python stdlib only, no third-party
deps) listening on a public port and forwarding each accepted connection
either to the primary or backup realm listener. A separate probe loop
TCP-connects to each backend every `interval_sec` seconds and tracks
failure / success streaks.

## Layout

```
   :443 (public)
        │
   ┌────▼────────────┐
   │ xwpf-failover  │       systemd: xwpf-failover.service
   │ /etc/xwpf/     │       binary:    /usr/local/bin/xwpf-failover
   │  failover.json │       config:    /etc/xwpf/failover.json
   └───┬────────┬───┘
   :10443     :10444
      │         │
   rule-A     rule-B (separate realm endpoints on loopback)
   remote=    remote=
    1.2.3.4    5.6.7.8
        :443        :443
```

The menu under `pf` → 转发配置管理 → 6. 负载均衡管理 → 4. 主动/被动主备
auto-generates both realm rules (A and B) and the `failover.json`, then
restarts `realm` and `xwpf-failover`.

## Configuration schema

`/etc/xwpf/failover.json`:

```json
[
  {
    "name": "tcp-443",
    "listen":  "0.0.0.0:443",
    "primary": "127.0.0.1:10443",
    "backups": ["127.0.0.1:10444"],
    "probe": {
      "interval_sec":      4,
      "timeout_sec":       3,
      "fail_threshold":    2,
      "success_threshold": 2,
      "cooldown_sec":      120
    }
  }
]
```

| Key | Default | Meaning |
|-----|---------|---------|
| `interval_sec`      | 4   | seconds between probes per backend |
| `timeout_sec`       | 3   | probe connect timeout |
| `fail_threshold`    | 2   | consecutive failures before marking primary as down |
| `success_threshold` | 2   | consecutive successes required before switching back |
| `cooldown_sec`      | 120 | minimum time between any switch (prevents flapping) |

## Failure semantics

The daemon **does NOT terminate existing connections** on a switch — only
new connections are routed to the active backend. Old connections on the
failed backend either continue or fail naturally.

This matches typical Linux/Unix `ip rule` semantics and avoids the
half-open-connection problem with active-active load balancers.

## Running

```sh
# install
cp cmd/xwpf-failover.py        /usr/local/bin/xwpf-failover
chmod +x /usr/local/bin/xwpf-failover
mkdir -p /etc/xwpf
cp cmd/xwpf-failover.service   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now xwpf-failover

# verify
journalctl -fu xwpf-failover     # look for "listening on" + state transitions
systemctl status xwpf-failover
```

## Why not just round-robin?

Realm upstream (`zhboner/realm`) only implements `off` / `roundrobin` /
`iphash`. None of these is true primary/backup; roundrobin distributes
even when primary is up, and iphash gives the same IP to the same backend
but still doesn't auto-failover on backend death.

This daemon sits in front of realm and does what realm itself cannot.

## Why Python 3 (not Go / not bash)?

Python 3 is a default part of Debian 12. Single-file, stdlib-only, ~250
LOC. `asyncio` handles thousands of concurrent TCP connections.
