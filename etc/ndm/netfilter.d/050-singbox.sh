#!/bin/sh
# Made with Gemini
export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin

POLICY_NAME="SingBox"
MARK_CACHE="/opt/etc/ndm/netfilter.d/singbox-mark"
PROXY_PORT="61219"
DNS_PORT="8053"
FWMARK_TPROXY="0x1"
TABLE_TPROXY="101"

log_msg() {
    logger -t "singbox-netfilter" "$1" 2>/dev/null
    echo "$1"
}

is_valid_mark() {
    printf '%s\n' "$1" | grep -qE '^0x[0-9a-fA-F]{7,8}/0xffffffff$'
}

resolve_policy_mark() {
    mark="$(/opt/bin/python3 - "$POLICY_NAME" << 'EOF'
import json
import sys
import urllib.request

target = sys.argv[1]
try:
    with urllib.request.urlopen("http://127.0.0.1:79/rci/show/ip/policy", timeout=3) as resp:
        data = json.load(resp)
except Exception:
    sys.exit(1)

items = data.values() if isinstance(data, dict) else (data if isinstance(data, list) else [])
for item in items:
    if isinstance(item, dict) and item.get("description") == target:
        raw = str(item.get("mark", "")).strip().lower()
        if raw.startswith("0x"):
            raw = raw[2:]
        if raw:
            print(f"0x{raw}/0xffffffff")
            sys.exit(0)

sys.exit(1)
EOF
)"
    if is_valid_mark "$mark"; then
        printf '%s\n' "$mark" > "${MARK_CACHE}.tmp" && mv "${MARK_CACHE}.tmp" "$MARK_CACHE"
        printf '%s\n' "$mark"
        return 0
    fi
    return 1
}

get_policy_mark() {
    if [ -f "$MARK_CACHE" ]; then
        cached="$(head -n 1 "$MARK_CACHE" 2>/dev/null | tr -d '\r\n ')"
        if is_valid_mark "$cached"; then
            printf '%s\n' "$cached"
            return 0
        fi
        rm -f "$MARK_CACHE"
    fi
    resolve_policy_mark
}

cleanup() {
    while iptables -w -t nat -D PREROUTING -j SINGBOX_TCP 2>/dev/null; do :; done
    iptables -w -t nat -F SINGBOX_TCP 2>/dev/null
    iptables -w -t nat -X SINGBOX_TCP 2>/dev/null

    while iptables -w -t mangle -D PREROUTING -j SINGBOX_UDP 2>/dev/null; do :; done
    iptables -w -t mangle -F SINGBOX_UDP 2>/dev/null
    iptables -w -t mangle -X SINGBOX_UDP 2>/dev/null

    while ip rule del fwmark "$FWMARK_TPROXY" table "$TABLE_TPROXY" 2>/dev/null; do :; done
    ip route flush table "$TABLE_TPROXY" 2>/dev/null
}

# Режим принудительного обновления кэша метки (вызывается из singkeen.sh)
if [ "${1:-}" = "--refresh-mark" ]; then
    rm -f "$MARK_CACHE"
    if mark="$(resolve_policy_mark)"; then
        log_msg "Метка политики '${POLICY_NAME}' обновлена: ${mark}"
        exit 0
    else
        log_msg "Ошибка: политика '${POLICY_NAME}' не найдена в RCI API." >&2
        exit 1
    fi
fi

[ "${type:-}" = "ip6tables" ] && exit 0
[ "${table:-}" != "mangle" ] && [ "${table:-}" != "nat" ] && exit 0

if [ -z "$(pidof sing-box)" ]; then
    cleanup
    exit 0
fi

POLICY_MARK="$(get_policy_mark)"
if [ -z "$POLICY_MARK" ]; then
    log_msg "Ошибка: не удалось определить валидную метку политики '${POLICY_NAME}'." >&2
    exit 1
fi

sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=300 >/dev/null 2>&1
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=60 >/dev/null 2>&1

if [ "$table" = "nat" ]; then
    iptables -w -t nat -N SINGBOX_TCP 2>/dev/null || iptables -w -t nat -F SINGBOX_TCP

    # Перехват DNS до исключений приватных подсетей (чтобы ловить запросы к 192.168.x.1:53)
    iptables -w -t nat -A SINGBOX_TCP -p udp --dport 53 -m connmark --mark "$POLICY_MARK" -j REDIRECT --to-ports "$DNS_PORT"
    iptables -w -t nat -A SINGBOX_TCP -p tcp --dport 53 -m connmark --mark "$POLICY_MARK" -j REDIRECT --to-ports "$DNS_PORT"

    # Исключение локальных и служебных сетей
    iptables -w -t nat -A SINGBOX_TCP -d 127.0.0.0/8 -j RETURN
    iptables -w -t nat -A SINGBOX_TCP -d 10.0.0.0/8 -j RETURN
    iptables -w -t nat -A SINGBOX_TCP -d 172.16.0.0/12 -j RETURN
    iptables -w -t nat -A SINGBOX_TCP -d 192.168.0.0/16 -j RETURN
    iptables -w -t nat -A SINGBOX_TCP -d 169.254.0.0/16 -j RETURN
    iptables -w -t nat -A SINGBOX_TCP -d 224.0.0.0/3 -j RETURN

    # Перенаправление TCP-трафика в sing-box
    iptables -w -t nat -A SINGBOX_TCP -p tcp -m connmark --mark "$POLICY_MARK" -j REDIRECT --to-ports "$PROXY_PORT"

    iptables -w -t nat -C PREROUTING -j SINGBOX_TCP 2>/dev/null || \
        iptables -w -t nat -I PREROUTING 1 -j SINGBOX_TCP
fi

if [ "$table" = "mangle" ]; then
    while ip rule del fwmark "$FWMARK_TPROXY" table "$TABLE_TPROXY" 2>/dev/null; do :; done
    ip rule add fwmark "$FWMARK_TPROXY" table "$TABLE_TPROXY"
    ip route replace local 0.0.0.0/0 dev lo table "$TABLE_TPROXY"

    iptables -w -t mangle -N SINGBOX_UDP 2>/dev/null || iptables -w -t mangle -F SINGBOX_UDP

    # Исключение локальных и служебных сетей
    iptables -w -t mangle -A SINGBOX_UDP -d 127.0.0.0/8 -j RETURN
    iptables -w -t mangle -A SINGBOX_UDP -d 10.0.0.0/8 -j RETURN
    iptables -w -t mangle -A SINGBOX_UDP -d 172.16.0.0/12 -j RETURN
    iptables -w -t mangle -A SINGBOX_UDP -d 192.168.0.0/16 -j RETURN
    iptables -w -t mangle -A SINGBOX_UDP -d 169.254.0.0/16 -j RETURN
    iptables -w -t mangle -A SINGBOX_UDP -d 224.0.0.0/3 -j RETURN

    # Прозрачное перенаправление UDP (кроме DNS) в TPROXY
    iptables -w -t mangle -A SINGBOX_UDP -p udp ! --dport 53 -m connmark --mark "$POLICY_MARK" \
        -j TPROXY --on-port "$PROXY_PORT" --on-ip 0.0.0.0 --tproxy-mark "${FWMARK_TPROXY}/0xffffffff"

    # В mangle обязательно -A, чтобы цепочка шла ПОСЛЕ _NDM_HOTSPOT_PREROUTING_MANGL
    iptables -w -t mangle -C PREROUTING -j SINGBOX_UDP 2>/dev/null || \
        iptables -w -t mangle -A PREROUTING -j SINGBOX_UDP
fi