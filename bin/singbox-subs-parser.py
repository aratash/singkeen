#!/usr/bin/python3
from argparse import ArgumentParser, ArgumentTypeError
from urllib.parse import urlsplit, parse_qs, unquote
from urllib.request import urlopen, Request
from base64 import urlsafe_b64decode
from json import dumps, loads, JSONDecodeError
from platform import uname
from hashlib import sha256
from re import Pattern, compile as re_compile, error as re_error
import os
import sys

# Программа # Made with Gemini
app_name = "sing-box-subs-parser"
app_version = "v2.4"

# Поддерживаемые парсером proxy-протоколы (нормализованные имена sing-box 1.14.4)
SUPPORTED_PROXY_PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria2",
    "hysteria",
    "tuic",
    "anytls",
    "naive",
    "socks",
    "http",
)

# Нормализация URI-схем в имена протоколов sing-box
SCHEME_TO_PROTOCOL = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "shadowsocks",
    "shadowsocks": "shadowsocks",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "hysteria": "hysteria",
    "hy": "hysteria",
    "tuic": "tuic",
    "anytls": "anytls",
    "naive+https": "naive",
    "naive+quic": "naive",
    "socks": "socks",
    "socks5": "socks",
    "socks4": "socks",
    "socks4a": "socks",
    "http": "http",
    "https": "http",
}

# Допустимые методы шифрования Shadowsocks и VMess по спецификации sing-box
SHADOWSOCKS_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
}
VMESS_SECURITIES = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr"}
TUIC_CONGESTION_CONTROLS = {"cubic", "new_reno", "bbr"}
NAIVE_CONGESTION_CONTROLS = {"bbr", "bbr2", "cubic", "reno"}

# Обязательные значения скорости по умолчанию для Hysteria v1 (если отсутствуют в URI)
DEFAULT_HYSTERIA_UP_MBPS = 50
DEFAULT_HYSTERIA_DOWN_MBPS = 100

# ID устройства
# Нужно для идентификации устройства на сервисах подписок. Можно указать свои значения
_sys_info = uname()
device_os = f"{_sys_info.system}/{_sys_info.release}/{_sys_info.version}"
node = _sys_info.node
hwid = sha256(device_os.encode("utf-8")).hexdigest()

# Токенизатор JSONC / JSON5:
# 1: Строки JSON | 2: Комментарии (//, #, /* */) | 3: Скобки и разделители | 4: Примитивы
TOKEN_RE = re_compile(
    r'("(?:\\.|[^"\\])*")'
    r'|(//[^\r\n]*|#[^\r\n]*|/\*[\s\S]*?\*/)'
    r'|([\{\}\[\]:,])'
    r'|([^\s\{\}\[\]:,"/#]+)'
)

# Настройки балансировщиков (пересоздаются при каждой интеграции)
default_balancer = {
    "type": "selector",
    "tag": "balancer",
    "outbounds": [],
    "default": "auto",
    "interrupt_exist_connections": False,
}

auto_balancer = {
    "type": "urltest",
    "tag": "auto",
    "outbounds": [],
    # "url": "https://cp.cloudflare.com/generate_204",
    "url": "https://www.gstatic.com/generate_204",
    # "url": "https://www.youtube.com/generate_204",
    "interval": "10m",
    "tolerance": 80,
    "idle_timeout": "10m",
    "interrupt_exist_connections": False,
}

# === Функции обработки подписок и прокси-конфигураций ===

def parse_subscription(url: str) -> list[str]:
    """
    Делает запрос по указанной ссылке и получает в ответ url-конфиги.
    Если ответ закодирован в base64, сначала декодирует его.
    """
    print(f"[I] Парсинг подписки: {url}")
    try:
        req = Request(
            url,
            headers={
                "User-Agent": f"{app_name}/{app_version}",
                "Accept": "*/*",
                "x-hwid": hwid,
                "x-device-os": device_os,
                "x-app-version": f"{app_name}/{app_version}",
                "x-client-name": node,
            },
        )
        with urlopen(req, timeout=15) as resp:
            response = resp.read().decode("UTF-8")
    except Exception as e:
        print(f"[E] Ошибка запроса подписки: {e}")
        return []
        
    if "://" in response:
        return response.splitlines()

    try:
        return _decode_b64(response).splitlines()
    except (ValueError, UnicodeDecodeError) as e:
        print(f"[W] Ошибка декодирования Base64 ({e}), обработка ответа как plain-text")
        return response.splitlines()


def _decode_b64(data: str) -> str:
    """Декодирует стандартную или URL-safe строку Base64 с автоматическим padding."""
    cleaned = "".join(data.split())
    padded = cleaned + "=" * (-len(cleaned) % 4)
    return urlsafe_b64decode(padded).decode("UTF-8")


def _parse_mbps(val: str | None) -> int | None:
    """Извлекает целое положительное значение скорости в Mbps из строки URI."""
    if not val:
        return None
    cleaned = str(val).strip().lower().removesuffix("mbps").removesuffix("m").strip()
    if cleaned.isdigit() and int(cleaned) > 0:
        return int(cleaned)
    return None


def _append_port_ranges(raw_ports: str, target: list[str]) -> None:
    """Парсит строку портов/диапазонов (вида '443,20000-30000') и добавляет их в список sing-box."""
    for item in raw_ports.split(","):
        item = item.strip()
        if "-" in item:
            p1, p2 = item.split("-", 1)
            if p1.isdigit() and p2.isdigit():
                hop_range = f"{p1}:{p2}"
                if hop_range not in target:
                    target.append(hop_range)
        elif item.isdigit():
            hop_range = f"{item}:{item}"
            if hop_range not in target:
                target.append(hop_range)


def parse_host_and_ports(url_split, parse_url: dict, default_port: int = 443) -> tuple[str, int, list[str]]:
    """
    Безопасно извлекает хост, основной порт и диапазоны портов (port hopping).
    """
    hostname = url_split.hostname or ""
    hostport = url_split.netloc.rsplit("@", 1)[-1]

    port_str = ""
    if "]:" in hostport:
        port_str = hostport.rsplit("]:", 1)[1]
    elif ":" in hostport and not hostport.endswith("]"):
        port_str = hostport.rsplit(":", 1)[1]

    port = default_port
    server_ports = []

    if port_str:
        if "-" in port_str or "," in port_str:
            first_part = port_str.split(",")[0].split("-")[0]
            if first_part.isdigit():
                port = int(first_part)
            _append_port_ranges(port_str, server_ports)
        elif port_str.isdigit():
            port = int(port_str)

    for key in ("mport", "ports"):
        if key in parse_url and parse_url[key][0]:
            _append_port_ranges(parse_url[key][0], server_ports)

    return hostname, port, server_ports


def parse_headers(raw_headers: str) -> dict[str, str]:
    """Парсит кастомные заголовки из query-параметра headers."""
    result = {}
    for item in raw_headers.split(","):
        if "|" in item:
            k, v = item.split("|", 1)
            result[k.strip()] = v.strip()
        elif ":" in item:
            k, v = item.split(":", 1)
            result[k.strip()] = v.strip()
    return result


def parse_bool(val: str) -> bool:
    """Преобразует строковый параметр URI в логическое значение."""
    return str(val).strip().lower() in ("1", "true", "yes")

def _extract_userinfo_password(url_split) -> str:
    """Безопасно извлекает пароль из userinfo (поддерживает 'pass', 'user:pass', ':pass' и 'pass:')."""
    user = unquote(url_split.username) if url_split.username else ""
    if url_split.password is not None:
        return f"{user}:{unquote(url_split.password)}"
    return user

def build_tls(
    parse_url: dict,
    hostname: str,
    allow_utls: bool = True,
    default_alpn: list[str] | None = None,
    default_security: str = "none",
    force_tls: bool = False,
) -> dict | None:
    """
    Формирует блок TLS / Reality в соответствии со спецификацией sing-box.
    Возвращает {} если TLS отключён, dict с настройками TLS или None при неподдерживаемом security.
    """
    raw_sec = parse_url.get("security", [default_security])[0].strip().lower()
    security = raw_sec if raw_sec else default_security

    if force_tls:
        if security in ("", "none"):
            security = "tls"
        elif security != "tls":
            print(f"[W] Неподдерживаемый security-протокол '{security}', конфигурация пропущена")
            return None
    else:
        if security in ("", "none"):
            return {}
        if security not in ("tls", "reality"):
            print(f"[W] Неподдерживаемый security-протокол '{security}', конфигурация пропущена")
            return None

    sni = parse_url.get("sni", parse_url.get("peer", [hostname]))[0]
    tls = {
        "enabled": True,
        "server_name": sni,
    }

    insecure_val = parse_url.get(
        "allowInsecure",
        parse_url.get("insecure", parse_url.get("allow_insecure", [None])),
    )[0]
    if insecure_val is not None:
        tls["insecure"] = parse_bool(insecure_val)

    if "alpn" in parse_url:
        alpn_list = [a.strip() for raw in parse_url["alpn"] for a in raw.split(",") if a.strip()]
        if alpn_list:
            tls["alpn"] = alpn_list
    elif default_alpn is not None:
        tls["alpn"] = default_alpn

    fp = parse_url.get("fp", [""])[0]
    if security == "reality":
        pbk = parse_url.get("pbk", [""])[0]
        if not pbk:
            print("[W] Отсутствует public_key (pbk) для Reality, конфигурация пропущена")
            return None
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp if fp else "chrome",
        }
        reality = {
            "enabled": True,
            "public_key": pbk,
        }
        if "sid" in parse_url and parse_url["sid"][0]:
            reality["short_id"] = parse_url["sid"][0]
        tls["reality"] = reality
    elif allow_utls and fp:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }

    return tls


def _parse_vmess_b64(url: str) -> dict | None:
    """Декодирует классический V2RayN Base64-JSON формат ссылки vmess://."""
    raw_body = url.split("://", 1)[1].split("#", 1)[0].strip()
    if "@" in raw_body:
        return None
    try:
        data = loads(_decode_b64(raw_body))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _parse_shadowsocks_uri(url: str) -> tuple[str, int, str, str, dict, str] | None:
    """
    Разбирает ссылки ss:// (SIP002 и legacy Base64).
    Возвращает кортеж (hostname, port, method, password, query_dict, fragment) или None.
    """
    without_scheme = url.split("://", 1)[1]
    if "#" in without_scheme:
        body, fragment = without_scheme.split("#", 1)
        fragment = unquote(fragment).strip()
    else:
        body, fragment = without_scheme, ""

    if "?" in body:
        main_part, query_str = body.split("?", 1)
        query_dict = parse_qs(query_str)
    else:
        main_part, query_dict = body, {}

    main_part = main_part.rstrip("/")

    if "@" in main_part:
        userinfo, hostport = main_part.rsplit("@", 1)
        userinfo = unquote(userinfo)
        if ":" not in userinfo:
            try:
                userinfo = _decode_b64(userinfo)
            except Exception:
                return None
    else:
        try:
            decoded = _decode_b64(main_part)
        except Exception:
            return None
        if "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)

    if ":" not in userinfo:
        return None
    method, password = userinfo.split(":", 1)

    try:
        parsed_hp = urlsplit(f"ss://{hostport}")
        hostname = parsed_hp.hostname or ""
        port = parsed_hp.port or 0
    except ValueError:
        return None
    if not hostname or not port:
        return None

    return hostname, port, method.strip().lower(), password, query_dict, fragment


def build_transport(parse_url: dict) -> tuple[dict | None, str]:
    """
    Формирует блок transport для sing-box.
    Возвращает (словарь transport, имя транспорта) или (None, имя транспорта),
    если транспорт не поддерживается sing-box.
    """
    net_type = parse_url.get("type", ["tcp"])[0].lower()
    header_type = parse_url.get("headerType", ["none"])[0].lower()

    if net_type in ("tcp", "raw") and header_type == "http":
        net_type = "http"

    match net_type:
        case "tcp" | "raw" | "none":
            return {}, "tcp"

        case "ws":
            transport = {"type": "ws"}
            path = parse_url.get("path", ["/"])[0]
            headers = {}

            if "headers" in parse_url and parse_url["headers"][0]:
                headers.update(parse_headers(parse_url["headers"][0]))
            if "host" in parse_url and parse_url["host"][0]:
                headers["Host"] = parse_url["host"][0]
            if headers:
                transport["headers"] = headers

            ed_val = parse_url.get("ed", [None])[0]
            if "?ed=" in path:
                path, ed_part = path.split("?ed=", 1)
                ed_val = ed_part.split("&")[0]

            transport["path"] = path if path else "/"
            if ed_val and str(ed_val).isdigit():
                transport["max_early_data"] = int(ed_val)
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"

            return transport, "ws"

        case "grpc":
            transport = {"type": "grpc"}
            service_name = parse_url.get("serviceName", parse_url.get("path", [""]))[0].lstrip("/")
            if service_name:
                transport["service_name"] = service_name
            return transport, "grpc"

        case "http" | "h2":
            transport = {"type": "http"}
            if "host" in parse_url and parse_url["host"][0]:
                transport["host"] = [h.strip() for h in parse_url["host"][0].split(",") if h.strip()]
            if "path" in parse_url and parse_url["path"][0]:
                transport["path"] = parse_url["path"][0]
            if "headers" in parse_url and parse_url["headers"][0]:
                transport["headers"] = parse_headers(parse_url["headers"][0])
            return transport, "http"

        case "httpupgrade":
            transport = {"type": "httpupgrade"}
            if "host" in parse_url and parse_url["host"][0]:
                transport["host"] = parse_url["host"][0]
            if "path" in parse_url and parse_url["path"][0]:
                transport["path"] = parse_url["path"][0]
            if "headers" in parse_url and parse_url["headers"][0]:
                transport["headers"] = parse_headers(parse_url["headers"][0])
            return transport, "httpupgrade"

        case "quic":
            return {"type": "quic"}, "quic"

        case _:
            print(f"[W] Транспорт '{net_type}' не поддерживается в sing-box, конфигурация пропущена")
            return None, net_type


def url2json(url: str, tag: str = "", allowed_protocols: set[str] | None = None) -> dict:
    """
    Получает из url-ссылки параметры конфига и собирает outbound для sing-box 1.14.4.
    Отбрасывает неподдерживаемые протоколы, транспорты, методы шифрования и фильтрует по allowed_protocols.
    """
    url_split = urlsplit(url)
    scheme = url_split.scheme.lower()
    protocol = SCHEME_TO_PROTOCOL.get(scheme)

    if protocol is None:
        print(f"[W] Неподдерживаемый proxy-protocol: '{scheme}', конфигурация пропущена")
        return {}

    if allowed_protocols is not None and protocol not in allowed_protocols:
        return {}

    print(f"[I] Обработка url-конфигурации: {url}")
    parse_url = parse_qs(url_split.query)
    fragment = unquote(url_split.fragment).strip()

    default_port = 80 if scheme == "http" else (1080 if protocol == "socks" else 443)
    hostname, port, server_ports = parse_host_and_ports(url_split, parse_url, default_port=default_port)

    transport_name = "tcp"
    security_name = parse_url.get("security", ["none"])[0].lower()

    if protocol not in ("vmess", "shadowsocks") and not hostname:
        print(f"[W] Отсутствует адрес сервера, конфигурация пропущена: {url}")
        return {}

    match protocol:
        case "vless":
            uuid = unquote(url_split.username) if url_split.username else ""
            if not uuid:
                print(f"[W] Отсутствует UUID в VLESS-ссылке, конфигурация пропущена: {url}")
                return {}

            encryption = parse_url.get("encryption", ["none"])[0].strip().lower()
            if encryption not in ("", "none"):
                print(f"[W] Неподдерживаемый VLESS encryption '{encryption}', конфигурация пропущена")
                return {}

            transport, transport_name = build_transport(parse_url)
            if transport is None:
                return {}

            tls = build_tls(parse_url, hostname, allow_utls=True, default_security="none")
            if tls is None:
                return {}

            outbound = {
                "type": "vless",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "uuid": uuid,
            }
            if "flow" in parse_url and parse_url["flow"][0]:
                outbound["flow"] = parse_url["flow"][0]
            if "packetEncoding" in parse_url and parse_url["packetEncoding"][0]:
                outbound["packet_encoding"] = parse_url["packetEncoding"][0]
            if transport:
                outbound["transport"] = transport
            if tls:
                outbound["tls"] = tls

        case "vmess":
            vmess_cfg = _parse_vmess_b64(url)
            if vmess_cfg is not None:
                hostname = str(vmess_cfg.get("add", "")).strip()
                raw_port = str(vmess_cfg.get("port", "")).strip()
                uuid = str(vmess_cfg.get("id", "")).strip()
                if not hostname or not raw_port.isdigit() or not uuid:
                    print(f"[W] Невалидный VMess JSON, конфигурация пропущена: {url}")
                    return {}
                port = int(raw_port)
                raw_aid = str(vmess_cfg.get("aid") or "0").strip()
                alter_id = int(raw_aid) if raw_aid.isdigit() else 0
                scy = str(vmess_cfg.get("scy") or "auto").strip().lower()
                if vmess_cfg.get("ps"):
                    fragment = str(vmess_cfg["ps"]).strip()

                tls_flag = str(vmess_cfg.get("tls") or "none").strip().lower()
                security_name = tls_flag if tls_flag else "none"
                parse_url = {
                    "type": [str(vmess_cfg.get("net") or "tcp")],
                    "headerType": [str(vmess_cfg.get("type") or "none")],
                    "host": [str(vmess_cfg.get("host") or "")],
                    "path": [str(vmess_cfg.get("path") or "")],
                    "security": [security_name],
                    "sni": [str(vmess_cfg.get("sni") or vmess_cfg.get("host") or hostname)],
                    "alpn": [str(vmess_cfg.get("alpn") or "")],
                    "fp": [str(vmess_cfg.get("fp") or "")],
                }
            else:
                uuid = unquote(url_split.username) if url_split.username else ""
                if not hostname or not uuid:
                    print(f"[W] Невалидная VMess-ссылка, конфигурация пропущена: {url}")
                    return {}
                raw_aid = parse_url.get("alterId", parse_url.get("aid", ["0"]))[0]
                alter_id = int(raw_aid) if str(raw_aid).isdigit() else 0
                scy = parse_url.get("encryption", parse_url.get("scy", ["auto"]))[0].strip().lower()

            if scy not in VMESS_SECURITIES:
                print(f"[W] Неподдерживаемый VMess security '{scy}', конфигурация пропущена")
                return {}

            transport, transport_name = build_transport(parse_url)
            if transport is None:
                return {}

            tls = build_tls(parse_url, hostname, allow_utls=True, default_security="none")
            if tls is None:
                return {}

            outbound = {
                "type": "vmess",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "uuid": uuid,
                "security": scy,
                "alter_id": alter_id,
            }
            if "packetEncoding" in parse_url and parse_url["packetEncoding"][0]:
                outbound["packet_encoding"] = parse_url["packetEncoding"][0]
            if transport:
                outbound["transport"] = transport
            if tls:
                outbound["tls"] = tls

        case "trojan":
            password = _extract_userinfo_password(url_split)
            if not password:
                print(f"[W] Отсутствует пароль в Trojan-ссылке, конфигурация пропущена: {url}")
                return {}

            transport, transport_name = build_transport(parse_url)
            if transport is None:
                return {}

            tls = build_tls(parse_url, hostname, allow_utls=True, default_security="tls")
            if tls is None:
                return {}
            security_name = "reality" if "reality" in tls else ("tls" if tls else "none")

            outbound = {
                "type": "trojan",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "password": password,
            }
            if transport:
                outbound["transport"] = transport
            if tls:
                outbound["tls"] = tls

        case "shadowsocks":
            ss_parsed = _parse_shadowsocks_uri(url)
            if ss_parsed is None:
                print(f"[W] Невалидная Shadowsocks-ссылка, конфигурация пропущена: {url}")
                return {}

            hostname, port, method, password, parse_url, fragment = ss_parsed
            security_name = "none"

            if method not in SHADOWSOCKS_METHODS:
                print(f"[W] Неподдерживаемый метод Shadowsocks '{method}', конфигурация пропущена")
                return {}

            outbound = {
                "type": "shadowsocks",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "method": method,
                "password": password,
            }

            plugin_raw = parse_url.get("plugin", [""])[0].strip()
            if plugin_raw:
                plugin_parts = plugin_raw.split(";", 1)
                plugin_name = plugin_parts[0].strip().lower()
                if plugin_name == "simple-obfs":
                    plugin_name = "obfs-local"
                if plugin_name not in ("obfs-local", "v2ray-plugin"):
                    print(f"[W] Неподдерживаемый SIP003-плагин '{plugin_name}', конфигурация пропущена")
                    return {}
                outbound["plugin"] = plugin_name
                if len(plugin_parts) == 2 and plugin_parts[1].strip():
                    outbound["plugin_opts"] = plugin_parts[1].strip()

            uot = parse_url.get("uot", parse_url.get("udp-over-tcp", [None]))[0]
            if uot is not None and parse_bool(uot):
                outbound["udp_over_tcp"] = True

        case "hysteria2":
            transport_name = "quic"
            security_name = "tls"

            tls = build_tls(parse_url, hostname, allow_utls=False, default_alpn=["h3"], force_tls=True)
            if tls is None:
                return {}

            obfs_type = parse_url.get("obfs", [""])[0].strip().lower()
            obfs_pwd = parse_url.get("obfs-password", parse_url.get("obfsParam", [""]))[0]
            if obfs_type and obfs_type not in ("none", "salamander", "gecko"):
                print(f"[W] Неподдерживаемый тип обфускации Hysteria2 '{obfs_type}', конфигурация пропущена")
                return {}

            outbound = {
                "type": "hysteria2",
                "tag": "",
                "server": hostname,
            }
            if server_ports:
                outbound["server_ports"] = server_ports
            else:
                outbound["server_port"] = port

            password = _extract_userinfo_password(url_split) or parse_url.get("auth", [""])[0]

            if password:
                outbound["password"] = password

            if "hop_interval" in parse_url and parse_url["hop_interval"][0]:
                interval = parse_url["hop_interval"][0]
                outbound["hop_interval"] = f"{interval}s" if interval.isdigit() else interval

            up_mbps = _parse_mbps(parse_url.get("upmbps", parse_url.get("up", [None]))[0])
            down_mbps = _parse_mbps(parse_url.get("downmbps", parse_url.get("down", [None]))[0])
            if up_mbps is not None:
                outbound["up_mbps"] = up_mbps
            if down_mbps is not None:
                outbound["down_mbps"] = down_mbps

            if obfs_type in ("salamander", "gecko") or (not obfs_type and obfs_pwd):
                if not obfs_pwd:
                    print(f"[W] Указана обфускация Hysteria2 '{obfs_type}' без пароля, конфигурация пропущена")
                    return {}
                outbound["obfs"] = {
                    "type": obfs_type if obfs_type in ("salamander", "gecko") else "salamander",
                    "password": obfs_pwd,
                }

            outbound["tls"] = tls

        case "hysteria":
            transport_name = "quic"
            security_name = "tls"

            hy_proto = parse_url.get("protocol", ["udp"])[0].lower()
            if hy_proto != "udp":
                print(f"[W] Протокол Hysteria '{hy_proto}' не поддерживается в sing-box, конфигурация пропущена")
                return {}

            tls = build_tls(parse_url, hostname, allow_utls=False, default_alpn=["h3"], force_tls=True)
            if tls is None:
                return {}

            outbound = {
                "type": "hysteria",
                "tag": "",
                "server": hostname,
            }
            if server_ports:
                outbound["server_ports"] = server_ports
            else:
                outbound["server_port"] = port

            if "hop_interval" in parse_url and parse_url["hop_interval"][0]:
                interval = parse_url["hop_interval"][0]
                outbound["hop_interval"] = f"{interval}s" if interval.isdigit() else interval

            auth = parse_url.get("auth", [unquote(url_split.username) if url_split.username else ""])[0]
            if auth:
                outbound["auth_str"] = auth

            up_mbps = _parse_mbps(parse_url.get("upmbps", parse_url.get("up", [None]))[0])
            down_mbps = _parse_mbps(parse_url.get("downmbps", parse_url.get("down", [None]))[0])
            outbound["up_mbps"] = up_mbps if up_mbps is not None else DEFAULT_HYSTERIA_UP_MBPS
            outbound["down_mbps"] = down_mbps if down_mbps is not None else DEFAULT_HYSTERIA_DOWN_MBPS

            obfs_val = parse_url.get("obfsParam", parse_url.get("obfs", [""]))[0]
            if obfs_val and obfs_val.lower() != "none":
                outbound["obfs"] = obfs_val

            outbound["tls"] = tls

        case "tuic":
            transport_name = "quic"
            security_name = "tls"

            uuid = unquote(url_split.username) if url_split.username else ""
            if not uuid:
                print(f"[W] Отсутствует UUID в TUIC-ссылке, конфигурация пропущена: {url}")
                return {}

            tls = build_tls(parse_url, hostname, allow_utls=False, default_alpn=["h3"], force_tls=True)
            if tls is None:
                return {}

            outbound = {
                "type": "tuic",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "uuid": uuid,
            }
            if url_split.password:
                outbound["password"] = unquote(url_split.password)

            cc = parse_url.get("congestion_control", [""])[0].strip().lower()
            if cc in TUIC_CONGESTION_CONTROLS:
                outbound["congestion_control"] = cc

            uos = parse_url.get("udp_over_stream", [None])[0]
            if uos is not None and parse_bool(uos):
                outbound["udp_over_stream"] = True
            else:
                relay_mode = parse_url.get("udp_relay_mode", [""])[0].strip().lower()
                if relay_mode in ("native", "quic"):
                    outbound["udp_relay_mode"] = relay_mode

            z_rtt = parse_url.get("zero_rtt_handshake", parse_url.get("reduce_rtt", [None]))[0]
            if z_rtt is not None:
                outbound["zero_rtt_handshake"] = parse_bool(z_rtt)

            if "heartbeat" in parse_url and parse_url["heartbeat"][0]:
                hb = parse_url["heartbeat"][0]
                outbound["heartbeat"] = f"{hb}s" if hb.isdigit() else hb

            outbound["tls"] = tls

        case "anytls":
            security_name = "tls"

            password = _extract_userinfo_password(url_split)

            if not password:
                print(f"[W] Отсутствует пароль в AnyTLS-ссылке, конфигурация пропущена: {url}")
                return {}

            tls = build_tls(parse_url, hostname, allow_utls=True, force_tls=True)
            if tls is None:
                return {}

            outbound = {
                "type": "anytls",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "password": password,
                "tls": tls,
            }
            for key in ("idle_session_check_interval", "idle_session_timeout", "client_metadata"):
                if key in parse_url and parse_url[key][0]:
                    outbound[key] = parse_url[key][0]
            min_idle = parse_url.get("min_idle_session", [None])[0]
            if min_idle and str(min_idle).isdigit():
                outbound["min_idle_session"] = int(min_idle)

        case "naive":
            is_quic = scheme == "naive+quic"
            transport_name = "quic" if is_quic else "http"
            security_name = "tls"

            sni = parse_url.get("sni", parse_url.get("peer", [hostname]))[0]
            outbound = {
                "type": "naive",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                },
            }
            if url_split.username:
                outbound["username"] = unquote(url_split.username)
            if url_split.password:
                outbound["password"] = unquote(url_split.password)
            if is_quic:
                outbound["quic"] = True
                qcc = parse_url.get("quic_congestion_control", [""])[0].strip().lower()
                if qcc in NAIVE_CONGESTION_CONTROLS:
                    outbound["quic_congestion_control"] = qcc

        case "socks":
            security_name = "none"
            version = "4" if scheme == "socks4" else ("4a" if scheme == "socks4a" else "5")
            outbound = {
                "type": "socks",
                "tag": "",
                "server": hostname,
                "server_port": port,
                "version": version,
            }

            username = unquote(url_split.username) if url_split.username else ""
            password = unquote(url_split.password) if url_split.password else ""
            if username and not password:
                try:
                    decoded = _decode_b64(username)
                    if ":" in decoded:
                        username, password = decoded.split(":", 1)
                except (ValueError, UnicodeDecodeError):
                    pass

            if username:
                outbound["username"] = username
            if password and version == "5":
                outbound["password"] = password

        case "http":
            is_https = scheme == "https"
            security_name = "tls" if is_https else "none"
            outbound = {
                "type": "http",
                "tag": "",
                "server": hostname,
                "server_port": port,
            }
            if url_split.username:
                outbound["username"] = unquote(url_split.username)
            if url_split.password:
                outbound["password"] = unquote(url_split.password)
            if url_split.path and url_split.path != "/":
                outbound["path"] = url_split.path
            if "headers" in parse_url and parse_url["headers"][0]:
                outbound["headers"] = parse_headers(parse_url["headers"][0])
            if is_https:
                tls = build_tls(parse_url, hostname, allow_utls=True, force_tls=True)
                if tls is None:
                    return {}
                outbound["tls"] = tls

    base_tag = fragment if fragment else f"{hostname}-{outbound['type']}-{transport_name}-{security_name}"
    tag_parts = [p for p in (tag, base_tag) if p]
    outbound["tag"] = "_".join(tag_parts)

    return outbound


def _outbound_signature(outbound: dict) -> str:
    """
    Возвращает строковое представление параметров outbound без поля tag
    для простого сравнения конфигураций на идентичность.
    """
    data = {k: v for k, v in outbound.items() if k != "tag"}
    return dumps(data, sort_keys=True, ensure_ascii=False)


def resolve_tag_collisions(outbounds_list: list[dict], reserved_tags: set[str] | None = None) -> list[dict]:
    """
    Разрешает коллизии одинаковых тегов:
    - Если конфигурации с одинаковым тегом идентичны, дубликат отбрасывается.
    - Если конфигурации различаются (или тег зарезервирован), добавляется суффикс _n.
    """
    resolved = []
    seen_by_base_tag: dict[str, set[str]] = {}
    used_tags: set[str] = set(reserved_tags) if reserved_tags else set()

    for outbound in outbounds_list:
        base_tag = outbound["tag"]
        signature = _outbound_signature(outbound)

        if signature in seen_by_base_tag.get(base_tag, set()):
            continue

        seen_by_base_tag.setdefault(base_tag, set()).add(signature)

        if base_tag not in used_tags:
            final_tag = base_tag
        else:
            index = 1
            while f"{base_tag}_{index}" in used_tags:
                index += 1
            final_tag = f"{base_tag}_{index}"
            outbound["tag"] = final_tag

        used_tags.add(final_tag)
        resolved.append(outbound)

    return resolved


def create_json_config(outbounds: dict, file_path: str) -> bool:
    """
    Сохраняет outbounds в указанный JSON-файл без автоматического создания директорий.
    Возвращает True при успехе и False при ошибке.
    """
    abs_path = os.path.abspath(file_path)
    parent_dir = os.path.dirname(abs_path)

    if os.path.isdir(abs_path):
        print(f"[E] Указанный путь является директорией, требуется путь к файлу: {file_path}")
        return False

    if not os.path.isdir(parent_dir):
        print(f"[E] Директория для сохранения не существует: {parent_dir}")
        return False

    outbounds_json = dumps(outbounds, indent=2, ensure_ascii=False)
    try:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            config.write(outbounds_json)
    except OSError as e:
        print(f"[E] Ошибка записи файла {file_path}: {e}")
        return False

    print(f"[I] Конфигурация сохранена в: {file_path}")
    return True


# === Функции парсинга и модификации JSONC / JSON5 с сохранением комментариев ===

def tokenize_json5(text: str) -> list[tuple[str, int, int]]:
    """Извлекает значимые токены JSON, игнорируя однострочные и блочные комментарии."""
    tokens = []
    for match in TOKEN_RE.finditer(text):
        if match.group(2):  # Игнорируем комментарии (//, #, /* */)
            continue
        tokens.append((match.group(0), match.start(), match.end()))
    return tokens


def parse_json5_node(tokens: list[tuple[str, int, int]], idx: int = 0) -> tuple[dict, int]:
    """Строит дерево координат объектов и массивов с поддержкой trailing commas."""
    val, start, end = tokens[idx]

    if val == "{":
        props = {}
        idx += 1
        last_elem_end = None
        has_trailing_comma = False
        while idx < len(tokens) and tokens[idx][0] != "}":
            key = loads(tokens[idx][0])
            if tokens[idx + 1][0] != ":":
                raise ValueError(f"Ожидалось ':', получено {tokens[idx + 1][0]}")
            idx += 2
            child, idx = parse_json5_node(tokens, idx)
            props[key] = child
            last_elem_end = child["end"]
            has_trailing_comma = False
            if idx < len(tokens) and tokens[idx][0] == ",":
                child["comma_start"] = tokens[idx][1]
                child["comma_end"] = tokens[idx][2]
                has_trailing_comma = True
                idx += 1
        close_start, close_end = tokens[idx][1], tokens[idx][2]
        return {
            "type": "object",
            "props": props,
            "start": start,
            "end": close_end,
            "close_start": close_start,
            "last_elem_end": last_elem_end,
            "has_trailing_comma": has_trailing_comma,
        }, idx + 1

    if val == "[":
        elements = []
        idx += 1
        last_elem_end = None
        has_trailing_comma = False
        while idx < len(tokens) and tokens[idx][0] != "]":
            child, idx = parse_json5_node(tokens, idx)
            elements.append(child)
            last_elem_end = child["end"]
            has_trailing_comma = False
            if idx < len(tokens) and tokens[idx][0] == ",":
                child["comma_start"] = tokens[idx][1]
                child["comma_end"] = tokens[idx][2]
                has_trailing_comma = True
                idx += 1
        close_start, close_end = tokens[idx][1], tokens[idx][2]
        return {
            "type": "array",
            "elements": elements,
            "start": start,
            "end": close_end,
            "close_start": close_start,
            "last_elem_end": last_elem_end,
            "has_trailing_comma": has_trailing_comma,
        }, idx + 1

    return {
        "type": "primitive",
        "value": loads(val),
        "start": start,
        "end": end,
    }, idx + 1


def parse_json5_root(text: str) -> dict:
    """Разбирает корневой JSONC/JSON5-объект конфигурации."""
    tokens = tokenize_json5(text)
    if not tokens:
        raise ValueError("Пустой конфигурационный файл")
    root, next_idx = parse_json5_node(tokens, 0)
    if next_idx != len(tokens) or root["type"] != "object":
        raise ValueError("Некорректная корневая структура JSON")
    return root


def _get_line_indent(text: str, pos: int) -> tuple[str, int]:
    """Определяет отступ строки и индекс её начала."""
    line_start = text.rfind("\n", 0, pos) + 1
    indent = ""
    for ch in text[line_start:pos]:
        if ch in (" ", "\t"):
            indent += ch
        else:
            break
    return indent, line_start


def _splice_into_container(text: str, node: dict, raw_entries: list[str]) -> str:
    """
    Точечно вставляет новые элементы в конец JSON-массива или JSON-объекта,
    сохраняя все существующие комментарии и отступы.
    """
    if not raw_entries:
        return text

    closing_indent, line_start = _get_line_indent(text, node["close_start"])
    multiline_close = line_start > node["start"] and text[line_start : node["close_start"]].strip() == ""
    if not multiline_close:
        closing_indent, _ = _get_line_indent(text, node["start"])

    item_indent = closing_indent + "  "
    indented_entries = []
    for entry in raw_entries:
        indented_entries.append("\n".join(item_indent + line for line in entry.splitlines()))
    items_block = ",\n".join(indented_entries)

    if multiline_close:
        text = text[:line_start] + f"{items_block}\n" + text[line_start:]
    else:
        text = text[: node["close_start"]] + f"\n{items_block}\n{closing_indent}" + text[node["close_start"] :]

    if node["last_elem_end"] is not None and not node["has_trailing_comma"]:
        text = text[: node["last_elem_end"]] + "," + text[node["last_elem_end"] :]

    return text


def append_to_json_array(text: str, arr_node: dict, items: list) -> str:
    """Сериализует элементы и добавляет их в конец JSON-массива."""
    raw_entries = [dumps(item, indent=2, ensure_ascii=False) for item in items]
    return _splice_into_container(text, arr_node, raw_entries)


def insert_json_object_key(text: str, obj_node: dict, key: str, value) -> str:
    """Добавляет новый ключ со значением в конец JSON-объекта."""
    entry = f"{dumps(key, ensure_ascii=False)}: {dumps(value, indent=2, ensure_ascii=False)}"
    return _splice_into_container(text, obj_node, [entry])


def _get_node_tag(elem: dict) -> str | None:
    """Извлекает строковое значение поля 'tag' из узла JSON-объекта."""
    if elem["type"] != "object":
        return None
    tag_node = elem["props"].get("tag")
    if tag_node and tag_node["type"] == "primitive" and isinstance(tag_node["value"], str):
        return tag_node["value"]
    return None


def _extract_balancer_tags(outbounds_node: dict) -> set[str]:
    """
    Возвращает множество тегов из существующих балансировщиков 'balancer' и 'auto'.
    По этому списку определяются конфиги, которые были автоматически добавлены скриптом ранее.
    """
    managed_tags = set()
    for elem in outbounds_node["elements"]:
        if _get_node_tag(elem) in ("balancer", "auto"):
            bal_out = elem["props"].get("outbounds")
            if bal_out and bal_out["type"] == "array":
                for item in bal_out["elements"]:
                    if item["type"] == "primitive" and isinstance(item["value"], str):
                        managed_tags.add(item["value"])
    return managed_tags


def _remove_array_elements(text: str, arr_node: dict, remove_indices: set[int]) -> str:
    """
    Точечно удаляет элементы массива по их индексам, сохраняя все внешние и соседние комментарии
    и корректируя запятые, чтобы структура оставалась валидным JSON.
    """
    if not remove_indices:
        return text

    elements = arr_node["elements"]
    n = len(elements)
    kept_indices = [i for i in range(n) if i not in remove_indices]

    spans = []
    for idx in sorted(remove_indices):
        elem = elements[idx]
        start = elem["start"]
        end = elem.get("comma_end", elem["end"])

        line_start = text.rfind("\n", 0, start) + 1
        if line_start > arr_node["start"] and text[line_start:start].strip() == "":
            start = line_start
            if end < len(text) and text[end : end + 2] == "\r\n":
                end += 2
            elif end < len(text) and text[end : end + 1] == "\n":
                end += 1

        spans.append((start, end))

    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))

    ops = [(s, e, "") for s, e in merged]

    if kept_indices:
        last_kept = elements[kept_indices[-1]]
        if "comma_start" in last_kept and not arr_node["has_trailing_comma"]:
            ops.append((last_kept["comma_start"], last_kept["comma_end"], ""))

    for s, e, repl in sorted(ops, key=lambda x: x[0], reverse=True):
        text = text[:s] + repl + text[e:]

    return text


def integrate_config(new_outbounds: list[dict], config_path: str) -> bool:
    """
    Обновляет конфигурационный файл sing-box (с поддержкой JSONC/JSON5 и сохранением комментариев):
    - Удаляет устаревшие прокси (присутствовавшие в старых 'balancer'/'auto'), повторяющиеся прокси и сами 'balancer'/'auto'.
    - Вставляет актуальный список прокси и свежие блоки 'auto' и 'balancer'.
    Возвращает True при успехе и False при ошибке.
    """
    if not os.path.exists(config_path) or os.path.isdir(config_path):
        print(f"[E] Файл конфигурации sing-box не найден: {config_path}")
        return False

    try:
        with open(config_path, "r", encoding="utf-8-sig") as f:
            raw_text = f.read()
        root = parse_json5_root(raw_text)
    except (JSONDecodeError, ValueError, IndexError, KeyError, OSError) as e:
        print(f"[E] Ошибка чтения конфигурации {config_path}: {e}")
        return False

    new_tags = [ob["tag"] for ob in new_outbounds]
    current_auto = {**auto_balancer, "outbounds": new_tags}
    current_balancer = {**default_balancer, "outbounds": ["auto"] + new_tags}

    outbounds_node = root["props"].get("outbounds")
    if outbounds_node is None or outbounds_node["type"] != "array":
        raw_text = insert_json_object_key(
            raw_text, root, "outbounds", new_outbounds + [current_auto, current_balancer]
        )
    else:
        old_managed_tags = _extract_balancer_tags(outbounds_node)
        tags_to_purge = old_managed_tags | set(new_tags) | {"balancer", "auto"}

        remove_indices = set()
        for idx, elem in enumerate(outbounds_node["elements"]):
            if _get_node_tag(elem) in tags_to_purge:
                remove_indices.add(idx)

        if remove_indices:
            raw_text = _remove_array_elements(raw_text, outbounds_node, remove_indices)
            root = parse_json5_root(raw_text)
            outbounds_node = root["props"]["outbounds"]

        raw_text = append_to_json_array(
            raw_text, outbounds_node, new_outbounds + [current_auto, current_balancer]
        )

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(raw_text)
    except OSError as e:
        print(f"[E] Ошибка записи конфигурации {config_path}: {e}")
        return False

    print(f"[I] Интеграция завершена: актуализировано {len(new_outbounds)} прокси в {config_path}")
    return True

# === Функции управления скриптом и вводными данными ===

def read_config(file_path: str) -> list[tuple[str, str]]:
    """
    Читает ссылки из файла.
    Ожидаемый формат строки: 'URL' или 'TAG URL'. Поддерживаются комментарии через '#'.
    """
    links = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(maxsplit=1)
                if "://" in parts[0]:
                    links.append((line, ""))
                elif len(parts) == 2:
                    links.append((parts[1].strip(), parts[0].strip()))
                else:
                    links.append((parts[0], ""))
    except OSError as e:
        print(f"[E] Ошибка чтения файла ссылок {file_path}: {e}")

    return links


def parse_proxy_protocols(value: str) -> set[str]:
    """
    Валидирует список proxy-протоколов, переданных через запятую в параметре -pp.
    При ошибке выводит допустимый список протоколов.
    """
    allowed_str = ", ".join(SUPPORTED_PROXY_PROTOCOLS)
    items = [item.strip().lower() for item in value.split(",")]

    if not value.strip() or any(not item for item in items):
        raise ArgumentTypeError(f"укажите протоколы через запятую без пустых значений. Допустимые значения: {allowed_str}")

    invalid = [item for item in items if item not in SUPPORTED_PROXY_PROTOCOLS]
    if invalid:
        raise ArgumentTypeError(
            f"недопустимый протокол: {', '.join(invalid)}. Допустимые значения: {allowed_str}"
        )

    return set(items)


def parse_regex_pattern(value: str) -> Pattern:
    """Валидирует и компилирует регулярное выражение из параметра -rf."""
    try:
        return re_compile(value)
    except re_error as e:
        raise ArgumentTypeError(f"некорректное регулярное выражение: {e}")


def args_parser():
    """Обрабатывает аргументы командной строки."""
    protocols_list = ", ".join(SUPPORTED_PROXY_PROTOCOLS)
    argparser = ArgumentParser(
        prog=app_name,
        description="Парсер подписок для sing-box. Сбор ссылок конфигураций, фильтрация и экспорт или интеграция в JSON/JSON5 конфиг.",
    )
    argparser.add_argument(
        "--url",
        action="append",
        help=f"Ссылка на подписку (http/https) или прокси ({protocols_list}). Можно указать несколько раз.",
    )
    argparser.add_argument(
        "-c", "--config",
        action="append",
        help="Файл со ссылками подписок и прокси (по одной в строке). Поддерживается префикс тега в формате 'TAG URL' и комментарии '#'. Можно указать несколько раз.",
    )

    output_group = argparser.add_mutually_exclusive_group()
    output_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        default="",
        help="Путь к выходному JSON-файлу (перезаписывается целиком; несуществующие директории не создаются). По умолчанию создаётся outbounds.json в директории скрипта. Несовместим с -I.",
    )
    output_group.add_argument(
        "-I", "--integration",
        metavar="FILE",
        default="",
        help="Путь к существующему конфигу sing-box (JSON/JSONC/JSON5) для обновления прокси и балансировщиков 'balancer' и 'auto' с сохранением комментариев. Несовместим с -o.",
    )

    argparser.add_argument(
        "-pp", "--proxy-protocol",
        metavar="PROTOCOLS",
        type=parse_proxy_protocols,
        default=None,
        help=f"Фильтр proxy-протоколов через запятую слитно (например: vless,hysteria2). Допустимые значения: {protocols_list}.",
    )
    argparser.add_argument(
        "-rf", "--regex-filter",
        metavar="REGEX",
        type=parse_regex_pattern,
        default=None,
        help="RegEx-фильтр (поиск совпадения), применяемый к fragment ссылки до добавления тега из файла -c.",
    )
    argparser.add_argument(
        "-if", "--invert-filter",
        action="store_true",
        help="Инвертирует поведение -rf: при совпадении с фильтром конфигурация не будет добавлена.",
    )
    argparser.add_argument(
        "-V", "--version",
        action="version",
        version=f"{app_name}/{app_version}",
        help="Вывести версию программы.",
    )
    return argparser.parse_args()


def regex_filter(pattern: Pattern | None, tag: str, invert: bool = False) -> bool:
    """Проверяет тег на соответствие скомпилированному регулярному выражению с учётом инверсии."""
    if pattern is None:
        return True
    result = bool(pattern.search(tag))
    return not result if invert else result


def _extract_url_fragment(raw_url: str) -> str:
    """Извлекает имя узла (fragment) из ссылки, включая поле 'ps' для Base64-ссылок vmess://."""
    fragment = unquote(urlsplit(raw_url).fragment).strip()
    if not fragment and raw_url.lower().startswith("vmess://"):
        vmess_cfg = _parse_vmess_b64(raw_url)
        if vmess_cfg and vmess_cfg.get("ps"):
            return str(vmess_cfg["ps"]).strip()
    return fragment


def process_single_url(raw_url: str, file_tag: str, args, outbounds_list: list) -> None:
    """Проверяет ссылку по фильтрам протокола и RegEx, затем добавляет outbound в общий список."""
    clean_url = raw_url.strip()
    if not clean_url:
        return

    if args.proxy_protocol is not None:
        scheme = urlsplit(clean_url).scheme.lower()
        protocol = SCHEME_TO_PROTOCOL.get(scheme)
        if protocol is not None and protocol not in args.proxy_protocol:
            return

    if args.regex_filter is not None:
        fragment = _extract_url_fragment(clean_url)
        if not regex_filter(pattern=args.regex_filter, tag=fragment, invert=args.invert_filter):
            return

    outbound = url2json(clean_url, file_tag, args.proxy_protocol)
    if outbound:
        outbounds_list.append(outbound)


def main() -> None:
    """Точка входа: разбирает аргументы, собирает и сохраняет/интегрирует конфигурации."""
    args = args_parser()
    links = []
    outbounds_list = []

    if args.config:
        for config_file in args.config:
            print(f"[I] Чтение конфига: {config_file}")
            for url, line_tag in read_config(config_file):
                links.append((url, line_tag if line_tag else ""))

    if args.url:
        for url in args.url:
            links.append((url, ""))

    if not links:
        print("[E] Необходимо указать ссылку --url или файл конфигурации -c. Справка: -h")
        sys.exit(1)

    for url, file_tag in links:
        if url.lower().startswith(("https://", "http://")):
            config_urls = parse_subscription(url)
            for config_url in config_urls:
                process_single_url(config_url, file_tag, args, outbounds_list)
        else:
            process_single_url(url, file_tag, args, outbounds_list)

    if not outbounds_list:
        print("[E] Конфигурации не найдены. Завершение работы.")
        sys.exit(1)

    reserved_tags = {"balancer", "auto"} if args.integration else None
    resolved_outbounds = resolve_tag_collisions(outbounds_list, reserved_tags=reserved_tags)

    if args.integration:
        ok = integrate_config(resolved_outbounds, args.integration)
    else:
        default_output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outbounds.json")
        output_path = args.output if args.output else default_output
        ok = create_json_config({"outbounds": resolved_outbounds}, output_path)

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()