#!/bin/sh
# Made with Gemini
export PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# === Параметры репозитория ===
REPO_OWNER="aratash"
REPO_NAME="singkeen"
REPO_BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"

# === Значения по умолчанию (для неинтерактивного запуска) ===
DEFAULT_DISABLE_PPE="yes"
DEFAULT_ENABLE_PPE_ON_REMOVE="yes"
DEFAULT_PARSE_CRON="0 4 * * *"          # Раз в сутки в 04:00 (пусто = отключено)
DEFAULT_AUTOUPDATE_CRON=""    # (пусто = отключено)

# === Пути в системе ===
OPT_DIR="/opt"
SINGBOX_BIN="/opt/bin/sing-box"
INIT_SCRIPT="/opt/etc/init.d/S99sing-box"
NETFILTER_HOOK="/opt/etc/ndm/netfilter.d/050-singbox.sh"
MARK_CACHE="/opt/etc/ndm/netfilter.d/singbox-mark"
SB_LINK="/opt/bin/sb"
SELF_PATH="/opt/bin/singkeen.sh"
CONF_DIR="/opt/etc/sing-box"
LOG_DIR="/opt/var/log/sing-box"

# Скрипты, обновляемые по SHA-256
MANAGED_SCRIPTS="
etc/init.d/S99sing-box
etc/ndm/netfilter.d/050-singbox.sh
bin/singbox-subs-parser.py
bin/singkeen.sh
"

# Дефолтные конфиги (не затрагиваются при update)
DEFAULT_CONFIGS="
etc/sing-box/config.json
etc/sing-box/subs.txt
"

TMP_DIR="/tmp/singkeen.$$"
UPDATED_ANY=0

cleanup_tmp() {
    [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}
trap cleanup_tmp EXIT INT TERM

read_tty() {
    if [ -r /dev/tty ]; then
        read -r "$1" < /dev/tty
    else
        read -r "$1"
    fi
}

ask_yes_no() {
    prompt="$1"
    default="$2" # yes | no
    if [ "$default" = "yes" ]; then
        hint="[Y/n]"
    else
        hint="[y/N]"
    fi
    while true; do
        printf '%s %s: ' "$prompt" "$hint"
        read_tty ans
        ans="$(printf '%s' "$ans" | tr 'A-Z' 'a-z')"
        case "$ans" in
            "") [ "$default" = "yes" ] && return 0 || return 1 ;;
            y|yes|д|да) return 0 ;;
            n|no|н|нет) return 1 ;;
            *) echo "Введите y или n." ;;
        esac
    done
}

check_entware() {
    if [ ! -x /opt/bin/opkg ]; then
        echo "[E] Entware не обнаружен (/opt/bin/opkg не найден)." >&2
        exit 1
    fi
}

check_netfilter_modules() {
    kver="$(uname -r)"
    if grep -q "xt_TPROXY" /proc/modules 2>/dev/null; then
        return 0
    fi
    if [ -d "/lib/modules/${kver}" ] && find "/lib/modules/${kver}" -name "xt_TPROXY.ko*" 2>/dev/null | grep -q .; then
        return 0
    fi
    echo "[E] Модуль ядра xt_TPROXY не найден." >&2
    echo "    Установите системный компонент «Модули ядра подсистемы Netfilter» в веб-интерфейсе KeeneticOS и повторите установку." >&2
    exit 1
}

install_dependencies() {
    needed=""
    installed="$(/opt/bin/opkg list-installed 2>/dev/null | awk '{print $1}')"
    for pkg in curl ca-bundle cron iptables ip-full python3; do
        if ! printf '%s\n' "$installed" | grep -qx "$pkg"; then
            needed="${needed} ${pkg}"
        fi
    done

    if [ -n "$needed" ]; then
        echo "[I] Установка пакетов Entware:${needed}"
        /opt/bin/opkg update || { echo "[E] Ошибка opkg update." >&2; exit 1; }
        # shellcheck disable=SC2086
        /opt/bin/opkg install $needed || { echo "[E] Ошибка установки пакетов." >&2; exit 1; }
    else
        echo "[=] Зависимости Entware уже установлены."
    fi
}

detect_singbox_arch() {
    opkg_arch="$(/opt/bin/opkg print-architecture 2>/dev/null | awk '{print $2}')"
    case "$opkg_arch" in
        *aarch64*) echo "arm64"; return 0 ;;
        *armv7*)   echo "armv7"; return 0 ;;
        *mipsel*)  echo "mipsle-softfloat"; return 0 ;;
        *mips-*)   echo "mips-softfloat"; return 0 ;;
        *x86_64*)  echo "amd64"; return 0 ;;
    esac

    case "$(uname -m)" in
        aarch64|arm64) echo "arm64" ;;
        armv7*)        echo "armv7" ;;
        x86_64)        echo "amd64" ;;
        mipsel)        echo "mipsle-softfloat" ;;
        *)
            echo "[E] Не удалось определить архитектуру для sing-box (uname: $(uname -m))." >&2
            return 1
            ;;
    esac
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        /opt/bin/python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
    fi
}

install_or_update_singbox() {
    arch="$(detect_singbox_arch)" || return 1

    latest_tag="$(curl -fsSI --connect-timeout 10 --max-time 20 "https://github.com/SagerNet/sing-box/releases/latest" \
        | awk 'tolower($1)=="location:" {sub(/.*\/tag\//, "", $2); gsub(/\r/, "", $2); print $2; exit}')"

    case "$latest_tag" in
        v*) latest_ver="${latest_tag#v}" ;;
        *)
            echo "[E] Не удалось получить версию последнего релиза sing-box." >&2
            return 1
            ;;
    esac

    local_ver=""
    if [ -x "$SINGBOX_BIN" ]; then
        local_ver="$("$SINGBOX_BIN" version 2>/dev/null | awk 'NR==1 {print $3}')"
    fi

    if [ "$local_ver" = "$latest_ver" ]; then
        echo "[=] sing-box актуален (v${local_ver}, ${arch})."
        return 0
    fi

    echo "[I] Загрузка sing-box v${latest_ver} (${arch})..."
    mkdir -p "$TMP_DIR"
    archive="${TMP_DIR}/sing-box.tar.gz"
    dl_url="https://github.com/SagerNet/sing-box/releases/download/${latest_tag}/sing-box-${latest_ver}-linux-${arch}.tar.gz"

    if ! curl -fsSL --connect-timeout 15 --max-time 120 "$dl_url" -o "$archive"; then
        echo "[E] Ошибка скачивания: ${dl_url}" >&2
        rm -f "$archive"
        return 1
    fi

    if ! tar -xzf "$archive" -C "$TMP_DIR"; then
        echo "[E] Ошибка распаковки архива sing-box." >&2
        rm -f "$archive"
        return 1
    fi

    extracted="${TMP_DIR}/sing-box-${latest_ver}-linux-${arch}/sing-box"
    if [ ! -s "$extracted" ]; then
        echo "[E] Бинарник sing-box не найден внутри архива." >&2
        return 1
    fi

    chmod +x "$extracted"
    mv "$extracted" "$SINGBOX_BIN"
    rm -rf "$archive" "${TMP_DIR}/sing-box-${latest_ver}-linux-${arch}"
    UPDATED_ANY=1
    echo "[+] Установлен sing-box v${latest_ver} (${arch})."
}

sync_script_file() {
    rel_path="$1"
    dst="${OPT_DIR}/${rel_path}"
    url="${RAW_BASE}/${rel_path}"
    mkdir -p "$TMP_DIR"
    tmp_raw="${TMP_DIR}/$(basename "$rel_path").raw"
    tmp_lf="${TMP_DIR}/$(basename "$rel_path").lf"

    if ! curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "$tmp_raw"; then
        echo "[E] Не удалось скачать: ${url}" >&2
        rm -f "$tmp_raw"
        return 1
    fi

    if [ ! -s "$tmp_raw" ]; then
        echo "[E] Пустой файл: ${url}" >&2
        rm -f "$tmp_raw"
        return 1
    fi

    # Нормализация CRLF -> LF до расчёта хеша
    tr -d '\r' < "$tmp_raw" > "$tmp_lf"
    rm -f "$tmp_raw"

    new_hash="$(file_sha256 "$tmp_lf")"
    old_hash=""
    [ -f "$dst" ] && old_hash="$(file_sha256 "$dst")"

    if [ "$new_hash" = "$old_hash" ]; then
        rm -f "$tmp_lf"
        echo "[=] Актуален: ${dst}"
        return 0
    fi

    mkdir -p "$(dirname "$dst")"
    mv "$tmp_lf" "$dst"
    chmod +x "$dst"
    UPDATED_ANY=1
    echo "[+] Обновлён: ${dst}"
}

install_default_config() {
    rel_path="$1"
    non_interactive="$2"
    dst="${OPT_DIR}/${rel_path}"
    url="${RAW_BASE}/${rel_path}"

    if [ -f "$dst" ]; then
        if [ "$non_interactive" = "1" ]; then
            echo "[=] Конфиг сохранён (существует): ${dst}"
            return 0
        fi
        if ! ask_yes_no "Конфиг ${dst} уже существует. Перезаписать дефолтным?" "no"; then
            echo "[=] Конфиг оставлен без изменений: ${dst}"
            return 0
        fi
    fi

    mkdir -p "$TMP_DIR" "$(dirname "$dst")"
    tmp_cfg="${TMP_DIR}/$(basename "$rel_path").cfg"
    if ! curl -fsSL --connect-timeout 10 --max-time 30 "$url" -o "$tmp_cfg"; then
        echo "[E] Не удалось скачать конфиг: ${url}" >&2
        rm -f "$tmp_cfg"
        return 1
    fi

    tr -d '\r' < "$tmp_cfg" > "$dst"
    rm -f "$tmp_cfg"
    echo "[+] Установлен конфиг: ${dst}"
}

set_ppe() {
    mode="$1" # off | on
    if ! command -v ndmq >/dev/null 2>&1; then
        echo "[W] Утилита ndmq недоступна, пропуск настройки PPE."
        return 0
    fi
    if [ "$mode" = "off" ]; then
        ndmq -p "no ppe hardware" >/dev/null 2>&1
        ndmq -p "no ppe software" >/dev/null 2>&1
        ndmq -p "system configuration save" >/dev/null 2>&1
        echo "[I] Сетевой ускоритель PPE отключён (hardware/software)."
    else
        ndmq -p "ppe hardware" >/dev/null 2>&1
        ndmq -p "ppe software" >/dev/null 2>&1
        ndmq -p "system configuration save" >/dev/null 2>&1
        echo "[I] Сетевой ускоритель PPE включён (hardware/software)."
    fi
}

update_cron_tasks() {
    parse_sched="$1"
    update_sched="$2"

    [ -x /opt/etc/init.d/S10cron ] && /opt/etc/init.d/S10cron start >/dev/null 2>&1 || true

    current="$(crontab -l 2>/dev/null | grep -v '# singkeen:' | grep -v 'singkeen\.sh update' | grep -v '/opt/bin/sb parse' || true)"
    new_cron="$current"

    if [ -n "$parse_sched" ]; then
        line="${parse_sched} ${SB_LINK} parse >/dev/null 2>&1 # singkeen:parse"
        if [ -n "$new_cron" ]; then
            new_cron="$(printf '%s\n%s' "$new_cron" "$line")"
        else
            new_cron="$line"
        fi
    fi

    if [ -n "$update_sched" ]; then
        line="${update_sched} ${SELF_PATH} update >/dev/null 2>&1 # singkeen:update"
        if [ -n "$new_cron" ]; then
            new_cron="$(printf '%s\n%s' "$new_cron" "$line")"
        else
            new_cron="$line"
        fi
    fi

    if [ -n "$new_cron" ]; then
        printf '%s\n' "$new_cron" | crontab -
    else
        crontab -r 2>/dev/null || true
    fi
    echo "[I] Задачи cron обновлены."
}

choose_parse_schedule() {
    echo ""
    echo "Как часто обновлять подписки (sb parse)?"
    echo "  1) Каждые 6 часов"
    echo "  2) Каждые 12 часов"
    echo "  3) Раз в сутки в 04:00 (по умолчанию)"
    echo "  4) Раз в неделю (воскресенье 04:00)"
    echo "  5) Не обновлять автоматически"
    printf "Выбор [3]: "
    read_tty choice
    case "$choice" in
        1) PARSE_CRON="0 */6 * * *" ;;
        2) PARSE_CRON="0 */12 * * *" ;;
        ""|3) PARSE_CRON="0 4 * * *" ;;
        4) PARSE_CRON="0 4 * * 0" ;;
        5) PARSE_CRON="" ;;
        *) PARSE_CRON="$DEFAULT_PARSE_CRON" ;;
    esac
}

choose_autoupdate_schedule() {
    echo ""
    if ! ask_yes_no "Включить автообновление sing-box и скриптов (singkeen.sh update)?" "no"; then
        AUTOUPDATE_CRON=""
        return 0
    fi
    echo "Как часто проверять обновления?"
    echo "  1) Раз в сутки в 04:30"
    echo "  2) Раз в неделю (воскресенье 04:30, по умолчанию)"
    echo "  3) Раз в месяц (1-го числа в 04:30)"
    printf "Выбор [2]: "
    read_tty choice
    case "$choice" in
        1) AUTOUPDATE_CRON="30 4 * * *" ;;
        ""|2) AUTOUPDATE_CRON="30 4 * * 0" ;;
        3) AUTOUPDATE_CRON="30 4 1 * *" ;;
        *) AUTOUPDATE_CRON="$DEFAULT_AUTOUPDATE_CRON" ;;
    esac
}

do_install() {
    non_interactive="${1:-0}"
    echo "=== Установка / Переустановка singkeen ==="
    check_entware
    check_netfilter_modules
    install_dependencies

    mkdir -p "$CONF_DIR" "$LOG_DIR" "/opt/etc/ndm/netfilter.d" "/opt/etc/init.d" "/opt/bin"

    install_or_update_singbox || exit 1

    for rel in $MANAGED_SCRIPTS; do
        sync_script_file "$rel" || exit 1
    done

    for rel in $DEFAULT_CONFIGS; do
        install_default_config "$rel" "$non_interactive" || exit 1
    done

    ln -sf "$INIT_SCRIPT" "$SB_LINK"
    echo "[I] Симлинк обновлён: ${SB_LINK} -> ${INIT_SCRIPT}"

    # Сброс и принудительный поиск метки политики SingBox
    if [ -x "$NETFILTER_HOOK" ]; then
        "$NETFILTER_HOOK" --refresh-mark || echo "[W] Создайте политику 'SingBox' в веб-интерфейсе Keenetic и перезапустите службу: sb restart"
    fi

    # Настройка PPE
    if [ "$non_interactive" = "1" ]; then
        [ "$DEFAULT_DISABLE_PPE" = "yes" ] && set_ppe "off"
    else
        echo ""
        echo "Внимание: для стабильной работы REDIRECT+TPROXY рекомендуется отключить PPE."
        echo "На гигабитных тарифах это может снизить потолок прямой маршрутизации на CPU роутера."
        if ask_yes_no "Отключить ppe hardware и ppe software?" "$DEFAULT_DISABLE_PPE"; then
            set_ppe "off"
        fi
    fi

    # Настройка cron
    if [ "$non_interactive" = "1" ]; then
        PARSE_CRON="$DEFAULT_PARSE_CRON"
        AUTOUPDATE_CRON="$DEFAULT_AUTOUPDATE_CRON"
    else
        choose_parse_schedule
        choose_autoupdate_schedule
    fi
    update_cron_tasks "$PARSE_CRON" "$AUTOUPDATE_CRON"

    # Включение автозапуска и старт, если конфиг валиден
    "$SB_LINK" enable >/dev/null 2>&1 || true
    if "$SINGBOX_BIN" check -c "${CONF_DIR}/config.json" -D "$CONF_DIR" >/dev/null 2>&1; then
        "$SB_LINK" restart
    else
        echo "[W] Конфигурация не прошла проверку (вероятно, нужно добавить подписки в ${CONF_DIR}/subs.txt и выполнить 'sb parse')."
    fi

    echo "=== Установка завершена ==="
}

do_update() {
    echo "=== Обновление singkeen ==="
    check_entware
    UPDATED_ANY=0

    install_or_update_singbox || exit 1

    for rel in $MANAGED_SCRIPTS; do
        sync_script_file "$rel" || exit 1
    done

    ln -sf "$INIT_SCRIPT" "$SB_LINK"

    # Принудительное обновление кэша метки политики
    if [ -x "$NETFILTER_HOOK" ]; then
        "$NETFILTER_HOOK" --refresh-mark || echo "[W] Не удалось обновить метку политики SingBox."
    fi

    if [ "$UPDATED_ANY" = "1" ]; then
        if [ -n "$(pidof sing-box)" ]; then
            echo "[I] Перезапуск sing-box для применения обновлений..."
            "$SB_LINK" restart
        else
            echo "[I] Обновления установлены (служба sing-box сейчас остановлена)."
        fi
    else
        if [ -n "$(pidof sing-box)" ] && [ -x "$NETFILTER_HOOK" ]; then
            table=nat type=iptables "$NETFILTER_HOOK"
            table=mangle type=iptables "$NETFILTER_HOOK"
        fi
        echo "[=] Все компоненты актуальны, перезапуск не требуется."
    fi
}

do_remove() {
    non_interactive="${1:-0}"
    echo "=== Удаление singkeen ==="

    if [ "$non_interactive" != "1" ]; then
        if ! ask_yes_no "Удалить sing-box, скрипты, конфигурации, логи и задачи cron?" "no"; then
            echo "Отменено."
            exit 0
        fi
    fi

    # 1. Остановка службы (автоматически закрывает активные сокеты)
    if [ -x "$INIT_SCRIPT" ]; then
        "$INIT_SCRIPT" stop >/dev/null 2>&1 || true
    fi
    killall sing-box 2>/dev/null || true

    # 2. Сброс правил netfilter и таблицы TPROXY
    if command -v iptables >/dev/null 2>&1; then
        while iptables -w -t nat -D PREROUTING -j SINGBOX_TCP 2>/dev/null; do :; done
        iptables -w -t nat -F SINGBOX_TCP 2>/dev/null || true
        iptables -w -t nat -X SINGBOX_TCP 2>/dev/null || true

        while iptables -w -t mangle -D PREROUTING -j SINGBOX_UDP 2>/dev/null; do :; done
        iptables -w -t mangle -F SINGBOX_UDP 2>/dev/null || true
        iptables -w -t mangle -X SINGBOX_UDP 2>/dev/null || true
    fi
    while ip rule del fwmark 0x1 table 101 2>/dev/null; do :; done
    ip route flush table 101 2>/dev/null || true

    # 3. Очистка задач cron
    if command -v crontab >/dev/null 2>&1; then
        clean_cron="$(crontab -l 2>/dev/null | grep -v '# singkeen:' | grep -v 'singkeen\.sh update' | grep -v '/opt/bin/sb parse' || true)"
        if [ -n "$clean_cron" ]; then
            printf '%s\n' "$clean_cron" | crontab -
        else
            crontab -r 2>/dev/null || true
        fi
    fi

    # 4. Удаление файлов и директорий (пакеты opkg не трогаем)
    rm -f "$SINGBOX_BIN" "$SB_LINK" "$INIT_SCRIPT" "$NETFILTER_HOOK" "$MARK_CACHE" "/opt/bin/singbox-subs-parser.py"
    rm -rf "$CONF_DIR" "$LOG_DIR"
    rm -f "$SELF_PATH"

    # 5. Восстановление PPE
    if [ "$non_interactive" = "1" ]; then
        [ "$DEFAULT_ENABLE_PPE_ON_REMOVE" = "yes" ] && set_ppe "on"
    else
        if ask_yes_no "Включить ppe hardware и ppe software обратно?" "$DEFAULT_ENABLE_PPE_ON_REMOVE"; then
            set_ppe "on"
        fi
    fi

    echo "=== Удаление завершено (установленные пакеты opkg сохранены) ==="
}

show_menu() {
    echo "=============================="
    echo "     singkeen installer"
    echo "=============================="
    echo "  1) Установить / Переустановить"
    echo "  2) Обновить"
    echo "  3) Удалить"
    echo "  0) Выход"
    echo "=============================="
    printf "Выберите действие [1-3, 0]: "
    read_tty action
    case "$action" in
        1) do_install 0 ;;
        2) do_update ;;
        3) do_remove 0 ;;
        0) exit 0 ;;
        *) echo "Неверный выбор." >&2; exit 1 ;;
    esac
}

case "${1:-}" in
    install) do_install 1 ;;
    update)  do_update ;;
    remove)  do_remove 1 ;;
    "")      show_menu ;;
    *)
        echo "Использование: $0 [install|update|remove]" >&2
        exit 1
        ;;
esac