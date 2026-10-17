#!/usr/bin/env bash
# Bootstrap a new Ubuntu VPS. Credentials are created by broker, never printed.
set -Eeuo pipefail
umask 077

SOURCE_COMMIT=6e75e0975ed51cc1621d1a611e4e31de9db5de17
SOURCE_URL=https://github.com/teplydom12-boop/remote222.git
CERTBOT_VERSION=5.8.0
BASE=/opt/remote222
STATE=/var/lib/remote222
CONFIG=/etc/remote222-vps
VENV=/opt/remote222-certbot
WEBROOT=/var/www/letsencrypt
SITE=/etc/nginx/sites-available/remote222-vps
CONTAINER=remote222-broker
IMAGE=remote222-broker:v0.3.0
MARKER='remote222-vps-installer-v1'
EMAIL=''
PREFLIGHT_ONLY=0

say() { printf '\n%s\n' "$*"; }
die() { printf '\nОшибка: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
Новый VPS Ubuntu 22.04/24.04, запуск от root:
  PUBLIC_IP=95.163.231.24 bash scripts/install_vps.sh [--email адрес]
  PUBLIC_IP=95.163.231.24 bash scripts/install_vps.sh --preflight-only

Устанавливает Docker, nginx, Certbot 5.8 и Remote222 с публичным HTTPS по IP.
Нужны входящие TCP 80/443 и исходящий HTTPS. SSH и правила firewall не меняются.
Повторный запуск сохраняет ключи и базу. Значения ключей не выводятся.
--preflight-only выполняет только локальные проверки, без установки и ACME.
HELP
}
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --preflight-only) PREFLIGHT_ONLY=1; shift ;;
        --email) (($# >= 2)) || die 'После --email нужен адрес.'; EMAIL=$2; shift 2 ;;
        *) die "Неизвестный параметр: $1" ;;
    esac
done
[[ $EUID == 0 ]] || die 'Запустите скрипт от root в консоли VPS.'
[[ -n ${PUBLIC_IP:-} ]] || die 'Укажите PUBLIC_IP — публичный IPv4 вашего VPS.'
command -v python3 >/dev/null || die 'На VPS отсутствует python3.'
python3 - "$PUBLIC_IP" <<'PY' || die 'PUBLIC_IP должен быть публичным IPv4.'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
if address.version != 4 or not address.is_global:
    sys.exit(1)
PY
[[ -z $EMAIL || ( $EMAIL == *@*.* && $EMAIL != -* && $EMAIL != *[[:space:]]* ) ]] || die 'Некорректный --email.'
[[ -r /etc/os-release ]] || die 'Не удалось определить ОС.'
# /etc/os-release is system-owned configuration, not user-supplied input.
# shellcheck source=/dev/null
. /etc/os-release
[[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 ) ]] || die 'Поддерживается только Ubuntu 22.04 или 24.04.'
[[ $(ps -p 1 -o comm=) == systemd ]] || die 'Нужна обычная Ubuntu с systemd.'
command -v ss >/dev/null || die 'Отсутствует ss (пакет iproute2).'

RESUME=0
if [[ -f $CONFIG/installation ]]; then
    [[ $(head -n 1 "$CONFIG/installation") == "$MARKER" ]] || die "Неизвестный файл $CONFIG/installation."
    grep -Fxq -- "PUBLIC_IP=$PUBLIC_IP" "$CONFIG/installation" || die 'Установка относится к другому IP; автоматическая миграция запрещена.'
    RESUME=1
else
    for path in "$CONFIG" "$BASE" "$STATE" "$VENV" "$WEBROOT" /etc/nginx /etc/apache2 /etc/caddy /etc/letsencrypt /etc/docker /var/lib/docker /etc/systemd/system/remote222-cert-renew.service /etc/systemd/system/remote222-cert-renew.timer; do
        [[ ! -e $path && ! -L $path ]] || die "Уже существует $path. Нужен новый VPS; существующие данные не заменяются."
    done
    ! command -v docker >/dev/null || die 'Docker уже установлен; чужие контейнеры и daemon не будут изменены.'
    [[ -z $(ss -H -ltn '( sport = :80 or sport = :443 or sport = :8770 )') ]] || die 'Порт 80, 443 или 8770 уже занят.'
fi
for path in "$CONFIG" "$BASE" "$STATE" "$VENV" "$WEBROOT" "$SITE" "$CONFIG/reload-nginx"; do
    [[ ! -L $path ]] || die "Символическая ссылка $path не будет использована как каталог или файл установки."
done
if [[ -e $CONFIG/reload-nginx ]]; then
    [[ $(sed -n '2p' "$CONFIG/reload-nginx") == "# Managed by $MARKER" ]] || die 'Hook обновления nginx не принадлежит установщику.'
fi
for path in "$SITE" /etc/systemd/system/remote222-cert-renew.service /etc/systemd/system/remote222-cert-renew.timer; do
    [[ ! -L $path ]] || die "Сторонняя ссылка $path не будет заменена."
    [[ ! -e $path || $(head -n 1 "$path") == "# Managed by $MARKER" ]] || die "Файл $path не принадлежит установщику."
done
if command -v docker >/dev/null && docker inspect "$CONTAINER" >/dev/null 2>&1; then
    [[ $RESUME == 1 && $(docker inspect -f '{{ index .Config.Labels "io.remote222.installer" }}' "$CONTAINER") == "$MARKER" ]] || die "Контейнер $CONTAINER уже занят другой установкой."
    [[ $(docker inspect -f '{{json .Config.Cmd}}' "$CONTAINER") == '["python","-m","remote222.broker","--host","127.0.0.1","--port","8770","--state-dir","/var/data/remote222"]' ]] || die 'Команда контейнера изменена; автоматическая замена запрещена.'
    [[ $(docker inspect -f '{{.Config.Image}}' "$CONTAINER") == "$IMAGE" ]] || die 'Контейнер использует другой образ.'
    [[ $(docker inspect -f '{{.Image}}' "$CONTAINER") == $(docker image inspect -f '{{.Id}}' "$IMAGE") ]] || die 'Образ работающего контейнера отличается от установленного.'
    docker inspect -f '{{json .Mounts}}' "$CONTAINER" | python3 -c 'import json,sys; m=json.load(sys.stdin); sys.exit(not(len(m)==1 and m[0]["Type"]=="bind" and m[0]["Source"]=="/var/lib/remote222" and m[0]["Destination"]=="/var/data/remote222" and m[0]["RW"]))' || die 'Каталог данных контейнера отличается от установленного.'
    [[ $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}' "$CONTAINER") == 'true ["ALL"] ["no-new-privileges"]' ]] || die 'Защитные настройки контейнера изменены.'
fi
if [[ $RESUME == 1 ]] && command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    others=$(docker ps -a --format '{{.Names}}' | grep -Fxv "$CONTAINER" || true)
    [[ -z $others ]] || die 'Обнаружены другие Docker-контейнеры; установка не будет менять их daemon.'
fi
if [[ $RESUME == 1 && -d /etc/nginx ]]; then
    if [[ -f $CONFIG/nginx-main.sha256 ]]; then
        sha256sum --status -c "$CONFIG/nginx-main.sha256" || die 'Основная конфигурация nginx изменена; автоматическая перезапись запрещена.'
    fi
    for path in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*; do
        [[ -e $path || -L $path ]] || continue
        case "$path" in
            /etc/nginx/sites-enabled/remote222-vps) [[ $(readlink "$path") == "$SITE" ]] || die 'Неожиданная конфигурация nginx.' ;;
            /etc/nginx/sites-enabled/default) [[ $(readlink "$path") == /etc/nginx/sites-available/default ]] || die 'Неожиданная конфигурация nginx.' ;;
            *) die "Обнаружена сторонняя конфигурация $path. Она не будет изменена." ;;
        esac
    done
    listeners=$(ss -H -ltnp '( sport = :80 or sport = :443 )')
    [[ -z $listeners ]] || ! grep -qv '"nginx"' <<< "$listeners" || die 'На порту 80 или 443 работает сторонняя служба.'
fi
if [[ -n $(ss -H -ltn '( sport = :8770 )') ]]; then
    command -v docker >/dev/null && [[ $(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null) == true ]] || die 'Порт 8770 занят вне работающего контейнера этой установки.'
    broker_pid=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
    listeners=$(ss -H -ltnp '( sport = :8770 )')
    [[ $listeners != *$'\n'* && $listeners == *'127.0.0.1:8770'* && $listeners == *"pid=$broker_pid,"* ]] || die 'Порт 8770 слушает другой процесс или публичный интерфейс.'
fi
say "Локальная проверка завершена: Ubuntu $VERSION_ID, IP $PUBLIC_IP."
say 'На стороне REG.RU и ОС должны быть разрешены TCP 80/443. Скрипт не открывает порты и не меняет SSH.'
if [[ $PREFLIGHT_ONLY == 1 ]]; then
    say 'Проверка завершена без изменений. Доступность IP извне и выпуск сертификата ещё не проверены.'
    exit 0
fi
trap 'printf "\nУстановка остановлена на строке %s. Ключи и база сохранены. Исправьте причину и повторите ту же команду.\n" "$LINENO" >&2' ERR
install -d -m 700 "$CONFIG" "$STATE"
if [[ ! -f $CONFIG/installation ]]; then
    printf '%s\nPUBLIC_IP=%s\n' "$MARKER" "$PUBLIC_IP" > "$CONFIG/installation"
fi

say 'Устанавливаю зависимости из репозиториев Ubuntu.'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl git docker.io nginx python3-venv
systemctl enable --now docker
install -d -m 755 "$BASE" "$WEBROOT"
if [[ ! -f $CONFIG/nginx-main.sha256 ]]; then
    sha256sum /etc/nginx/nginx.conf > "$CONFIG/nginx-main.sha256"
fi
# This default link was supplied by the nginx package during our installation.
if [[ -L /etc/nginx/sites-enabled/default ]]; then
    mv /etc/nginx/sites-enabled/default "$CONFIG/nginx-default.link"
fi

say 'Получаю проверенную версию Remote222.'
if [[ ! -d $BASE/src/.git ]]; then
    [[ ! -e $BASE/src ]] || die "Каталог $BASE/src уже существует, но не является нашим checkout."
    git init "$BASE/src"
    git -C "$BASE/src" remote add origin "$SOURCE_URL"
fi
[[ $(git -C "$BASE/src" remote get-url origin) == "$SOURCE_URL" ]] || die 'Неожиданный источник кода.'
[[ -z $(git -C "$BASE/src" status --porcelain) ]] || die 'Исходники изменены; они не будут перезаписаны.'
git -C "$BASE/src" fetch --depth 1 origin "$SOURCE_COMMIT"
[[ $(git -C "$BASE/src" rev-parse FETCH_HEAD) == "$SOURCE_COMMIT" ]] || die 'Хеш исходников не совпал.'
git -C "$BASE/src" checkout --detach "$SOURCE_COMMIT"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build --pull --label "io.remote222.installer=$MARKER" --label "io.remote222.source=$SOURCE_COMMIT" -t "$IMAGE" "$BASE/src"
fi
[[ $(docker image inspect -f '{{ index .Config.Labels "io.remote222.installer" }}' "$IMAGE") == "$MARKER" ]] || die 'Docker-образ не принадлежит установщику.'
[[ $(docker image inspect -f '{{ index .Config.Labels "io.remote222.source" }}' "$IMAGE") == "$SOURCE_COMMIT" ]] || die 'Существующий Docker-образ относится к другой версии.'
if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    docker run -d --name "$CONTAINER" --label "io.remote222.installer=$MARKER" \
        --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
        --restart unless-stopped --log-driver local --log-opt max-size=5m --log-opt max-file=2 \
        --mount "type=bind,src=$STATE,dst=/var/data/remote222" \
        "$IMAGE" python -m remote222.broker --host 127.0.0.1 --port 8770 --state-dir /var/data/remote222 >/dev/null
else
    [[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CONTAINER") == host ]] || die 'Неожиданный сетевой режим контейнера.'
    docker start "$CONTAINER" >/dev/null
fi
healthy=0
for _ in {1..30}; do
    if curl --silent --fail --max-time 2 http://127.0.0.1:8770/healthz | python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(r!={"ok": True, "service": "remote222-broker"})' 2>/dev/null; then
        healthy=1; break
    fi
    sleep 1
done
[[ $healthy == 1 ]] || die 'Broker не ответил. Проверьте docker logs remote222-broker; ключи в журнал не выводятся.'
say 'Broker отвечает локально. Порт 8770 не публикуется Docker и слушает только 127.0.0.1.'

say 'Устанавливаю Certbot в отдельное окружение Python.'
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --disable-pip-version-check "certbot==$CERTBOT_VERSION"
cat > "$CONFIG/reload-nginx" <<HOOK
#!/bin/sh
# Managed by $MARKER
set -eu
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
HOOK
chmod 700 "$CONFIG/reload-nginx"

write_site() {
    local mode=$1 previous had_previous=0
    previous=$(mktemp "$CONFIG/nginx-previous.XXXXXX")
    if [[ -f $SITE ]]; then cp "$SITE" "$previous"; had_previous=1; fi
    cat > "$SITE" <<NGINX
# Managed by $MARKER
server {
    listen 80 default_server;
    server_name $PUBLIC_IP;
    access_log off;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
NGINX
    if [[ $mode == tls ]]; then
        cat >> "$SITE" <<NGINX
    location / { return 301 https://$PUBLIC_IP\$request_uri; }
}
server {
    listen 443 ssl default_server;
    server_name $PUBLIC_IP;
    ssl_certificate /etc/letsencrypt/live/remote222-ip/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/remote222-ip/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 12m;
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:8770;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 30s;
    }
}
NGINX
    else
        printf '    location / { return 503; }\n}\n' >> "$SITE"
    fi
    chmod 644 "$SITE"
    if [[ ! -L /etc/nginx/sites-enabled/remote222-vps ]]; then
        ln -s "$SITE" /etc/nginx/sites-enabled/remote222-vps
    fi
    if ! nginx -t; then
        if [[ $had_previous == 1 ]]; then cp "$previous" "$SITE"; else rm "$SITE" /etc/nginx/sites-enabled/remote222-vps; fi
        die 'nginx отклонил конфигурацию; предыдущий файл восстановлен.'
    fi
    rm "$previous"
    systemctl enable --now nginx
    systemctl reload nginx
}
if [[ -f /etc/letsencrypt/live/remote222-ip/fullchain.pem ]]; then
    write_site tls
else
    write_site http
fi
say 'Запрашиваю HTTPS-сертификат для IP. TCP 80 должен быть доступен из интернета.'
email_args=(--register-unsafely-without-email)
[[ -z $EMAIL ]] || email_args=(--email "$EMAIL")
"$VENV/bin/certbot" certonly --non-interactive --agree-tos "${email_args[@]}" \
    --webroot --webroot-path "$WEBROOT" --ip-address "$PUBLIC_IP" \
    --required-profile shortlived --cert-name remote222-ip \
    --deploy-hook "$CONFIG/reload-nginx"
write_site tls

cat > /etc/systemd/system/remote222-cert-renew.service <<UNIT
# Managed by $MARKER
[Unit]
Description=Renew Remote222 IP certificate
Wants=network-online.target
After=network-online.target nginx.service

[Service]
Type=oneshot
ExecStart=$VENV/bin/certbot renew --quiet --cert-name remote222-ip --deploy-hook $CONFIG/reload-nginx
UNIT
cat > /etc/systemd/system/remote222-cert-renew.timer <<UNIT
# Managed by $MARKER
[Unit]
Description=Check Remote222 IP certificate twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
UNIT
chmod 644 /etc/systemd/system/remote222-cert-renew.{service,timer}
systemctl daemon-reload
systemctl enable --now remote222-cert-renew.timer
curl --fail --silent --show-error --max-time 15 --resolve "$PUBLIC_IP:443:127.0.0.1" "https://$PUBLIC_IP/healthz" | \
    python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if r=={"ok": True, "service": "remote222-broker"} else 1)'
say "Готово: https://$PUBLIC_IP"
say "Ключ контроллера: $STATE/controller.token; ключ Windows: $STATE/worker.token. Значения не показаны."
say 'Скопируйте ключи самостоятельно в защищённые поля настроек. Не отправляйте их в чат.'
say 'Проверка обновления сертификата: systemctl list-timers remote222-cert-renew.timer'
say 'Осталось проверить /healthz из Windows и облачной среды, затем подключить новый Remote222.exe.'
