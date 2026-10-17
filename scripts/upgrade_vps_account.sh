#!/usr/bin/env bash
# Upgrade only the VPS previously created by install_vps.sh.
set -Eeuo pipefail
umask 077

# Reviewed v0.4.0 application source; upgrades never track a moving branch.
SOURCE_COMMIT=c3e9428e08ca8b67ad2117eeaabb06b98d8ca98a
PREVIOUS_COMMIT=6e75e0975ed51cc1621d1a611e4e31de9db5de17
SOURCE_URL=https://github.com/teplydom12-boop/remote222.git
IMAGE=remote222-broker:v0.4.0
CONTAINER=remote222-broker
OLD_CONTAINER=remote222-broker-before-account
STATE=/var/lib/remote222
CONFIG=/etc/remote222-vps
UPGRADE=$CONFIG/account-upgrade
SOURCE=/opt/remote222/account-src
SITE=/etc/nginx/sites-available/remote222-vps
SERVICE=/etc/systemd/system/remote222-cert-renew.service
TIMER=/etc/systemd/system/remote222-cert-renew.timer
CERTBOT=/opt/remote222-certbot/bin/certbot
WEBROOT=/var/www/letsencrypt
MARKER=remote222-vps-installer-v1
UPGRADE_MARKER=remote222-account-upgrade-v1
PUBLIC_HOST=${PUBLIC_HOST:-95-163-231-24.sslip.io}
PREFLIGHT_ONLY=0
ROLLBACK=0
SWITCHING=0

say() { printf '\n%s\n' "$*"; }
atomic_write() {
    local target=$1 mode=${2:-600} temporary
    temporary=$(mktemp "${target}.tmp.XXXXXX") || return 1
    if ! cat > "$temporary" || ! chmod "$mode" "$temporary" || ! mv -fT "$temporary" "$target"; then
        rm -f "$temporary"
        return 1
    fi
}
atomic_copy() {
    local source=$1 target=$2 mode=${3:-600} temporary
    temporary=$(mktemp "${target}.tmp.XXXXXX") || return 1
    if ! cp "$source" "$temporary" || ! chmod "$mode" "$temporary" || ! mv -fT "$temporary" "$target"; then
        rm -f "$temporary"
        return 1
    fi
}
wait_for_account_https() {
    # nginx reload signals its master; new workers/certificates become ready later.
    # Retry read-only probes, retaining normal TLS verification on every attempt.
    local deadline=$((SECONDS + ${1:-30})) temporary endpoint ready
    temporary=$(mktemp -d) || return 1
    while :; do
        ready=1
        for endpoint in healthz auth/v1/meta; do
            if ! curl --fail --silent --show-error --connect-timeout 2 --max-time 3 \
                --resolve "$PUBLIC_HOST:443:127.0.0.1" "https://$PUBLIC_HOST/$endpoint" \
                --output "$temporary/body" 2> "$temporary/error"; then
                ready=0
                break
            fi
            if ! python3 - "$temporary/body" "$endpoint" <<'PY'
import json, sys
expected = {"ok": True, "service": "remote222-broker"} if sys.argv[2] == 'healthz' else {"ok": True, "configured": True}
try:
    with open(sys.argv[1], encoding='utf-8') as stream:
        valid = json.load(stream) == expected
except (OSError, ValueError):
    valid = False
sys.exit(0 if valid else 1)
PY
            then
                printf 'HTTPS ответил, но /%s не подтвердил готовность сервера.\n' "$endpoint" > "$temporary/error"
                ready=0
                break
            fi
        done
        if [[ $ready == 1 ]]; then
            rm -rf "$temporary"
            return 0
        fi
        if ((SECONDS >= deadline)); then
            cat "$temporary/error" >&2
            rm -rf "$temporary"
            return 1
        fi
        sleep 1
    done
}
configure_account_https() {
    atomic_write "$SITE" 644 <<NGINX
# Managed by $MARKER
server {
    listen 80 default_server;
    server_name $PUBLIC_HOST;
    access_log off;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://$PUBLIC_HOST\$request_uri; }
}
server {
    listen 443 ssl default_server;
    server_name $PUBLIC_HOST;
    ssl_certificate /etc/letsencrypt/live/remote222-account/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/remote222-account/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 12m;
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:8770;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header Connection "";
        # Correct browser form navigation for the pinned v0.4.0 broker as well.
        proxy_hide_header Referrer-Policy;
        add_header Referrer-Policy same-origin always;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 30s;
    }
}
NGINX
    nginx -t
    systemctl reload nginx
    say 'Ожидаю применения HTTPS-конфигурации nginx…'
    wait_for_account_https || die 'HTTPS не подтвердил готовность после перезагрузки nginx. Исправьте указанную ошибку и повторите запуск.'
}
die() {
    printf '\nОшибка: %s\n' "$*" >&2
    if [[ $SWITCHING == 1 ]]; then on_error; fi
    exit 1
}
usage() {
    cat <<'HELP'
В root-консоли VPS, уже установленного через install_vps.sh:
  bash upgrade_vps_account.sh
  bash upgrade_vps_account.sh --preflight-only
  bash upgrade_vps_account.sh --rollback

По умолчанию: 95-163-231-24.sslip.io. Свой адрес: PUBLIC_HOST=ваше.имя bash upgrade_vps_account.sh.
DNS должен указывать на публичный IPv4 этой установки.
Установка предложит создать логин и пароль в приватной консоли.
Пароль не передаётся в аргументах, окружении или журнале.
--preflight-only: локальные проверки и DNS; без изменения VPS и ACME.
--rollback: вернуть прежний контейнер и старые ключи доступа без очистки базы.
HELP
}
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --preflight-only) PREFLIGHT_ONLY=1; shift ;;
        --rollback) ROLLBACK=1; shift ;;
        *) die "Неизвестный параметр: $1" ;;
    esac
done
[[ $EUID == 0 ]] || die 'Откройте root-консоль VPS.'
[[ $SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] || die 'Этот черновик ещё не закреплён на проверенном исходном коммите. Не запускайте установку из черновика.'
[[ -n ${PUBLIC_HOST:-} ]] || die 'Задайте PUBLIC_HOST — подтверждённое DNS-имя вашего сервера.'
[[ $PREFLIGHT_ONLY == 0 || $ROLLBACK == 0 ]] || die '--preflight-only и --rollback нельзя объединять.'
for command in python3 docker git curl nginx systemctl ss openssl; do
    command -v "$command" >/dev/null || die "Не найдена команда $command; требуется существующая установка Remote222."
done
[[ -f $CONFIG/installation && ! -L $CONFIG/installation ]] || die 'Нет маркера прежней установки.'
[[ $(head -n 1 "$CONFIG/installation") == "$MARKER" ]] || die 'Неизвестный маркер установки.'
PUBLIC_IP=$(sed -n 's/^PUBLIC_IP=//p' "$CONFIG/installation")
python3 - "$PUBLIC_HOST" "$PUBLIC_IP" "$ROLLBACK" <<'PY' || die 'DNS-имя должно разрешаться только в публичный IPv4 этой установки.'
import ipaddress, re, socket, sys
host, expected, rollback = sys.argv[1:]
try:
    address = ipaddress.ip_address(expected)
    assert address.version == 4 and address.is_global
    assert len(host) <= 253 and host == host.lower() and '.' in host
    assert all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in host.split('.'))
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError('DNS name required')
    if rollback != '1':
        resolved = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        assert resolved == {expected}
except (AssertionError, ValueError, OSError):
    sys.exit(1)
PY
# shellcheck source=/dev/null
. /etc/os-release
[[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 ) ]] || die 'Поддерживается Ubuntu 22.04/24.04.'
for path in "$STATE" "$CONFIG" "$UPGRADE" "$SOURCE" "$SITE" "$SERVICE" "$TIMER" "$CERTBOT" "$CONFIG/reload-nginx"; do
    [[ ! -L $path ]] || die "Символическая ссылка $path не будет использована для обновления."
done
for path in "$STATE"/{broker.sqlite3,auth.sqlite3,controller.token,worker.token} "$UPGRADE"/{installation,previous.nginx,previous.service,previous.timer,broker-before-account.sqlite3,switching,completed,account-prompt-started,account-configured,rolled-back,rolled-back-switching}; do
    [[ ! -L $path ]] || die "Символическая ссылка $path не будет использована как файл состояния."
done
[[ -x $CERTBOT && -x $CONFIG/reload-nginx ]] || die 'Certbot или hook nginx отсутствует.'
[[ $(sed -n '2p' "$CONFIG/reload-nginx") == "# Managed by $MARKER" ]] || die 'Неизвестный hook nginx.'
[[ -d $STATE && -f $STATE/broker.sqlite3 && -f $STATE/controller.token && -f $STATE/worker.token ]] || die 'Данные прежнего broker не найдены; новая база не будет создана вместо них.'
[[ $(readlink /etc/nginx/sites-enabled/remote222-vps) == "$SITE" ]] || die 'Неизвестная схема подключения nginx.'
if [[ ! -f $CONFIG/nginx-main.sha256 ]] || ! sha256sum --status -c "$CONFIG/nginx-main.sha256"; then
    die 'Основная конфигурация nginx отличается от установленной.'
fi
for path in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*; do
    [[ -e $path || -L $path ]] || continue
    [[ $path == /etc/nginx/sites-enabled/remote222-vps ]] || die "Обнаружена сторонняя конфигурация nginx: $path."
done
if [[ -e $UPGRADE ]]; then
    [[ -f $UPGRADE/installation && $(head -n 1 "$UPGRADE/installation") == "$UPGRADE_MARKER" ]] || die 'Неизвестный каталог обновления.'
    grep -Fxq "PUBLIC_HOST=$PUBLIC_HOST" "$UPGRADE/installation" || die 'Обновление относится к другому DNS-имени.'
    grep -Fxq "SOURCE_COMMIT=$SOURCE_COMMIT" "$UPGRADE/installation" || die 'Обновление относится к другому исходному коммиту.'
else
    [[ ! -e $SOURCE ]] || die 'Каталог новых исходников уже существует без маркера обновления.'
fi
for kind in nginx service timer; do
    case "$kind" in nginx) path=$SITE ;; service) path=$SERVICE ;; timer) path=$TIMER ;; esac
    if [[ $ROLLBACK == 1 && -f $UPGRADE/installation ]]; then
        [[ -f $UPGRADE/previous.$kind && $(head -n 1 "$UPGRADE/previous.$kind") == "# Managed by $MARKER" ]] || die 'Нет проверенной резервной конфигурации для возврата.'
    else
        [[ -f $path && $(head -n 1 "$path") == "# Managed by $MARKER" ]] || die "Файл $path не принадлежит прежнему установщику."
    fi
done

owned_container() {
    local name=$1 expected_commit=$PREVIOUS_COMMIT image_id
    [[ $(docker inspect -f '{{ index .Config.Labels "io.remote222.installer" }}' "$name" 2>/dev/null) == "$MARKER" ]] || die "Контейнер $name не принадлежит установщику."
    if [[ $(docker inspect -f '{{ index .Config.Labels "io.remote222.account-upgrade" }}' "$name") == "$UPGRADE_MARKER" ]]; then expected_commit=$SOURCE_COMMIT; fi
    image_id=$(docker inspect -f '{{.Image}}' "$name")
    [[ $(docker image inspect -f '{{ index .Config.Labels "io.remote222.source" }}' "$image_id") == "$expected_commit" ]] || die 'Контейнер имеет неизвестную версию исходников.'
    docker inspect -f '{{json .Config.Cmd}}' "$name" | python3 -c 'import json,sys; expected=["python","-m","remote222.broker","--host","127.0.0.1","--port","8770","--state-dir","/var/data/remote222"]; expected += ["--public-url", "https://"+sys.argv[2], "--account-only"] if sys.argv[1]=="account" else []; sys.exit(json.load(sys.stdin)!=expected)' "$([[ $expected_commit == "$SOURCE_COMMIT" ]] && printf account || printf legacy)" "$PUBLIC_HOST" || die 'Команда контейнера изменена; автоматическая замена запрещена.'
    docker inspect -f '{{json .Mounts}}' "$name" | python3 -c 'import json,sys; m=json.load(sys.stdin); sys.exit(not(len(m)==1 and m[0]["Type"]=="bind" and m[0]["Source"]=="/var/lib/remote222" and m[0]["Destination"]=="/var/data/remote222" and m[0]["RW"]))' || die 'У контейнера неизвестный каталог данных.'
    [[ $(docker inspect -f '{{.HostConfig.NetworkMode}} {{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}' "$name") == 'host true ["ALL"] ["no-new-privileges"]' ]] || die 'Неожиданные параметры контейнера.'
}
if docker inspect "$CONTAINER" >/dev/null 2>&1; then owned_container "$CONTAINER"; fi
if docker inspect "$OLD_CONTAINER" >/dev/null 2>&1; then
    [[ -f $UPGRADE/installation ]] || die 'Имя резервного контейнера занято.'
    [[ $(docker inspect -f '{{ index .Config.Labels "io.remote222.account-upgrade" }}' "$OLD_CONTAINER") != "$UPGRADE_MARKER" ]] || die 'Резервный контейнер не является прежней версией.'
    owned_container "$OLD_CONTAINER"
fi
docker inspect "$CONTAINER" >/dev/null 2>&1 || docker inspect "$OLD_CONTAINER" >/dev/null 2>&1 || die 'Контейнер прежней установки не найден.'
if [[ $ROLLBACK == 0 ]] && ! nginx -t; then
    if [[ $PREFLIGHT_ONLY == 0 && -f $UPGRADE/switching && -f $UPGRADE/previous.nginx && $(head -n 1 "$UPGRADE/previous.nginx") == "# Managed by $MARKER" ]]; then
        say 'Восстанавливаю прежний файл nginx для продолжения. Старый broker и прежняя авторизация не запускаются.'
        atomic_copy "$UPGRADE/previous.nginx" "$SITE" 644
        nginx -t
        systemctl reload nginx
    else
        die 'nginx отклонил конфигурацию. Если обновление прерывалось, доступен явный --rollback.'
    fi
fi
say "Проверки завершены: $PUBLIC_HOST → $PUBLIC_IP. Данные и ключи останутся на VPS."
[[ $PREFLIGHT_ONLY == 0 ]] || exit 0

queue_idle() {
    python3 - "$STATE/broker.sqlite3" <<'PY'
import sqlite3, sys
with sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True) as db:
    busy = db.execute("SELECT 1 FROM jobs WHERE state IN ('queued','claimed') LIMIT 1").fetchone()
sys.exit(1 if busy else 0)
PY
}
account_configured() {
    python3 - "$STATE/auth.sqlite3" <<'PY'
import sqlite3, sys
try:
    with sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True) as db:
        ready = db.execute('SELECT 1 FROM account WHERE singleton=1').fetchone() is not None
except sqlite3.Error:
    ready = False
sys.exit(0 if ready else 1)
PY
}

restore_previous() {
    local failed=0
    [[ -f $UPGRADE/previous.nginx && -f $UPGRADE/previous.service && -f $UPGRADE/previous.timer ]] || return 1
    # Never remove a working new broker unless an actual old container survives.
    if ! docker inspect "$OLD_CONTAINER" >/dev/null 2>&1; then
        if ! docker inspect "$CONTAINER" >/dev/null 2>&1 || [[ $(docker inspect -f '{{ index .Config.Labels "io.remote222.account-upgrade" }}' "$CONTAINER") == "$UPGRADE_MARKER" ]]; then
            say 'Резервный контейнер прежней версии отсутствует. Работающий новый контейнер не изменён.'
            return 1
        fi
    fi
    if docker inspect "$CONTAINER" >/dev/null 2>&1 && [[ $(docker inspect -f '{{ index .Config.Labels "io.remote222.account-upgrade" }}' "$CONTAINER") == "$UPGRADE_MARKER" ]]; then
        docker stop "$CONTAINER" >/dev/null || failed=1
        docker rm "$CONTAINER" >/dev/null || failed=1
    fi
    if docker inspect "$OLD_CONTAINER" >/dev/null 2>&1; then
        docker rename "$OLD_CONTAINER" "$CONTAINER" || failed=1
    fi
    docker start "$CONTAINER" >/dev/null || failed=1
    atomic_copy "$UPGRADE/previous.nginx" "$SITE" 644 || failed=1
    atomic_copy "$UPGRADE/previous.service" "$SERVICE" 644 || failed=1
    atomic_copy "$UPGRADE/previous.timer" "$TIMER" 644 || failed=1
    systemctl daemon-reload || failed=1
    nginx -t && systemctl reload nginx || failed=1
    systemctl enable --now remote222-cert-renew.timer || failed=1
    return "$failed"
}
on_error() {
    trap - ERR INT TERM
    if [[ $SWITCHING == 1 ]]; then
        if [[ -f $UPGRADE/account-prompt-started ]]; then
            say 'Настройка аккаунта уже начата. Старый broker не запускается автоматически, чтобы не включать прежние ключи доступа.'
            say 'Повторите ту же команду для продолжения. Явный --rollback вернёт прежнюю систему ключей.'
        else
            say 'Ошибка переключения; возвращаю прежний контейнер и nginx без восстановления старой копии базы.'
            restore_previous || say 'Автоматический возврат не завершён. Резервные файлы и контейнер сохранены; проверьте состояние в консоли.'
        fi
    fi
    say 'Обновление остановлено. SQLite и ключи не удалялись. Исправьте причину и повторите запуск.'
    exit 1
}
if [[ $ROLLBACK == 1 ]]; then
    queue_idle || die 'Есть незавершённое задание. Дождитесь результата; возврат не очищает очередь.'
    say 'Возврат включает прежнюю авторизацию по ключам: v0.3.0 не использует аккаунт и подтверждения браузера.'
    restore_previous || die 'Не удалось полностью вернуть прежнюю конфигурацию.'
    [[ ! -f $UPGRADE/completed ]] || mv "$UPGRADE/completed" "$UPGRADE/rolled-back"
    [[ ! -f $UPGRADE/switching ]] || mv "$UPGRADE/switching" "$UPGRADE/rolled-back-switching"
    say 'Прежняя версия возвращена с текущей базой. Старые ключи не показываются; сертификат прежнего IP должен оставаться действительным.'
    exit 0
fi
[[ -t 0 && -t 1 ]] || die 'Запустите сохранённый файл в интерактивной root-консоли: пароль вводится локально.'
trap on_error ERR INT TERM
if [[ -f $UPGRADE/completed ]]; then
    account_configured || die 'База аккаунта недоступна. Прежние ключи не включаются; восстановите приватную базу аккаунта перед запуском.'
    docker start "$CONTAINER" >/dev/null
    configure_account_https
    say "Обновление уже завершено. Адрес: https://$PUBLIC_HOST. Повторный запуск не меняет пароль."
    exit 0
fi
if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    if [[ ! -f $UPGRADE/switching ]] || ! docker inspect "$OLD_CONTAINER" >/dev/null; then
        die 'Прежний контейнер отсутствует; сначала восстановите установку.'
    fi
elif [[ $(docker inspect -f '{{ index .Config.Labels "io.remote222.account-upgrade" }}' "$CONTAINER") == "$UPGRADE_MARKER" ]]; then
    [[ -f $UPGRADE/switching ]] || die 'Новая версия запущена без записи переключения; автоматическое изменение запрещено.'
fi
install -d -m 700 "$UPGRADE"
if [[ ! -f $UPGRADE/installation ]]; then
    printf '%s\nPUBLIC_HOST=%s\nSOURCE_COMMIT=%s\n' "$UPGRADE_MARKER" "$PUBLIC_HOST" "$SOURCE_COMMIT" | atomic_write "$UPGRADE/installation"
fi
say 'Получаю и собираю закреплённую версию; действующий broker продолжает работать.'
if [[ ! -d $SOURCE/.git ]]; then
    [[ ! -e $SOURCE ]] || die 'Каталог новых исходников не является checkout.'
    git init "$SOURCE"
    git -C "$SOURCE" remote add origin "$SOURCE_URL"
fi
[[ $(git -C "$SOURCE" remote get-url origin) == "$SOURCE_URL" && -z $(git -C "$SOURCE" status --porcelain) ]] || die 'Новые исходники изменены; перезапись запрещена.'
git -C "$SOURCE" fetch --depth 1 origin "$SOURCE_COMMIT"
[[ $(git -C "$SOURCE" rev-parse FETCH_HEAD) == "$SOURCE_COMMIT" ]] || die 'Хеш исходников не совпал.'
git -C "$SOURCE" checkout --detach "$SOURCE_COMMIT"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build --pull --label "io.remote222.installer=$MARKER" --label "io.remote222.source=$SOURCE_COMMIT" -t "$IMAGE" "$SOURCE"
fi
[[ $(docker image inspect -f '{{ index .Config.Labels "io.remote222.source" }}' "$IMAGE") == "$SOURCE_COMMIT" ]] || die 'Образ новой версии имеет другой исходный коммит.'

say 'Получаю сертификат DNS-имени через существующий HTTP01 webroot. Старый HTTPS по IP пока не меняется.'
"$CERTBOT" certonly --non-interactive --agree-tos --register-unsafely-without-email \
    --webroot --webroot-path "$WEBROOT" --domain "$PUBLIC_HOST" --cert-name remote222-account \
    --deploy-hook "$CONFIG/reload-nginx"
openssl verify -verify_hostname "$PUBLIC_HOST" \
    -untrusted /etc/letsencrypt/live/remote222-account/chain.pem \
    /etc/letsencrypt/live/remote222-account/cert.pem >/dev/null || \
    die 'Полученный сертификат не прошёл проверку доверия или имени сервера. Переключение остановлено.'

for kind in nginx service timer; do
    case "$kind" in nginx) path=$SITE ;; service) path=$SERVICE ;; timer) path=$TIMER ;; esac
    [[ -f $UPGRADE/previous.$kind ]] || atomic_copy "$path" "$UPGRADE/previous.$kind"
done
queue_idle || die 'Есть незавершённое задание. Дождитесь результата и закройте Remote222.exe перед обновлением.'
printf '%s\n' "$SOURCE_COMMIT" | atomic_write "$UPGRADE/switching"
SWITCHING=1
if docker inspect "$CONTAINER" >/dev/null 2>&1; then docker stop "$CONTAINER" >/dev/null; fi
# Consistent backup is retained for disaster recovery, never restored automatically.
python3 - "$STATE/broker.sqlite3" "$UPGRADE/broker-before-account.sqlite3" <<'PY'
from contextlib import closing
import os, pathlib, sqlite3, sys, tempfile
source, target = sys.argv[1:]
if not pathlib.Path(target).exists():
    fd, temporary = tempfile.mkstemp(prefix='broker-backup.', dir=pathlib.Path(target).parent)
    os.close(fd)
    try:
        with closing(sqlite3.connect('file:' + source + '?mode=ro', uri=True)) as src, closing(sqlite3.connect(temporary)) as dst:
            src.backup(dst)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
PY
if [[ ! -f $UPGRADE/account-configured ]] || ! account_configured; then
    say 'Прежний broker остановлен. Задайте логин и пароль только в этой приватной консоли.'
    printf '%s\n' "$SOURCE_COMMIT" | atomic_write "$UPGRADE/account-prompt-started"
    docker run --rm -it --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
        --mount "type=bind,src=$STATE,dst=/var/data/remote222" "$IMAGE" \
        python -m remote222.broker --state-dir /var/data/remote222 --set-account
    printf '%s\n' "$SOURCE_COMMIT" | atomic_write "$UPGRADE/account-configured"
fi
account_configured || die 'Аккаунт не настроен. Новая версия не будет запущена с прежними ключами.'
if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    if [[ $(docker inspect -f '{{ index .Config.Labels "io.remote222.account-upgrade" }}' "$CONTAINER") == "$UPGRADE_MARKER" ]]; then
        docker rm "$CONTAINER" >/dev/null
    else
        docker rename "$CONTAINER" "$OLD_CONTAINER"
    fi
fi
docker run -d --name "$CONTAINER" --label "io.remote222.installer=$MARKER" \
    --label "io.remote222.account-upgrade=$UPGRADE_MARKER" \
    --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
    --restart unless-stopped --log-driver local --log-opt max-size=5m --log-opt max-file=2 \
    --mount "type=bind,src=$STATE,dst=/var/data/remote222" "$IMAGE" \
    python -m remote222.broker --host 127.0.0.1 --port 8770 --state-dir /var/data/remote222 \
    --public-url "https://$PUBLIC_HOST" --account-only >/dev/null
healthy=0
for _ in {1..30}; do
    if curl --fail --silent --max-time 2 http://127.0.0.1:8770/healthz | python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(r!={"ok": True, "service": "remote222-broker"})' 2>/dev/null; then healthy=1; break; fi
    sleep 1
done
[[ $healthy == 1 ]] || die 'Новая версия не ответила на локальную проверку.'
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8770/auth/v1/meta | \
    python3 -c 'import json,sys; sys.exit(json.load(sys.stdin)!={"ok": True, "configured": True})'
configure_account_https
atomic_write "$SERVICE" 644 <<UNIT
# Managed by $MARKER
[Unit]
Description=Renew Remote222 account server certificate
Wants=network-online.target
After=network-online.target nginx.service

[Service]
Type=oneshot
ExecStart=$CERTBOT renew --quiet --cert-name remote222-account --deploy-hook $CONFIG/reload-nginx
UNIT
atomic_write "$TIMER" 644 <<UNIT
# Managed by $MARKER
[Unit]
Description=Check Remote222 account certificate twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now remote222-cert-renew.timer
mv "$UPGRADE/switching" "$UPGRADE/completed"
SWITCHING=0
say "Готово: https://$PUBLIC_HOST. В новом EXE используйте этот адрес, логин и пароль."
say 'Для управления из чата откройте выданную ссылку подтверждения в браузере и войдите в свой аккаунт. Ключи копировать не требуется.'
say "Прежний контейнер сохранён остановленным: $OLD_CONTAINER. SQLite и прежние файлы ключей сохранены."
