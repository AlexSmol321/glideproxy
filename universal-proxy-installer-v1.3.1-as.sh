#!/bin/bash
# ==================================================================
# UNIVERSAL REVERSE PROXY INSTALLER – MINIMAL STABILITY EDITION
# Версия: 1.4  (Node.js 20 LTS + Frame-Embedding DENY + /health)
# Автор: Proxy Deployment System
#
# ИСТОРИЯ ВЕРСИЙ
#   1.0 – Initial release
#   1.1 – HTTPS + nginx SSL termination
#   1.2 – PM2 integration, rate-limit
#   1.3 – Minimal architecture, header cleanup, ALLOWALL (iframe)
#   1.4 – ▶ Node 20 LTS, X-Frame-Options: DENY, /health endpoints
#
# ИСПОЛЬЗОВАНИЕ
#   Интерактивно:
#       sudo ./universal-proxy-installer.sh
#
#   Автоматически:
#       export PROXY_DOMAIN="proxy.example.com"
#       export TARGET_DOMAIN="old.example.com"
#       export SSL_EMAIL="admin@example.com"
#       export PROJECT_NAME="my-proxy"
#       sudo ./universal-proxy-installer.sh
# ==================================================================

set -e

# Цветовые константы
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# --- функции логирования ------------------------------------------------------
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

check_status() {
    if [ $? -eq 0 ]; then
        log_success "$1"
    else
        log_error "$2"
        exit 1
    fi
}

# --- баннер -------------------------------------------------------------------
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              UNIVERSAL REVERSE PROXY INSTALLER               ║"
echo "║                    Minimal Stability Edition                 ║"
echo "║                                                               ║"
echo "║  Автоматическое развертывание Node.js reverse proxy с HTTPS  ║"
echo "║  • Node.js 20 LTS (версия 1.4)                               ║"
echo "║  • nginx SSL termination                                     ║"
echo "║  • PM2 process management                                    ║"
echo "║  • Полный запрет <iframe> (X-Frame-Options: DENY)            ║"
echo "║  • URL rewriting для HTML/CSS/JS                             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# --- проверка root ------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "Скрипт должен выполняться от root"
    echo "Используйте: sudo $0"
    exit 1
fi

# --- ввод параметров ----------------------------------------------------------
if [ -z "$PROXY_DOMAIN" ]; then
    echo -e "${YELLOW}=== НАСТРОЙКА КОНФИГУРАЦИИ ===${NC}"
    read -p "Домен прокси (proxy.example.com): " PROXY_DOMAIN
    read -p "Целевой домен (old.example.com): " TARGET_DOMAIN
    read -p "Email для SSL: " SSL_EMAIL
    read -p "Имя проекта (my-proxy): " PROJECT_NAME

    echo -e "${BLUE}=== ДОП. ПАРАМЕТРЫ (Enter — по умолчанию) ===${NC}"
    read -p "Порт приложения [3000]: " NODE_PORT
    read -p "Протокол цели [https]: " TARGET_PROTOCOL
    read -p "Макс. память PM2 [512M]: " MAX_MEMORY
    read -p "Лимит запросов/сек [10]: " RATE_LIMIT

    NODE_PORT=${NODE_PORT:-3000}
    TARGET_PROTOCOL=${TARGET_PROTOCOL:-https}
    MAX_MEMORY=${MAX_MEMORY:-512M}
    RATE_LIMIT=${RATE_LIMIT:-10}
    PROJECT_NAME=${PROJECT_NAME:-reverse-proxy}
fi

# обязательные
if [ -z "$PROXY_DOMAIN" ] || [ -z "$TARGET_DOMAIN" ] || [ -z "$SSL_EMAIL" ]; then
    log_error "Не указаны обязательные параметры (PROXY_DOMAIN, TARGET_DOMAIN, SSL_EMAIL)"
    exit 1
fi

# дефолты
NODE_PORT=${NODE_PORT:-3000}
TARGET_PROTOCOL=${TARGET_PROTOCOL:-https}
MAX_MEMORY=${MAX_MEMORY:-512M}
RATE_LIMIT=${RATE_LIMIT:-10}
PROJECT_NAME=${PROJECT_NAME:-reverse-proxy}

# --- подтверждение ------------------------------------------------------------
echo
echo -e "${GREEN}=== КОНФИГУРАЦИЯ ===${NC}"
echo "Прокси-домен : $PROXY_DOMAIN"
echo "Целевой домен: $TARGET_DOMAIN"
echo "Email SSL    : $SSL_EMAIL"
echo "Проект       : $PROJECT_NAME"
echo "Port         : $NODE_PORT"
echo "Протокол цели: $TARGET_PROTOCOL"
echo "PM2 memory   : $MAX_MEMORY"
echo "Rate limit   : $RATE_LIMIT/сек"
echo
if [ -z "$AUTO_CONFIRM" ]; then
    read -p "Продолжить установку? (y/N): " -n 1 -r; echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && { log_info "Отмена."; exit 0; }
fi

# --- директория ---------------------------------------------------------------
PROJECT_DIR="/opt/$PROJECT_NAME"

if [ -d "$PROJECT_DIR" ]; then
    log_warning "Проект уже существует ($PROJECT_DIR)"
    if [ -z "$AUTO_CONFIRM" ]; then
        read -p "Удалить и переустановить? (y/N): " -n 1 -r; echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && { log_info "Отмена."; exit 0; }
    fi
    rm -rf "$PROJECT_DIR"
    if command -v pm2 >/dev/null 2>&1 && pm2 list | grep -q "$PROJECT_NAME"; then
        pm2 delete "$PROJECT_NAME" 2>/dev/null || true
    fi
fi

# проверка порта
if command -v ss >/dev/null 2>&1; then
    ss -tuln | grep -q ":$NODE_PORT " && { log_error "Порт $NODE_PORT занят"; exit 1; }
elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep -q ":$NODE_PORT " && { log_error "Порт $NODE_PORT занят"; exit 1; }
fi

# --- установка системных пакетов ---------------------------------------------
log_info "Обновление пакетов…"; apt-get update -qq
check_status "apt update OK" "apt update FAIL"

log_info "Установка зависимостей…"
apt-get install -y curl wget gnupg2 software-properties-common nginx certbot python3-certbot-nginx ufw jq net-tools
check_status "deps OK" "deps FAIL"

# --- Node.js 20 LTS -----------------------------------------------------------
if ! command -v node &>/dev/null; then
    log_info "Установка Node.js 20 LTS…"
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    check_status "Node 20 OK" "Node 20 FAIL"
else
    log_success "Node уже есть: $(node -v)"
fi

# --- PM2 ----------------------------------------------------------------------
if ! command -v pm2 &>/dev/null; then
    log_info "Установка PM2…"; npm install -g pm2
    check_status "PM2 OK" "PM2 FAIL"
else
    log_success "PM2 уже установлен"
fi

# --- структура проекта --------------------------------------------------------
log_info "Создание структуры проекта…"
mkdir -p "$PROJECT_DIR"/{src,config,logs,ssl,scripts}
check_status "структура OK" "mkdir FAIL"

# --- package.json -------------------------------------------------------------
log_info "package.json…"
cat > "$PROJECT_DIR/package.json" << EOF
{
  "name": "$PROJECT_NAME",
  "version": "1.0.0",
  "description": "Minimal Reverse Proxy ($PROXY_DOMAIN → $TARGET_DOMAIN)",
  "main": "src/app.js",
  "scripts": { "start": "node src/app.js" },
  "dependencies": {
    "express": "^4.18.2",
    "http-proxy-middleware": "^2.0.6",
    "dotenv": "^16.3.1"
  },
  "license": "MIT"
}
EOF

# --- .env ---------------------------------------------------------------------
log_info ".env…"
cat > "$PROJECT_DIR/.env" << EOF
NODE_ENV=production
PORT=$NODE_PORT
PROXY_DOMAIN=$PROXY_DOMAIN
TARGET_DOMAIN=$TARGET_DOMAIN
TARGET_PROTOCOL=$TARGET_PROTOCOL
LOG_LEVEL=info
LOG_DIR=./logs
ENHANCED_COMPATIBILITY=true
MINIMAL_MODE=true
EOF

# --- src/app.js ---------------------------------------------------------------
log_info "app.js (Node 20, XFO DENY, /health)…"
cat > "$PROJECT_DIR/src/app.js" << 'APPEOF'
require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app           = express();
const PORT          = process.env.PORT || 3000;
const TARGET_PROTO  = process.env.TARGET_PROTOCOL || 'https';
const TARGET_DOMAIN = process.env.TARGET_DOMAIN;
const PROXY_DOMAIN  = process.env.PROXY_DOMAIN;

console.log('Minimal proxy started (Node 20 LTS)…');
console.log(` → Target: ${TARGET_PROTO}://${TARGET_DOMAIN}`);
console.log(` ← Proxy : https://${PROXY_DOMAIN}`);

//
// health endpoints
//
app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/health/detailed', (_req, res) => res.json({
  status: 'ok',
  target: `${TARGET_PROTO}://${TARGET_DOMAIN}`,
  uptime: process.uptime()
}));

//
// proxy
//
app.use('/', createProxyMiddleware({
  target       : `${TARGET_PROTO}://${TARGET_DOMAIN}`,
  changeOrigin : true,
  secure       : true,
  onProxyRes(proxyRes, req, _res) {
      delete proxyRes.headers['glide-allow-embedding'];
      delete proxyRes.headers['x-frame-options'];
      delete proxyRes.headers['content-security-policy'];

      // жёсткий запрет iframe
      proxyRes.headers['x-frame-options'] = 'DENY';

      // CORS
      proxyRes.headers['access-control-allow-origin']  = '*';
      proxyRes.headers['access-control-allow-methods'] = 'GET,POST,PUT,DELETE,OPTIONS,PATCH';
      proxyRes.headers['access-control-allow-headers'] = 'Content-Type,Authorization,X-Requested-With,Accept';
      proxyRes.headers['access-control-allow-credentials'] = 'true';

      // базовый CSP
      proxyRes.headers['content-security-policy'] = "default-src * data: blob:;";

      console.log(`${req.method} ${req.url} → ${proxyRes.statusCode}`);
  },
  onError(err, _req, res) {
      console.error('Proxy error:', err.message);
      if (!res.headersSent) res.status(502).send('Bad Gateway');
  }
}));

app.listen(PORT, () => console.log(`Listening on ${PORT}`));

['SIGTERM','SIGINT'].forEach(sig =>
  process.on(sig, () => {
    console.log(`${sig} received, shutting down…`);
    process.exit(0);
  })
);
APPEOF

# --- ecosystem PM2 ------------------------------------------------------------
log_info "ecosystem.config.js…"
cat > "$PROJECT_DIR/ecosystem.config.js" << EOF
module.exports = {
  apps: [{
    name: '$PROJECT_NAME',
    script: 'src/app.js',
    instances: 1,
    exec_mode: 'fork',
    max_memory_restart: '$MAX_MEMORY',
    env_production: { NODE_ENV: 'production', PORT: $NODE_PORT },
    log_file: './logs/pm2-combined.log',
    out_file: './logs/pm2-out.log',
    error_file: './logs/pm2-error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    cron_restart: '0 3 * * *'
  }]
};
EOF

# --- nginx конфигурация -------------------------------------------------------
log_info "nginx конфиг…"
create_nginx() {
cat > "$PROJECT_DIR/config/nginx-proxy.conf" << 'NGINX'
upstream PROJECT_BACKEND {
    server 127.0.0.1:NODE_PORT;
    keepalive 32;
}
limit_req_zone $binary_remote_addr zone=PROJECT_LIMIT:10m rate=RATE_LIMITr/s;
limit_conn_zone $binary_remote_addr zone=PROJECT_CONN:10m;

server {
    listen 80;
    server_name PROXY_DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://$server_name$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name PROXY_DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/PROXY_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/PROXY_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy "no-referrer-when-downgrade";

    limit_req zone=PROJECT_LIMIT burst=20 nodelay;
    limit_conn PROJECT_CONN 10;

    access_log /var/log/nginx/PROXY_DOMAIN.access.log;
    error_log  /var/log/nginx/PROXY_DOMAIN.error.log;

    gzip on; gzip_vary on; gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript image/svg+xml;

    location / {
        proxy_pass http://PROJECT_BACKEND;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    location /nginx-health {
        access_log off;
        return 200 "nginx healthy\n";
    }

    location ~* \.(git|svn|env|log|bak|php)$ { deny all; return 404; }
}
NGINX
sed -i "s/PROXY_DOMAIN/$PROXY_DOMAIN/g" "$PROJECT_DIR/config/nginx-proxy.conf"
sed -i "s/PROJECT_BACKEND/${PROJECT_NAME}_backend/g" "$PROJECT_DIR/config/nginx-proxy.conf"
sed -i "s/NODE_PORT/$NODE_PORT/g"         "$PROJECT_DIR/config/nginx-proxy.conf"
sed -i "s/PROJECT_LIMIT/${PROJECT_NAME}_limit/g" "$PROJECT_DIR/config/nginx-proxy.conf"
sed -i "s/PROJECT_CONN/${PROJECT_NAME}_conn/g"   "$PROJECT_DIR/config/nginx-proxy.conf"
sed -i "s/RATE_LIMIT/$RATE_LIMIT/g"       "$PROJECT_DIR/config/nginx-proxy.conf"
}
create_nginx

# --- npm install --------------------------------------------------------------
log_info "npm install (prod)…"
cd "$PROJECT_DIR"; npm install --production
check_status "npm OK" "npm FAIL"

# --- certbot ------------------------------------------------------------------
log_info "Временный vhost для SSL…"
cat > /etc/nginx/sites-available/$PROJECT_NAME-temp << EOF
server {
    listen 80;
    server_name $PROXY_DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 "Temp page"; add_header Content-Type text/plain; }
}
EOF
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/$PROJECT_NAME-temp /etc/nginx/sites-enabled/$PROJECT_NAME-temp
nginx -t && systemctl reload nginx

mkdir -p /var/www/html
log_info "Получение сертификата…"
certbot certonly --webroot -w /var/www/html -d "$PROXY_DOMAIN" --email "$SSL_EMAIL" --agree-tos --non-interactive
check_status "certbot OK" "certbot FAIL"

rm -f /etc/nginx/sites-enabled/$PROJECT_NAME-temp /etc/nginx/sites-available/$PROJECT_NAME-temp

# --- основной nginx -----------------------------------------------------------
log_info "Активация production nginx конфига…"
cp "$PROJECT_DIR/config/nginx-proxy.conf" /etc/nginx/sites-available/$PROJECT_NAME
ln -sf /etc/nginx/sites-available/$PROJECT_NAME /etc/nginx/sites-enabled/$PROJECT_NAME
nginx -t && systemctl reload nginx
check_status "nginx reloaded" "nginx FAIL"

# --- запуск через PM2 ---------------------------------------------------------
log_info "PM2 старт…"
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup systemd -u root --hp /root
systemctl enable pm2-root
check_status "PM2 online" "PM2 FAIL"

# --- UFW ----------------------------------------------------------------------
log_info "Firewall…"
if ! ufw status | grep -q "Status: active"; then ufw --force enable; fi
ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw limit 22/tcp
check_status "UFW OK" "UFW FAIL"

# --- скрипты управления -------------------------------------------------------
log_info "Утилиты управления…"
cat > "$PROJECT_DIR/scripts/status.sh" << EOF
#!/bin/bash
echo "=== $PROJECT_NAME STATUS ==="
pm2 status $PROJECT_NAME
systemctl status nginx --no-pager -l
certbot certificates | grep -A 5 "$PROXY_DOMAIN"
curl -sk https://$PROXY_DOMAIN/health
EOF

cat > "$PROJECT_DIR/scripts/restart.sh" << EOF
#!/bin/bash
pm2 restart $PROJECT_NAME
systemctl reload nginx
EOF

cat > "$PROJECT_DIR/scripts/logs.sh" << EOF
#!/bin/bash
pm2 logs $PROJECT_NAME --lines 50
EOF

cat > "$PROJECT_DIR/scripts/renew-ssl.sh" << EOF
#!/bin/bash
certbot renew --quiet
systemctl reload nginx
EOF

chmod +x "$PROJECT_DIR/scripts/"*.sh

# --- README -------------------------------------------------------------------
log_info "README.md…"
cat > "$PROJECT_DIR/README.md" << EOF
# $PROJECT_NAME – Minimal Stability Edition 1.4

Reverse-proxy $PROXY_DOMAIN → $TARGET_DOMAIN  
Node.js 20 LTS | X-Frame-Options: **DENY**

## Новое в 1.4
* Переход на Node 20 LTS  
* Заголовок \`X-Frame-Options: DENY\` для полного запрета iframe  
* Endpoints \`/health\`, \`/health/detailed\`  

## Управление
\`\`\`bash
$PROJECT_DIR/scripts/status.sh   # Статус
$PROJECT_DIR/scripts/restart.sh  # Перезапуск
$PROJECT_DIR/scripts/logs.sh     # Логи
$PROJECT_DIR/scripts/renew-ssl.sh# Обновить SSL
\`\`\`

## Endpoints
* Main Proxy   → <https://$PROXY_DOMAIN/>
* Health       → <https://$PROXY_DOMAIN/health>
* Detailed     → <https://$PROXY_DOMAIN/health/detailed>
EOF

# --- верификация --------------------------------------------------------------
log_info "Проверка сервисов…"; sleep 10
pm2 list | grep -q "$PROJECT_NAME.*online" && log_success "PM2 OK" || { log_error "PM2 FAIL"; exit 1; }
systemctl is-active --quiet nginx && log_success "nginx OK" || { log_error "nginx FAIL"; exit 1; }

log_info "HTTP → HTTPS redirect…"
curl -I "http://$PROXY_DOMAIN" 2>/dev/null | grep -q "301" && log_success "redirect OK" || log_warning "redirect ?"

log_info "HTTPS health…"
curl -sk "https://$PROXY_DOMAIN/health" | grep -q "status" && log_success "health OK" || log_warning "health ?"

# --- финал --------------------------------------------------------------------
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    УСТАНОВКА ЗАВЕРШЕНА                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
log_success "Minimal Universal Reverse Proxy 1.4 установлен!"
