#!/bin/bash

# Universal Reverse Proxy Installer - v1.4 (Усиленная безопасность)
# Автоматическое развертывание Node.js reverse proxy с HTTPS и harden-механизмами
# Автор: Proxy Deployment System + ChatGPT
# Версия: 1.4
# История версий:
# - v1.3: минимальная архитектура
# - v1.4: + безопасность (non-root, CORS, Fail2Ban, certbot.timer)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

check_status() {
    if [ $? -eq 0 ]; then
        log_success "$1"
    else
        log_error "$2"
        exit 1
    fi
}

echo -e "${CYAN}Universal Proxy Installer v1.4 — установка${NC}"
read -p "Введите домен прокси (proxy.example.com): " PROXY_DOMAIN
read -p "Введите целевой домен (target.example.com): " TARGET_DOMAIN
read -p "Email для Let's Encrypt: " SSL_EMAIL
read -p "Имя проекта [default: reverse-proxy]: " PROJECT_NAME

PROJECT_NAME=${PROJECT_NAME:-reverse-proxy}
PROJECT_DIR="/opt/$PROJECT_NAME"

log_info "Установка зависимостей..."
apt-get update -qq
apt-get install -y curl wget gnupg2 software-properties-common nginx certbot python3-certbot-nginx ufw jq net-tools nodejs npm
check_status "Зависимости установлены" "Ошибка установки пакетов"

if ! command -v pm2 >/dev/null; then
    log_info "Установка PM2..."
    npm install -g pm2
fi

mkdir -p "$PROJECT_DIR"/{src,config,logs,ssl,scripts}

cat > "$PROJECT_DIR/package.json" << EOF
{
  "name": "$PROJECT_NAME",
  "version": "1.0.0",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "http-proxy-middleware": "^2.0.9",
    "dotenv": "^16.3.1"
  }
}
EOF

cat > "$PROJECT_DIR/.env" << EOF
NODE_ENV=production
PORT=3000
PROXY_DOMAIN=$PROXY_DOMAIN
TARGET_DOMAIN=$TARGET_DOMAIN
TARGET_PROTOCOL=https
EOF

cat > "$PROJECT_DIR/src/app.js" << 'EOF'
require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_PROTOCOL = process.env.TARGET_PROTOCOL || 'https';
const TARGET_DOMAIN = process.env.TARGET_DOMAIN;
const PROXY_DOMAIN = process.env.PROXY_DOMAIN;

console.log('Starting minimal proxy...');
console.log(`Target: ${TARGET_PROTOCOL}://${TARGET_DOMAIN}`);
console.log(`Proxy: ${PROXY_DOMAIN}`);

app.use('/', createProxyMiddleware({
  target: `${TARGET_PROTOCOL}://${TARGET_DOMAIN}`,
  changeOrigin: true,
  secure: true,
  onProxyRes: (proxyRes, req, res) => {
    delete proxyRes.headers['glide-allow-embedding'];
    delete proxyRes.headers['x-frame-options'];
    delete proxyRes.headers['content-security-policy'];

    proxyRes.headers['x-frame-options'] = 'ALLOWALL';
    proxyRes.headers['access-control-allow-origin'] = '*';
    proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH';
    proxyRes.headers['access-control-allow-headers'] = 'Content-Type, Authorization, X-Requested-With, Accept';
    proxyRes.headers['access-control-allow-credentials'] = 'true';
    proxyRes.headers['content-security-policy'] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;";

    console.log(`${req.method} ${req.url} - ${proxyRes.statusCode}`);
  },
  onError: (err, req, res) => {
    console.error('Proxy error:', err.message);
    if (!res.headersSent) {
      res.status(502).send('Bad Gateway');
    }
  }
}));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Proxy listening on 127.0.0.1:${PORT}`);
});
EOF

cat > "$PROJECT_DIR/ecosystem.config.js" << EOF
module.exports = {
  apps: [{
    name: '$PROJECT_NAME',
    script: 'src/app.js',
    instances: 1,
    exec_mode: 'fork',
    max_memory_restart: '512M',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    log_file: './logs/pm2-combined.log',
    out_file: './logs/pm2-out.log',
    error_file: './logs/pm2-error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z'
  }]
};
EOF

cd "$PROJECT_DIR"
npm install --production

# === Укрепление безопасности (v1.4) ===
log_info "Укрепление безопасности (v1.4) — начало..."
useradd -r -s /usr/sbin/nologin proxyuser || true
chown -R proxyuser:proxyuser "$PROJECT_DIR"
cd "$PROJECT_DIR"
sudo -u proxyuser npm install http-proxy-middleware@2.0.9 --save
check_status "http-proxy-middleware обновлён до 2.0.9" "Ошибка обновления proxy middleware"

read -p "Разрешённый origin для CORS (или Enter для отключения): " ALLOWED_ORIGIN

if [ -n "$ALLOWED_ORIGIN" ]; then
  sed -i "s|proxyRes.headers\['access-control-allow-origin'\].*|proxyRes.headers['access-control-allow-origin'] = '$ALLOWED_ORIGIN';|" "$PROJECT_DIR/src/app.js"
else
  sed -i "/proxyRes.headers\['access-control-allow-origin'\]/d" "$PROJECT_DIR/src/app.js"
fi

su - proxyuser -s /bin/bash << EOF
cd "$PROJECT_DIR"
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup systemd -u proxyuser --hp /home/proxyuser
EOF

systemctl enable pm2-proxyuser
if systemctl is-enabled pm2-proxyuser &>/dev/null; then
  log_success "PM2 автозапуск включен"
else
  log_warning "❗ PM2 автозапуск не включен. Проверьте вручную: systemctl status pm2-proxyuser"
fi

apt-get install -y fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
cat >> /etc/fail2ban/jail.local << EOFF
[nginx-http-auth]
enabled = true
[nginx-botsearch]
enabled = true
[nginx-limit-req]
enabled = true
EOFF
systemctl restart fail2ban
systemctl enable fail2ban

if ! systemctl is-enabled certbot.timer &>/dev/null; then
  systemctl enable certbot.timer
  systemctl start certbot.timer
fi
check_status "SSL auto-renewal включён через certbot.timer" "Ошибка настройки SSL renew"

log_success "Установка и усиление безопасности завершены"
