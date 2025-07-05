cat > installer-v1.5-unified.sh <<'EOF'
#!/bin/bash
# =====================================================================
# UNIVERSAL REVERSE PROXY INSTALLER — Minimal Stability Edition
# Версия: 1.5-unified  (Node.js 20 LTS | dual-cert LE/Timeweb | auto-renew)
# Автор  : Proxy Deployment System
#
# ▸ Что умеет
#   ▪ Node 20 LTS + PM2  ▪ Nginx SSL-termination
#   ▪ X-Frame-Options: DENY        ▪ Разрешающий CSP для Glide
#   ▪ CERT_MODE  = letsencrypt | timeweb
#   ▪ Для Timeweb PRO ➜ автоматическая пролонгация через cron
# =====================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
info (){ echo -e "${BLUE}[INFO]${NC} $1"; }
good (){ echo -e "${GREEN}[ OK ]${NC} $1"; }
fail (){ echo -e "${RED}[ERR]${NC} $1"; exit 1; }
[[ $EUID -ne 0 ]] && fail "Запустите скрипт через sudo"

read_var(){ local v=$1 p=$2 d=$3 silent=${4:-0}
  [[ -n "${!v:-}" ]] && return
  if (( silent )); then read -s -p "$p" $v && echo; else read -p "$p" $v; fi
  [[ -z "${!v}" ]] && eval "$v=$d"
}

# ── ввод ─────────────────────────────────────────────────────────────
read_var PROXY_DOMAIN   "Proxy-домен                : " ""
read_var TARGET_DOMAIN  "Целевой домен (Glide)      : " ""
read_var SSL_EMAIL      "Email для Let's Encrypt    : " ""
read_var PROJECT_NAME   "Имя проекта     [my-proxy] : " "my-proxy"
read_var NODE_PORT      "Порт Node.js    [3000]     : " "3000"
read_var MAX_MEMORY     "PM2 max memory  [512M]     : " "512M"

CERT_MODE=${CERT_MODE:-letsencrypt}
if [[ $CERT_MODE == timeweb ]]; then
  read_var TIMEWEB_TOKEN    "Timeweb API-token (скрытый ввод): " "" 1
  read_var TIMEWEB_CERT_ID  "ID заказа сертификата            : " ""
fi

PROJECT_DIR=/opt/$PROJECT_NAME
mkdir -p "$PROJECT_DIR"/{src,config,logs,scripts}

# ── пакеты ───────────────────────────────────────────────────────────
info "Установка Node 20, Nginx, PM2…"
apt-get update -qq
apt-get install -y curl wget gnupg2 software-properties-common nginx ufw jq unzip > /dev/null
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
apt-get install -y nodejs >/dev/null
npm install -g pm2 >/dev/null
[[ $CERT_MODE == letsencrypt ]] && apt-get install -y certbot python3-certbot-nginx >/dev/null
good "Базовые пакеты готовы"

# ── .env ─────────────────────────────────────────────────────────────
cat > "$PROJECT_DIR/.env" <<EOF_ENV
NODE_ENV=production
PORT=$NODE_PORT
PROXY_DOMAIN=$PROXY_DOMAIN
TARGET_DOMAIN=$TARGET_DOMAIN
TARGET_PROTOCOL=https
CERT_MODE=$CERT_MODE
TIMEWEB_TOKEN=${TIMEWEB_TOKEN:-}
TIMEWEB_CERT_ID=${TIMEWEB_CERT_ID:-}
EOF_ENV
chmod 600 "$PROJECT_DIR/.env"

# ── package.json ────────────────────────────────────────────────────
cat > "$PROJECT_DIR/package.json" <<EOF_PKG
{ "name":"$PROJECT_NAME","version":"1.0.0",
  "main":"src/app.js",
  "dependencies":{
    "dotenv":"^16.3.1",
    "express":"^4.18.2",
    "http-proxy-middleware":"^2.0.6"}
}
EOF_PKG

# ── src/app.js ───────────────────────────────────────────────────────
cat > "$PROJECT_DIR/src/app.js" <<'EOF_JS'
require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app   = express();
const PORT  = process.env.PORT || 3000;
const TARGET= `${process.env.TARGET_PROTOCOL || 'https'}://${process.env.TARGET_DOMAIN}`;

console.log('Proxy →', TARGET);

app.get('/health',          (_req,res)=>res.json({status:'ok'}));
app.get('/health/detailed', (_req,res)=>res.json({
  status:'ok', target:TARGET, uptime:process.uptime()
}));

app.use('/', createProxyMiddleware({
  target: TARGET,
  changeOrigin: true,
  secure: true,
  onProxyRes(pr){
    delete pr.headers['content-security-policy'];
    pr.headers['x-frame-options']                  = 'DENY';
    pr.headers['access-control-allow-origin']      = '*';
    pr.headers['access-control-allow-methods']     = 'GET, POST, PUT, DELETE, OPTIONS, PATCH';
    pr.headers['access-control-allow-headers']     = 'Content-Type, Authorization, X-Requested-With, Accept';
    pr.headers['access-control-allow-credentials'] = 'true';
    pr.headers['content-security-policy']          = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;";
  },
  onError(err, _req, res){ if(!res.headersSent) res.status(502).send('Bad Gateway'); }
}));
app.listen(PORT, ()=>console.log('Listening on', PORT));
['SIGINT','SIGTERM'].forEach(sig=>process.on(sig,()=>process.exit(0)));
EOF_JS

# ── ecosystem ────────────────────────────────────────────────────────
cat > "$PROJECT_DIR/ecosystem.config.js" <<EOF_ECO
module.exports={apps:[{name:'$PROJECT_NAME',script:'src/app.js',
  instances:1,exec_mode:'fork',max_memory_restart:'$MAX_MEMORY',
  env_production:{NODE_ENV:'production',PORT:$NODE_PORT},
  cron_restart:'0 3 * * *'}]};
EOF_ECO

# ── nginx конфиги ────────────────────────────────────────────────────
ACME_CONF="$PROJECT_DIR/config/nginx-acme.conf"
PROD_CONF="$PROJECT_DIR/config/nginx-proxy.conf"

cat > "$ACME_CONF" <<EOF
server {
  listen 80;
  server_name $PROXY_DOMAIN;
  root /var/www/html;
  location / { return 200 "ACME host"; }
  location /.well-known/acme-challenge/ { root /var/www/html; }
}
EOF

cat > "$PROD_CONF" <<EOF
upstream ${PROJECT_NAME}_up { server 127.0.0.1:$NODE_PORT; keepalive 16; }
server { listen 80; server_name $PROXY_DOMAIN;
  location /.well-known/acme-challenge/ { root /var/www/html; }
  location / { return 301 https://\$host\$request_uri; } }
server { listen 443 ssl http2; server_name $PROXY_DOMAIN;
  ssl_certificate     /etc/ssl/certs/$PROXY_DOMAIN.pem;
  ssl_certificate_key /etc/ssl/private/$PROXY_DOMAIN.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  add_header X-Frame-Options DENY always;
  add_header Content-Security-Policy "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;" always;
  location / {
    proxy_pass http://${PROJECT_NAME}_up;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
EOF

ln -sf "$ACME_CONF" /etc/nginx/sites-enabled/$PROJECT_NAME
nginx -t && systemctl reload nginx
mkdir -p /var/www/html

# ── сертификат ───────────────────────────────────────────────────────
if [[ $CERT_MODE == letsencrypt ]]; then
  info "Получаем Let's Encrypt…"
  certbot certonly --webroot -w /var/www/html -d "$PROXY_DOMAIN" \
        --email "$SSL_EMAIL" --agree-tos --non-interactive
  cp /etc/letsencrypt/live/$PROXY_DOMAIN/fullchain.pem /etc/ssl/certs/$PROXY_DOMAIN.pem
  cp /etc/letsencrypt/live/$PROXY_DOMAIN/privkey.pem   /etc/ssl/private/$PROXY_DOMAIN.key
else
  info "Скачиваем Timeweb PRO сертификат…"
  api="https://api.timeweb.cloud/api/v2"
  hdr=(-H "Authorization: Bearer $TIMEWEB_TOKEN" -H "Accept: application/zip")
  tmp=$(mktemp -d); trap 'rm -r $tmp' EXIT
  curl -sf "${hdr[@]}" "$api/ssl-certificates/$TIMEWEB_CERT_ID/download" -o "$tmp/c.zip"
  unzip -qo "$tmp/c.zip" -d "$tmp"
  cat "$tmp/certificate.crt" "$tmp/ca_bundle.crt" > /etc/ssl/certs/$PROXY_DOMAIN.pem
  mv  "$tmp/private.key" /etc/ssl/private/$PROXY_DOMAIN.key
  chmod 600 /etc/ssl/private/$PROXY_DOMAIN.key
fi
chmod 644 /etc/ssl/certs/$PROXY_DOMAIN.pem

rm /etc/nginx/sites-enabled/$PROJECT_NAME
ln -sf "$PROD_CONF" /etc/nginx/sites-enabled/$PROJECT_NAME
nginx -t && systemctl reload nginx

# ── npm + PM2 ────────────────────────────────────────────────────────
cd "$PROJECT_DIR"
npm ci --production -s
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup systemd -u root --hp /root >/dev/null
systemctl enable pm2-root

# ── UFW ──────────────────────────────────────────────────────────────
ufw --force enable >/dev/null
ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp

# ── renew-script + cron для Timeweb ──────────────────────────────────
if [[ $CERT_MODE == timeweb ]]; then
  info "Настраиваем auto-renew Timeweb…"
  cat > "$PROJECT_DIR/scripts/renew-timeweb.sh" <<'RENEW'
#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/../.env"
[[ $CERT_MODE != timeweb ]] && exit 0
threshold=25
domain=$PROXY_DOMAIN
remain=$(( ( $(date -d "$(openssl x509 -noout -enddate -in /etc/ssl/certs/$domain.pem | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
(( remain > threshold )) && exit 0
api="https://api.timeweb.cloud/api/v2"
auth=(-H "Authorization: Bearer $TIMEWEB_TOKEN")
curl -sf "${auth[@]}" -H "Content-Type: application/json" -X POST \
     "$api/ssl-certificates/$TIMEWEB_CERT_ID/renew" -d '{}' >/dev/null
for i in {1..12}; do
  status=$(curl -sf "${auth[@]}" "$api/ssl-certificates/$TIMEWEB_CERT_ID" | jq -r .status)
  [[ $status == issued ]] && break; sleep 60
done
tmp=$(mktemp -d); trap 'rm -r $tmp' EXIT
curl -sf "${auth[@]}" -H "Accept: application/zip" \
     "$api/ssl-certificates/$TIMEWEB_CERT_ID/download" -o "$tmp/c.zip"
unzip -qo "$tmp/c.zip" -d "$tmp"
cat "$tmp"/certificate.crt "$tmp"/ca_bundle.crt > /etc/ssl/certs/$domain.pem
cp  "$tmp"/private.key /etc/ssl/private/$domain.key
chmod 600 /etc/ssl/private/$domain.key
systemctl reload nginx
echo "$(date) — Timeweb PRO renewed"
RENEW
  chmod 700 "$PROJECT_DIR/scripts/renew-timeweb.sh"
  echo "0 4 4 * * root $PROJECT_DIR/scripts/renew-timeweb.sh >> /var/log/timeweb-renew.log 2>&1" \
      > /etc/cron.d/timeweb-renew
  good "Cron-renew настроен"
fi

good "✅ Установка завершена → https://$PROXY_DOMAIN/"
EOF

chmod +x installer-v1.5-unified.sh
echo "Скрипт сохранён и готов к запуску."
