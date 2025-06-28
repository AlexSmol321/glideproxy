#!/bin/bash
# ==================================================================
# UNIVERSAL REVERSE PROXY INSTALLER – MINIMAL STABILITY EDITION
# Версия: 1.4  (Node.js 20 LTS + Frame-Embedding DENY + permissive CSP)
# Автор: Proxy Deployment System
#
# ИСТОРИЯ ВЕРСИЙ
#   1.0 – Initial release
#   1.1 – HTTPS + nginx SSL termination
#   1.2 – PM2 integration, rate-limit
#   1.3 – Minimal architecture, header cleanup, ALLOWALL
#   1.4 – Node 20 LTS, X-Frame-Options: DENY, relaxed CSP, /health endpoints
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
# ----- цветовые коды ---------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_info(){ echo -e "${BLUE}[INFO]${NC} $1"; }
log_success(){ echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning(){ echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error(){ echo -e "${RED}[ERROR]${NC} $1"; }
check_status(){ [ $? -eq 0 ] && log_success "$1" || { log_error "$2"; exit 1; }; }

# ----- баннер ----------------------------------------------------------------
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              UNIVERSAL REVERSE PROXY INSTALLER               ║"
echo "║                    Minimal Stability Edition                 ║"
echo "║                                                               ║"
echo "║  Node.js 20 LTS | HTTPS | X-Frame-Options: DENY | CSP ready  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

[ $EUID -ne 0 ] && { log_error "Run as root (sudo)"; exit 1; }

# ----- ввод ------------------------------------------------------------------
if [ -z "$PROXY_DOMAIN" ]; then
  read -p "Прокси‑домен: " PROXY_DOMAIN
  read -p "Целевой домен: " TARGET_DOMAIN
  read -p "Email SSL   : " SSL_EMAIL
  read -p "Имя проекта [my-proxy]: " PROJECT_NAME
  read -p "Порт Node   [3000]: " NODE_PORT
  PROJECT_NAME=${PROJECT_NAME:-my-proxy}
  NODE_PORT=${NODE_PORT:-3000}
fi

[ -z "$TARGET_DOMAIN" ] && { log_error "TARGET_DOMAIN пуст"; exit 1; }

NODE_PORT=${NODE_PORT:-3000}
PROJECT_DIR="/opt/$PROJECT_NAME"

# ----- apt & deps ------------------------------------------------------------
log_info "Обновление apt…"; apt-get update -qq; check_status "apt OK" "apt FAIL"
log_info "Зависимости…"
apt-get install -y curl wget gnupg2 software-properties-common nginx certbot python3-certbot-nginx ufw jq
check_status "deps OK" "deps FAIL"

# ----- Node 20 LTS -----------------------------------------------------------
if ! command -v node >/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
  check_status "Node 20 OK" "Node 20 FAIL"
fi
npm install -g pm2 >/dev/null

# ----- структура -------------------------------------------------------------
mkdir -p "$PROJECT_DIR"/{src,config,logs,scripts}
cat > "$PROJECT_DIR/.env" <<EOF
NODE_ENV=production
PORT=$NODE_PORT
PROXY_DOMAIN=$PROXY_DOMAIN
TARGET_DOMAIN=$TARGET_DOMAIN
TARGET_PROTOCOL=https
EOF

cat > "$PROJECT_DIR/package.json" <<EOF
{ "name":"$PROJECT_NAME","version":"1.0.0",
  "main":"src/app.js",
  "dependencies":{"express":"^4.18.2","http-proxy-middleware":"^2.0.6","dotenv":"^16.3.1"}}
EOF

# ----- app.js ----------------------------------------------------------------
cat > "$PROJECT_DIR/src/app.js" <<'JS'
require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const TARGET_PROTO = process.env.TARGET_PROTOCOL || 'https';
const TARGET_DOMAIN = process.env.TARGET_DOMAIN;
const PROXY_DOMAIN = process.env.PROXY_DOMAIN;

console.log('Minimal proxy Node20 started');
console.log(` → Target: ${TARGET_PROTO}://${TARGET_DOMAIN}`);
console.log(` ← Proxy : https://${PROXY_DOMAIN}`);

app.get('/health', (_req,res)=>res.json({status:'ok'}));
app.get('/health/detailed', (_req,res)=>res.json({
  status:'ok',target:`${TARGET_PROTO}://${TARGET_DOMAIN}`,uptime:process.uptime()
}));

app.use('/', createProxyMiddleware({
  target: `${TARGET_PROTO}://${TARGET_DOMAIN}`,
  changeOrigin: true,
  secure: true,
  onProxyRes(proxyRes, req, _res){
    delete proxyRes.headers['glide-allow-embedding'];
    delete proxyRes.headers['x-frame-options'];
    delete proxyRes.headers['content-security-policy'];

    proxyRes.headers['x-frame-options'] = 'DENY';
    proxyRes.headers['access-control-allow-origin'] = '*';
    proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH';
    proxyRes.headers['access-control-allow-headers'] = 'Content-Type, Authorization, X-Requested-With, Accept';
    proxyRes.headers['access-control-allow-credentials'] = 'true';
    proxyRes.headers['content-security-policy'] =
      "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;";
    console.log(`${req.method} ${req.url} → ${proxyRes.statusCode}`);
  },
  onError(err,_req,res){
    console.error('Proxy error:',err.message);
    if(!res.headersSent) res.status(502).send('Bad Gateway');
  }
}));

app.listen(PORT, ()=>console.log(`Listening on ${PORT}`));
['SIGINT','SIGTERM'].forEach(sig=>process.on(sig,()=>process.exit(0)));
JS

# ----- PM2 ecosystem ---------------------------------------------------------
cat > "$PROJECT_DIR/ecosystem.config.js" <<EOF
module.exports = { apps:[{
  name:'$PROJECT_NAME', script:'src/app.js', instances:1, exec_mode:'fork',
  max_memory_restart:'512M',
  env_production:{NODE_ENV:'production',PORT:$NODE_PORT},
  cron_restart:'0 3 * * *',
  log_file:'./logs/all.log', out_file:'./logs/out.log', error_file:'./logs/err.log'
}]};
EOF

# ----- nginx vhost -----------------------------------------------------------
cat > "$PROJECT_DIR/config/nginx-proxy.conf" <<EOF
upstream ${PROJECT_NAME}_backend { server 127.0.0.1:$NODE_PORT; keepalive 32; }
server { listen 80; server_name $PROXY_DOMAIN;
  location /.well-known/acme-challenge/ { root /var/www/html; }
  location / { return 301 https://\$server_name\$request_uri; } }
server { listen 443 ssl http2; server_name $PROXY_DOMAIN;
  ssl_certificate /etc/letsencrypt/live/$PROXY_DOMAIN/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/$PROXY_DOMAIN/privkey.pem;
  add_header X-Frame-Options DENY always;
  location / { proxy_pass http://${PROJECT_NAME}_backend; proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme; } }
EOF

# ----- npm install -----------------------------------------------------------
cd "$PROJECT_DIR"; npm install --production -s

# ----- SSL -------------------------------------------------------------------
mkdir -p /var/www/html
rm -f /etc/nginx/sites-enabled/default
ln -sf "$PROJECT_DIR/config/nginx-proxy.conf" /etc/nginx/sites-enabled/$PROJECT_NAME-tmp
systemctl reload nginx
certbot certonly --webroot -w /var/www/html -d "$PROXY_DOMAIN" --email "$SSL_EMAIL" --agree-tos --non-interactive
rm -f /etc/nginx/sites-enabled/$PROJECT_NAME-tmp
ln -sf "$PROJECT_DIR/config/nginx-proxy.conf" /etc/nginx/sites-enabled/$PROJECT_NAME
systemctl reload nginx

# ----- PM2 start -------------------------------------------------------------
pm2 start "$PROJECT_DIR/ecosystem.config.js" --env production
pm2 save
pm2 startup systemd -u root --hp /root
systemctl enable pm2-root

# ----- ufw -------------------------------------------------------------------
ufw --force enable
ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp

log_success "Proxy 설치 완료! Visit https://$PROXY_DOMAIN"
