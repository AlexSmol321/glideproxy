#!/bin/bash

# Universal Proxy Installer v1.3.1 — стабильная сборка с безопасными улучшениями
# Улучшения:
# - Создание non-root пользователя (proxyuser)
# - Автозапуск через PM2
# Без: Fail2Ban, лишнего CORS, SSL renew и правок исходников

set -e

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "\033[0;36m[INFO]\033[0m $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

read -p "Введите домен прокси (proxy.example.com): " PROXY_DOMAIN
read -p "Введите целевой домен (target.example.com): " TARGET_DOMAIN
read -p "Email для Let's Encrypt: " SSL_EMAIL
read -p "Имя проекта [default: reverse-proxy]: " PROJECT_NAME

PROJECT_NAME=${PROJECT_NAME:-reverse-proxy}
PROJECT_DIR="/opt/$PROJECT_NAME"

log_info "Установка зависимостей..."
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx nodejs npm git

log_info "Настройка HTTPS..."
certbot --nginx -d "$PROXY_DOMAIN" --non-interactive --agree-tos -m "$SSL_EMAIL"

log_info "Клонирование репозитория..."
git clone https://github.com/AlexSmol321/glideproxy.git "$PROJECT_DIR"

log_info "Создание пользователя proxyuser..."
useradd -r -s /usr/sbin/nologin proxyuser || true
chown -R proxyuser:proxyuser "$PROJECT_DIR"

log_info "Установка зависимостей Node.js..."
cd "$PROJECT_DIR"
sudo -u proxyuser npm install

log_info "Установка PM2 и автозапуск от proxyuser..."
npm install -g pm2
su - proxyuser -s /bin/bash -c "cd $PROJECT_DIR && pm2 start ecosystem.config.js --env production && pm2 save && pm2 startup systemd -u proxyuser --hp /home/proxyuser"
systemctl enable pm2-proxyuser

log_success "Установка завершена. Прокси-домен: https://$PROXY_DOMAIN → $TARGET_DOMAIN"
