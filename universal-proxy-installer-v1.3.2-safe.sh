#!/bin/bash

# Universal Proxy Installer v1.3.2-safe — проверенная версия, совместимая с Glide
# Облегчённый install-скрипт без конфликтующих "улучшений безопасности"
# Только user=proxyuser, HTTPS и автозапуск

set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Пожалуйста, запускайте от root: sudo ./universal-proxy-installer.sh"
  exit 1
fi

read -p "Домен прокси (например, proxy.example.com): " PROXY_DOMAIN
read -p "Целевой домен (например, glide.page): " TARGET_DOMAIN
read -p "Email для Let's Encrypt: " SSL_EMAIL
read -p "Имя проекта (по умолчанию: reverse-proxy): " PROJECT_NAME

PROJECT_NAME=${PROJECT_NAME:-reverse-proxy}
PROJECT_DIR="/opt/$PROJECT_NAME"

echo "➡ Очистка предыдущей установки (если есть)..."
rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR"

echo "➡ Установка зависимостей..."
apt-get update
apt-get install -y git curl nginx certbot python3-certbot-nginx nodejs npm

echo "➡ Клонирование проекта..."
git clone https://github.com/AlexSmol321/glideproxy-core.git "$PROJECT_DIR"

echo "➡ Установка зависимостей Node.js..."
cd "$PROJECT_DIR"
npm install

echo "➡ Выдача прав пользователю proxyuser..."
useradd -r -s /usr/sbin/nologin proxyuser || true
chown -R proxyuser:proxyuser "$PROJECT_DIR"

echo "➡ Настройка прокси..."
sed -i "s|const TARGET = .*|const TARGET = 'https://${TARGET_DOMAIN}';|" src/app.js
sed -i "s|const DOMAIN = .*|const DOMAIN = '${PROXY_DOMAIN}';|" src/app.js

echo "➡ Настройка SSL через certbot..."
certbot --nginx --non-interactive --agree-tos -m "$SSL_EMAIL" -d "$PROXY_DOMAIN"

echo "➡ Установка PM2 и запуск от proxyuser..."
npm install pm2 -g
sudo -u proxyuser pm2 start ecosystem.config.js --env production
sudo -u proxyuser pm2 save
pm2 startup systemd -u proxyuser --hp /home/proxyuser
systemctl enable pm2-proxyuser

echo "✅ Установка завершена: https://${PROXY_DOMAIN} → https://${TARGET_DOMAIN}"
