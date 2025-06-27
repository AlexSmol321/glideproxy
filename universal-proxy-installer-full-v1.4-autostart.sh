#!/bin/bash

# Universal Reverse Proxy Installer - v1.4 (Усиленная безопасность)
# Автоматическое развертывание Node.js reverse proxy с HTTPS и harden-механизмами
# Автор: Proxy Deployment System + ChatGPT (на основе v1.3)
# История версий:
# - v1.3: минимальная стабильная архитектура
# - v1.4: добавлены улучшения безопасности: non-root user, обновление зависимостей, Fail2Ban, SSL auto-renewal

set -e

# Цвета
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

# Пример простого запроса параметров
echo -e "${CYAN}Universal Proxy Installer v1.4 — установка${NC}"
read -p "Введите домен прокси (proxy.example.com): " PROXY_DOMAIN
read -p "Введите целевой домен (target.example.com): " TARGET_DOMAIN
read -p "Email для Let's Encrypt: " SSL_EMAIL
read -p "Имя проекта [default: reverse-proxy]: " PROJECT_NAME

PROJECT_NAME=${PROJECT_NAME:-reverse-proxy}
PROJECT_DIR="/opt/$PROJECT_NAME"


#!/bin/bash

# Universal Reverse Proxy Installer - v1.4 (Усиленная безопасность)
# Автоматическое развертывание Node.js reverse proxy с HTTPS и harden-механизмами
# Автор: Proxy Deployment System + ChatGPT (на основе v1.3)
# История версий:
# - v1.3: минимальная стабильная архитектура
# - v1.4: добавлены улучшения безопасности: non-root user, обновление зависимостей, Fail2Ban, SSL auto-renewal

# Прочее содержимое остаётся без изменений, вплоть до шага установки Node-приложения и PM2
# Добавляется в блоки после установки приложения и перед финальным выводом

# === [ДОБАВЛЕНО В V1.4] ===

log_info "Укрепление безопасности (v1.4) — начало..."

# 1. Создание системного пользователя
log_info "Создание пользователя proxyuser..."
useradd -r -s /usr/sbin/nologin proxyuser || true
chown -R proxyuser:proxyuser "$PROJECT_DIR"

# 2. Правка app.js — app.listen на 127.0.0.1
sed -i "s/app.listen(PORT)/app.listen(PORT, '127.0.0.1')/" "$PROJECT_DIR/src/app.js"

# 3. Обновление proxy middleware до безопасной версии
cd "$PROJECT_DIR"
sudo -u proxyuser npm install http-proxy-middleware@2.0.9 --save
check_status "http-proxy-middleware обновлён до 2.0.9" "Ошибка обновления proxy middleware"

# 4. Уточнение CORS
if [ -z "$ALLOWED_ORIGIN" ]; then
  echo
  echo -e "${YELLOW}Хотите разрешить CORS-домены? Введите, например: https://go.glideapps.com или оставьте пустым:${NC}"
  read -p "Разрешённый origin: " ALLOWED_ORIGIN
fi

if [ -n "$ALLOWED_ORIGIN" ]; then
  sed -i "s|proxyRes.headers\['access-control-allow-origin'\].*|proxyRes.headers['access-control-allow-origin'] = '$ALLOWED_ORIGIN';|" "$PROJECT_DIR/src/app.js"
else
  sed -i "/proxyRes.headers\['access-control-allow-origin'\]/d" "$PROJECT_DIR/src/app.js"
fi

# 5. PM2 от proxyuser
su - proxyuser -s /bin/bash << EOF
cd "$PROJECT_DIR"
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup systemd -u proxyuser --hp /home/proxyuser
# Принудительное включение systemd-сервиса pm2-proxyuser
systemctl enable pm2-proxyuser

# Проверка статуса автозапуска
if systemctl is-enabled pm2-proxyuser &>/dev/null; then
  log_success "PM2 автозапуск включен"
else
  log_warning "❗ PM2 автозапуск не включен. Проверьте вручную: systemctl status pm2-proxyuser"
fi

EOF

# 6. Установка и настройка Fail2Ban
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

# 7. Автоматическое обновление сертификатов
if ! systemctl is-enabled certbot.timer &>/dev/null; then
  systemctl enable certbot.timer
  systemctl start certbot.timer
fi
check_status "SSL auto-renewal включён через certbot.timer" "Ошибка настройки SSL renew"

log_success "Укрепление безопасности выполнено (v1.4)"

# === [КОНЕЦ ДОБАВЛЕНИЙ V1.4] ===
