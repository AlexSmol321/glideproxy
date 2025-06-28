# GlideProxy - Universal Reverse Proxy Installer

🚀 **Автоматический установщик production-ready Node.js reverse proxy с HTTPS**

Полностью автономный скрипт для развертывания reverse proxy сервера с SSL сертификатами, мониторингом и управлением в один клик.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Node.js](https://img.shields.io/badge/Node.js-18.x-brightgreen.svg)](https://nodejs.org/)
[![nginx](https://img.shields.io/badge/nginx-SSL-blue.svg)](https://nginx.org/)

## ✨ Особенности

- 🔒 **Автоматические SSL сертификаты** (Let's Encrypt)
- 🛡️ **Production-ready безопасность** (Rate limiting, Security headers, Firewall)
- 🔄 **Продвинутый URL rewriting** (HTML/CSS/JS transformation)
- 📊 **Comprehensive мониторинг** (Health checks, Logging, PM2)
- 🎛️ **Простое управление** (Готовые скрипты, Автоматические обновления)

## 🚀 Быстрый старт

### Интерактивная установка
```bash
# Скачайте установщик
curl -O https://raw.githubusercontent.com/AlexSmol321/glideproxy/refs/heads/main/universal-proxy-installer-v1.3.1-as.sh

# Запустите установку
chmod +x universal-proxy-installer-v1.3.1-as.sh
sudo ./universal-proxy-installer-v1.3.1-as.sh
```

### Автоматическая установка
```bash
export PROXY_DOMAIN="proxy.example.com"
export TARGET_DOMAIN="old.example.com"
export SSL_EMAIL="admin@example.com"
export PROJECT_NAME="my-proxy"
sudo ./universal-proxy-installer.sh
```

### One-liner установка
```bash
curl -sSL https://raw.githubusercontent.com/bramox/glideproxy/main/universal-proxy-installer.sh | \
PROXY_DOMAIN="proxy.example.com" \
TARGET_DOMAIN="old.example.com" \
SSL_EMAIL="admin@example.com" \
sudo bash
```

## 📋 Требования

- **OS**: Ubuntu 18.04+, Debian 10+
- **RAM**: 512MB+ (рекомендуется 1GB+)
- **Root доступ** для установки системных пакетов
- **DNS записи** для вашего домена должны указывать на сервер

## ⚙️ Конфигурация

### Обязательные параметры
- `PROXY_DOMAIN` - ваш домен прокси (например, proxy.example.com)
- `TARGET_DOMAIN` - целевой домен (например, old.example.com)
- `SSL_EMAIL` - email для Let's Encrypt сертификата

### Опциональные параметры
- `PROJECT_NAME` - имя проекта (по умолчанию: reverse-proxy)
- `NODE_PORT` - порт Node.js (по умолчанию: 3000)
- `TARGET_PROTOCOL` - протокол цели (по умолчанию: https)
- `MAX_MEMORY` - лимит памяти PM2 (по умолчанию: 512M)
- `RATE_LIMIT` - лимит запросов/сек (по умолчанию: 10)

### Файлы конфигурации

В репозитории доступны примеры конфигурации:
- **config.env.example** - пример переменных окружения
- **nginx.conf.example** - пример nginx конфигурации

При установке создаются:
- **.env** - рабочие переменные окружения
- **nginx конфигурация** - автоматически генерируется для ваших доменов

## 🏗️ Архитектура

```
Internet (443) → nginx SSL → Node.js (3000) → Target Server
                     ↓
              Let's Encrypt SSL
              Security Headers
              Rate Limiting
                     ↓
              Express + Proxy
              URL Rewriting
              Health Monitoring
                     ↓
              PM2 Process Manager
              Auto-restart
              Memory Management
```

## 📁 Что создается

```
/opt/project-name/
├── src/                    # Node.js приложение
│   ├── app.js             # Express сервер с proxy
│   ├── logger.js          # Winston логирование
│   ├── urlRewriter.js     # URL rewriting
│   └── healthcheck.js     # Health monitoring
├── config/
│   └── nginx-proxy.conf   # nginx конфигурация
├── scripts/               # Управление
│   ├── status.sh         # Проверка статуса
│   ├── restart.sh        # Перезапуск
│   ├── logs.sh           # Просмотр логов
│   └── renew-ssl.sh      # Обновление SSL
├── logs/                 # Логи приложения
├── package.json          # Node.js зависимости
├── ecosystem.config.js   # PM2 конфигурация
├── .env                  # Переменные окружения
└── README.md            # Документация
```

## 🔗 Endpoints

После установки доступны:
- **Main Proxy**: `https://your-domain.com/`
- **Health Check**: `https://your-domain.com/health`
- **Detailed Health**: `https://your-domain.com/health/detailed`
- **nginx Health**: `https://your-domain.com/nginx-health`

## 🛠️ Управление

```bash
cd /opt/your-project-name

# Статус всех сервисов
./scripts/status.sh

# Перезапуск
./scripts/restart.sh

# Просмотр логов
./scripts/logs.sh

# Обновление SSL
./scripts/renew-ssl.sh
```

## 📊 Мониторинг

```bash
# PM2 мониторинг
pm2 monit

# Health check
curl https://your-domain.com/health

# nginx статус
systemctl status nginx

# Логи
tail -f /opt/your-project-name/logs/app-*.log
```

## 🛡️ Безопасность

Автоматически настраивается:
- **TLS 1.2/1.3** шифрование
- **HSTS** headers
- **Rate limiting** (настраиваемый)
- **Security headers** (X-Frame-Options, X-XSS-Protection, etc.)
- **Attack pattern blocking**
- **UFW Firewall** (порты 22, 80, 443)

## 🔄 Автоматические процессы

- **SSL сертификаты** обновляются автоматически
- **PM2** перезапускает приложение при сбоях
- **Daily restart** в 3:00 AM для очистки памяти
- **Health monitoring** проверяет целевой сервер каждые 30 секунд
- **Log rotation** предотвращает переполнение диска

## 📖 Примеры использования

### Простой reverse proxy
```bash
export PROXY_DOMAIN="proxy.mysite.com"
export TARGET_DOMAIN="old.mysite.com"
export SSL_EMAIL="webmaster@mysite.com"
sudo ./universal-proxy-installer.sh
```

### High-performance API proxy
```bash
export PROXY_DOMAIN="api-proxy.company.com"
export TARGET_DOMAIN="legacy-api.company.com"
export SSL_EMAIL="devops@company.com"
export NODE_PORT="8080"
export MAX_MEMORY="1G"
export RATE_LIMIT="50"
sudo ./universal-proxy-installer.sh
```

### HTTPS proxy для HTTP backend
```bash
export PROXY_DOMAIN="secure.example.com"
export TARGET_DOMAIN="internal.example.com"
export TARGET_PROTOCOL="http"
export SSL_EMAIL="security@example.com"
sudo ./universal-proxy-installer.sh
```

## 🔧 Troubleshooting

### Проблемы с SSL
```bash
certbot certificates
certbot renew --dry-run
nginx -t
```

### Проблемы с приложением
```bash
pm2 logs your-project-name
tail -f /opt/your-project-name/logs/error-*.log
```

### Проблемы с сетью
```bash
netstat -tlnp | grep -E ":80|:443|:3000"
ufw status
curl -I https://your-target-domain.com
```

## 📚 Документация

- **[USAGE.md](USAGE.md)** - Подробная инструкция по использованию
- **[memory_bank/tasks.md](memory_bank/tasks.md)** - История разработки и технические детали

## 🤝 Поддержка

При возникновении проблем:
1. Проверьте статус: `./scripts/status.sh`
2. Просмотрите логи: `./scripts/logs.sh`
3. Используйте health endpoints для диагностики
4. Изучите документацию в USAGE.md

## 📄 Лицензия

MIT License - свободное использование и модификация.

---

**Создано на базе успешного production развертывания**

Этот установщик основан на реальном production решении, которое успешно работает с полным SSL, мониторингом и автоматическим управлением. 
