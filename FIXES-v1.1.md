# Исправления в universal-proxy-installer-v1.4-as.sh
1. Назначение
Цель	Что реализовано
Слой HTTPS-терминации	Nginx + Let’s Encrypt, автоматическое обновление сертификатов
Прозрачное проксирование Glide-приложения	http-proxy-middleware c изменением заголовков
Запрет встраивания в <iframe>	X-Frame-Options: DENY выдаётся на все ответы
CSP, совместимая с Glide	default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;
Минимальная архитектура	Один app.js, управление — PM2, автоперезапуск, cron-restart в 03:00

2. Файловая структура
bash
Копировать
Редактировать
/opt/my-proxy/
├── src/app.js            # основное приложение Node.js
├── ecosystem.config.js   # конфиг PM2
├── .env                  # переменные окружения (домен-цель, порты…)
├── config/nginx-proxy.conf   # готовый virtual-host
├── scripts/              # status/restart/logs/renew-ssl
└── logs/                 # логи приложения и PM2
3. Ключевые параметры (.env)
env
Копировать
Редактировать
NODE_ENV=production
PORT=3000

PROXY_DOMAIN=as-csoftware.ru
TARGET_DOMAIN=ascs-projects.glide.page
TARGET_PROTOCOL=https

# включены:
ENHANCED_COMPATIBILITY=true
MINIMAL_MODE=true
Менять домены/порт — строго здесь; после правки → pm2 restart my-proxy --update-env.

4. Основные заголовки, выставляемые прокси
text
Копировать
Редактировать
X-Frame-Options: DENY                              # запрет <iframe>
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;
Access-Control-Allow-Origin: *                     # CORS (можно сузить)
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH
Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept
Access-Control-Allow-Credentials: true
5. Эксплуатация
Операция	Команда / файл
Статус сервисов	/opt/my-proxy/scripts/status.sh
Live-логи	/opt/my-proxy/scripts/logs.sh или pm2 logs my-proxy
Перезапуск приложения	/opt/my-proxy/scripts/restart.sh
Обновить SSL вручную	/opt/my-proxy/scripts/renew-ssl.sh
Снять дамп процессов	pm2 save
Старт / стоп PM2	`pm2 start

6. Точки контроля
Health-чек приложения

css
Копировать
Редактировать
curl -s https://as-csoftware.ru/health        # { "status": "ok" }
HTTP→HTTPS редирект

perl
Копировать
Редактировать
curl -I http://as-csoftware.ru/ | grep "301"
Заголовок CSP

css
Копировать
Редактировать
curl --http1.1 -I https://as-csoftware.ru/ | grep -i content-security-policy
7. Как изменить политику CSP или разрешить отдельные домены
Файл: /opt/my-proxy/src/app.js, блок onProxyRes

js
Копировать
Редактировать
// пример более строгого варианта
proxyRes.headers['content-security-policy'] =
  "default-src 'self'; script-src 'self' https://*.glideapps.com 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src * data: blob:;";
После правки:

bash
Копировать
Редактировать
pm2 restart my-proxy
pm2 save
8. Резервное копирование / миграция
bash
Копировать
Редактировать
tar czf proxy-backup_$(date +%F).tgz /opt/my-proxy /etc/nginx/sites-available/my-proxy /etc/letsencrypt/live/as-csoftware.ru
# восстановление на чистом сервере:
tar xf proxy-backup.tgz -C /
pm2 resurrect          # если PM2-dump присутствует
systemctl reload nginx

# Исправления в Universal Proxy Installer v1.1

## 🔧 Основные исправления

### 1. Исправлены escape символы в nginx конфигурации
**Проблема**: Неправильное экранирование `\\$` в nginx конфигурации приводило к синтаксическим ошибкам.

**Решение**: 
- Создана функция `create_nginx_config()` с правильными escape символами
- `\\$` заменено на `\$` для корректной работы nginx

### 2. Добавлена проверка существующих проектов
**Проблема**: Установщик не проверял существование проекта с тем же именем.

**Решение**:
- Добавлена проверка директории `/opt/$PROJECT_NAME`
- Возможность перезаписи существующего проекта с подтверждением
- Автоматическая очистка при `AUTO_CONFIRM=yes`

### 3. Добавлена проверка конфликта портов
**Проблема**: Установщик не проверял, занят ли указанный порт.

**Решение**:
- Проверка через `netstat` перед установкой
- Предупреждение о возможном конфликте
- Возможность продолжить установку с предупреждением

### 4. Улучшена структура создания скриптов
**Проблема**: Скрипты управления создавались без проверок и могли не создаваться при прерванной установке.

**Решение**:
- Создана функция `create_management_scripts()`
- Гарантированное создание всех скриптов управления
- Правильные права доступа

### 5. Обновлена информация о версии
**Проблема**: Не было индикации исправленной версии.

**Решение**:
- Обновлена версия до 1.1 (исправленная)
- Добавлена информация в заголовок установщика

## 🛠️ Технические детали

### nginx конфигурация
```bash
# Было (неправильно):
return 301 https://\\$server_name\\$request_uri;

# Стало (правильно):
return 301 https://\$server_name\$request_uri;
```

### Проверки перед установкой
```bash
# Проверка существующего проекта
if [ -d "$PROJECT_DIR" ]; then
    log_warning "Проект $PROJECT_NAME уже существует"
    # Запрос подтверждения...
fi

# Проверка портов
if netstat -tlnp 2>/dev/null | grep -q ":$NODE_PORT "; then
    log_warning "Порт $NODE_PORT уже используется"
    # Предупреждение...
fi
```

## 📋 Результат

Эти исправления решают проблемы, возникшие при установке второго экземпляра `otter-proxy`:

1. ✅ **nginx конфигурация** теперь создается без синтаксических ошибок
2. ✅ **Конфликты проектов** предотвращаются проверками
3. ✅ **Конфликты портов** обнаруживаются заранее  
4. ✅ **Скрипты управления** создаются гарантированно
5. ✅ **Версионность** отслеживается правильно

## 🚀 Использование

Исправленный установщик можно использовать для множественных установок на одном сервере:

```bash
# Первый прокси
export PROXY_DOMAIN="proxy1.example.com"
export TARGET_DOMAIN="target1.example.com"
export PROJECT_NAME="proxy1"
export NODE_PORT="3000"
sudo ./universal-proxy-installer.sh

# Второй прокси
export PROXY_DOMAIN="proxy2.example.com"
export TARGET_DOMAIN="target2.example.com"
export PROJECT_NAME="proxy2"
export NODE_PORT="3001"
sudo ./universal-proxy-installer.sh
```

Установщик автоматически обнаружит и предотвратит конфликты. 
