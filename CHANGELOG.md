# Changelog - Universal Proxy Installer
## Версия 1.4 – Node 20 LTS / Frame-Embedding DENY (2025-06-28)

### Главное
- ⬆️ **Node.js 20 LTS** вместо 18 LTS: более длочная поддержка и новые функции ECMAScript 2024.  
- 🚫 **X-Frame-Options: DENY** — полное исключение любого встраивания проксируемого сайта в `<iframe>`.  
- 🔒 **Единый CSP**, совместимый с Glide, но достаточный для безопасности:  
  `default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;`  
- 🩺 **Endpoint’ы `/health` и `/health/detailed`** добавлены прямо в `app.js`.  
- ♻️ **Упрощённая архитектура**: 1 файл `app.js`, без промежуточных middleware.

### Технические изменения
| Компонент | Было (v 1.3) | Стало (v 1.4) |
|-----------|--------------|---------------|
| Node.js   | 18 LTS (Maintenance c 2025-10) | **20 LTS** |
| CSP       | `default-src * data: blob:` | `default-src * 'unsafe-inline' 'unsafe-eval' data: blob:` |
| Заголовок `X-Frame-Options` | `ALLOWALL` | **`DENY`** |
| Endpoints | `/health` отсутствовал | `/health`, `/health/detailed` |
| Installer | `setup_18.x` | **`setup_20.x`** |

### Обновления безопасности
- Убраны все inline-перезаписывания CSP; теперь политика выставляется единственным, контролируемым хедером.  
- Удалены дубли `content-security-policy`, из-за которых CSP могла «скатываться» в базовую версию.  
- Усилены проверки на наличие `.env`; при отсутствии обязательных переменных сервис стартует с ошибкой, а не с `undefined`-целями.

### Исправления
- Исправлен баг с двукратным сохранением `pm2 save` без `--update-env`.  
- Устранён конфликт переменных окружения, из-за которого Node получал `undefined` вместо доменов.  
- Исправлены обрезанные строки CORS-хедеров в `app.js` (символ `>` в nano).

### Миграция с 1.3 → 1.4
1. **Сделайте бэкап**: `tar czf backup.tgz /opt/<PROJECT>`  
2. Замените скрипт установщика на свежий `universal-proxy-installer-v1.4-as.sh`.  
3. Выполните:  
   ```bash
   pm2 stop <PROJECT>
   # обновите Node до 20 LTS, если использовался 18
   curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
   apt-get install -y nodejs
   pm2 start <PROJECT> --update-env
   pm2 save
4. Убедитесь, что curl -I https://<proxy-domain>/ | grep -i content-security-policy
возвращает строку с 'unsafe-inline' 'unsafe-eval'.

Полный скрипт установщика v 1.4 (Node 20 LTS Edition) расположен здесь:
raw/universal-proxy-installer-v1.4-as.sh – обеспечивает чистую установку или обновление поверх 1.3.

## Версия 1.2 - Enhanced Stability Edition

### Основные улучшения
- ✅ **Повышенная стабильность сборки**: Добавлен модуль `stabilityEnhancer.js` для автоматического управления заголовками
- ✅ **Улучшенная совместимость**: Расширенная поддержка различных типов целевых сайтов
- ✅ **Расширенная обработка ошибок**: Graceful error handling во всех критических модулях

### Технические изменения

#### Новые модули и функции
- `src/stabilityEnhancer.js` - модуль для повышения совместимости
- Улучшенный `urlRewriter.js` с fallback механизмами
- Расширенная обработка ошибок в `app.js`

#### Конфигурация
- `ENHANCED_COMPATIBILITY=true` - активация режима повышенной совместимости
- `TRUST_PROXY=true` - улучшенная поддержка прокси
- Оптимизированная nginx конфигурация с удалением конфликтующих заголовков

#### Улучшения стабильности
- Автоматическое удаление проблематичных заголовков (`x-frame-options`, `content-security-policy`, `glide-allow-embedding`)
- Добавление совместимых заголовков для максимальной поддержки встраивания
- Защита от `ERR_HTTP_HEADERS_SENT` через проверки `res.headersSent`
- Улучшенная обработка `transfer-encoding` заголовков

#### Безопасность и производительность
- Адаптивное rate limiting (отключается в режиме совместимости)
- Оптимизированные security headers
- Graceful shutdown с обработкой uncaught exceptions
- Fallback механизмы для критических операций

### Совместимость
- Полная обратная совместимость с версией 1.1
- Автоматическая активация режима повышенной совместимости
- Поддержка всех существующих конфигураций

### Исправления
- Устранение потенциальных конфликтов заголовков
- Улучшенная обработка ошибок в потоках данных
- Стабилизация работы с различными типами контента

---

## Версия 1.1 - Production Ready

### Основные функции
- Автоматическое развертывание Node.js reverse proxy
- SSL сертификаты Let's Encrypt
- nginx SSL termination
- PM2 process management
- URL rewriting для HTML/CSS/JS
- Production monitoring
- Health check endpoints
- Firewall configuration
- Автоматические скрипты управления

## [1.1.0] - 2024-06-26 - ИСПРАВЛЕННАЯ ВЕРСИЯ

### 🔧 Critical Fixes
- **nginx Configuration**: Fixed double escape symbols (\\$ → \$) causing syntax errors
- **Port Conflicts**: Added port usage detection with netstat before installation
- **Project Conflicts**: Added existing project detection with cleanup option
- **Script Creation**: Ensured all management scripts are created reliably

### ✨ New Features
- **create_nginx_config()**: New function with proper escape handling using << 'EOF'
- **create_management_scripts()**: Dedicated function for management script creation
- **Project Validation**: Pre-installation checks for conflicts and dependencies

### 🛠 Improvements
- Added `net-tools` package for netstat command
- Enhanced error handling and user feedback
- Better validation of installation parameters
- Improved documentation and troubleshooting guides

### 🐛 Bug Fixes
- Fixed nginx configuration syntax errors
- Fixed SSL certificate acquisition issues
- Fixed PM2 process management conflicts
- Fixed management script creation interruptions

### 📦 Dependencies
- Added: net-tools (for netstat command)

### 🔄 Migration
- Fully backward compatible with v1.0 installations
- Can be used to update existing configurations
- No breaking changes to existing deployments

## [1.1.0] - 2024-12-28

### Fixed
- Fixed nginx configuration escaping issues (\\$ -> \$)
- Added project existence check with cleanup option
- Added port conflict detection and warnings
- Improved script creation with proper functions
- Better error handling and validation

### Improved
- Multiple proxy instances support on same server
- Enhanced installer reliability and robustness
- Better user feedback and warnings

## [1.0.0] - 2024-12-28

### Added
- Initial release of GlideProxy Universal Reverse Proxy Installer
- Automatic Node.js 18.x installation and configuration
- PM2 process manager with memory limits and auto-restart
- nginx SSL termination with Let's Encrypt certificates
- Advanced URL rewriting for HTML/CSS/JavaScript content
- Comprehensive health monitoring with periodic target checks
- Winston logging with daily rotation
- Production-ready security configuration (HSTS, rate limiting, security headers)
- UFW firewall automatic configuration
- Interactive and automated installation modes
- One-liner installation support
- Management scripts (status, restart, logs, SSL renewal)
- Comprehensive documentation and usage examples

### Features
- **Automatic SSL**: Let's Encrypt certificates with auto-renewal
- **Security**: TLS 1.2/1.3, HSTS headers, rate limiting, attack pattern blocking
- **Monitoring**: Health checks, comprehensive logging, PM2 monitoring
- **URL Rewriting**: Advanced content transformation for HTML/CSS/JS
- **Management**: Ready-to-use scripts for common operations
- **Flexibility**: Configurable parameters for different use cases

### Supported Systems
- Ubuntu 18.04+ (recommended 20.04+)
- Debian 10+
- CentOS 8+ (requires adaptation)

### Minimum Requirements
- RAM: 512MB (recommended 1GB+)
- Disk: 2GB free space
- Network: Internet access for package installation
- Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS) 
