# Настройка обратного прокси

Tobimaru по умолчанию привязывает HTTP-сервер к `127.0.0.1:8080` и не
завершает TLS. **Никогда не открывайте API напрямую в сеть в продакшене.**
Используйте обратный прокси, который обеспечивает терминацию TLS, фильтрацию
запросов и опциональное ограничение частоты запросов.

В этом руководстве рассмотрены два популярных варианта: **nginx** и **Caddy**.

## Общие рекомендации

- **TLS обязателен** для удалённого доступа. Дашборд передаёт сессионные
  cookie, а API принимает учётные данные — оба должны быть защищены при
  передаче.
- **SSE (Server-Sent Events)** требует отключения буферизации ответов на
  прокси для эндпоинта `/api/stream`. Без этого события задерживаются или
  теряются.
- **WebSocket** не используется; SSE — это обычный длительный HTTP-ответ,
  поэтому стандартная конфигурация прокси работает при отключённой буферизации.
- **CORS** обрабатывается Tobimaru, если задано `api.cors.allowed_origins`.
  Если прокси перезаписывает заголовок `Origin` или добавляет свои CORS-заголовки,
  убедитесь, что конфликта нет.

## nginx

### Установка

```bash
# Debian/Ubuntu
sudo apt install nginx

# Fedora/RHEL
sudo dnf install nginx
```

### Конфигурация

Создайте `/etc/nginx/sites-available/tobimaru`:

```nginx
server {
    listen 443 ssl http2;
    server_name tobimaru.example.com;

    # TLS — укажите пути к вашим сертификатам
    ssl_certificate     /etc/ssl/certs/tobimaru.pem;
    ssl_certificate_key /etc/ssl/private/tobimaru.key;

    # Рекомендуемые настройки TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE: отключить буферизацию ответов
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }

    # Строгие таймауты для не-SSE маршрутов API (опционально)
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Эндпоинт SSE находится по пути /api/stream
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }
}

# Перенаправление HTTP на HTTPS
server {
    listen 80;
    server_name tobimaru.example.com;
    return 301 https://$host$request_uri;
}
```

### Активация сайта

```bash
sudo ln -s /etc/nginx/sites-available/tobimaru /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Ключевые моменты

- `proxy_buffering off` необходим для корректной работы SSE.
- `proxy_read_timeout 86400s` предотвращает преждевременное закрытие
  SSE-соединения nginx. Настройте под свои нужды.
- Заголовок `X-Forwarded-Proto` информирует Tobimaru об исходной схеме,
  если это потребуется в будущем.

## Caddy

Caddy автоматически получает и обновляет TLS-сертификаты через Let's Encrypt,
что делает его самым простым вариантом.

### Установка

```bash
# Debian/Ubuntu
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy

# Fedora/RHEL
sudo dnf install 'dnf-command(copr)'
sudo dnf copr enable @caddy/caddy
sudo dnf install caddy
```

Инструкции для других платформ см. на <https://caddyserver.com/docs/install>.

### Конфигурация

Отредактируйте `/etc/caddy/Caddyfile`:

```
tobimaru.example.com {
    reverse_proxy 127.0.0.1:8080 {
        # SSE: отключить буферизацию
        flush_interval -1
    }
}
```

### Запуск

```bash
sudo systemctl restart caddy
```

### Ключевые моменты

- `flush_interval -1` указывает Caddy немедленно сбрасывать ответ, что
  необходимо для SSE-потоков.
- Caddy автоматически обрабатывает получение и обновление TLS-сертификатов.
- Если сервер находится за файрволом, убедитесь, что порты 80 и 443 открыты
  для ACME-челленджа HTTP-01 или TLS-ALPN-01.

## Конфигурация Tobimaru

Независимо от прокси, Tobimaru должен оставаться привязанным к loopback:

```yaml
api:
  enabled: true
  listen: "127.0.0.1:8080"
```

Если необходимо принимать соединения от прокси на другом адресе
(например, в Docker-сети), измените `listen`, но никогда не привязывайтесь
к `0.0.0.0` на хосте, доступном из интернета.

Для CORS укажите публичный origin:

```yaml
api:
  cors:
    allowed_origins:
      - "https://tobimaru.example.com"
```

## Проверка настройки

1. **TLS**: `curl -v https://tobimaru.example.com/api/status` — должен вернуть
   JSON со статусом `200` и валидный TLS-сертификат.
2. **SSE**: Откройте дашборд в браузере, перейдите на страницу Events и
   убедитесь, что события поступают в реальном времени без задержек.
3. **Перенаправление HTTP**: `curl -I http://tobimaru.example.com/` должен
   вернуть перенаправление `301` или `308` на `https://`.
