# Reverse Proxy Setup

Tobimaru binds its HTTP server to `127.0.0.1:8080` by default and does not
terminate TLS. **Never expose the API directly to the network in production.**
Use a reverse proxy that handles TLS termination, request filtering, and
optional rate limiting.

This guide covers two popular options: **nginx** and **Caddy**.

## Common Considerations

- **TLS is mandatory** for remote access. The dashboard transmits session
  cookies and the API accepts credentials — both must be protected in transit.
- **SSE (Server-Sent Events)** requires the proxy to disable response buffering
  for the `/api/stream` endpoint. Otherwise, events are delayed or dropped.
- **WebSocket** is not used; SSE is a plain HTTP long-lived response, so
  standard proxy configuration works as long as buffering is off.
- **CORS** is handled by Tobimaru when `api.cors.allowed_origins` is set. If
  the proxy rewrites the `Origin` header or adds CORS headers itself, ensure
  there is no conflict.

## nginx

### Installation

```bash
# Debian/Ubuntu
sudo apt install nginx

# Fedora/RHEL
sudo dnf install nginx
```

### Configuration

Create `/etc/nginx/sites-available/tobimaru`:

```nginx
server {
    listen 443 ssl http2;
    server_name tobimaru.example.com;

    # TLS — adjust paths to your certificate
    ssl_certificate     /etc/ssl/certs/tobimaru.pem;
    ssl_certificate_key /etc/ssl/private/tobimaru.key;

    # Recommended TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE: disable response buffering
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }

    # Stricter timeouts for non-SSE API routes (optional)
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE endpoint lives under /api/stream
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name tobimaru.example.com;
    return 301 https://$host$request_uri;
}
```

### Enable the site

```bash
sudo ln -s /etc/nginx/sites-available/tobimaru /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Key points

- `proxy_buffering off` is required for SSE to work correctly.
- `proxy_read_timeout 86400s` prevents nginx from closing the SSE connection
  prematurely. Adjust to your needs.
- The `X-Forwarded-Proto` header lets Tobimaru know the original scheme if
  future features need it.

## Caddy

Caddy obtains and renews TLS certificates automatically via Let's Encrypt,
which makes it the simplest option.

### Installation

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

Refer to <https://caddyserver.com/docs/install> for other platforms.

### Configuration

Edit `/etc/caddy/Caddyfile`:

```
tobimaru.example.com {
    reverse_proxy 127.0.0.1:8080 {
        # SSE: disable buffering
        flush_interval -1
    }
}
```

### Run

```bash
sudo systemctl restart caddy
```

### Key points

- `flush_interval -1` tells Caddy to flush the response immediately, which is
  essential for SSE streams.
- Caddy handles TLS certificate provisioning and renewal automatically.
- If your server is behind a firewall, ensure ports 80 and 443 are open for
  the HTTP-01 or TLS-ALPN-01 ACME challenge.

## Tobimaru Configuration

Regardless of the proxy, keep Tobimaru bound to loopback:

```yaml
api:
  enabled: true
  listen: "127.0.0.1:8080"
```

If you need to accept connections from the proxy on a different address
(e.g., a Docker network), adjust `listen` accordingly, but never bind to
`0.0.0.0` on an internet-facing host.

For CORS, list the public origin:

```yaml
api:
  cors:
    allowed_origins:
      - "https://tobimaru.example.com"
```

## Verifying the Setup

1. **TLS**: `curl -v https://tobimaru.example.com/api/status` — should return
   JSON with a `200` status and a valid TLS certificate.
2. **SSE**: Open the dashboard in a browser, navigate to the Events page, and
   verify that events stream in real time without stalling.
3. **HTTP redirect**: `curl -I http://tobimaru.example.com/` should return a
   `301` or `308` redirect to `https://`.
