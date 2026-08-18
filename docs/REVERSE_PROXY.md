# Reverse proxy

The node control API can sit behind a reverse proxy. The peer mTLS/data port should
prefer a direct connection or TCP/TLS passthrough so the node validates the peer
certificate end to end.

The browser-facing Control Tower should normally be the only public HTTP service.
Proxy it to port `8090`, enable HTTPS, and set
`CONTROL_TOWER_SECURE_COOKIES=true`. Keep the node API on a private network when
the deployment topology permits it.

## Nginx

```nginx
server {
    listen 443 ssl;
    server_name jolt.example.test;

    client_max_body_size 0;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;

    location / {
        proxy_pass http://jolt-node:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }
}
```

Do not terminate peer mTLS with this HTTP server block. Use a direct route or the
Nginx stream module with `ssl_preread` and no TLS termination.

## Traefik

Traefik streams request bodies by default when no buffering middleware is attached.
Do not configure the buffering middleware for the jolt router:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.jolt.rule=Host(`jolt.example.test`)
  - traefik.http.routers.jolt.entrypoints=websecure
  - traefik.http.routers.jolt.tls=true
  - traefik.http.services.jolt.loadbalancer.server.port=8080
```

For the peer/data listener, use a TCP router with TLS passthrough:

```yaml
labels:
  - traefik.tcp.routers.jolt-peer.rule=HostSNI(`peer.example.test`)
  - traefik.tcp.routers.jolt-peer.entrypoints=peer
  - traefik.tcp.routers.jolt-peer.tls.passthrough=true
  - traefik.tcp.services.jolt-peer.loadbalancer.server.port=8443
```

Ingress timeouts outside these examples must also allow idle periods expected
during large transfers.

## Control Tower

```nginx
server {
    listen 443 ssl;
    server_name control.example.test;

    client_max_body_size 0;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;

    location / {
        proxy_pass http://jolt-control:8090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }
}
```

The Control Tower streams uploads and downloads to nodes. Request buffering or
short proxy timeouts would defeat that behavior.
