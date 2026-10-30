# Reverse proxy e TLS

Em produção, o proxy HTTPS do Control Tower deve ser o único serviço HTTP público.
O backend permanece em `127.0.0.1:8090` no manifest de `deploy/`. A API do node
fica em rede privada/VPN; não a publique por este proxy. O peer TCP 8443 precisa
de conexão direta ou TLS passthrough para preservar mTLS de ponta a ponta.

Defina `CONTROL_TOWER_PUBLIC_BASE_URL=https://control.example.test` e mantenha
`CONTROL_TOWER_SECURE_COOKIES=true`. O proxy deve encaminhar `Host` e
`X-Forwarded-Proto`, não bufferizar uploads/downloads/SSE e permitir streams de
longa duração. O Jolt deliberadamente não confia em `X-Forwarded-For` para o
lockout; use o proxy/firewall para limites por IP adicionais.

## Nginx — Control Tower

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name control.example.test;

    # Configure ssl_certificate and ssl_certificate_key for this host.
    client_max_body_size 0;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }
}
```

Não use `proxy_cache` para API, conteúdo ou shares. Uploads retomáveis continuam
dependendo dos offsets persistidos no node; desligar buffering evita mudar seu
comportamento de streaming.

## Traefik — Control Tower

Não associe middleware de buffering/compressão às rotas de stream:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.jolt-control.rule=Host(`control.example.test`)
  - traefik.http.routers.jolt-control.entrypoints=websecure
  - traefik.http.routers.jolt-control.tls=true
  - traefik.http.services.jolt-control.loadbalancer.server.port=8090
```

Adapte a descoberta Docker e a rede para alcançar a porta 8090 sem publicar o
backend externamente.

## Peer mTLS — passthrough

Não termine nem reescreva o TLS de peers. Com Nginx stream, o roteamento SNI é
opcional quando há IP/porta dedicados:

```nginx
stream {
    upstream jolt_node_a_peer {
        server 10.20.0.12:8443;
    }
    server {
        listen 8443;
        proxy_pass jolt_node_a_peer;
        proxy_connect_timeout 10s;
        proxy_timeout 1h;
    }
}
```

Com Traefik, use TCP router com passthrough:

```yaml
labels:
  - traefik.tcp.routers.jolt-peer.rule=HostSNI(`node-a.example.test`)
  - traefik.tcp.routers.jolt-peer.entrypoints=peer
  - traefik.tcp.routers.jolt-peer.tls.passthrough=true
  - traefik.tcp.services.jolt-peer.loadbalancer.server.port=8443
```

`mtls_public_endpoint` deve ser o DNS/IP e porta que os outros nodes realmente
alcançam. Confirme firewall e hairpin NAT quando origem e destino estiverem na
mesma rede. Um proxy HTTP comum ou TLS termination quebra a autenticação do peer.

## API privada do node

Quando o Control Tower estiver em outro host, prefira VPN e bind de TCP 8080
somente no endereço privado, conforme [PRODUCTION.md](PRODUCTION.md). Se usar TLS
na API, configure os certificados no YAML do node e a CA/client certificate no
Control Tower. Não substitua mTLS de peer por bearer token nem use
`--no-check-certificate` fora do health check local do exemplo.
