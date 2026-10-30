# Operação e observabilidade

O Jolt expõe logs estruturados no stdout dos containers, probes HTTP e métricas
Prometheus. Não há tracing distribuído, API de logs, notificações nativas ou HA.
Prometheus/Grafana/Alertmanager e o agendador de backups são componentes externos.

## Rotinas

**Diária**

- conferir `up`, `/readyz`, taxa de 5xx, jobs falhos e capacidade dos mounts;
- revisar nodes `offline`/`untrusted`, mounts indisponíveis e jobs em
  `waiting_validation`, `waiting_mount`, `waiting_peer` ou `waiting_user_decision`;
- confirmar que o backup agendado terminou e que alertas de login/compartilhamento
  foram triados.

**Semanal**

- revisar auditoria administrativa e service accounts sem grupo ativo;
- verificar crescimento dos volumes de estado, duração de jobs e uploads ativos
  antigos; uploads expirados são limpos pelo node;
- avaliar atualizações de segurança de Go, npm, imagem base e da camada C nativa.

**Mensal e antes de cada release**

- ensaiar restore em diretórios vazios, sem tocar nos volumes ativos;
- revisar secrets, acessos admin, políticas `sudo`, grants e endpoints públicos;
- registrar versão, SHA e digests em produção e comparar com a Release aprovada.

Os comandos de backup exigem parada e são detalhados em
[DISASTER_RECOVERY.md](DISASTER_RECOVERY.md). Faça backup independente dos mounts:
os snapshots não contêm os arquivos publicados.

## Logs e probes

```sh
docker compose --env-file .env -f docker-compose.yml logs --since=1h jolt-control
docker compose --env-file .env -f docker-compose.node.yml logs --since=1h jolt-node
curl --fail http://127.0.0.1:8090/livez
curl --fail http://127.0.0.1:8090/readyz
```

`/health` permanece como alias de liveness. Não use `/livez` para disparar
restores nem `/readyz` como garantia de que peers/mounts estejam saudáveis.
Envie logs a um coletor externo com rotação e retenção; não grave tokens,
conteúdo de secrets ou URLs de share em alertas.

## Prometheus

`/metrics` só existe quando o token dedicado está configurado e exige
`Authorization: Bearer`. Não use token operacional, sessão ou API key. Restrinja
o scrape por rede/TLS e armazene os tokens no secret store do Prometheus.

```yaml
scrape_configs:
  - job_name: jolt-control
    scheme: https
    authorization:
      credentials_file: /run/secrets/jolt_control_metrics_token
    static_configs:
      - targets: [control.internal.example:8090]
  - job_name: jolt-node
    scheme: https
    authorization:
      credentials_file: /run/secrets/jolt_node_metrics_token
    static_configs:
      - targets: [node-a.internal.example:8080, node-b.internal.example:8080]
```

Adapte scheme/porta à API TLS e à rede real. Não exponha `/metrics` na Internet.
Labels usam padrões de rota, não caminhos de arquivos ou tokens de share.

### Métricas úteis

- Control Tower: `jolt_control_info`, `jolt_control_http_requests_total`,
  `jolt_control_http_request_duration_seconds`, `jolt_control_logins_total`,
  `jolt_control_login_failures_total`, `jolt_control_login_lockouts_total`,
  `jolt_control_authorization_denied_total`, `jolt_control_node_proxy_total`,
  `jolt_control_shares_created_total`, `jolt_control_shares_revoked_total`,
  `jolt_control_share_downloads_total` e
  `jolt_control_share_unlock_failures_total`.
- Node: `jolt_node_info`, `jolt_http_requests_total`,
  `jolt_http_request_duration_seconds`, `jolt_http_response_bytes_total`,
  `jolt_jobs_total`, `jolt_jobs_active`, `jolt_job_bytes_total`,
  `jolt_max_concurrent_jobs`, `jolt_uploads_started_total`,
  `jolt_uploads_completed_total`, `jolt_uploads_failed_total`,
  `jolt_uploads_aborted_total`, `jolt_uploads_active` e
  `jolt_upload_bytes_total`.
- Ambos exportam métricas de runtime Go com prefixo `go_`/`process_` conforme o
  registro nativo. Counters só aumentam; use `rate()`/`increase()`.

## Alertas de referência

Os limiares abaixo são iniciais e precisam ser calibrados com carga real. Um job
falho pode ser decisão de conflito ou autorização; correlacione com UI/auditoria
antes de reiniciar serviços.

```yaml
groups:
  - name: jolt-availability
    rules:
      - alert: JoltTargetDown
        expr: up{job=~"jolt-control|jolt-node"} == 0
        for: 5m
        labels: {severity: critical}
        annotations:
          summary: "Jolt não está sendo coletado: {{ $labels.instance }}"
      - alert: JoltControlServerErrors
        expr: sum(rate(jolt_control_http_requests_total{status=~"5.."}[5m])) > 0.1
        for: 10m
        labels: {severity: warning}
      - alert: JoltNodeServerErrors
        expr: sum(rate(jolt_http_requests_total{status=~"5.."}[5m])) > 0.1
        for: 10m
        labels: {severity: warning}
      - alert: JoltNodeProxyFailures
        expr: sum(rate(jolt_control_node_proxy_total{result!="success"}[5m])) > 0.1
        for: 10m
        labels: {severity: warning}
      - alert: JoltLoginFailures
        expr: sum(rate(jolt_control_login_failures_total[5m])) > 0.2
        for: 10m
        labels: {severity: warning}
      - alert: JoltSharePasswordFailures
        expr: sum(rate(jolt_control_share_unlock_failures_total[5m])) > 0.2
        for: 10m
        labels: {severity: warning}
```

Antes de ativar o alerta de proxy, confira os valores de `result` no ambiente e
exclua resultados esperados de política, se necessário. Adicione alertas de disco
e filesystem por `node_filesystem_*` do node_exporter: as métricas Jolt não
substituem telemetria do host nem informam peers/mounts individualmente.

## Dashboard Grafana de referência

Crie uma linha por produto, com variável `instance`, e use estes painéis:

| Painel | Consulta principal |
| --- | --- |
| Disponibilidade | `jolt_control_info` ou `jolt_node_info` |
| Requisições/s | `sum by (route,status) (rate(jolt_http_requests_total[5m]))` (prefixo `jolt_control_` no Control) |
| Latência p95 | `histogram_quantile(0.95, sum by (le,route) (rate(jolt_http_request_duration_seconds_bucket[5m])))` |
| Jobs ativos/capacidade | `jolt_jobs_active` e `jolt_max_concurrent_jobs` |
| Jobs terminais | `sum by (type,state) (rate(jolt_jobs_total[1h]))` |
| Bytes de jobs/s | `sum by (type) (rate(jolt_job_bytes_total[5m]))` |
| Uploads | `jolt_uploads_active` e `sum(rate(jolt_uploads_completed_total[1h]))` |
| Falhas de upload | `sum(rate(jolt_uploads_failed_total[1h]))` |
| Autenticação | `rate(jolt_control_login_failures_total[5m])`, lockouts e logins |
| Autorização | `sum by (capability) (rate(jolt_control_authorization_denied_total[5m]))` |
| Proxy de nodes | `sum by (node_id,result) (rate(jolt_control_node_proxy_total[5m]))` |
| Shares | criação, revogação, downloads e falhas de senha por hora |
| Runtime | heap/goroutines/CPU e espaço de disco do host |

Latência de streaming inclui duração do download/upload; não trate p95 alto como
erro sem segmentar rota. `jolt_node_info` e `jolt_control_info` indicam scrape da
aplicação, não readiness ou integridade de dados.

## Resposta a incidentes

1. Preserve logs, métricas, auditoria, versão e digests; não exponha secrets.
2. Para conter escrita, pause/cancele jobs ou revogue grants/peers conforme o caso.
3. Para credencial comprometida, use a recuperação offline documentada e atualize
   token no node e Control Tower de forma coordenada.
4. Para inconsistência de estado, pare o serviço, preserve evidências e restaure
   em local separado. Não execute comandos de recovery sobre instância ativa.
5. Antes de voltar, execute readiness, diagnóstico e uma transferência pequena;
   registre impacto e ações no relatório de release/incidente.

Vulnerabilidades devem ser reportadas por GitHub Security Advisory privada, sem
issue pública com segredo, dados pessoais ou prova contendo arquivos reais.
Inclua versão/SHA/digest, arquitetura, configuração redigida, impacto e passos
mínimos de reprodução. Não há neste repositório promessa de SLA de resposta.
