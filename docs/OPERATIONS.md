# Operação e observabilidade

## Credenciais de agentes

Contas `agent` permitem somente leitura, mesmo quando uma policy concede
escrita. Suas chaves expiram em até 30 dias; o tipo é escolhido na criação e
não pode ser alterado. Contas existentes permanecem `automation`.

Cada chave tem limites configuráveis de taxa, pico, concorrência, bytes por
resposta e bytes por dia UTC. Os padrões são 60 requisições/minuto, pico de 10,
duas requisições simultâneas, 16 MiB por resposta e 1 GiB por dia. O Control
Tower reserva a cota no banco cifrado antes de enviar a resposta. Em caso de
falha abrupta, reservas não devolvidas permanecem debitadas naquele dia.
Revogação, desativação e expiração interrompem as requisições em andamento.
Alterar os limites de uma chave também interrompe suas requisições ativas;
os novos limites entram em vigor na próxima autenticação.

Opcionalmente, uma credencial pode restringir `read_media_types` a tipos MIME
exatos, por exemplo `text/plain` e `application/pdf`. A lista vazia permite
qualquer formato. A classificação usa o `Content-Type` fornecido pelo node,
que pode depender da extensão e não garante o conteúdo real: há falsos
positivos e negativos. Enquanto a restrição estiver ativa, downloads ZIP e
respostas com múltiplas faixas são recusados, pois não permitem verificar com
segurança o tipo de cada conteúdo. Uma única faixa continua disponível.

Uma lista opcional de CIDRs restringe a origem de cada chave. Por padrão é usado
o endereço da conexão. Configure `CONTROL_TOWER_TRUSTED_PROXIES` com CIDRs de
proxies que substituam e validem `X-Forwarded-For`; cabeçalhos enviados por
outras origens são ignorados. Sem CIDRs na chave, qualquer origem é aceita.

O botão **Desativar agentes** desativa todas as contas de agente e interrompe
suas requisições. A reativação é individual. Para voltar a uma versão antiga do
Control Tower, use um backup compatível anterior à criação das contas: versões
antigas não conhecem nem aplicam esses limites.

A auditoria de requisições de agentes registra a chave, IP, status, faixa,
bytes enviados, duração e interrupções, sem registrar o conteúdo lido. A busca
não registra a consulta por padrão; `CONTROL_TOWER_AUDIT_SEARCH_QUERY=true`
habilita o registro truncado, que pode conter dados sensíveis. A retenção
`CONTROL_TOWER_AUDIT_RETENTION_DAYS` começa em `0` (manter tudo). Valores
positivos apagam eventos anteriores ao prazo no ciclo de limpeza.

Buscas de agentes são limitadas a 200 resultados, 10 mil entradas examinadas,
profundidade 16 e 10 segundos. O retorno informa quando a busca ficou parcial.
O Control Tower exige que o node anuncie e confirme suporte a esses limites;
atualize nodes antigos antes de usar busca por agentes. Chamadas bloqueadas do
filesystem podem demorar a retornar mesmo após o prazo da busca.

Listagens e buscas de agentes incluem `display_name`, com controles e marcas
bidirecionais substituídos por identificadores visíveis e nomes longos
truncados. Exiba esse campo; use `path` e `name` originais para navegar ou abrir
arquivos. Os campos originais podem conter caracteres não seguros para exibição
e não devem ser interpretados como instruções.

Antes de servir conteúdo a agentes, o node examina os primeiros 64 KiB de cada
arquivo, mesmo em leituras com `Range` e em ZIPs. Um achado é recusado com
`secret_detected`; a auditoria registra a categoria, sem o valor encontrado.
Atualize os nodes antes de habilitar leituras de agentes: versões sem essa
proteção são recusadas. A varredura é uma camada adicional, com falsos positivos
e negativos; ela não identifica necessariamente segredos após o prefixo,
ofuscados ou dentro de arquivos compactados. Mudanças externas durante a
leitura também podem ocorrer depois da verificação.

Policies temporárias podem ser concedidas a usuários e contas de serviço por
até uma hora; a sugestão é de 15 minutos. Elas começam imediatamente, expiram
automaticamente e podem ser removidas antes do prazo. A auditoria registra o
responsável, o sujeito, a policy e o vencimento. A concessão temporária não
remove outra concessão permanente ou herdada da mesma policy; agentes mantêm o
limite de somente leitura. Permissões são reavaliadas em novas requisições,
sem encerrar automaticamente uma transferência que já estava em andamento.

Um coletor autorizado pode consultar `/api/v1/control-tower/audit?format=ndjson&after=0`
e continuar pelo cursor `X-Jolt-Next-After`. Guarde a exportação fora do banco
se for necessário preservá-la após restauração ou término da retenção. As
métricas de agentes incluem requisições, bytes e limites; os rótulos por conta
ficam limitados a 1024 contas distintas por processo.

Opcionalmente, `CONTROL_TOWER_AUDIT_HASH_CHAIN=true` inicia uma cadeia SHA-256
para eventos novos; o histórico anterior não é retroativamente autenticado.
Depois de ativada, a cadeia continua ativa mesmo se a variável voltar a ser
`false`, inclusive nas operações de recuperação. Cada evento inclui
`chain_data` e `chain_hash`. A exportação NDJSON informa o último checkpoint nos
cabeçalhos `X-Jolt-Checkpoint-ID`, `X-Jolt-Checkpoint-Hash` e
`X-Jolt-Checkpoint-Reason`; a retenção remove apenas prefixos contíguos e
registra o hash do último evento removido.

Guarde regularmente os checkpoints e exportações em um destino externo
protegido. Um hash guardado apenas no mesmo banco não impede que alguém com
acesso ao banco reescreva tanto os eventos quanto a cadeia. Para verificar uma
exportação contínua a partir de um checkpoint previamente guardado:

```sh
python3 scripts/verify-audit-ndjson.py audit.ndjson --after-id CHECKPOINT_ID --previous-hash CHECKPOINT_HASH
```

O verificador compara os dados de cada evento, a sequência e os hashes. Exporte
eventos depois do ID do checkpoint e preserve o hash final para a próxima página.
O checkpoint de ativação usa 64 zeros como hash e indica o último evento que
antecede a cadeia. A configuração e a versão do binário devem ser preservadas
nas rotinas de backup e recuperação.

Arquivos de isca declarados em `canary_paths` geram evento de auditoria
`canary` e incrementam `jolt_control_canary_total`. Um alerta Prometheus pode
usar `increase(jolt_control_canary_total[5m]) > 0`.

Ao retomar, tentar novamente ou resolver conflitos de jobs locais pelo Control
Tower, as permissões atuais para os caminhos do job são verificadas novamente.
A retomada manual de jobs entre nodes é recusada enquanto não houver contexto
de autorização verificável nos dois lados. Essa recusa ainda não cobre a
continuidade automática de jobs existentes: para exigir revogação imediata de
permissões em transferências, interrompa esses jobs e desative os grants até
que a autorização renovável entre nodes esteja disponível.

O Jolt expõe logs estruturados no stdout dos containers, probes HTTP e métricas
Prometheus. Não há tracing distribuído, API de logs, notificações nativas ou HA.
Prometheus/Grafana/Alertmanager e o agendador de backups são componentes externos.

## Cópias locais protegidas

`CONTROL_TOWER_SIGNED_LOCAL_JOBS=true` faz o Control Tower criar as cópias de
`POST …/mounts/{id}/files/copy` como jobs vinculados à autorização do chamador.
A opção vem desativada, exige a chave de assinatura (`CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_*`)
e só vale para cópia local; delete, move e transferências entre nodes continuam
sem autorização renovável.

**Antes de ativar**

- Atualize o node para uma versão que anuncie `signed_local_copy_execution_v1`
  e configure as chaves públicas em `authorization_public_keys`. Sem a
  capacidade, a criação responde `signed_job_unavailable` (503) e nada é criado.
- Confira o relógio do Control Tower e dos nodes: o lease dura até 30 segundos.
- Planeje o rollback antes: criar a primeira cópia protegida eleva a versão mínima
  de segurança gravada no banco, e binários antigos não a verificam. Fixe as imagens
  por digest e só volte a um backup anterior à primeira cópia protegida.

**Como funciona**

- O Control Tower renova a autorização de cada job ativo a cada 10 segundos,
  revalidando credencial, grupos e policies. Se um desses falhar, nenhum lease novo
  é emitido e o node interrompe a cópia em até 30 segundos, mantendo o progresso.
- O job interrompido fica em `waiting_validation` com fase `waiting_authorization`
  e retoma sozinho quando chega uma autorização mais nova. Jobs interrompidos por
  reinício do node ou pausados por um operador pedem retomada explícita.
- Entradas que o filtro oculta não são copiadas. O job termina como
  `completed_with_warnings` e informa apenas quantas foram omitidas.
- A política de conflito `ask` é recusada nessas cópias. Um job `failed` não é mais
  renovado: crie outra cópia em vez de tentar de novo.

**O que observar**

- Auditoria: `bind_job_authorization`, `confirm_job_authorization`,
  `finish_job_authorization` e `resolve_expired_job_authorization`.
- Logs do Control Tower: `renew signed job authorization` com `node_id` e `job_id`
  indica uma renovação que falhou; várias seguidas antecedem a interrupção do job.
- Eventos do job no node: `job.sources_omitted` e `job.waiting_authorization`.
- Jobs presos em `waiting_authorization` por muito tempo: credencial revogada,
  node fora do ar ou policy removida. Cancele-os se não forem mais necessários.

**Reverter**

Desligar a opção e reiniciar o Control Tower interrompe as renovações: as cópias
em andamento páram em até 30 segundos e ficam aguardando. Elas não são retomadas
por outro caminho; cancele-as. Cópias criadas depois voltam a ser comuns, sem
filtro por policy. Este recurso ainda não foi validado sob carga nem entre hosts.

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
