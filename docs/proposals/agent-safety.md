# Proposta — Segurança para acesso de agentes de IA

> **Status:** implementação em andamento · **Origem:** uso do Jolt no homelab para dar a agentes de IA acesso somente leitura ao filesystem dos hosts, sem SSH · **Complementa:** [`file-type-restrictions.md`](file-type-restrictions.md) (a camada A dele é pré-requisito) · **Código lido:** `control/internal/httpapi/server.go`, `control/internal/store/store.go`, `control/internal/rbac/rbac.go`, `control/cmd/jolt-control/main.go`

> **Acompanhamento em 5 de novembro de 2026:** o perfil de agente, limites e teto de capabilities por credencial, auditoria, canaries, varredura e JIT têm implementação parcial. O proxy pode emitir leitura assinada mediante configuração explícita; cópias locais protegidas recebem renovação opcional, enquanto delete, move e transferências ainda não. Aprovação humana de delete, move e copy de arquivos (S10) existe, opcional e sem pedidos por agentes; a lixeira por mount (S9) existe no node e no Control Tower, sem cota nem métricas; JWT/SVID e MCP seguem como descrito no consolidado. Consulte o [plano consolidado](plano-consolidado-seguranca.md) para as evidências e os próximos passos. As seções abaixo descrevem a intenção original; em caso de divergência, prevalece o consolidado.

## 1. Resumo

O `docs/REQUIREMENTS.md` já prevê o Jolt como "filesystem por API para
agentes de IA com escopo limitado, auditável e revogável". O RBAC por caminho e
as service accounts entregam o "escopo" e a "revogação". Faltam os controles que
tornam um agente **comprometido ou com defeito** um incidente contido e
detectável: limites de uso, tetos de leitura, auditoria útil, alarme, resposta
rápida e reversibilidade.

A proposta reúne treze funcionalidades em sete marcos e introduz um conceito que
as amarra: o **perfil `agent`** de service account, com tetos aplicados pelo
servidor mesmo que uma policy esteja errada.

## 2. Modelo de ameaça

| # | Cenário | Exemplo |
| --- | --- | --- |
| T1 | **Injeção de prompt** | um nome de arquivo ou o conteúdo de um `README` instrui o agente a ler segredos ou apagar coisas |
| T2 | **Chave vazada** | a API key do agente aparece num log, num prompt ou numa conversa |
| T3 | **Agente com defeito** | loop de busca, varredura recursiva de milhões de entradas, download de 50 GiB |
| T4 | **Policy errada** | um `allow` largo demais dá `delete` a quem só devia listar |

Objetivos, em ordem: **conter** (limitar o dano possível), **detectar** (saber
que aconteceu), **responder** (parar rápido) e **reverter** (desfazer o que for
destrutivo).

Fora de escopo: o Jolt não impede o agente de **resumir ou repetir** o que leu
(canal de saída é do agente), não é sandbox do agente e não é DLP.

## 3. Estado na elaboração da proposta (referência histórica)

| Aspecto | Hoje | Referência |
| --- | --- | --- |
| Autenticação do agente | bearer `jolt_svc_…`, hash SHA-256 armazenado; `expires_at`, `last_used_at`, `revoked_at` existem na tabela, expiração **opcional** | `store.go:208`, `server.go:231`, `server.go:1090` |
| Desativar conta | `service_accounts.enabled`; chave sem grupo ativo falha com 401 `api_key_without_active_group` | `store.go:182`, `server.go:247` |
| Limite de taxa por chave | **inexistente**; só o bloqueio de login (`RegisterLoginFailure`) | `server.go:350` |
| Tamanho de leitura | sem teto por chave; só limites do node para ZIP (`archive_max_entries` 50.000, `archive_max_bytes` 100 GiB) | `node.yaml` |
| Auditoria | `audit_events(actor_id, action, resource, result, correlation_id, created_at, actor_type, policy_ids, evaluated_path, capability)`; **sem** query, faixa de bytes, bytes servidos nem retenção | `store.go:253`, `server.go:672` |
| Retenção | o sweeper do Control Tower (`sweep.New`, a cada 30 min) só limpa tentativas de login e shares expirados | `cmd/jolt-control/main.go:127` |
| `delete` | `unlink` permanente; sem lixeira nem dry-run | node, `safe_paths.go` |
| Plano prévio de operação | existe para cópia (`POST files/copy/plan`) e transferência (`transfers/*/plan`) | `server.go`, `nodeAuthorizationRequirements` |
| Atribuição de policy | `policy_assignments(policy_id, subject_type, subject_id, created_at)`, **sem expiração** | `store.go:223` |
| Headers do node propagados ao cliente | lista fixa em `proxyNode`, incluindo `X-Jolt-*` de upload e ZIP | `server.go:2768` |
| Proxy de bytes | `io.Copy(w, response.Body)` após copiar os headers; o `Content-Length` do node já é conhecido antes de `WriteHeader` | `server.go:2768` |
| Instância | Control Tower único, sem HA (`docs/PRODUCTION.md`), então estado em memória não precisa de coordenação | — |

## 4. O perfil `agent`

`service_accounts` ganha `kind TEXT NOT NULL DEFAULT 'automation'` com os
valores `automation` (comportamento atual) e `agent`. Contas `agent` recebem
**tetos aplicados pelo servidor**, independentes das policies:

| Teto | Valor padrão (configurável) |
| --- | --- |
| Capabilities efetivas | no máximo `list` e `read`; `create`, `update`, `delete`, `execute`, `sudo` são sempre negadas, mesmo que uma policy as conceda (T4) |
| Expiração da chave | obrigatória, máximo de 30 dias |
| Origem | lista de CIDRs opcional por credencial; vazia permite qualquer origem |
| Taxa e cota | valores padrão do S1 |
| Teto de leitura | valores padrão do S2 |
| Listagem e busca | `limit` máximo menor que o do node (por exemplo, 200) |
| Rótulos de segurança | varredura de segredo (S8) e saneamento de nomes (S13) ligados |
| Auditoria | detalhe completo (S5) |

O teto de capabilities fica em `evaluateAuthorization` (`server.go:750`), depois
de `rbac.Evaluate`, de modo que nenhuma regra de policy o ultrapassa. Isso
fecha T4 para agentes por construção.

## 5. Funcionalidades

### S1. Limite de taxa e cota por chave

- **Taxa:** token bucket em memória por `token_id`, aplicado em `authenticateServiceAccount`. Excesso devolve 429 com `Retry-After`. Memória basta (instância única); reiniciar zera o balde.
- **Cota diária:** tabela `token_usage(token_id, day, requests, bytes_out)` atualizada no fim de `proxyNode`. Excedida a cota, 429 até o dia seguinte.
- **Configuração:** padrões por perfil e sobrescrita por chave.
- **Aceite:** teste que dispara N requisições e vê o 429; cota sobrevive a reinício.

### S2. Tetos de leitura

- **Por arquivo:** em `proxyNode`, antes de `WriteHeader`, comparar o `Content-Length` da resposta do node (ou o tamanho da faixa em `Range`) com o teto da chave; acima dele, 413 `read_too_large`.
- **Streams sem tamanho prévio (ZIP):** envolver o `io.Copy` num contador que aborta ao passar do teto (e registra `aborted_by_quota` na auditoria).
- **Por dia:** é a cota de bytes do S1.
- **Tipo lido:** opção `read_media_types` por perfil (por exemplo, só `text/*` e `application/json`), checada pelo `Content-Type` da resposta do node; binário recebe 415. Combina com a [camada B de tipos](file-type-restrictions.md).

### S3. Escopo extra da chave

- **CIDR de origem** por chave (`allowed_cidrs`), verificado em `authenticateServiceAccount`; fora da lista, 401. Atenção a proxies: usar o IP da conexão, não `X-Forwarded-For`, a menos que configurado com proxy confiável.
- **Expiração obrigatória** para `kind=agent` (seção 4).
- **Teto de capability por chave** abaixo do teto do perfil, quando se quer uma chave ainda mais restrita que a conta.

### S4. Kill switch

- `POST /api/v1/control-tower/service-accounts/disable?kind=agent` desativa todas as contas do tipo em uma transação; botão no Access Center.
- Reativação individual, nunca em lote.
- **Requisições em curso:** manter um registro de contextos ativos por `token_id` e cancelá-los na desativação, senão um ZIP em andamento continua.
- **Aceite:** com um download longo ativo, o kill switch interrompe o stream.

### S5. Auditoria útil

- **Colunas novas** em `audit_events`: `detail TEXT` (JSON com `query` truncado, `range`, `status`, `bytes_out`, `aborted_by`) e `source_ip`. O `audit()` de hoje (`server.go:672`) recebe um parâmetro de detalhe opcional.
- **Retenção:** tarefa nova no sweeper (`main.go:127`) que remove registros mais antigos que `CONTROL_TOWER_AUDIT_RETENTION_DAYS` (0 = manter tudo, o comportamento atual).
- **Exportação:** `GET /audit?format=ndjson&after=<id>` para um coletor externo guardar cópia. Importante porque a reconstrução do banco apaga o histórico.
- **Cadeia de hash (opcional):** `prev_hash` e `hash` por registro, para detectar remoção ou edição no meio. Só vale se a exportação externa existir.
- **Privacidade:** a `query` de busca pode conter dado sensível; truncar e permitir desligar.

### S6. Detecção de anomalia

- Rótulo `actor_id` nas métricas de proxy existentes (`jolt_control_node_proxy_total`); o número de service accounts é pequeno, então a cardinalidade é segura.
- Métricas novas: `jolt_control_denied_total{actor,capability}`, `jolt_control_bytes_out_total{actor}`, `jolt_control_rate_limited_total{actor}`.
- `docs/OPERATIONS.md` ganha regras de alerta de exemplo: pico de 403, varredura acima de X entradas, bytes fora do padrão, chave usada fora do horário esperado.

### S7. Arquivos-isca (canary)

- `node.yaml`: `canary_paths` por mount (caminhos relativos de arquivos que o operador colocou, com aparência de segredo).
- Qualquer `content` ou `metadata` desses caminhos devolve o conteúdo normal e acrescenta o cabeçalho `X-Jolt-Canary: 1`.
- `proxyNode` já copia uma lista fixa de headers do node (`server.go`); incluir esse e, ao vê-lo, gravar `audit` com `action=canary` e incrementar `jolt_control_canary_total{actor}`. O ator só é conhecido no Control Tower, por isso o aviso passa pelo cabeçalho de resposta.
- **Aceite:** ler o isca gera um registro e a métrica; um alerta no Prometheus dispara.

### S8. Varredura de segredo na leitura

- Para sujeitos `kind=agent`, o Control Tower pede ao node (cabeçalho `X-Jolt-Scan: secrets`) que examine os primeiros 64 KiB do arquivo antes de servir.
- Padrões: cabeçalhos PEM de chave privada, formatos de token conhecidos (AWS, GitHub, JWT) e pares `chave=valor` com nomes como `password`, `secret`, `token`.
- Achado: 403 `secret_detected`; auditoria com o tipo de padrão, nunca o valor.
- **Limite honesto:** é uma camada extra, não fronteira. Tem falso positivo (um exemplo de documentação) e falso negativo (segredo fora dos primeiros 64 KiB, ofuscado, dentro de arquivo compactado).

### S9. Lixeira, dry-run e confirmação

- **Lixeira por mount** (`node.yaml: trash: {enabled: true, retention: 30d}`): `delete` vira `rename` atômico para `.jolt-trash/<timestamp>-<id>/<caminho relativo>` no mesmo filesystem. A pasta fica oculta da API pelo mesmo mecanismo dos parciais (`isInternalPartialName`, `service.go:1507`, a estender). Um sweeper do node (mesmo padrão de `sweepUploadSessions`) apaga o vencido. API `POST …/trash/{id}/restore`.
- **Dry-run:** `DELETE …?dry_run=true` e o equivalente para `move` de árvore devolvem o plano (arquivos, bytes) e um `confirm_token` ligado ao sujeito, aos caminhos e ao hash do plano, válido por 5 minutos. A execução de árvore exige o token. Segue o precedente de `files/copy/plan`.
- **Espaço:** itens na lixeira ainda ocupam disco; `disk-usage` os exclui e a operação de restauração e a retenção ficam visíveis ao admin.
- **Hardlinks:** `rename` preserva o inode, então não libera espaço até a purga. Aceitável e documentado.

### S10. Aprovação humana de operação destrutiva

- Uma capability pode ser marcada `needs_approval` numa regra. Ao ser exigida, `proxyNode` não executa: grava em `pending_operations` (sujeito, método, recurso, hash do corpo) e responde 202 com o id.
- Um admin aprova ou rejeita na UI; aprovada, o Control Tower executa a operação **guardada** (apenas corpos pequenos em JSON, como `delete`, `move` e `copy`; uploads ficam fora).
- Notificação do pedido por webhook genérico configurável.
- É a ponte para o dia em que algum agente precise de `delete`: o perfil `agent` continua negando, e a exceção passa por uma pessoa.

### S11. Elevação temporária (JIT)

- `policy_assignments` ganha `expires_at`; `Evaluate` ignora atribuições vencidas. Uma "elevação" é uma atribuição com prazo (por exemplo, `cleanup` por 15 minutos).
- A auditoria registra quem concedeu, a quem e até quando.
- Não se aplica ao perfil `agent` (os tetos da seção 4 prevalecem); serve ao operador humano e a automações.

### S12. Identidade sem segredo estático e MCP nativo

- **JWT/SVID:** `authenticateServiceAccount` passa a aceitar `Authorization: Bearer <JWT>` validado por JWKS configurado, mapeando `iss` + `sub` + `aud` a uma service account (`service_account_identities`). Elimina a chave `jolt_svc_` de longa duração e alinha com identidade de workload (SPIFFE/SPIRE).
- **`jolt-mcp`:** binário novo (`control/cmd/jolt-mcp`) que expõe só `list`, `search`, `disk_usage` e `read_text`, chamando a API do Control Tower. O agente nunca vê a credencial, e a superfície é somente leitura por construção, mesmo que a conta tivesse mais.

### S13. Saneamento de nomes e limites de listagem

- Para `kind=agent`, nomes devolvidos em listagem e busca passam por saneamento: caracteres de controle, sequências ANSI e controles bidirecionais (U+202A–U+202E, U+2066–U+2069) viram marcador visível; nomes acima de um tamanho são truncados com indicação.
- `limit` máximo menor por perfil e profundidade máxima de busca.
- **Limite honesto:** reduz truques tipográficos, não impede injeção em linguagem natural dentro de um nome comum.

## 6. Marcos

| Marco | Escopo | Critério de aceite |
| --- | --- | --- |
| **A0** | Pré-requisito: camada A de [`file-type-restrictions.md`](file-type-restrictions.md) (`hidden_patterns`) | segredos de host somem da listagem e dão 404 |
| **A1** | Perfil `agent`, teto de capabilities, expiração obrigatória, CIDR, kill switch (S3, S4) | policy com `delete` não dá `delete` a conta `agent`; kill switch interrompe stream ativo |
| **A2** | Taxa, cota e tetos de leitura (S1, S2) | 429 e 413 reproduzidos em teste; cota persiste |
| **A3** | Auditoria, retenção, exportação e alertas (S5, S6) | `detail` gravado; purga por dias; regras de exemplo em `OPERATIONS.md` |
| **A4** | Canary e varredura de segredo (S7, S8) | leitura do isca gera audit, métrica e alerta; chave PEM é bloqueada |
| **A5** | Lixeira, dry-run e confirmação (S9) | `delete` reversível dentro da retenção; árvore exige token |
| **A6** | Aprovação humana e JIT (S10, S11) | operação pendente só executa após aprovação; atribuição vence no prazo |
| **A7** | JWT/SVID e `jolt-mcp` (S12) | agente autentica sem chave estática; `jolt-mcp` não oferece escrita |

**Pacote mínimo para agentes:** A0, A1, A2, A3 e o canary de A4. Sua conclusão depende também da validação integrada registrada no [plano consolidado](plano-consolidado-seguranca.md). Agentes continuam sem escrita direta; aprovações futuras são realizadas por humanos com suas próprias permissões.

## 7. Compatibilidade e downgrade

Todas as colunas novas são aditivas, pelo padrão `ALTER TABLE … ADD COLUMN`
tolerante já usado em `store.go`. O risco é o mesmo da proposta de tipos: uma
versão anterior do Control Tower **ignora** `kind`, `allowed_cidrs` e os tetos, e
trataria o agente como automação comum (fail-open). O marcador de versão mínima
descrito em `file-type-restrictions.md` §6 é gravado ao criar a primeira conta
`agent` e verificado por binários que implementam essa verificação. Binários
antigos não passam a verificá-lo automaticamente: fixe as imagens por digest e
faça rollback somente com backup compatível anterior à ativação de agentes.

## 8. Riscos

| Risco | Mitigação |
| --- | --- |
| Falsa sensação de segurança (varredura de segredo, saneamento de nomes) | declarados como camadas extras; o que protege de fato são os tetos, o RBAC e a ocultação por mount |
| Custo de desempenho do contador de bytes e do detalhe de auditoria | contador por requisição, sem lock global; medir com o perfil de `docs/ACCEPTANCE.md` |
| Crescimento do banco de auditoria | retenção (S5) e exportação |
| Aprovação humana vira clique automático | notificação com resumo do que será apagado (arquivos, bytes) e expiração do pedido |
| Contadores em memória zeram no restart | aceitável para taxa; cota diária é persistida |
| Complexidade: treze funcionalidades | marcos independentes; pacote mínimo definido |

## 9. Alternativas consideradas

| Alternativa | Por que não |
| --- | --- |
| Só RBAC, sem perfil | um erro de policy (T4) dá escrita a um agente; o teto do servidor remove essa classe de erro |
| Limite de taxa só no proxy reverso | não conhece a chave nem o ator; serve como complemento |
| Isolar agente em instância separada do Jolt | duplica operação e estado; o perfil dá o mesmo isolamento lógico |
| Deixar o agente só com MCP, sem controles no Jolt | um MCP comprometido ou contornado volta à API sem teto; os dois níveis se somam |

## 10. Questões abertas

1. `kind` como enumeração fechada (`automation`, `agent`) ou rótulos livres com perfis configuráveis?
2. CIDR por chave ou por conta? Chaves distintas de uma conta podem rodar em lugares diferentes.
3. A aprovação humana (S10) deve aceitar canais além da UI (por exemplo, link assinado no webhook)?
4. A exportação de auditoria (S5) deve ser *pull* (endpoint) ou *push* (webhook/arquivo)?
5. Cota em bytes conta só `bytes_out` ou também upload? Para `kind=agent` upload é negado, então só importa para automações.
6. Vale um perfil `agent-readonly-text` já pronto (S2 e S8 ligados, só `text/*`) como padrão recomendado?
