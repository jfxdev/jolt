# Roadmap

Última atualização: 2026-08-17. Inclui achados de análise profunda de código
(seção "Achados de análise profunda").

Este documento consolida os achados de uma análise da plataforma (node +
Control Tower). Cada item descreve o **problema**, a **evidência** no código e a
**solução proposta**. A priorização vem ao final.

Correções em nível de código (com trechos) estão em
[`docs/REMEDIATION.md`](REMEDIATION.md).

Legenda de severidade:

- 🔴 **Crítico**: risco de segurança ou defeito que compromete confiança.
- 🟠 **Alto**: lacuna operacional relevante para produção.
- 🟡 **Médio**: melhoria de produto ou experiência.
- 🔵 **Futuro**: diferencial pós-MVP.

---

## P0 — Segurança e correções

### P0.1 🔴 Documentação diverge da stack real do frontend

**Problema.** `README.md` e `docs/IMPLEMENTATION.md` descrevem o frontend do
Control Tower como "Vue 3" em vários pontos. O frontend real é **React 19 +
Radix/shadcn + Tailwind + react-router 7**.

**Evidência.**
- `control/frontend/package.json`: `"react": "^19.0.0"`, `"react-dom"`,
  `"react-router-dom": "^7.1.5"`, componentes `@radix-ui/react-*`.
- Todo o código-fonte em `control/frontend/src/**` é `.tsx`.
- `README.md` (ex.: "responsive Vue 3 interface") e `docs/IMPLEMENTATION.md`
  ("mobile-first Vue 3 interface", "Vue 3 frontend").

**Solução proposta.** Corrigir todas as menções a Vue nos documentos para React
19. Revisar o restante da documentação buscando outras divergências de stack.
Custo baixo, impacto alto em confiabilidade da documentação.

---

### P0.2 🔴 Login sem proteção contra força bruta

**Problema.** O endpoint `POST /api/v1/control-tower/auth/login` não possui
rate-limit, lockout, backoff nem MFA. Tentativas de senha são ilimitadas. Único
endpoint de autenticação público exposto pelo Control Tower.

**Evidência.** `control/internal/httpapi/server.go:229` (`login`). Verifica
senha com `security.VerifyPassword`, audita `denied`, mas nada bloqueia
tentativas repetidas. Nenhum middleware de throttle no servidor
(`grep ratelimit|throttle` = vazio). Argon2id impõe custo por tentativa, mas não
impede spray distribuído ou enumeração paciente.

**Solução proposta.**
1. Rate-limit por IP **e** por usuário no `login` (ex.: token-bucket em memória,
   ou tabela `login_attempts` no store para durabilidade entre réplicas).
2. Lockout progressivo após N falhas consecutivas por conta (backoff
   exponencial, com auditoria e evento).
3. MFA/TOTP opcional por usuário (segredo cifrado no SQLCipher, verificação no
   fluxo de login e recovery de emergência).
4. Considerar resposta com tempo constante para não vazar existência de usuário
   (hoje `UserByUsername` erro vs senha inválida seguem o mesmo caminho — bom —
   mas validar timing).

---

### P0.3 🟠 Assimetria de criptografia em repouso (node DB em texto claro)

**Problema.** O Control Tower cifra todo o banco com SQLCipher. O **node** usa
SQLite puro, sem criptografia. O banco do node contém grants, identidades de
peers confiáveis, paths de mount, checkpoints e idempotência.

**Evidência.**
- Control: `control/internal/database/sqlcipher.go` (full-page SQLCipher).
- Node: `node/backend/internal/infra/db/sqlite.go:12` importa
  `modernc.org/sqlite`; `sqlite.go:23` `sql.Open("sqlite", path)` sem
  `PRAGMA key`. Nenhuma referência a cipher/encrypt no arquivo.

**Solução proposta.** Adicionar criptografia opcional/obrigatória ao node DB com
paridade ao Control Tower:
- Trocar o driver do node para o toolchain SQLCipher (CGO), reutilizando o
  padrão já validado no control (`docs/IMPLEMENTATION.md` cita imagem Alpine
  arm64 com SQLCipher CGO).
- Chave externa via env (ex.: `JOLT_DB_ENCRYPTION_KEY`), fail-closed sem chave,
  migração offline de bancos plaintext existentes (mesmo modelo do
  `encrypt-database` do control).
- Nota: a chave privada de identidade já vive em `JOLT_KEYS_DIR` fora do DB, mas
  o restante do estado operacional permanece exposto em disco hoje.

---

## P1 — Operabilidade

### P1.1 🟠 Observabilidade: sem métricas nem tracing

**Problema.** Não há métricas Prometheus, OpenTelemetry, endpoint `/metrics` nem
tracing distribuído. Observabilidade se resume a logs estruturados `slog`.
Operar uma frota de nodes fica cego a taxa de erro, latência, throughput de
transferência, profundidade de fila e saúde de peers.

**Evidência.** `grep -riE 'prometheus|otel|opentelemetry|/metrics'` sobre os
fontes Go = nenhuma ocorrência de instrumentação (apenas o rate-limiter de banda
interno de transferência).

**Solução proposta.**
1. Expor `/metrics` (Prometheus) em node e control com métricas-chave: jobs por
   estado, bytes transferidos, latência de request, falhas de auth, peers
   online/degraded/offline, profundidade da fila, tentativas de retry.
2. Instrumentar handlers HTTP e o motor de jobs com OpenTelemetry (spans
   correlacionados ao `X-Correlation-ID` já existente).
3. Dashboards de referência (Grafana) e alertas exemplo no `docs/`.

### P1.2 🟠 Health checks não separam liveness de readiness

**Problema.** Existe um único `GET /health`. Sem distinção entre liveness
(processo vivo) e readiness (DB acessível, migrations aplicadas, listeners mTLS
prontos). Orquestradores não conseguem drenar tráfego com segurança.

**Evidência.** `node/.../httpapi/server.go:59` e control `GET /health` únicos.

**Solução proposta.** Adicionar `/livez` e `/readyz`. `readyz` valida abertura
do DB, integridade básica, e prontidão do listener mTLS. Documentar uso em
Compose/K8s.

### P1.3 🟠 Sem API de logs recentes

**Problema.** Logs estruturados existem, mas não há API para consultá-los pelo
node ou Control Tower. Diagnóstico remoto exige acesso ao host/container.

**Evidência.** `docs/IMPLEMENTATION.md` (seção "Configuration and
observability") já marca "recent-log query API" como pendente.

**Solução proposta.** Buffer circular em memória de eventos estruturados
recentes + endpoint autenticado paginado (`GET /api/v1/logs?level=&since=`),
proxiado e exibido no Control Tower. Redigir segredos.

### P1.4 🟠 Configuração imutável exige restart

**Problema.** Toda configuração é via variável de ambiente. Não há API mutável
para timeouts, banda, concorrência, thresholds de heartbeat. Qualquer ajuste
exige recriar o container.

**Evidência.** `node/.../config/config.go` e `control/.../config/config.go`
leem apenas env. `docs/IMPLEMENTATION.md` marca "Mutable configuration update
APIs" como incompletas; hoje só há `GET /api/v1/config/effective`.

**Solução proposta.** API de configuração mutável com camadas
desired/effective/observed, auditoria, idempotência, persistência atômica e
mascaramento de segredos. Precedência arquivo > env para valores não sobrepostos
em runtime. Já é o "next milestone" implícito nos docs.

### P1.5 🟠 Sem notificações/alertas

**Problema.** Nenhum webhook, e-mail ou push para eventos operacionais: job
concluído/falho, peer offline, certificado mTLS próximo de expirar, rollout de
identidade pendente. O operador precisa observar a UI ativamente.

**Evidência.** `grep -riE 'webhook|notif|smtp|email'` = nenhuma implementação. O
monitor de peers (`node/.../services/peers/monitor.go`) detecta offline mas só
persiste estado.

**Solução proposta.** Subsistema de notificações no Control Tower: assinantes de
webhook (HMAC-assinados), canais de e-mail (SMTP), e regras por tipo de evento.
Reaproveitar o stream SSE de jobs como fonte. Incluir alerta de expiração de
certificado com antecedência configurável.

---

## P2 — Produto e transferência

### P2.1 🟡 Upload não resumável

**Problema.** O corpo do upload é streamado para arquivo temporário e publicado
atomicamente, mas não é persistido em chunks. Uma interrupção obriga reiniciar
do zero — assimétrico com a transferência node-a-node, que resume por range.

**Evidência.** `docs/IMPLEMENTATION.md` (seção "Streaming uploads"): "The
incoming request body is not persisted as resumable chunks. An interrupted
upload must currently be restarted from the beginning."
`node/.../filesystem/service.go:566` (`Upload`).

**Solução proposta.** Upload resumável tipo `tus`/range: sessão de upload
durável com checkpoint por chunk sincronizado, `Content-Range`, retomada por
offset, e publish atômico ao completar. Reusar o padrão de checkpoint já usado
em `CopyFileResumable`.

### P2.2 🟡 Transferência direta pela UI limitada a um arquivo por job

**Problema.** No workflow visual, uma transferência node-a-node de arquivo
regular processa um único arquivo por job. Diretórios têm fluxo separado com
manifesto, mas multi-seleção de arquivos avulsos não existe.

**Evidência.** `docs/IMPLEMENTATION.md` (seção "Direct remote transfer UX"):
"Direct transfer currently supports one regular file per job."
`control/frontend/src/components/workspace/RemoteTransferDialog.tsx`.

**Solução proposta.** Permitir multi-seleção de arquivos como um job com plano
itemizado (reusar o motor de diretório com uma lista explícita de itens em vez
de varredura de manifesto). Progresso agregado e resultados por item já
existem.

### P2.3 🟡 Descoberta remota de grants/mounts ausente

**Problema.** Não há descoberta pelo data-plane dos grants/mounts que um peer
expõe. O operador precisa conhecer previamente os identificadores. Dificulta
automação e agentes.

**Evidência.** `docs/IMPLEMENTATION.md`: "Remote mount/grant discovery through
the peer data plane is not implemented" e Priority 5 "Remote files/grants
discovery suitable for automation and agents".

**Solução proposta.** Endpoint mTLS peer-facing que lista grants visíveis para a
identidade do chamador (respeitando visibilidade/enabled dos grants), com
paginação. Expor no Control Tower como navegação de origem e via API para
automação.

### P2.4 🟡 Sem transferências agendadas

**Problema.** Toda transferência é disparada manualmente. Não há agendamento
(cron) para cópias/backups recorrentes entre nodes.

**Evidência.** Nenhum scheduler nos serviços; jobs são criados sob demanda via
API.

**Solução proposta.** Agendador no Control Tower que cria jobs de transferência
conforme cron, com janela, política de conflito e limite de banda pré-definidos.
Auditoria e histórico por agendamento.

### P2.5 🟡 Internacionalização (i18n) ausente

**Problema.** UI e mensagens de erro estão hardcoded em português. Sem camada de
i18n. Limita adoção fora do pt-BR.

**Evidência.** Mensagens no backend, ex.:
`control/internal/httpapi/server.go:237` `"Usuário ou senha inválidos."`,
`server.go:288` `"Informe entre 1 e 100 Node Paths."`. Strings equivalentes no
frontend.

**Solução proposta.** Extrair strings para catálogos (frontend: biblioteca i18n;
backend: códigos de erro estáveis + mensagens localizadas resolvidas no cliente
a partir do `code`). Fornecer `en` e `pt` inicialmente. A API já retorna `code`
+ `message`; deslocar a tradução para o cliente via `code`.

### P2.6 🟡 Gestão de sessão limitada

**Problema.** Sessão fixa em 12h, sem sliding expiry, sem refresh, sem "lembrar
neste dispositivo", e o usuário não consegue listar/revogar suas próprias
sessões (apenas admin revoga indiretamente via troca de senha/disable).

**Evidência.** `control/internal/httpapi/server.go:245`
`expires := time.Now().UTC().Add(12 * time.Hour)`; cookie único de sessão sem
renovação.

**Solução proposta.** Sliding expiration com renovação, opção de duração longa
explícita, e tela "sessões ativas" para o próprio usuário listar dispositivos e
revogar individualmente. Reusar `DeleteSession` já existente.

---

## P3 — Diferenciais de produto

### P3.1 🔵 Sync contínuo/bidirecional (mirror)

**Problema.** A plataforma faz cópia one-shot, não replicação contínua. Não há
espelhamento nem sincronização bidirecional entre mounts de nodes.

**Solução proposta.** Modo "sync" durável: observador de mudanças (fs notify +
varredura periódica de reconciliação), resolução de conflitos por política, e
propagação incremental. Construir sobre o motor de jobs e grants existente.

### P3.2 🔵 Transferência delta (estilo rsync)

**Problema.** Resume é por-chunk, mas um arquivo grande que mudou é re-buscado
inteiro. Sem rolling checksum/delta para transferir só as diferenças.

**Solução proposta.** Algoritmo delta (rolling + strong checksum por bloco) na
origem/destino sobre o canal mTLS, transferindo apenas blocos divergentes.
Reusa a infraestrutura de checkpoint e validação de ETag/SHA-256.

### P3.3 🔵 Backup online/hot e destinos remotos

**Problema.** Snapshots são offline e exigem o processo parado (lock exclusivo).
Não há backup a quente, agendamento de snapshot, nem destino remoto (ex.: S3).

**Evidência.** `docs/IMPLEMENTATION.md` (Disaster recovery): "hold an exclusive
instance lock and refuse an offline snapshot while the corresponding process is
active."

**Solução proposta.** Backup consistente online (SQLite backup API / cópia
com WAL checkpoint), agendamento, e upload para destino remoto configurável
(S3/compatível) mantendo o DB cifrado e excluindo a chave externa, como já faz o
snapshot atual.

### P3.4 🔵 Import de certificado mTLS externo

**Problema.** Certificados mTLS são emitidos apenas pela identidade interna. Não
há import de certificado externo/pré-provisionado.

**Evidência.** `docs/IMPLEMENTATION.md` "Future roadmap — post-MVP" já registra
este item.

**Solução proposta.** Ingestão segura de chave privada, validação de cadeia,
posse de renovação e compatibilidade com o ciclo existente de rollout, grace,
rollback e revogação.

### P3.5 🔵 Push transfers e roteamento multi-hop

**Problema.** Transferência é exclusivamente pull (destino puxa da origem). Não
há push nem roteamento entre nodes não diretamente pareados.

**Solução proposta.** Modo push (origem inicia entrega para destino autorizado)
e, futuramente, relay multi-hop respeitando trust bilateral em cada salto.

---

## P4 — Validação pendente

### P4.1 🟠 Executar e registrar o acceptance-full

**Problema.** O perfil de aceitação `full` (arquivo 10 GiB, diretório
100 GiB/5.000 arquivos) ainda não foi executado e evidenciado em infra alvo. É o
único item marcado "Partial" restante em `docs/IMPLEMENTATION.md`.

**Solução proposta.** Rodar `make acceptance-full` em host descartável
representativo, coletar tempos/checksums e registrar evidência no `docs/`.

---

## Achados de análise profunda (código)

Achados adicionais de leitura direta do código-fonte. Referências em
`arquivo:linha`.

### C1 🟠 SQLCipher em modo raw-key sem KDF; passphrase só com SHA-256

**Problema.** O banco do Control Tower é aberto em **modo raw-key**
(`PRAGMA key = x'<hex>'`), que ignora o PBKDF2 do SQLCipher. Quando o operador
fornece uma passphrase (caminho "≥ 32 caracteres"), a chave é derivada com um
**único SHA-256**, sem stretching. Se o arquivo do banco vazar, uma passphrase
de baixa entropia é força-bruta offline barata (um SHA-256 por tentativa vs. os
~256k iterações de PBKDF2 padrão do SQLCipher).

**Evidência.** `control/internal/config/config.go:60`
`sum := sha256.Sum256([]byte(rawKey))`; `control/internal/database/sqlcipher.go:154`
`"_pragma_key": {fmt.Sprintf("x'%s'", hex.EncodeToString(key))}`.

**Solução proposta.** Preferir chave base64 de 32 bytes de alta entropia (já
suportada). Para o caminho passphrase, derivar com um KDF forte
(Argon2id/scrypt/PBKDF2 com sal persistido) antes de virar raw-key, ou passar a
passphrase ao SQLCipher deixando o PBKDF2 nativo agir (não usar raw-key). No
mínimo, documentar que a passphrase não recebe stretching e exigir chave
aleatória.

### C2 🟡 Chave única para SQLCipher e AES-GCM de campo (sem separação)

**Problema.** A mesma `EncryptionKey` cifra o banco (SQLCipher) e os campos
AES-GCM (tokens de node, segredos de convite). Não há derivação de subchaves.
A camada de campo, descrita como proteção "adicional", não agrega defesa em
profundidade real: comprometida a chave, ambos caem juntos.

**Evidência.** `control/internal/config/config.go:40` (mesma
`cfg.EncryptionKey`); usada em `security.Encrypt/Decrypt`
(`control/internal/security/security.go:60`) e no DSN do SQLCipher.

**Solução proposta.** Derivar subchaves distintas via HKDF com rótulos
(`info`) separados por finalidade (ex.: `db`, `field`), a partir da chave-mestre
única.

### C3 🟡 Fingerprint de identidade truncado a 80 bits

**Problema.** A fingerprint que ancora a confiança do peer é os primeiros
**10 bytes (80 bits)** do SHA-256 da chave pública Ed25519. Abaixo da prática
moderna (≥ 128 bits) para um âncora de trust; a verificação humana explica a
truncagem, mas reduz margem contra segundo-preimagem.

**Evidência.** `node/backend/internal/infra/crypto/certificates.go:693`
`return ed25519.PublicKey(raw), formatFingerprint(sum[:10]), nil`.

**Solução proposta.** Elevar para 16 bytes (128 bits) mantendo formatação
legível em grupos, ou exibir fingerprint completa com opção resumida para
conferência humana. Avaliar impacto de migração de peers existentes.

> Nota positiva: a validação mTLS em si é sólida — assinatura Ed25519 sobre
> `RawTBSCertificate` verificada contra a chave embutida na extensão crítica, e
> match exato por `node_id` **e** fingerprint no registry de peers confiáveis
> (`certificates.go:533-588`). Sem brechas de spoofing identificadas.

### C4 🟡 CSRF: validação de Origin ignorada quando o header está ausente

**Problema.** O middleware CSRF só valida `Origin` em métodos mutáveis **quando
o header existe**. Requisição sem `Origin` passa direto. Mitigado por cookies
`SameSite=Strict`, mas a checagem tem furo e não há fallback de `Referer` nem
token anti-CSRF.

**Evidência.** `control/internal/httpapi/server.go:174` (bloco condicional
`if origin := r.Header.Get("Origin"); origin != ""`).

**Solução proposta.** Rejeitar mutação sem `Origin` **nem** `Referer` de mesma
origem, ou adotar token anti-CSRF por sessão. Manter `SameSite=Strict` como
camada complementar.

### C5 🟠 Node DB serializado por `SetMaxOpenConns(1)` — gargalo de throughput

**Problema.** Node e Control Tower fixam **uma única conexão** ao SQLite. Todo
request de API, worker de job e stream SSE contendem pela mesma conexão. Correto
para consistência, mas limita concorrência sob carga (transferências paralelas +
navegação + eventos disputam o mesmo lock).

**Evidência.** `node/backend/internal/infra/db/sqlite.go:27`
`database.SetMaxOpenConns(1)`; `control/internal/database/sqlcipher.go:42` idem.

**Solução proposta.** WAL já habilitado no node permite múltiplos leitores com
um escritor. Separar pool de leitura (várias conexões RO) do escritor único, ou
elevar `MaxOpenConns` para leituras mantendo escrita serializada por transação
`IMMEDIATE`. Medir com o perfil de aceitação antes/depois.

### C6 🟡 TOCTOU no componente final ao criar arquivos (`allowMissing`)

**Problema.** Em operações de criação (`allowMissing=true`), `resolve` só
reavalia symlinks do **diretório pai**; o componente final não é reavaliado.
Há janela TOCTOU entre `resolve` e a operação de arquivo se um symlink for
inserido out-of-band (mount compartilhado com SMB/usuários locais).

**Evidência.** `node/backend/internal/services/filesystem/service.go:1511-1527`
(`check = filepath.Dir(candidate)` no ramo `allowMissing`).

**Mitigação atual.** Writes usam arquivo temporário + `os.Rename` atômico, que
**substitui** o symlink em vez de segui-lo — o principal vetor de escrita está
protegido.

**Solução proposta.** Reavaliar o componente final antes de operar, ou usar
`openat2`/`O_NOFOLLOW` no destino. Hardening para cenários de mount
compartilhado.

### C7 🔵 Trailer `X-Jolt-Final-ETag` sem ramo de erro na origem (defesa em profundidade)

**Problema.** No endpoint de conteúdo peer-a-peer, o trailer final só é setado
se `source.CurrentETag()` tiver sucesso; em erro de stat o corpo vai sem trailer.

**Reavaliação (deep dive).** **Não é um gap explorável de corretude.** O
**destino** trata trailer ausente ou divergente como fonte-alterada e falha
fechado — não publica: `transfers/service.go:452` e `:491`
(`finalETag == "" || finalETag != etag` → `ErrSourceChanged`). Logo a
consistência é preservada; a melhoria é apenas de clareza no lado da origem.

**Evidência.** `node/backend/internal/infra/mtlsapi/server.go:84-86` (origem,
sem ramo de erro); consumidores em `transfers/service.go:452,491` (destino,
fail-closed).

**Solução proposta.** Cosmética/defensiva: na origem, emitir trailer sentinela
explícito (`!error`) em erro de stat, para logs/diagnóstico. Comportamento de
segurança já está correto no destino.

### C8 🟠 Segredos apenas via variáveis de ambiente (sem `_FILE`/Docker secrets)

**Problema.** `CONTROL_TOWER_TOKEN`, `CONTROL_TOWER_ADMIN_PASSWORD` e
`CONTROL_TOWER_DB_ENCRYPTION_KEY` chegam por env. Env é visível em
`docker inspect`, `/proc/<pid>/environ` e propaga para subprocessos; risco de
vazamento em logs/telemetria.

**Evidência.** `docker-compose.yml:11,60,61`; `config.go` lê tudo de `os.Getenv`.

**Solução proposta.** Suportar convenção `*_FILE` (ler segredo de arquivo/Docker
secret/tmpfs) com precedência sobre a env equivalente. Documentar o padrão.

### C9 🟡 Containers sem hardening nem limites de recurso

**Problema.** O Compose não aplica `cap_drop`, `security_opt:
no-new-privileges`, limites de CPU/memória nem `read_only` rootfs. Uma
transferência descontrolada pode exaurir recursos do host; superfície de
privilégio maior que o necessário.

**Evidência.** `docker-compose.yml` (sem `deploy.resources`, `cap_drop`,
`security_opt`).

**Solução proposta.** Após o drop de privilégio do entrypoint, aplicar
`cap_drop: [ALL]` (readicionar apenas o necessário), `no-new-privileges`,
`mem_limit`/`cpus` e `read_only` onde viável (com tmpfs para escrita
temporária).

### C10 🟡 `CONTROL_TOWER_SECURE_COOKIES` default `false`

**Problema.** Cookie de sessão sem `Secure` por padrão. Em deploy sem proxy TLS
correto, a sessão trafega sem a flag, permitindo captura em texto claro.

**Evidência.** `control/internal/config/config.go:30`
`boolValue("CONTROL_TOWER_SECURE_COOKIES", false)`; `docker-compose.yml:62`.

**Solução proposta.** Default `true` e exigir opt-out explícito para
desenvolvimento local, ou detectar HTTPS/`X-Forwarded-Proto` e forçar `Secure`.

### C11 🔵 Higiene de repositório

**Problema.** Diretórios órfãos vazios `backend/` e `deploy/` na raiz (o código
real do node vive em `node/backend/`). Além disso, todo o código está
**não versionado** — apenas `LICENSE` está no commit inicial.

**Evidência.** `find backend -type f` vazio; `git ls-files | wc -l` = 1.

**Solução proposta.** Remover diretórios órfãos e realizar o commit inicial
completo do código com histórico adequado.

### C12 🟡 Sessões e convites expirados nunca são purgados

**Problema.** `SessionUser` rejeita sessões expiradas na leitura
(`expires_at>?`), o que é seguro, mas nenhuma rotina remove as linhas expiradas.
Convites/requests de pairing são marcados `expired` de forma preguiçosa na
listagem, também sem exclusão. Ambos crescem indefinidamente no banco.

**Evidência.** `control/internal/store/store.go:1533` (filtro na leitura);
ausência de `DeleteExpiredSessions`/sweeper (`grep` = vazio);
`node/backend/internal/services/pairing/service.go:122,186` (marcação lazy).

**Solução proposta.** Sweeper periódico (ticker) que apaga sessões
`expires_at < now` e convites/requests terminais antigos, com auditoria. Rodar
também no boot. Ver correção detalhada em `docs/REMEDIATION.md#c12`.

> Notas positivas da inspeção: `go vet` limpo em node e control; SQL usa
> placeholders parametrizados (sem injeção — concatenação apenas em helpers de
> migração com nomes de tabela/coluna hardcoded, `store.go:310,332`); claim de
> jobs é compare-and-swap correto (`sqlite.go:643`, `WHERE state='queued'` +
> `RowsAffected`); auth por bearer usa comparação constante-no-tempo
> (`secureEqual`).

## Deep dive: arquivos, mounts, transferências e permissão no node

Achados de leitura aprofundada do subsistema de arquivos
(`filesystem`, `grants`, `transfers`) e dos controles de upload/download.

### F1 🟠 Escape de escopo de grant via symlink

**Problema.** Um grant de transferência escopa um peer a um **subcaminho** de um
mount (`grant.Path`). O enforcement do subcaminho (`withinGrant`) opera sobre o
path **lógico**, mas a resolução de symlink (`filesystem.resolve`) valida apenas
contra a **raiz do mount**, não contra a base do grant. Um symlink colocado
dentro do subtree concedido, apontando para outro ponto do **mesmo mount** fora
do subtree, permite ao peer ler conteúdo fora do escopo do grant (embora ainda
dentro do mount).

**Evidência.** `node/backend/internal/services/transfers/service.go:171,979-983`
(`withinGrant` checa string lógica); `.../transfers/service.go:175`
(`s.files.Open(grant.MountID, sourcePath)`);
`node/backend/internal/services/filesystem/service.go:1522`
(`within(root, evaluated)` usa a raiz do **mount**). O mesmo vale para
`OpenManifest` e para o destino de escrita (`receiveDestination`).

**Impacto.** Confidencialidade: peer com grant `send` num subdiretório lê outros
diretórios do mount via symlink. Requer symlink colocado out-of-band (o node não
cria symlinks pela API), plausível em mount compartilhado (SMB/usuários locais).
Também afeta escrita: um symlink no subtree de um grant `receive` poderia
direcionar escrita para fora do subtree (dentro do mount).

**Solução proposta.** Reancorar a validação de contenção na base **real** do
grant: resolver `grant.Path` para o caminho real uma vez e, após
`filesystem.resolve` do alvo, exigir `within(grantRealBase, resolvedTarget)`, não
só `within(mountRoot, resolvedTarget)`. Ver `docs/REMEDIATION.md#f1`.

### F2 🟠 Upload sem limite de tamanho (exaustão de disco)

**Problema.** Somente o modo `editor` aplica `MaxBytesReader` (512 KB). Uploads
normais transmitem para arquivo temporário sem qualquer limite de tamanho de
corpo nem cota de mount. Um cliente autorizado pode encher o disco do mount.

**Evidência.** `node/backend/internal/infra/httpapi/server.go:683-724`
(`upload`) — `MaxBytesReader` só no ramo `editor`; `Upload` em
`filesystem/service.go:566` faz `io.Copy` sem teto.

**Solução proposta.** Limite configurável de tamanho por upload
(`MAX_UPLOAD_BYTES`) e verificação de espaço livre antes de publicar; opcional:
cota por mount. Ver `docs/REMEDIATION.md#f2`.

### F3 🟡 `overwrite=false` é TOCTOU (garantia não atômica)

**Problema.** `Upload`/`Copy` checam existência com `Lstat` e depois fazem
`os.Rename`, que **substitui** o destino incondicionalmente. Entre a checagem e o
rename, outro escritor pode criar o arquivo; `overwrite=false` não garante
ausência de sobrescrita sob concorrência.

**Evidência.** `filesystem/service.go:574-602` (Lstat, depois `os.Rename`).

**Impacto.** Baixo hoje (plano de controle único como escritor via proxy). Vira
relevante se múltiplos atores escreverem concorrentemente.

**Solução proposta.** Publicar com `link(2)`/`renameat2(RENAME_NOREPLACE)` para
falhar atômico quando o destino existir e `overwrite=false`.

### F4 🟡 Semântica de symlink em Delete/Move

**Problema.** `resolve(allowMissing=false)` retorna o caminho **real** (symlink
resolvido). `Delete`/`Move` então operam sobre o **alvo**, não sobre o link. Não
é possível remover um symlink pela API (remove-se o alvo apontado, se dentro do
mount); um symlink para fora do mount dá `ErrTraversal`.

**Evidência.** `filesystem/service.go:1525-1527` (retorna `evaluated`);
`Delete:493`, `Move:510`.

**Impacto.** Sem escape de segurança (alvo sempre dentro do mount), mas semântica
surpreendente para operadores.

**Solução proposta.** Tratar o componente final como link explicitamente:
`Lstat` do próprio componente e operar sobre o link quando for symlink
(remover/mover o link, não o alvo). Documentar o comportamento.

### F5 🟡 `Content-Disposition` sem codificação RFC 5987

**Problema.** O nome de arquivo no download só remove aspas
(`strings.ReplaceAll(name, '"', "")`); não há `filename*=` (RFC 5987) para
nomes não-ASCII, e a proteção contra CR/LF depende da sanitização do `net/http`.

**Evidência.** `node/backend/internal/infra/httpapi/server.go:679`.

**Solução proposta.** Emitir `filename` ASCII-safe + `filename*=UTF-8''<pct>` e
sanitizar explicitamente caracteres de controle.

### F6 🔵 RBAC sem wildcard recursivo (usabilidade)

**Problema.** `match` exige **contagem exata de segmentos**; `*` casa exatamente
um segmento e não existe `**` para subárvores. Cobrir uma subárvore inteira
exige uma regra por profundidade.

**Evidência.** `control/internal/rbac/rbac.go:128-145`
(`len(patternParts) != len(pathParts)` → sem match).

**Impacto.** Operacional, não de segurança (o design fail-closed é correto e a
precedência de `deny` é global).

**Solução proposta.** Suportar um segmento final `**` que casa um ou mais
segmentos, com especificidade menor que qualquer literal, preservando a
precedência de `deny`.

> Pontos fortes confirmados no deep dive:
> - Cadeia de confiança **cert mTLS → identidade Ed25519 → CommonName → grant**
>   é consistente; `OpenSource`/`receiveGrant` revalidam peer exato, `enabled`,
>   direção e permissão a cada operação (`transfers/service.go:167,916`).
> - Dupla contenção de path (subcaminho do grant + `resolve` do mount), exceto
>   pela lacuna de symlink em [F1](#).
> - Validação de grant robusta: peer confiável, mount existente/habilitado,
>   `published` para visibilidade, path existente, e coerência
>   direção↔permissão↔modo do mount (`grants/service.go:112-155`).
> - Download via `http.ServeContent` (Range/ETag/If-Modified-Since corretos);
>   uploads e cópias usam temp-file + `rename` atômico.
> - Precedência de `deny` global e correta no RBAC.

## Deep dive: consistência de transferência, confiança e rotação de identidade

Análise dos mecanismos de consistência de transferência node-a-node, confiança
entre peers (pairing/revogação) e rotação de identidade propagada (handover).

### Consistência de transferência — sólida

Cadeia de garantias verificada em `transfers/service.go`:

- **Revalidação por range.** Cada range concorrente revalida o peer exato
  (`trustedPeer`) e o grant de destino (`receiveGrant`: enabled, direção,
  permissão, política de conflito) antes de abrir a requisição
  (`service.go:421-428`).
- **Pinagem de ETag.** `If-Match` com o `SourceETag` persistido; a origem
  responde `412` se mudou (`service.go:439-441,465-466`).
- **Validação exata de range.** Exige `206`, `X-Jolt-File-Size == total`,
  `ETag == etag` e `Content-Range == bytes start-end/total`; qualquer divergência
  → `ErrSourceChanged` (`service.go:442-450`).
- **Trailer final fail-closed.** Trailer ausente/divergente é tratado como
  fonte-alterada; o destino **não publica** (`service.go:452,491`). (Ver
  reavaliação de [C7](#).)
- **Checkpoint durável.** O checkpoint só avança após o batch contíguo estar
  totalmente sincronizado; retry trunca bytes além do checkpoint
  (`ReceiveFileResumableRanges`). Publicação por `rename` atômico.
- **`checksum` de conflito.** Pula destino idêntico (`service.go:403-413`).

Conclusão: sem holes na publicação, sem replay de range, sem TOCTOU de
peer/grant durante a transferência (revalida a cada range).

### Confiança e revogação de peers — sólida, com nuance

- **Pairing.** Confiança só após confirmação humana de fingerprint exata;
  cria peer bilateral `trusted`. Convites one-time, expiráveis
  (`pairing/service.go`).
- **Revogação atômica.** `store.RevokePeer` é transacional: marca peer
  `revoked`, desabilita **todos** os grants do peer e grava eventos, tudo numa tx
  (`sqlite.go` `RevokePeer`).
- **Cancelamento de jobs.** O handler `revokePeer` chama, além da revogação,
  `jobs.CancelPeer(peerNodeID)` que cancela jobs ativos/relacionados
  (`httpapi/server.go:1164-1168`).
- **Bloqueio imediato.** mTLS rejeita peer `revoked`
  (`certificates.go:582` exclui estados não-confiáveis); transferências em voo
  falham na próxima revalidação de range.

**T1 🟡 Revogação e cancelamento de jobs não são uma única transação.**
`RevokePeer` (tx) e `CancelPeer` (operação separada) rodam em sequência, não
atomicamente. Uma janela mínima existe entre as duas, fechada na prática pela
revalidação-por-range e pela rejeição mTLS do peer revogado.
*Evidência:* `httpapi/server.go:1164,1168`.
*Solução:* unir revogação + cancelamento numa transação (ou tornar o cancel
idempotente e reexecutá-lo se a revogação truncar no meio).

### Rotação de identidade propagada (handover) — sólida

- **Envelope duplo-assinado.** O handover carrega epochs consecutivos, ambas as
  chaves/fingerprints e é assinado **pela chave anterior e pela próxima**
  (`identity.go:createIdentityHandover`), provando continuidade.
- **Verificação.** `VerifyIdentityHandover` exige `nextEpoch == prevEpoch+1`,
  fingerprint == hash(pubkey) para ambas, e valida as duas assinaturas sobre o
  payload canônico (`identity.go:261-289`).
- **Aplicação como CAS.** `ApplyPeerIdentityHandover` só aplica com
  `WHERE identity_epoch=? AND fingerprint=? AND state!='revoked'` e checa
  `RowsAffected` (`sqlite.go`), fechando o TOCTOU entre leitura e escrita.
  Rejeita peer `revoked` e epoch/fingerprint que não sejam o estado confiável
  atual (`pairing/service.go:358-361`).
- **Replay barrado por monotonicidade.** Um handover antigo `N→N+1` falha assim
  que o peer avança de epoch (o CAS não casa mais).
- **Sobreposição limitada.** Durante a troca, mTLS aceita a fingerprint anterior
  **ou** a próxima (`certificates.go:583`); a anterior é aposentada
  automaticamente após um heartbeat autenticado provar o novo epoch
  (`peers/monitor.go:96,163`).
- **Distribuição.** O Control Tower distribui o envelope assinado aos peers
  registrados e reporta acks/pendentes; aplicar a cadeia não muda `node_id` nem
  grants — exige mTLS fresco.
- **Recuperação manual.** Perda do elo de continuidade cai em
  `identity_changed` + confirmação manual de fingerprint (`RecoverPeerIdentity`,
  exige fingerprint diferente e confirmada).

**Nota (informativa).** `VerifyIdentityHandover` só impõe limite **superior** de
tempo (rejeita `issuedAt` > 10 min no futuro), sem limite inferior. Não é
explorável: o CAS por epoch impede aplicação fora do estado atual, e o envelope
assinado só é produzível pelo nó em rotação. A fingerprint de 80 bits reaparece
aqui — ver [C3](#c3).

## Pontos adicionais (proxy, SSE, servidor HTTP, preview)

Achados de uma varredura das áreas ainda não cobertas: proxy do Control Tower,
streaming SSE, timeouts do servidor HTTP, preview de mídia e cópia/manifesto de
diretórios.

### G1 🟡 Preview inline aceita `image/svg+xml`

**Problema.** O proxy marca `Content-Disposition: inline` para respostas cujo
tipo é `audio/*`, `video/*` ou **`image/*`** — o que inclui `image/svg+xml`. SVG
pode conter script; servido inline na **mesma origem** do Control Tower, é vetor
de XSS armazenado (um arquivo malicioso gravado num mount seria pré-visualizado
no contexto da aplicação).

**Mitigação existente.** A CSP `default-src 'self'` (sem `unsafe-inline` para
script) **bloqueia scripts inline** do SVG; `X-Content-Type-Options: nosniff` e
`X-Frame-Options: DENY` também ajudam. Logo o risco está contido hoje.

**Evidência.** `control/internal/httpapi/server.go` `isInlineMediaType`
(`strings.HasPrefix(mediaType, "image/")`); CSP em `securityHeaders:203`.

**Solução proposta (hardening).** Excluir `image/svg+xml` do allow-list inline
(tratar como download) ou servir previews por origem/sandbox isolada. Defesa em
profundidade além da CSP.

### G2 🟡 Servidor HTTP sem `ReadTimeout`/`WriteTimeout`

**Problema.** Node e Control Tower configuram apenas `ReadHeaderTimeout` e
`IdleTimeout`. Sem `ReadTimeout` de corpo, um cliente que envia o corpo muito
devagar (slow-body/slowloris) segura um worker e uma conexão indefinidamente; sem
teto de escrita, downloads lentos idem.

**Evidência.** `node/backend/cmd/jolt-node/main.go:122-131`;
`control/cmd/jolt-control/main.go:112-117`.

**Solução proposta.** Como uploads/downloads são streams longos legítimos, não
usar `ReadTimeout`/`WriteTimeout` globais fixos; aplicar **deadlines por-leitura**
via `http.ResponseController.SetReadDeadline`/`SetWriteDeadline` no handler de
upload/download, alinhados ao `TRANSFER_IDLE_READ_TIMEOUT`. Assim streams ativos
seguem, mas conexões ociosas/lentas caem.

### G3 🟡 Manifesto e cópia de diretório falham-duro em qualquer symlink

**Problema.** A geração de manifesto remoto e a cópia local de diretório
**abortam com erro** ao encontrar qualquer symlink na árvore
(`symlinks are not included in manifests` / `symlinks are not copied`). Uma única
symlink em qualquer nível impede transferir/copiar a árvore inteira.

**Evidência.** `filesystem/service.go:355-356,411-412` (manifesto);
`copyDirectory` (`... symlinks are not copied`).

**Impacto.** Não é falha de segurança (evita seguir symlink), mas quebra
operações legítimas em mounts compartilhados que contenham symlinks.

**Solução proposta.** Trocar o erro por **pular-com-aviso**: omitir a symlink do
manifesto/cópia, contabilizar como item ignorado e reportar no resultado
agregado, em vez de abortar o job.

### G4 🔵 Tabela `idempotency` sem expiração

**Problema.** Os registros de idempotência
(`key → job_id`) nunca são removidos; a tabela cresce indefinidamente, como as
sessões de [C12](#).

**Evidência.** `node/backend/internal/infra/db/sqlite.go:85` (schema),
`:497` (insert); sem rotina de expurgo.

**Solução proposta.** Estender o sweeper (ver [C12](#c12)) para apagar registros
de idempotência mais antigos que uma janela configurável.

### G5 🔵 SSE por polling não escala com muitos clientes

**Problema.** Cada cliente SSE faz `ListEvents` a cada 500 ms e um `Get`
**por evento** (N+1), tudo sobre a conexão única de escrita
([C5](#c5)). Muitos clientes simultâneos multiplicam a contenção no banco.

**Evidência.** `node/backend/internal/infra/httpapi/server.go`
`streamJobEvents` (ticker de 500 ms, `s.jobs.Get` por evento no loop).

**Solução proposta.** Fan-out orientado a eventos (um publisher in-process
notifica os assinantes SSE) em vez de polling por cliente; carregar o job junto
dos eventos numa única query. Reduz drasticamente a carga no banco.

> Confirmações positivas desta varredura:
> - Proxy do Control Tower avalia **RBAC antes** de encaminhar, valida allow-list
>   de recurso, injeta o token do node **apenas server-side** (nunca ao
>   navegador) e copia só um allow-list de headers de resposta
>   (`server.go:2251-2333`).
> - Cabeçalhos de segurança presentes: CSP `default-src 'self'`, `nosniff`,
>   `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
> - SSE encerra corretamente no `r.Context().Done()` — **sem vazamento de
>   goroutine**; heartbeats e `Last-Event-ID`/`after` para retomada.
> - `copyDirectory`/manifesto **não seguem** symlink (sem escape); apenas o
>   tratamento hard-fail é subótimo (G3).

## Autorização de usuário autenticado (não-admin)

Análise completa em [`docs/THREAT_MODEL.md`](THREAT_MODEL.md#atacante-autenticado-não-admin-operator--service-account).
Resumo dos itens acionáveis:

### E1 🟡 RBAC de arquivo é por-mount, não por-subpath

A decisão de acesso a arquivo usa `nodes/{node}/files/mounts/{mount}` sem o
caminho relativo; um operator com acesso a um mount alcança **todo** o mount.
Não é expressável restringir a um subdiretório via policy (só *grants*/
*transfers* escopam subpath). *Evidência:* `nodeAuthorizationRequirements`
(`control/internal/httpapi/server.go`). *Solução:* prefixo de subpath opcional na
policy de arquivo, ou mounts mais granulares.

### E2 🟠 Escalada por delegação de `sudo` em `control-tower/*`

`requireAdmin` exige a capability `sudo` no path `control-tower/<recurso>`
(`server.go:484-491`); não há separação entre gerir objetos de policy/usuário e
conceder o poder deles. Delegar `sudo` de gestão a um operator permite
auto-atribuir policies ou elevar o próprio `role` para `admin` (`updateUser` só
impede *remover* o próprio admin). *Solução:* separar administração de objetos da
capacidade de concedê-los; bloquear auto-concessão/auto-promoção; exigir segundo
admin para promoções.

## UX de autorização (definição de policy e visibilidade de acesso)

Avaliação da UI de policies (`control/frontend/src/components/admin/`). A
interface **executa** o modelo RBAC, mas **não o ensina nem revela**: assume
conhecimento implícito da taxonomia de Node Path e não oferece visão de acesso
efetivo. É a maior lacuna de usabilidade da plataforma para operadores.

### UX1 🟠 Node Path é texto livre, sem builder/validação

**Problema.** O campo Node Path é `<Input>` livre (`PoliciesDialog.tsx:265`),
placeholder `nodes/*/files/mounts/media`. Exige conhecer a gramática
(`nodes/{id}/files/mounts/{mount}`, `/jobs`, `/transfers`, `control-tower/...`).
Sem picker de node/mount, sem autocomplete, sem validação inline. Um typo produz
uma regra que **silenciosamente não casa nada** — falsa sensação de concessão.

**Solução proposta.** Construtor guiado: escolher node → tipo de recurso
(files/jobs/transfers/grants/peers/crypto/control-tower) → mount (de uma lista
real), gerando o path. Validar contra `rbac.ValidPath` ao digitar e mostrar
erro/aviso inline.

### UX2 🟠 Capabilities sem explicação nem receitas

**Problema.** As 9 capabilities são checkboxes sem descrição/tooltip
(`PoliciesDialog.tsx:272-290`; confirmado: nenhum `tooltip/title` no admin).
Semântica opaca: `list`≠`read`; `write` implica `create`+`update` (regra do
backend `grants()` não aparece); `execute` para jobs/transfers; `sudo` = admin.
Nada indica **quais capabilities uma operação exige** (ex.: transferência =
`execute` em `transfers` + `read` na origem + `create` no destino).

**Solução proposta.** Descrição/tooltip por capability + "receitas" prontas
("permitir download: `read`+`list` no mount"; "permitir transferência: `execute`
em transfers + `read` origem + `create` destino"). Opcional: templates de policy.

### UX3 🟡 Semântica de wildcard e deny não é sinalizada

**Problema.** `*` casa **um** segmento com profundidade exata (sem `**`), então
`nodes/*` não cobre a subárvore — contra a intuição. `deny` tem **precedência
global** (anula todos os allows de todas as policies/roles), mas a UI só o pinta
de vermelho, sem avisar o raio de impacto. Além disso, digitar subpath sob um
mount cria regra que nunca casa (reflexo de [E1](#)).

**Solução proposta.** Texto de ajuda sobre wildcard; aviso ao adicionar `deny`
("afeta todos os subjects"); aviso quando o path tem segmentos além do nível de
mount (não terá efeito enquanto E1 não for resolvido).

### UX4 🟠 Sem visão de acesso efetivo por subject

**Problema.** Não há tela que mostre "o que o usuário/serviço X pode fazer": o
admin compõe mentalmente policies diretas + roles + `deny` + node allow-list
(grep por `efetiv/effective/simula/test` no frontend = vazio). A atribuição
(`UsersDialog`) exibe só **nomes** de policy/role, sem resumo do que concedem.

**Solução proposta.** Painel de "acesso efetivo": para um subject, avaliar (via a
mesma engine de `/auth/permissions`) o conjunto de nodes/mounts atribuídos e
renderizar uma matriz subject × path × capabilities, destacando `deny` e o
allow-list de nodes. Expandir cada policy/role inline na atribuição.

### UX5 🟡 Ação negada é escondida sem explicação

**Problema.** Ações não autorizadas não são renderizadas
(`NodeActionsBar.tsx` embrulha botões em `hasPermission(...)`). Nem usuário nem
admin recebem "negado pela policy X" — apesar de o backend **auditar** a decisão
com os policy IDs aplicados.

**Solução proposta.** Superfície de diagnóstico "por que negado" reutilizando o
`AuditDecision` (path avaliado, capability, policy IDs, decisão) — ao menos numa
visão de administração/atividade.

> Positivos: a UI é permission-aware (esconde ações não permitidas do usuário
> atual, evitando becos); `deny` é visualmente distinto e mutuamente exclusivo no
> editor; o backend já audita decisões com policy IDs (matéria-prima para UX4/UX5).

**Proposta de solução consolidada:** uma página dedicada que centraliza policies,
roles, subjects, access groups e o **Explorador de Acesso Efetivo** — desenho
completo em [`docs/ACCESS_CENTER.md`](ACCESS_CENTER.md). Substitui os seis modais
isolados de hoje e endereça UX1–UX5 num só lugar.

## Dependências e supply chain

Resultado de `govulncheck` (executado nesta sessão) e revisão de `go.mod`.

### H1 🟠 `x/crypto` e `x/sys` desatualizados com CVEs conhecidos

**Problema.** `govulncheck` reporta, no Control Tower, ~17 vulnerabilidades em
`golang.org/x/crypto@v0.40.0` e 1 em `golang.org/x/sys@v0.36.0`; o node reporta 1
em `x/sys`. O código **não chama** os símbolos afetados (a maioria é
ssh/acme/etc não usados), então o risco imediato é baixo — mas os pacotes estão
atrás de correções disponíveis.

**Evidência.** `govulncheck ./...` em `control/` e `node/`:
`GO-2026-5013..5033` em `x/crypto@v0.40.0` (**fixed in v0.52.0**);
`GO-2026-5024` em `x/sys@v0.36.0` (**fixed in v0.44.0**);
`GO-2026-5932` em `x/crypto` (sem fix ainda). `x/crypto` é usado aqui para
Argon2id e (proposto) HKDF, então convém manter atualizado.

**Solução proposta.**
```sh
cd control && go get -u golang.org/x/crypto@v0.52.0 golang.org/x/sys@v0.44.0 && go mod tidy
cd ../node   && go get -u golang.org/x/sys@v0.44.0 && go mod tidy
```
Reexecutar `govulncheck` e fixar a checagem no CI.

### H2 🟡 Binding SQLCipher pouco mantido (ponto cego de CGO)

**Problema.** O Control Tower usa `github.com/mutecomm/go-sqlcipher/v4 v4.4.2`,
biblioteca com manutenção esparsa que **empacota** uma amálgama SQLCipher/SQLite.
`govulncheck` não analisa o código C embutido, então CVEs do SQLite empacotado
**não aparecem** na varredura.

**Evidência.** `control/go.mod` (`mutecomm/go-sqlcipher/v4 v4.4.2`); relatório do
`govulncheck` lista "18 vulnerabilities in modules you require" sem cobrir o C.

**Solução proposta.** Verificar a versão do SQLite/SQLCipher embutida vs.
advisories; avaliar alternativa mantida (ex.: binding SQLCipher ativo ou SQLCipher
via `modernc` quando disponível). Acompanhar em conjunto com [P0.3](#p03)
(criptografia do node), que também depende do toolchain SQLCipher.

> Positivo: nenhuma vulnerabilidade **alcançável** pelo código
> (`0 called vulnerabilities` em node e control); nenhum segredo
> (token/senha/chave) encontrado em logs.

## Áreas ainda não aprofundadas

Para transparência, estas áreas não receberam leitura linha-a-linha e são
candidatas a um próximo passo:

- Código do frontend React (renderização/escape, tratamento de erros, estados de
  permissão) — a sessão é por cookie `HttpOnly`, sem token em `localStorage`, o
  que reduz a superfície.
- Caminho de rotação do token operacional (duas fases) em código.
- Snapshot/restore e diagnósticos offline em código (cobertos por doc/testes).
- Completude do OpenAPI/Swagger e exemplos de payload de erro/evento.
- Auditoria de dependências (go.mod/npm) contra CVEs conhecidos.
- Diagnóstico de permissão de mount e enforcement read-only sob condições de
  corrida de FS.

## Priorização consolidada

| # | Item | Sev | Esforço | Ordem |
| --- | --- | --- | --- | --- |
| P0.1 | Corrigir docs Vue → React | 🔴 | Baixo | 1 |
| P0.2 | Rate-limit + lockout + MFA no login | 🔴 | Médio | 2 |
| P0.3 | Criptografia do node DB (SQLCipher) | 🟠 | Médio | 3 |
| P1.1 | Métricas + tracing | 🟠 | Médio | 4 |
| P1.2 | Liveness/readiness | 🟠 | Baixo | 5 |
| P1.3 | API de logs recentes | 🟠 | Médio | 6 |
| P1.4 | Config mutável | 🟠 | Alto | 7 |
| P1.5 | Notificações/webhooks | 🟠 | Médio | 8 |
| P2.1 | Upload resumável | 🟡 | Médio | 9 |
| P2.2 | Multi-arquivo na transferência direta | 🟡 | Médio | 10 |
| P2.3 | Descoberta remota de grants/mounts | 🟡 | Médio | 11 |
| P2.4 | Transferências agendadas | 🟡 | Médio | 12 |
| P2.5 | i18n | 🟡 | Alto | 13 |
| P2.6 | Gestão de sessão | 🟡 | Baixo | 14 |
| P3.1 | Sync contínuo/bidirecional | 🔵 | Alto | 15 |
| P3.2 | Transferência delta | 🔵 | Alto | 16 |
| P3.3 | Backup online + destino remoto | 🔵 | Médio | 17 |
| P3.4 | Import de certificado mTLS externo | 🔵 | Médio | 18 |
| P3.5 | Push transfers / multi-hop | 🔵 | Alto | 19 |
| P4.1 | Executar acceptance-full | 🟠 | Baixo | 20 |
| C1 | KDF forte p/ passphrase do SQLCipher | 🟠 | Baixo | — |
| C2 | Separação de subchaves (HKDF) | 🟡 | Baixo | — |
| C3 | Fingerprint 80→128 bits | 🟡 | Médio | — |
| C4 | Fechar furo de Origin no CSRF | 🟡 | Baixo | — |
| C5 | Pool de leitura no SQLite (throughput) | 🟠 | Médio | — |
| C6 | Reavaliar componente final (TOCTOU) | 🟡 | Médio | — |
| C7 | Trailer sentinela na origem (cosmético; destino já fail-closed) | 🔵 | Baixo | — |
| C8 | Segredos via `*_FILE`/Docker secrets | 🟠 | Baixo | — |
| C9 | Hardening + limites de container | 🟡 | Baixo | — |
| C10 | `SECURE_COOKIES` default `true` | 🟡 | Baixo | — |
| C11 | Higiene de repo (órfãos + commit) | 🔵 | Baixo | — |
| C12 | Sweeper de sessões/convites expirados | 🟡 | Baixo | — |
| F1 | Reancorar contenção na base real do grant | 🟠 | Médio | — |
| F2 | Limite de tamanho de upload + espaço livre | 🟠 | Baixo | — |
| F3 | Publicação atômica `RENAME_NOREPLACE` | 🟡 | Baixo | — |
| F4 | Semântica explícita de symlink em Delete/Move | 🟡 | Médio | — |
| F5 | `Content-Disposition` RFC 5987 | 🟡 | Baixo | — |
| F6 | Wildcard recursivo `**` no RBAC | 🔵 | Médio | — |
| T1 | Revogação + cancel de jobs numa única transação | 🟡 | Baixo | — |
| G1 | Excluir `image/svg+xml` do preview inline | 🟡 | Baixo | — |
| G2 | Deadlines por-leitura no upload/download | 🟡 | Médio | — |
| G3 | Manifesto/cópia: pular symlink com aviso | 🟡 | Baixo | — |
| G4 | Expurgo da tabela `idempotency` | 🔵 | Baixo | — |
| G5 | SSE orientado a eventos (fan-out) | 🔵 | Médio | — |
| H1 | Atualizar `x/crypto`/`x/sys` (CVEs) | 🟠 | Baixo | — |
| H2 | Revisar binding SQLCipher (CGO) | 🟡 | Médio | — |
| E1 | RBAC de arquivo por-subpath (não só mount) | 🟡 | Médio | — |
| E2 | Separar gestão de policy de auto-concessão | 🟠 | Médio | — |
| UX1 | Builder + validação de Node Path | 🟠 | Médio | — |
| UX2 | Descrições/receitas de capability | 🟠 | Baixo | — |
| UX3 | Avisos de wildcard/deny/subpath | 🟡 | Baixo | — |
| UX4 | Painel de acesso efetivo por subject | 🟠 | Alto | — |
| UX5 | Feedback "por que negado" | 🟡 | Médio | — |
