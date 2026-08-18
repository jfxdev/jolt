# Discovery — áreas pendentes de análise

Backlog de investigação para a **próxima sessão**. Lista as áreas que ainda não
receberam leitura linha-a-linha, o que procurar em cada uma, pontos de entrada no
código e o resultado esperado. Achados já cobertos estão em
[`docs/ROADMAP.md`](ROADMAP.md); correções em [`docs/REMEDIATION.md`](REMEDIATION.md).

Status: `pendente` = não iniciado. Ao concluir, mover achados para o ROADMAP e
marcar aqui como `feito`.

---

## D1 — Frontend React (Control Tower) · parcial (UX de autorização feita)

**Feito nesta sessão.** UX de policies/autorização revisada — ver **UX1–UX5** no
ROADMAP (Node Path livre sem builder, capabilities sem explicação, sem visão de
acesso efetivo, ação negada escondida sem motivo).

**Pendente.** O restante abaixo (sinks de XSS, preview de mídia/texto,
armazenamento de credencial, tratamento de erro).

**Por que.** Toda a UI autenticada roda na mesma origem que serve arquivos de
mount; renderização insegura vira XSS na sessão do operador.

**O que procurar.**
- Renderização de conteúdo não confiável: `dangerouslySetInnerHTML`, injeção em
  `href`/`src`, render de nomes de arquivo/paths vindos do node.
- Preview de mídia/texto: como `MediaPreviewDialog.tsx` e `TextEditorDialog.tsx`
  exibem bytes do node; risco de HTML/SVG inline (liga a **G1**).
- Armazenamento de credencial: confirmar que não há token em `localStorage`/
  `sessionStorage` (sessão é cookie `HttpOnly`; validar).
- Tratamento de erro: se mensagens do backend (que podem conter paths) são
  exibidas cruas.
- Estados de permissão: `PermissionsContext.tsx` esconde ações não autorizadas,
  mas o enforcement real é server-side — confirmar que a UI não é a única
  barreira em nenhum fluxo.

**Pontos de entrada.**
`control/frontend/src/components/files/MediaPreviewDialog.tsx`,
`.../files/TextEditorDialog.tsx`, `.../lib/api.ts`, `.../lib/media.ts`,
`.../context/PermissionsContext.tsx`, `.../context/AuthContext.tsx`.

**Resultado esperado.** Confirmar ausência de sinks de XSS; catalogar qualquer
render inseguro; validar modelo de sessão no cliente.

---

## D2 — Rotação do token operacional (duas fases) em código · pendente

**Por que.** Doc afirma rotação coordenada sem janela de indisponibilidade;
falta validar o código contra falhas intermediárias e replay.

**O que procurar.**
- `prepare` grava apenas o hash SHA-256 do novo token; `commit` invalida o
  antigo só após autenticação com o novo.
- Ordem de operações entre node e Control Tower; o que acontece se o processo
  cai entre `prepare` e `commit` (ambos os tokens devem autenticar no intervalo —
  já visto em `acceptOperationalToken`, confirmar o resto).
- Idempotência do `commit`; possibilidade de reverter/rollback.
- Auditoria e mascaramento (nenhum token em resposta/log).

**Pontos de entrada.**
`node/backend/internal/infra/httpapi/server.go` (`prepareOperationalToken`,
`commitOperationalToken`, `operationalTokenState`);
`control/internal/httpapi/server.go` (`rotate-token`);
tabela/estado em `node/backend/internal/infra/db/sqlite.go`
(`GetOperationalTokenState`).

**Resultado esperado.** Confirmar segurança da máquina de estados e ausência de
janela onde nenhum token autentica.

---

## D3 — Snapshot / restore offline em código · pendente

**Por que.** DR é crítico; hoje coberto por doc e testes, não por leitura de
código nesta análise.

**O que procurar.**
- Lock exclusivo de instância: correção contra corrida com processo ativo.
- Snapshot: consolidação do SQLite sem WAL/SHM transitórios, permissões `0600`,
  exclusão da chave externa (control), manifesto SHA-256.
- Restore diagnostics: integridade, correspondência chave pública/privada,
  detecção de mount ausente/divergente, partial-files.
- Recuperação de emergência: substituição atômica de token/credencial e de admin;
  revogação de sessões; saída sem segredos.

**Pontos de entrada.**
`node/backend/internal/infra/recovery/snapshot.go`,
`.../recovery/diagnostics.go`; `control/internal/recovery/snapshot.go`,
`.../recovery/diagnostics.go`; subcomandos em ambos os `main.go`.

**Resultado esperado.** Validar atomicidade, permissões e ausência de vazamento
de chave/segredo nos artefatos.

---

## D4 — Completude do OpenAPI/Swagger · pendente

**Por que.** Automação e clientes dependem de contrato preciso; doc marca
schemas de erro/evento como incompletos.

**O que procurar.**
- Cobertura de todas as rotas (comparar com os `mux.HandleFunc` de node e
  control).
- Schemas de payload de erro (`{code, message}`) e de eventos SSE.
- Exemplos e códigos de status documentados vs. reais.

**Pontos de entrada.**
`node/backend/.../httpapi/server.go` (`openapi`, `/openapi.yaml`, `/docs`);
arquivo OpenAPI embutido/servido.

**Resultado esperado.** Lista de lacunas de contrato; ligar à Priority 5 do
ROADMAP.

---

## D5 — Auditoria de dependências (CVE) · feito (resta ponto cego de CGO)

**Feito nesta sessão.**
- `govulncheck` em `node/` e `control/`: **0 vulnerabilidades alcançáveis**;
  `x/crypto@v0.40.0` (~17) e `x/sys@v0.36.0` (1) desatualizados → **H1**/**H2**
  no ROADMAP.
- `npm audit` em `control/frontend` (incl. dev): **0 vulnerabilidades**.
- Sem segredo (token/senha/chave) encontrado em logs.

**Resta.** Verificar a versão do SQLite/SQLCipher **embutida** no binding CGO
(`mutecomm/go-sqlcipher`), que o `govulncheck` não enxerga — ver **H2**.

**Por que.** Rápido e de alto valor; dependências desatualizadas são risco
direto.

**O que procurar.**
- Go: rodar `govulncheck ./...` em `node/` e `control/`; revisar `go.mod`
  (versões de `mutecomm/go-sqlcipher`, `modernc.org/sqlite`, `x/crypto`).
- Frontend: `npm audit` em `control/frontend`; revisar versões de React 19,
  Radix, Vite, react-router.
- Verificar se há dependências não usadas ou pinadas em versões vulneráveis.

**Comandos.**
```sh
cd node && govulncheck ./...
cd control && govulncheck ./...
cd control/frontend && npm audit
```

**Resultado esperado.** Lista priorizada de CVEs aplicáveis e upgrades
recomendados.

---

## D6 — Permissão de mount e read-only sob corrida de FS · pendente

**Por que.** Enforcement read-only e diagnósticos de permissão dependem de
estado do FS que pode mudar sob os pés (TOCTOU), especialmente em mounts
compartilhados.

**O que procurar.**
- `writable()` e `diagnose()`: como o modo do mount é reavaliado antes de cada
  escrita; janela entre diagnóstico e operação.
- Interação com **F1** (escape de escopo por symlink) e **C6** (TOCTOU no
  componente final).
- Comportamento quando o mount fica read-only/indisponível no meio de um job
  (transições `waiting_mount`).

**Pontos de entrada.**
`node/backend/internal/services/filesystem/service.go` (`writable`, `diagnose`,
`resolve`); monitor de mount em `jobs`/`filesystem`.

**Resultado esperado.** Confirmar que nenhuma escrita ocorre em mount read-only
sob corrida; catalogar hardening.

---

## D7 — Limitador de banda: correção e justiça · pendente

**Por que.** Ainda não foi lido o algoritmo do rate-limiter (token bucket?);
importa para justiça entre jobs e para não starвар conexões.

**O que procurar.**
- Implementação do `byteRateLimiter` (node-wide e por-job): tipo de algoritmo,
  precisão, comportamento com `0` (desabilitado) e composição node+job; risco de
starvation de conexões lentas.
- Justiça entre jobs concorrentes.
- Pacing-aware heartbeats (já citados) para não disparar timeout de no-progress.

**Pontos de entrada.**
`node/backend/internal/services/jobs/service.go` (`byteRateLimiter`,
`nodeBandwidth`, `jobBandwidth`, `BandwidthLimiter`).

**Resultado esperado.** Validar corretude do limitador e ausência de starvation.

---

## Ordem sugerida para a próxima sessão

1. **D5** (CVE) — rápido, alto valor, sem depender de contexto.
2. **D1** (frontend XSS) — superfície de segurança direta; complementa G1.
3. **D2** (rotação de token) — caminho de segurança crítico.
4. **D6** (mount/read-only TOCTOU) — complementa F1/C6.
5. **D3** (snapshot/restore) — DR.
6. **D7** (rate-limiter) — corretude/perf.
7. **D4** (OpenAPI) — contrato/automação.
