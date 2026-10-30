# Modelo de ameaça — estado atual

Este documento descreve a arquitetura atual e os limites de confiança da primeira
versão. A análise histórica e os achados reproduzidos permanecem em
[ROADMAP.md](ROADMAP.md), [REMEDIATION.md](REMEDIATION.md) e
[RELEASE_0.1.0.md](RELEASE_0.1.0.md); afirmações antigas de ausência de lockout,
RBAC por subpath ou criptografia no node não descrevem o código atual.

## Ativos e adversários

Ativos principais: bytes dos mounts, identidade privada Ed25519, certificados,
tokens operacionais e de service accounts, sessões, chaves externas, estado de
jobs/grants e banco SQLCipher do Control Tower.

Consideramos atacante remoto anônimo, visitante com link público, usuário/operator
ou service account autenticado, peer pareado, atacante on-path e comprometimento
do host/container. Não prometemos conter root no host, um admin malicioso ou um
processo que já possa escrever arbitrariamente nos mounts fora da API.

## Superfície e fronteiras

| Entrada | Controle atual | Exposição exigida |
| --- | --- | --- |
| Control Tower TCP 8090 | Cookie HttpOnly/SameSite ou bearer de service account; RBAC server-side | proxy HTTPS; backend em loopback |
| Node API TCP 8080 | bearer operacional de alta entropia; TLS e client CA opcionais | somente rede privada/VPN do Control Tower |
| Node peer TCP 8443 | TLS 1.3 mTLS e certificado vinculado ao peer/fingerprint exatos | somente peers autorizados por firewall |
| `/metrics` | bearer dedicado e independente | somente Prometheus/rede de observabilidade |
| `/livez`, `/readyz`, `/health` | sem dados de arquivos; readiness local | rede de infraestrutura |
| Login e shares públicos | lockout persistido; shares somente leitura | somente através do Control Tower HTTPS |

`/openapi.yaml` e `/docs` do node permanecem autenticados. O Control Tower injeta
o token do node apenas no proxy server-side; navegador e service account não o
recebem. Transferências entre nodes são pull no destino e os bytes não passam
pelo Control Tower.

## Controles implementados

### Autenticação e autorização

- Senhas de usuários usam Argon2id. Login e desbloqueio de share possuem lockout
  persistido com `Retry-After`; cookies de sessão são revogáveis e Secure por
  padrão. O IP considerado é o peer TCP, não um `X-Forwarded-For` falsificável.
- Admins possuem acesso amplo. Operators usam policies diretas e roles; service
  accounts precisam de policy **e** membership do node em access group ativo.
  Sem grupo ativo, a autenticação falha fechado.
- Node Paths suportam subpaths, `*` por segmento, `**` recursivo no final e
  precedência global de `deny`. A autorização ocorre antes do proxy e considera
  os caminhos efetivos de seleção, uploads persistidos e transferências.
- A capability `sudo` em recursos administrativos é equivalente a conceder
  administração. Não a delegue como permissão ordinária; não há separação entre
  gerir policies e conceder privilégios.
- RBAC é reavaliada em novas chamadas, mas alteração de policy não cancela um job
  já admitido. Para contenção, cancele o job ou revogue grant/peer.

### Arquivos, jobs e compartilhamentos

- A API usa caminhos relativos, contenção de mount e operações por descritores
  com no-follow. Partial files são internos e a publicação é atômica;
  `overwrite=false` usa operação de não substituição do kernel nas plataformas
  suportadas. Remover/mover um symlink não remove/move seu alvo.
- Jobs possuem checkpoints duráveis, revalidação de mount/peer/grants, ETag e
  publicação somente após batches sincronizados. Restarts podem exigir validação
  explícita. Limites de banda e paralelismo reduzem exaustão, mas não garantem
  justiça entre jobs.
- Uploads têm teto por arquivo, limite de sessões, reserva de bytes e margem de
  disco. Isso não substitui quotas e alertas do filesystem.
- Shares são read-only, com senha opcional, expiração, cota e revogação. Cada
  requisição de conteúdo/ZIP, inclusive Range, conta tentativa de download.
  Cada acesso reavalia a RBAC do criador e o confinamento impede symlink fora do
  escopo. Token desconhecido e revogado têm resposta indistinguível.
- O desbloqueio de share gera ticket HMAC próprio, com validade limitada e
  ligação ao hash da senha; revogação e perda de acesso do criador impedem acesso.

### Criptografia e segredos

- O node mantém journal/snapshots YAML com AES-256-GCM e identidade/chaves em
  diretório separado. Não contém SQLite/SQLCipher.
- O Control Tower usa SQLCipher de página inteira e AES-256-GCM adicional para
  tokens de node e convites pendentes. A chave externa não fica no banco nem nos
  snapshots.
- Use chaves Base64 aleatórias de 32 bytes. O caminho alternativo de passphrase
  do Control Tower deriva SHA-256 uma única vez e não oferece KDF lento; a chave
  mestra também é usada para derivação/proteção de campos, sem subchaves HKDF
  independentes. Isso reforça a exigência de alta entropia e controle de acesso.
- Todos os segredos operacionais relevantes aceitam `NOME` ou `NOME_FILE`, com
  erro fechado se ambos estiverem preenchidos ou o arquivo falhar. Arquivos
  read-only evitam exposição via `docker inspect`, mas root no host ainda lê os
  secrets e a memória do processo.
- Snapshots são offline, com lock exclusivo, integridade, manifest SHA-256 e modo
  `0600`. O snapshot do node contém chaves privadas; nenhum snapshot inclui os
  arquivos dos mounts ou a chave externa correspondente.

## Riscos residuais e compensações

| Risco/limite | Tratamento necessário |
| --- | --- |
| Sem MFA e sessões de 12 h, sem console de dispositivos | HTTPS, senha única, menor número de admins e recuperação offline |
| Lockout pode ser usado para indisponibilizar uma conta e não é rate limit distribuído | Control Tower single-instance, proxy/firewall e alertas de falhas |
| Peer confiável com grant amplo pode ler/escrever dentro desse grant | grants mínimos, paths específicos, revogação e auditoria |
| Admin ou `sudo` delegado tem privilégio elevado | não delegar gestão a operators comuns |
| Node token comprometido contorna a RBAC do Control Tower | API privada/TLS, rotação coordenada e recuperação offline |
| Root no host ou escritor externo no mount está fora da contenção completa | hardening do host, permissions, quotas e mounts dedicados |
| Backup exige parada; sem HA ou backup online | janela de manutenção, snapshots e restores periódicos |
| Sem tracing/API de logs/configuração mutável | coletor externo de logs/métricas e acesso operacional ao host |
| UI não recupera o arquivo após reload sem reseleção | documentar e testar resume por reseleção |
| Fingerprint humana truncada é uma âncora de confiança com margem menor que hash completo | confirmar fingerprint por canal independente e proteger handovers |

## Supply chain e evidências

A distribuição injeta versão/commit/data nos binários e labels OCI, publica
SBOM/provenance por Buildx, imagens por tag/digest e inventário nativo. A
promoção preserva tag, SHA e digests da prerelease, sem rebuild.

Inventário de referência: Go `1.26.10`, Node `24` no build do frontend, Alpine
`3.22`, binding `github.com/mutecomm/go-sqlcipher/v4 v4.4.2` e amalgamation
SQLite `3.33.0` (`SQLITE_VERSION_NUMBER 3033000`). O artifact da candidata é a
fonte da versão efetivamente publicada.

`govulncheck` avalia vulnerabilidades Go alcançáveis; não cobre C/SQLCipher.
Trivy bloqueia HIGH/CRITICAL na imagem, mas scan não é prova de ausência de
vulnerabilidades. A camada C e advisories sem cobertura do scanner exigem triagem
manual registrada no gate [RELEASE_V1.md](RELEASE_V1.md).

## Reporte de vulnerabilidades

Use uma GitHub Security Advisory privada em
`https://github.com/jfxdev/jolt/security/advisories/new`. Não abra issue pública
com exploit, token, arquivos pessoais ou segredos. Informe versão/SHA/digest,
arquitetura, configuração redigida, impacto e reprodução mínima. Não há SLA de
resposta declarado neste repositório.
