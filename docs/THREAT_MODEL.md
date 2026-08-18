# Modelo de ameaça

Análise da superfície de ataque para acesso ao **filesystem** do node e do
Control Tower. Foca no atacante **remoto não autenticado** e cita agravantes de
posição de rede e de host. Referências de achados em
[`docs/ROADMAP.md`](ROADMAP.md); correções em
[`docs/REMEDIATION.md`](REMEDIATION.md).

## Escopo e ativos

- **Ativo primário:** conteúdo dos mounts (FS do node) e o banco do Control
  Tower (usuários, sessões, tokens de node cifrados, auditoria).
- **Ativos de credencial:** token operacional do node, chave privada Ed25519 de
  identidade, certificados mTLS, senha de admin, chave de criptografia do banco.

## Perfis de atacante

1. **Remoto não autenticado** — só alcança as portas de rede expostas. Foco
   principal deste documento.
2. **On-path / mesma rede** — consegue observar/interceptar tráfego (relevante
   sem TLS).
3. **Local no host/container** — já tem execução ou leitura no host (pós-
   comprometimento); usado para contextualizar defesas em profundidade.

## Superfície exposta

| Porta | Serviço | Autenticação | Rotas públicas |
| --- | --- | --- | --- |
| 8080 | Node API | Bearer (`CONTROL_TOWER_TOKEN`) — envolve todo o mux | só `/health` (se `PUBLIC_HEALTHCHECK`) |
| 8443 | Node mTLS/peer | Certificado cliente identity-pinned (TLS 1.3) | nenhuma sem cert confiável |
| 8090 | Control Tower | Sessão por cookie ou bearer de service account | `/health`, assets estáticos, `POST /auth/login` |

Evidências: node `auth` envolve o mux inteiro
(`node/backend/internal/infra/httpapi/server.go` — `s.auth(mux)`), com bypass
apenas de `/health`; mTLS usa `certificateManager.TLSConfig()`
(`RequireAnyClientCert` + `VerifyPeerCertificate`) em
`node/backend/cmd/jolt-node/main.go:128-142`; rotas do Control Tower são
individualmente embrulhadas em `s.auth(...)`, exceto `login`/`health`
(`control/internal/httpapi/server.go:68-72`).

## As três "portas" para o FS (atacante remoto não autenticado)

### Porta 1 — Node API (8080) · dificuldade: MUITO ALTA

- **Barreira:** todo acesso a FS exige `Authorization: Bearer` igual ao token
  operacional, comparado em tempo constante (`secureEqual`), aceitando também os
  hashes staged/active (`acceptOperationalToken`, `server.go:148-170`).
- **Brute-force:** o node **não** tem rate-limit de auth, mas o token é segredo
  de alta entropia; espaço de busca inviável (~2¹²⁸+).
- **Via realista:** roubo do token (Porta 3 ou comprometimento de host), não
  ataque online.

### Porta 2 — Node mTLS (8443) · dificuldade: MUITO ALTA (criptográfica)

- **Barreira:** o handshake TLS 1.3 exige certificado cliente assinado pela
  chave Ed25519 de um peer **confiável exato**. `VerifyPeerCertificate` valida a
  assinatura sobre `RawTBSCertificate`, deriva a fingerprint da chave embutida e
  exige match de `node_id` + fingerprint no registry de peers
  (`certificates.go:533-588`). Sem cert válido, o atacante nem chega ao HTTP
  (inclusive `/peer/v1/heartbeat`).
- **Via realista:** obter a **chave privada de um peer confiável**. Sem ela,
  impossível.

### Porta 3 — Control Tower (8090) · dificuldade: MÉDIA · **elo mais fraco**

- **Superfície não autenticada:** apenas `/health`, assets estáticos e
  `POST /api/v1/control-tower/auth/login`.
- **Fraqueza:** o login **não tem rate-limit, lockout nem MFA** (achado
  **P0.2**). A única defesa é a força da senha do admin (mínimo 12 caracteres,
  Argon2id ~dezenas de ms/tentativa). Sem lockout, brute-force/spray online é
  viável com tempo se a senha for fraca ou adivinhável.
- **Consequência:** sessão de admin → proxy autenticado dos nodes → **FS
  completo** (o Control Tower detém o token do node cifrado e o injeta apenas
  server-side).
- **Via realista:** este é o **único vetor prático** para um atacante puramente
  remoto. A dificuldade colapsa para a força da senha do admin.

## Atacante autenticado não-admin (operator / service account)

Modelo de privilégio verificado no código:

- **operator** (usuário não-admin) — confinado **exclusivamente às suas
  policies**. `evaluateAuthorization` resolve policies diretas + de roles e aplica
  `rbac.Evaluate` com precedência de `deny` (`server.go:574-600`). Não possui o
  token operacional do node: **todo** acesso a FS passa pela RBAC do proxy do
  Control Tower.
- **admin** (`role == "admin"`) — **bypass total** da RBAC (`server.go:575`).
- **service account** — dupla trava: policy **e** pertencimento do node a um
  access-group (`server.go:582-593`, fail-closed se não for membro).

O mapeamento rota→(Node Path, capability) do proxy é **por-método e preciso**
(`nodeAuthorizationRequirements`): GET content/metadata → `read`, GET listagem →
`list`, PUT → `create`, DELETE → `delete`, copy → `read`+`create`+jobs, move →
`update`+jobs. Sem confusão read→write.

**Confinamento (bom).** Sem `sudo` de gestão, um operator não escala: não fala
direto com o node (sem token), não enumera usuários/policies/auditoria
(`requireAdmin`), e a RBAC é avaliada server-side. Burlar exigiria quebrar a
própria RBAC (match por segmento exato, sem `..`/wildcard, deny global — revisada
como sólida).

**Riscos reais (configuração/granularidade), não bypass de código:**

### E1 🟡 Granularidade de arquivo é por-mount, não por-subpath

A decisão de RBAC de arquivo usa `nodes/{node}/files/mounts/{mount}` e **não
inclui o caminho relativo**. Um operator com `read` num mount lê o **mount
inteiro**; não há como restringir a um subdiretório via policy (apenas *grants* e
*transfers* escopam subpath). Intenções de "dar acesso só a `/M/projetoA`" não
são expressáveis → sobre-exposição dentro do mount concedido.
*Evidência:* `nodeAuthorizationRequirements` (`filePath := prefix +
"/files/mounts/" + mountID`).
*Solução:* estender a RBAC de arquivo para considerar um prefixo de subpath
opcional na policy, ou orientar o uso de mounts mais granulares.

### E2 🟠 Escalada por delegação de `sudo` em `control-tower/*`

`requireAdmin` não é uma flag de role — exige a capability **`sudo`** no Node
Path `control-tower/<recurso>` (`server.go:484-491`). Delegar `sudo` em
`control-tower/users`, `/policies`, `/roles`, `/access-groups` ou
`/service-accounts` a um operator permite que ele **crie uma policy e a atribua a
si mesmo**, ou **defina o próprio `role=admin`** (`updateUser` protege apenas
contra *remover* o próprio admin, não contra *promover*). Não há separação entre
"gerir objetos de policy" e "o poder que esses objetos conferem": delegar
qualquer gestão do Control Tower equivale a conceder admin.
*Solução:* separar a capability de administração de objetos da capacidade de
concedê-los; impedir que um subject atribua a si mesmo policies/roles ou eleve o
próprio papel; exigir um segundo admin para promoções.

## Agravantes

- **Sem TLS por padrão** — `CONTROL_TOWER_SECURE_COOKIES=false` (achado **C10**)
  e HTTP simples. Sem um proxy HTTPS, um atacante **on-path** captura a senha do
  admin e/ou o cookie de sessão em texto claro, dispensando o brute-force.
- **Segredos em variáveis de ambiente** (achado **C8**) — token, senha e chave de
  criptografia ficam visíveis via `docker inspect`/`/proc/<pid>/environ` para um
  atacante que já tenha leitura no host.
- **Banco do node em texto claro** (achado **P0.3**) — mounts, grants e
  identidades de peers legíveis com acesso ao FS do host; sem paridade com o
  SQLCipher do Control Tower.

## Propriedades positivas (contra o não autenticado)

- Nenhum endpoint devolve bytes ou listagem de arquivo sem autenticação.
- `/docs` e `/openapi.yaml` **exigem token** (sem vazamento de schema da API).
- Erro de login genérico (`"Usuário ou senha inválidos."`) — sem enumeração de
  usuário.
- Cookies `HttpOnly`, `SameSite=Strict`; CSP `default-src 'self'`;
  `X-Frame-Options: DENY`; `nosniff`.
- Token do node nunca chega ao navegador; proxy copia só um allow-list de
  headers.

## Veredito

Para um atacante **remoto e não autenticado**, a API do node e o plano mTLS são
**fortes** (protegidos por segredo de alta entropia e por criptografia de
identidade). O **único vetor prático** é o brute-force do login do Control Tower,
cuja dificuldade depende **exclusivamente** da força da senha do admin, por causa
da ausência de rate-limit.

### Correções que fecham quase toda a exposição remota

1. **P0.2** — rate-limit + lockout + MFA no login
   ([`REMEDIATION.md#p02`](REMEDIATION.md#p02)).
2. **C10** — `SECURE_COOKIES=true` por padrão e HTTPS obrigatório em produção.
3. Reforço operacional: senha de admin forte e única; nunca expor 8080/8443
   fora da rede confiável; **C8** (segredos via `*_FILE`) e **P0.3**
   (cripto do banco do node) para reduzir o impacto de comprometimento de host.

### Matriz resumida

| Vetor | Pré-requisito | Dificuldade | Mitigação |
| --- | --- | --- | --- |
| Node API 8080 | token operacional | Muito alta | segredo de alta entropia (ok) |
| Node mTLS 8443 | chave privada de peer confiável | Muito alta | cripto de identidade (ok) |
| Login 8090 | senha do admin | **Média** | **P0.2** + senha forte |
| Sniffing on-path | posição de rede + sem TLS | Baixa (se sem TLS) | **C10** + HTTPS |
| Leitura de host | comprometimento prévio do host | — | **C8**, **P0.3** |
| Operator → mount inteiro | policy de arquivo num mount | Média (sobre-exposição) | **E1** (subpath na RBAC) |
| Operator → admin | `sudo` de gestão delegado | Baixa (se delegado) | **E2** (separar gestão de concessão) |
