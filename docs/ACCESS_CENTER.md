# Design — Access Center (página dedicada de autorização)

Proposta de uma página única que centraliza **policies, roles, usuários, service
accounts, access groups e a visão de acesso efetivo**, substituindo os seis
modais isolados de hoje. Responde às lacunas de UX de autorização
([`ROADMAP.md` UX1–UX5](ROADMAP.md#ux-de-autorização-definição-de-policy-e-visibilidade-de-acesso))
e ajuda a mitigar na prática [E1](ROADMAP.md) e [E2](ROADMAP.md).

## Motivação

Hoje a autorização vive em **6 diálogos modais** disparados do cabeçalho
(`Header.tsx`): `UsersDialog`, `ServiceAccountsDialog`, `AccessGroupsDialog`,
`RolesDialog`, `PoliciesDialog`, `AuditDialog`. Cada um isolado, sem rota
própria e sem contexto compartilhado. Consequências:

- Não há como ver, ao mesmo tempo, um subject e o que ele efetivamente pode
  fazer (UX4).
- Definir uma policy exige conhecer a taxonomia de Node Path de cabeça (UX1/UX2).
- Não há verificação do resultado nem explicação de negação (UX5).
- O admin não percebe que delegar `sudo` de gestão equivale a dar admin (E2) nem
  que um mount é concedido por inteiro (E1).

Uma página dedicada com um **explorador de acesso efetivo** no centro resolve a
raiz do problema.

## Arquitetura de informação

Nova rota protegida `/access` (link no cabeçalho, visível a quem tem `sudo` em
`control-tower/*`), dentro do `AppShell`, com abas:

```
/access
├── Visão geral      → Explorador de Acesso Efetivo (padrão)
├── Subjects         → Usuários + Service Accounts (lista unificada)
├── Policies         → CRUD de Node Path policies (com builder)
├── Roles            → CRUD de roles (composição de policies)
├── Access Groups    → nodes + policies reutilizáveis (service accounts)
└── Atividade        → auditoria + "por que negado"
```

Os formulários dos modais atuais são reaproveitados como painéis laterais
(side-panel) dentro de cada aba, preservando a lógica já existente.

## Componente central — Explorador de Acesso Efetivo

O coração da página (implementa UX4). Fluxo:

1. Selecionar um **subject** (usuário ou service account).
2. O sistema resolve o conjunto atribuído (policies diretas + roles + — para
   service account — access groups e seu allow-list de nodes).
3. Renderiza uma **matriz de acesso efetivo**: linhas = Node Paths relevantes
   (nodes/mounts/jobs/transfers/grants/peers/crypto e `control-tower/*`),
   colunas = capabilities; cada célula mostra permitido/negado e **a origem**
   (qual policy/role/group concedeu, com `deny` destacado).

```
┌ Acesso efetivo — usuário: joao (operator) ───────────────────────────┐
│ Node Path                         read list create update delete exec │
│ nodes/nas-home/files/mounts/media  ✓    ✓    ·     ·      ·     ·      │
│   ↳ via policy "leitura-media"                                        │
│ nodes/nas-home/files/mounts/backup ✗(deny) — via policy "bloqueio"    │
│ nodes/nas-home/transfers           ·    ·    ·     ·      ·     ✓      │
│ control-tower/policies             — nenhum acesso —                  │
│                                                                       │
│ ⚠ Este subject NÃO é admin. Nenhum sudo de gestão delegado.          │
└───────────────────────────────────────────────────────────────────────┘
```

Avisos de segurança embutidos (mitigam E1/E2):

- Badge **"admin de fato"** quando o subject tem `sudo` em qualquer
  `control-tower/{users,policies,roles,access-groups,service-accounts}` —
  explicando que isso permite auto-escalada (E2).
- Nota de granularidade: acesso a arquivo é concedido **por mount inteiro**, não
  por subdiretório (E1), exibida ao lado de qualquer linha `files/mounts/*`.
- Destaque de `deny` e da sua precedência global.

## Melhorias de autoria (dentro da aba Policies)

- **Builder de Node Path** (UX1): node (lista real) → tipo de recurso → mount
  (lista real) monta o path; validação inline via `rbac.ValidPath`; aviso quando
  há segmentos além do nível de mount (não terão efeito — E1).
- **Descrições e receitas de capability** (UX2): tooltip por capability +
  receitas ("download: `read`+`list` no mount"; "transferência: `execute` em
  `transfers` + `read` origem + `create` destino").
- **Avisos** (UX3): semântica de `*` (um segmento, sem `**`) e alerta ao marcar
  `deny` ("afeta todos os subjects").

## Aba Atividade — "por que negado" (UX5)

Reutiliza `AuditDecision` (path avaliado, capability, decisão, policy IDs,
correlação) já persistido no backend, com filtro por subject e por resultado
`denied`, para o admin diagnosticar exatamente qual regra bloqueou/permitiu.

## Backend — reuso e adição mínima

Reuso direto dos endpoints existentes sob `/api/v1/control-tower`: `policies`,
`roles`, `users`, `service-accounts`, `access-groups` (+ nested nodes/policies),
`audit`.

**Adição necessária:** avaliação de acesso para um subject **arbitrário** (hoje
`POST /auth/permissions` só avalia o **usuário atual**). Propor:

```
POST /api/v1/control-tower/subjects/{actorType}/{id}/effective-access
  body: { paths: [ ... ] }   # exige sudo em control-tower/authorization
  resp: { paths: { "<path>": { capability: {allowed, denied, policy_ids} } } }
```

Implementável sobre `store.RBACPoliciesForSubject(actorType, id)` +
`rbac.Evaluate`, já presentes. Para service accounts, compor também o allow-list
de nodes do grupo. Auditar a consulta.

## Faseamento

1. **Fase 1 (base):** criar a rota `/access` e mover os 6 modais para abas
   (mesma lógica, sem mudar comportamento). Ganho imediato de navegação.
2. **Fase 2 (visibilidade):** endpoint `effective-access` + Explorador de Acesso
   Efetivo (UX4) e a aba Atividade "por que negado" (UX5).
3. **Fase 3 (autoria):** builder de Node Path (UX1), descrições/receitas (UX2) e
   avisos (UX3) na aba Policies; badges de E1/E2 no Explorador.

## Impacto

- Fecha UX4/UX6/UX7 (visão unificada e acesso efetivo) e cria o lugar natural
  para UX1/UX2/UX3/UX5.
- Torna E1 e E2 **visíveis** ao admin no momento da configuração, reduzindo
  misconfiguration mesmo antes das correções de backend.
- Não altera o modelo RBAC nem a segurança do servidor; é camada de
  apresentação + um endpoint de leitura auditado.

## Arquivos afetados (frontend)

- Novo: `pages/AccessPage.tsx` (+ subcomponentes de aba e o Explorador).
- Ajuste: `App.tsx` (rota `/access`), `Header.tsx` (link, remoção dos modais).
- Reuso: `components/admin/*Dialog.tsx` convertidos em painéis/abas;
  `context/PermissionsContext.tsx` como referência para o cliente de avaliação.
