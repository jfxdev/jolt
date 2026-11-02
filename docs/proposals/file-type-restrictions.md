# Proposta — Restrição de acesso por tipo de arquivo

> **Documento irmão:** [`agent-safety.md`](agent-safety.md) (controles de uso, auditoria e resposta para agentes; a camada A daqui é o marco A0 de lá) · **Status:** implementação gradual · **Origem:** uso do Jolt no homelab (agentes de IA somente leitura, compartilhamento de mídia) · **Código lido:** `control/internal/rbac/rbac.go`, `control/internal/httpapi/server.go`, `control/internal/store/store.go`, `node/backend/internal/services/filesystem/*`

> **Andamento:** há proteção por nome no mount, avaliadores compartilhados e filtros internos no node. As regras de policy com `file_types` e `visibility` continuam recusadas pela API. O [plano consolidado](plano-consolidado-seguranca.md) distingue código existente, integração pendente e validação; as seções de proposta abaixo são históricas quando divergirem dele.

## 1. Resumo

Hoje uma policy do Jolt decide por **caminho** e por **capability**. Não existe
como dizer "ninguém lê `*.pem`", "este grupo só vê vídeo" ou "uploads aqui não
podem ser executáveis". Esta proposta adiciona isso em **duas camadas
independentes**, entregáveis separadamente:

| Camada | O que é | Quem configura | Vale para |
| --- | --- | --- | --- |
| **A. Padrões ocultos no mount** | `hidden_patterns` por mount no `node.yaml`; o node trata como inexistente | operador do node | todos, inclusive `admin`, o Control Tower e transferências entre nodes |
| **B. Regras por tipo no RBAC** | campo opcional `file_types` em uma regra de policy; o Control Tower autoriza e o node filtra | admin do Control Tower | por sujeito (usuário, service account, grupo) |

A camada A é pequena e resolve o caso mais urgente (segredos em árvores de
host). A camada B é o recurso completo, e a parte difícil dela é a mesma que o
Jolt já enfrenta com `deny_rule_within_scope`: operações sobre subárvores.

## 2. Motivação

Casos concretos do homelab que o Jolt atual não atende:

| Caso | Necessidade |
| --- | --- |
| Agente de IA inspeciona `/data/docker` de um host | ver nomes e tamanhos de tudo, **nunca** ler `.env`, `acme.json`, `*.pem`, `*.key` |
| Dispositivo da família navega a mídia | só vídeo, legenda e imagem; sem `.nfo`, `.sh`, `.exe` |
| Pasta `inbox` recebe upload do PC | recusar executáveis e scripts |
| Compartilhar uma pasta por link | o link não deve expor arquivos de certos tipos que estejam na pasta |

## 3. Estado na elaboração da proposta (referência histórica)

- **A autorização é só no Control Tower, antes do proxy.** `proxyNode` (`server.go:2768`) monta os requisitos de capability por caminho, autoriza e só então encaminha com o token operacional do node. O node **não conhece policies** (comentário em `rbac.DeniesWithin`).
- **O `deny` só casa por prefixo de caminho.** `ValidPath` (`rbac.go`) aceita `*` apenas como segmento inteiro e `**` apenas como último segmento; `*.pem` e `**/.env` são inválidos. `match()` compara segmento a segmento.
- **Operações de subárvore recusam em bloco.** Busca, uso de disco e ZIP (`subtreeReadResource`, `server.go:2734`) e `copy`/`move`/`delete` de árvore respondem 403 `deny_rule_within_scope` quando há `deny` dentro da raiz pedida, porque o Control Tower não enxerga os arquivos da árvore e o node não conhece a policy.
- **Uma listagem não é filtrada por regras sobre filhos**: um item negado ainda aparece pelo nome no diretório pai.
- **Existe um precedente de nome oculto no node.** `isInternalPartialName` (`service.go:1507`) esconde `.jolt-*.partial`: é aplicado na listagem paginada (`pages.go:58`), na busca (`browse.go:280`, `browse.go:377`), no uso de disco (`disk_usage.go:84`) e na resolução de caminho (`service.go:1472`, que devolve 404). A camada A generaliza esse mecanismo.
- **Policies são persistidas** em `policies` e `policy_rules(policy_id, path, capabilities, position)` (`store.go:218`), lidas por `policyRules` (`store.go:928`) e gravadas por `insertPolicyRules` (`store.go:995`). O projeto já evolui o schema com `ALTER TABLE … ADD COLUMN` tolerante a coluna existente (`store.go:316`).
- **Node e Control Tower são módulos Go separados** (`node/go.mod`, `control/go.mod`); não compartilham código.

> Não li o código de ZIP, manifesto de transferência, compartilhamento público
> nem upload em chunks. As seções 6 e 7 tratam esses pontos como **a confirmar**.

## 4. Camada A — `hidden_patterns` no mount

### 4.1 Configuração

```yaml
mounts:
  - id: inspect-docker
    local_path: /mnt/docker
    mode: read_only
    hidden_patterns:        # opcional; vazio = comportamento atual
      - ".env"
      - "*.pem"
      - "*.key"
      - "acme.json"
```

Padrões de **nome base** (não de caminho), sem `/`, usando `path.Match`
(`*`, `?`, classes). Casam sem diferenciar maiúsculas de minúsculas. Aplicam a
arquivos e a diretórios (ocultar `signing-certs` inteiro vale também).
Validados no carregamento do `node.yaml` (padrão inválido derruba o boot, como os
demais campos).

### 4.2 Semântica

O node passa a tratar um nome oculto **como se não existisse**, no mesmo ponto
em que hoje trata `.jolt-*.partial`:

| Operação | Comportamento |
| --- | --- |
| listagem, busca, uso de disco | entrada omitida; totais de diretório **não** a contam |
| ZIP, manifesto de transferência, cópia de diretório | entrada ignorada (a confirmar) |
| acesso direto (`content`, `metadata`, `download`) | 404, igual a um nome interno |
| `create`, upload, `mkdir`, `rename`/`move` **para** um nome oculto | recusado com `hidden_name` (não se cria o que não se pode ver) |
| `delete` de diretório com filho oculto | o filho permanece; o diretório não esvazia e a operação falha como hoje falha com diretório não vazio |

Efeito colateral aceito e documentado: um diretório que só tem conteúdo oculto
aparece vazio, e remover esse diretório falha.

### 4.3 Por que primeiro

- Mudança local ao node, sem tocar RBAC, store, UI nem OpenAPI de policy.
- Cobre também tráfego que **não passa** pelo Control Tower: pull de peer por mTLS e o próprio token operacional.
- Resolve o caso do agente de IA sem depender da camada B.

### 4.4 Limites

Configuração estática: muda com restart do node e vale igual para todo mundo.
Quem precisa ver o oculto (um admin) não consegue por essa camada; para isso a
camada B ou acesso direto ao host.

## 5. Camada B — regras por tipo no RBAC

### 5.1 Modelo

`rbac.Rule` ganha um campo opcional:

```go
type Rule struct {
    Path         string     `json:"path"`
    Capabilities []string   `json:"capabilities"`
    FileTypes    *FileTypes `json:"file_types,omitempty"`
}

type FileTypes struct {
    Classes    []string `json:"classes,omitempty"`    // video, audio, image, document, archive, executable, secret
    Extensions []string `json:"extensions,omitempty"` // "mkv", "pem" (sem ponto)
    Names      []string `json:"names,omitempty"`      // nome base exato: ".env", "acme.json"
}
```

Sem `file_types`, a regra se comporta exatamente como hoje. As três listas são
somadas (união). Classes são tabelas fixas no código, extensíveis por
`extensions`.

Persistência: nova coluna `file_types TEXT NOT NULL DEFAULT ''` em
`policy_rules` (JSON), pelo mesmo padrão de `ALTER TABLE` de `store.go:316`.

### 5.2 Semântica

O filtro vale **só para arquivos**; diretórios nunca são filtrados por tipo (senão
não dá para navegar até o arquivo permitido).

| Regra | Efeito |
| --- | --- |
| `allow` (capabilities normais) **com** `file_types` | concede as capabilities apenas para arquivos que casam; os demais caem em outras regras |
| `deny` **com** `file_types` | nega, para arquivos que casam, **as capabilities listadas** junto de `deny` (padrão: todas) |
| qualquer regra sem `file_types` | inalterado |

Hoje `deny` ignora as outras capabilities da regra e nega tudo. Com `file_types`
passa a poder negar só algumas, o que permite o caso do agente: `deny` de `read`
em `*.pem` mantendo `list` (nome visível, conteúdo não). Para regras `deny` sem
`file_types` o comportamento antigo é mantido.

Precedência igual à atual: qualquer `deny` que case vence qualquer `allow`; entre
`allow`, vence a regra mais específica por caminho.

Novo ponto de entrada no avaliador:

```go
func EvaluateFile(policies []Policy, path, capability string) Decision
```

`Evaluate` continua para diretórios. O nome base de `path` é o que se testa
contra `FileTypes`.

### 5.3 Onde cada operação é decidida

O Control Tower só consegue decidir sozinho quando **sabe o caminho do arquivo**.
Para tudo que percorre uma árvore, precisa do node.

| Operação | Decisão | Como |
| --- | --- | --- |
| `content`, `metadata`, download, `delete` de um arquivo | Control Tower | `EvaluateFile` sobre o caminho da requisição (alvos já extraídos por `fileTargetsFromRequest`) |
| upload simples e em chunks | Control Tower | nome declarado no início da sessão; capability `create` |
| `rename`/`move`/`copy` de um arquivo | Control Tower | ver 5.5 |
| listagem, busca, uso de disco | **node** | filtro enviado pelo Control Tower (5.4) |
| ZIP, cópia e `delete` de árvore, transferência de diretório, compartilhamento de pasta | **node** | idem (a confirmar nos respectivos serviços) |

### 5.4 Filtro enviado ao node

Para operações de subárvore o Control Tower calcula, a partir das policies do
sujeito, o conjunto de regras **que tocam a raiz pedida**, reescreve os caminhos
relativos à raiz e envia no cabeçalho `X-Jolt-Access-Filter` (JSON compacto em
base64url, com limite de tamanho). O node aplica o mesmo critério de precedência
a cada entrada, **antes de paginar**, e omite o que não é visível.

Pontos de projeto:

- **O node confia no Control Tower** exatamente como já confia no token operacional; o cabeçalho não acrescenta superfície, porque quem consegue forjá-lo já tem o token.
- **Falhar fechado no Control Tower:** toda rota de subárvore passa por uma função única que anexa o filtro; um teste percorre `subtreeReadResource` e `treeMutationResource` e falha se alguma rota sai sem ele.
- **Duas cópias da semântica** (módulos separados). Para não divergirem, um arquivo de casos dourados (`testdata/access-filter-cases.json`) é carregado pelos testes dos dois módulos.
- **Tamanho:** `file_types` limitado na gravação da policy (por exemplo, 64 entradas por regra) para o cabeçalho caber.
- **Interação com `deny_rule_within_scope`:** regras com `file_types` **não** disparam essa recusa, porque o node filtra. Só `deny` por caminho continua disparando.

### 5.5 Renomear, mover e copiar não podem virar contorno

Se negar `read` em `*.pem` deixasse `update`, renomear `a.pem` para `a.txt` e
ler em seguida contornaria a regra. Regras de consistência:

1. `rename`/`move` de um arquivo exige, no **nome de origem**, `update` **e** `read` (a operação revela o conteúdo sob outro nome).
2. O **nome de destino** precisa passar em `create` (e em `update`, se sobrescrever).
3. `copy` exige `read` na origem e `create` no nome de destino.

Resultado: com `allow` só de vídeo em `movies/**`, copiar `a.mkv` para `a.txt` é
recusado no destino; e um arquivo com tipo negado para leitura não pode ser
renomeado para um tipo liberado.

### 5.6 Visibilidade

Campo opcional na regra: `visibility: hidden | visible` (padrão `hidden`).

- `hidden`: o arquivo não aparece em listagem, busca nem ZIP, e o acesso direto responde 404 (não vaza existência). A auditoria registra o motivo real.
- `visible`: aparece na listagem e responde 403 `file_type_not_allowed` no acesso. Útil para o operador entender por que algo está bloqueado.

Uso de disco e totais excluem o que está `hidden` para o sujeito; senão o total
vira canal lateral para inferir a existência e o tamanho do que está oculto.

### 5.7 Uploads

- **Por nome (fase inicial):** a extensão declarada é checada no início da sessão e de novo na publicação.
- **Por conteúdo (opcional, fase posterior):** o node lê os primeiros 512 bytes do parcial na publicação e classifica por `http.DetectContentType` mais uma tabela de assinaturas (ELF, Mach-O, PE, shebang). Se o tipo detectado cai numa classe negada, apaga o parcial e responde `file_type_not_allowed`. Custo: uma leitura curta por upload.

### 5.8 Compartilhamento público e transferências entre nodes

- **Share link:** hoje o link é validado contra o acesso atual do criador (`stops working the moment the creator loses access`). Com tipos, o filtro do **criador** é calculado a cada requisição pública de lista, conteúdo e ZIP. A confirmar em `shares.go`.
- **Transferência node→node:** o pull do peer não carrega policy de usuário. A restrição vem da camada A (mount) ou de um novo campo `exclude` por grant em `transfer_grants`, aplicado ao montar o manifesto e na recepção. A confirmar em `services/transfers`.

### 5.9 UI (Access Center)

- Editor de regra: campo "Tipos de arquivo" com classes, extensões e nomes, e escolha de visibilidade.
- Matriz de acesso efetivo (`ACCESS_CENTER.md`): ganha uma coluna por classe.
- Navegador de arquivos: arquivo `visible` bloqueado aparece com cadeado e mensagem; upload recusado explica o motivo.

### 5.10 API, erros, auditoria, métricas

- OpenAPI (`docs/openapi/control.yaml`): `file_types` e `visibility` no schema de regra; novo código de erro `file_type_not_allowed` (403) e `hidden_name` (422).
- Auditoria: o registro `authorize` ganha `file_type_rule` (id da policy e da regra) e, nas listagens, a contagem de entradas ocultadas.
- Métricas: `jolt_control_file_type_decisions_total{result}` e `jolt_node_hidden_entries_total{mount}`.

## 6. Limites e não objetivos

- **Não é fronteira de segurança contra quem tem escrita.** Extensão e assinatura de início não detectam conteúdo disfarçado, e um arquivo comprimido esconde o que há dentro. A classe `archive` existe para restringir arquivos compactados quando isso importa.
- **Não inspeciona conteúdo de documentos** (nada de varredura de segredos dentro de `.txt`).
- **Não substitui** `deny` por caminho; os dois coexistem.
- **Não filtra por tamanho, data ou dono.**
- **Downgrade fail-open:** uma versão anterior do Control Tower pode ignorar `file_types` e aplicar `allow`/`deny` sem filtro. Um marcador de versão mínima permite que binários que o conheçam recusem um banco incompatível, mas não altera o comportamento de binários antigos. Fixar imagens por digest e permitir rollback somente com backup compatível anterior à ativação da restrição.

## 7. Alternativas consideradas

| Alternativa | Por que não |
| --- | --- |
| Recusar em bloco, como `deny_rule_within_scope` | para regras de tipo quase toda busca, ZIP e uso de disco a partir da raiz de um mount seria recusada; inutilizaria o recurso |
| Filtrar a resposta JSON no proxy do Control Tower | não funciona para streams (ZIP, `content`) e quebra paginação e totais |
| Motor de policy completo no node | duas fontes de verdade; o node passaria a depender do banco de policies |
| Só a camada A | simples e útil, mas igual para todos e estática; não atende "este grupo só vê vídeo" |
| `*.pem` direto no `ValidPath` do caminho | mistura caminho com tipo, torna `match()` e `DeniesWithin` bem mais complexos e não resolve a subárvore |

## 8. Plano de implementação

| Marco | Escopo | Critério de aceite |
| --- | --- | --- |
| **M0** | Camada A: `hidden_patterns`, validação no `node.yaml`, ocultação em listagem, busca, uso de disco, acesso direto e criação; testes ao lado de `browse_test.go`, `pages_test.go`, `disk_usage_test.go` | nome oculto não aparece, responde 404 e não pode ser criado; totais não o contam |
| **M1** | Camada B, decisões por caminho no Control Tower: modelo, `EvaluateFile`, coluna no store, regras de rename/move/copy (5.5), erros e auditoria | `content`, `metadata`, `delete`, upload e rename respeitam allow e deny por tipo; testes de contorno por renomeação |
| **M2** | Filtro para subárvore (5.4): cabeçalho, aplicação no node, casos dourados, teste de cobertura das rotas | listagem, busca, uso de disco e ZIP filtrados e consistentes; nenhuma rota de subárvore sem filtro |
| **M3** | Share links, `exclude` por grant, upload por conteúdo, marcador anti-downgrade | link público respeita o filtro do criador; peer não recebe nem envia tipo excluído |
| **M4** | UI do Access Center, métricas e OpenAPI | editor de regra, matriz e navegador atualizados; `openapi_valid_test` passa |

A ordem e as dependências definitivas são as do [plano consolidado](plano-consolidado-seguranca.md). A numeração M0–M4 acima preserva a proposta original e não representa, por si só, entregas concluídas.

## 9. Riscos

| Risco | Mitigação |
| --- | --- |
| Filtro esquecido numa rota de subárvore expõe o que deveria estar oculto | função única que anexa o filtro e teste de cobertura sobre as listas de rotas |
| Semântica diverge entre os dois módulos | arquivo dourado compartilhado nos testes |
| Ocultação por nome gera diretórios que "não esvaziam" | documentar; mensagem de erro que cita arquivos ocultos |
| Tabela de classes desatualizada | classes são só atalhos; `extensions` e `names` cobrem o resto |
| Desempenho: filtro por entrada em árvores de milhões | casos de correspondência pré-compilados na entrada da requisição; medir com o perfil de aceitação existente (`docs/ACCEPTANCE.md`) |
| Downgrade perde a restrição | marcador verificado por binários compatíveis, imagens fixadas por digest e rollback somente com backup anterior à ativação (seção 6) |

## 10. Questões abertas

1. `hidden_patterns` deve aceitar caminho relativo além de nome base (por exemplo, `signing-certs/*`)? Aumenta o poder e a superfície de erro.
2. Na camada B, `visibility` por regra ou por policy?
3. Classes extensíveis por configuração do Control Tower, ou só no código?
4. A auditoria deve guardar os nomes ocultados em cada listagem, ou só a contagem? Nomes ajudam a depurar e também são o dado que se quer proteger.
5. `exclude` por grant (5.8) pode ser derivado de `hidden_patterns` do mount, evitando um segundo campo?
