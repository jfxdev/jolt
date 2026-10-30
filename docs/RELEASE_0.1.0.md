# Plano histórico de release — Jolt 0.1.0

> **Documento histórico.** O gate atual é [RELEASE_V1.md](RELEASE_V1.md). A
> distribuição usa exclusivamente versões datadas `YYYY-MM-DD[.N]`, sem SemVer ou
> prefixo `v`; referências abaixo a `0.1.0`, `v0.1.0` e RC SemVer não são o plano
> atual. O diagnóstico continua útil para rastrear correções, mas seus resultados
> não substituem a validação das imagens datadas finais.

Análise realizada em **2026-10-21**, sobre `main` no commit
`1f9bc4c406039826cd9bf83184d9a9258aa945d1`, igual ao `main` remoto consultado.
Este documento preserva o diagnóstico do commit auditado e o plano da época.
A seção seguinte registra as correções preparadas após a análise.

## Correções preparadas neste PR

O diagnóstico original abaixo continua referindo-se ao SHA auditado. Na branch
de correção, foram implementados:

| Item | Correção e evidência |
| --- | --- |
| R01 | Autorização da seleção real e do destino; recusa conservadora de árvores com deny; escopos de grants no proxy legado; parent autorizado quando conflito pode renomear a saída |
| R02 | Operações de filesystem por descritores com no-follow em todos os componentes; remoção/movimento preservam o alvo do symlink; regressão anônima com containers reais |
| R03 | PATCH encaminhado; leitura/mutação de sessão autorizadas pelo destino persistido; listagem filtrada; substituição aguarda o abort; cliente respeita chunk_size |
| R04 | Publicação sem overwrite por operação atômica do kernel em Linux/macOS; regressões com concorrência e criação externa durante streaming |
| R05 | Go 1.26.10 em módulos/imagens/CI; zero vulnerabilidades Go alcançáveis nos scans locais; npm audit com zero alertas após upgrades compatíveis e remoção do CLI shadcn, preservando seu CSS original sob licença MIT |
| R06 | Teto por arquivo, limite de sessões, reserva de bytes pendentes e margem de disco verificada durante escrita; regressões de admissão concorrente, falta de espaço e requisição sem tamanho prévio |
| R08, parcial | Endpoint peer parametrizável, métricas encaminhadas com nomes corretos, exemplo de ambiente sem segredos e opção de não reconciliar ownership dos mounts |
| R09, parcial | Smoke HTTP real control → node incluído na CI, com operator/admin, upload, deny recursivo, ID de sessão, symlink e cota Range |
| Cota pública | Toda requisição de conteúdo/ZIP conta como tentativa, incluindo Range; não se promete isenção de retomada sem ticket de download |

Validação local: suítes Go com race nos dois módulos, vet, scans Go, 32 testes
do frontend, build, npm audit, aceitação rápida e smoke de containers Linux/arm64.
O CSS gerado manteve o mesmo hash da versão auditada após separar o stylesheet
do CLI. Builds locais e CI remota devem ser conferidos no SHA final do PR.

Continuam necessários para a **publicação da release**: qualificação de
linux/amd64, navegador/mobile, dois hosts, escala full, restore/upgrade/rollback,
publicação por tags e digests e inventário de bibliotecas C/SQLCipher. O binding
SQLCipher não foi trocado: não houve mudança de formato do banco ou KDF neste PR.
O scan Go do control registra um advisory em módulo não alcançado; isso não é uma
certificação da camada C embutida.

A autorização dos jobs é concedida na admissão. Alterar a policy de um usuário
bloqueia novas chamadas, mas não cancela retroativamente um job já autorizado.
Para interrupção operacional, cancelar o job ou revogar o grant/peer no node;
as validações existentes de grants e identidade permanecem ativas na transferência.
Conclusão de upload após crash entre rename e remoção da sessão, recuperação de UI
após reload e justiça de banda continuam como investigações delimitadas, sem
promessa de correção nesta rodada.

## Decisão

**Não publicar 0.1.0 a partir do commit atual.** Há recursos suficientes para uma
primeira versão, mas foram reproduzidos problemas de confidencialidade,
autorização, upload e preservação de arquivos. A CI existente passa e não cobre
esses cenários. Além disso, as consultas atuais de dependências já diferem da
CI de 11 de outubro.

A proposta é congelar o escopo funcional atual, corrigir os bloqueadores,
qualificar um `v0.1.0-rc.1` e promover os mesmos artefatos aprovados para
`v0.1.0`. O compromisso da primeira versão deve ser: **administrar arquivos e
copiar/mover entre nodes com autorização efetiva, integridade, retomada e
recuperação documentada**.

## Evidências verificadas

| Verificação | Resultado nesta análise | Limite da evidência |
| --- | --- | --- |
| Árvore inicial | Limpa, branch `main` | Não havia trabalho local a incorporar |
| `main` no GitHub | Mesmo SHA local | Consulta em 2026-10-21 |
| CI desse SHA | Oito jobs concluídos com sucesso | Execução de 2026-10-11; não equivale a auditoria atual |
| Issues e PRs abertos | Nenhum retornado pelas consultas | O backlog de release precisa sair deste plano |
| Tags e GitHub Releases | Listas remotas vazias | Primeira publicação ainda não existe |
| Proteção de `main` / rulesets | Branch sem proteção e lista de rulesets vazia | Recomenda-se proteção antes da publicação |
| Go node e control | `go test -race -count=1 -timeout 10m ./...` passou nos dois módulos | Suítes existentes, antes dos diagnósticos adicionais |
| Análise estática | `go vet ./...` passou nos dois módulos | Não detecta as falhas de autorização reproduzidas |
| Frontend | 31 testes passaram; TypeScript e build passaram | Testes são de funções/transporte injetado; não há suíte de navegador configurada |
| Build frontend | JS principal 791,31 kB; gzip 241,79 kB | Aviso de chunk grande; melhoria posterior, sem bloquear por tamanho isolado |
| Aceitação `quick` | Passou em 13,506 s | Retomada local e diretório, não qualificação integral de dois hosts |
| Imagens Docker | Builds node e control `linux/arm64` passaram | Imagens locais de auditoria; não publicadas; tags temporárias removidas ao final |
| Containers Linux isolados | Health, login, cadastro de node, criação de mount, conteúdo e arquivos estáticos responderam | Smoke via HTTP, sem inspeção visual do navegador nem segundo host físico |
| `govulncheck@v1.1.4` | Falhou nos dois módulos: `GO-2026-6809`, biblioteca padrão Go 1.26.9; scanner indica correção em 1.26.10 | Sinalização do scanner, não demonstração de exploração do Jolt |
| `npm audit` | 10 entradas de pacotes afetados: 9 high, 1 moderate | Inclui cadeia de ferramentas; não são 10 falhas independentes nem prova de exploração em produção |
| Aceitação `full` | Não executada | Exige ao menos 220 GiB livres; host local tinha aproximadamente 144 GiB |

CI consultada: [execução 38176318319](https://github.com/jfxdev/jolt/actions/runs/38176318319).
Tags e releases: [refs de tags](https://api.github.com/repos/jfxdev/jolt/git/matching-refs/tags/)
e [releases](https://github.com/jfxdev/jolt/releases).

Os diagnósticos usaram exclusivamente arquivos e credenciais fictícios. Os
containers, seus volumes anônimos e a rede temporária foram removidos. Testes
temporários que confirmavam o comportamento defeituoso foram removidos da árvore;
as correções deverão acrescentar regressões permanentes com o comportamento seguro.

## Escopo proposto para 0.1.0

| Área | O que já existe | O que precisa ser garantido na release |
| --- | --- | --- |
| Node independente | API Go, mounts, SQLite cifrado, identidade e listener mTLS | Instalação reproduzível e isolamento real dos caminhos autorizados |
| Control Tower | Sessão, usuários, service accounts, grupos, roles, policies e auditoria | Mesma autorização em leitura direta, operações em lote, upload e transferência |
| Gerenciador de arquivos | Listagem, busca, preview, editor, ZIP, diretórios, cópia, movimento, remoção | Arquivos preservados em conflito e operações recursivas respeitando negações |
| Upload | Streaming e sessões retomáveis com offset durável | Caminho navegador → control → node funcionando com conteúdo e permissões restritas |
| Jobs | Persistência, checkpoints, pausa, retomada, cancelamento, retry, SSE e limites de banda | Reinício e indisponibilidade sem publicar arquivo parcial ou perder origem |
| Transferência direta | Pull mTLS, batches, arquivos/pastas, grants, ETags e SHA-256 | Autorizar caminhos efetivos e excluir origem somente depois da validação prevista |
| Relacionamentos | Convites, confiança bilateral, revogação, rotação de identidade/certificados | Revogação persistida nos dois lados e estado correto após atualizar a UI |
| Links públicos | Arquivo/pasta, senha, expiração, cota e revogação | Confinamento ao compartilhamento e cota com semântica consistente |
| Operação | Métricas com token, snapshots offline, diagnósticos e recuperação emergencial | Procedimento ensaiado de instalação, backup, atualização e rollback |

Plataforma inicial proposta: **containers Linux**, com `linux/amd64` e
`linux/arm64` apenas quando cada arquitetura tiver build e smoke aprovados.
A auditoria local exerceu `linux/arm64`, sem certificar `linux/amd64`.
Publicação de binários nativos pode ficar
para depois; CGO/SQLCipher exige uma matriz própria de compilação e bibliotecas.

O frontend e o OpenAPI embutido do node já dizem `0.1.0`; isso não constitui
versionamento da distribuição. Node, control, imagens, UI, commit e contrato da
API precisam de identificação rastreável, com distinção entre versão do produto
e versão do contrato.

## Bloqueadores reproduzidos

### R01 — Autorizar os caminhos reais em operações recursivas e entre nodes

**Prioridade: P0.**

Com permissão sobre `media/**` e `deny` em `media/docs/private/**`, a leitura
direta de `docs/private/secret.txt` retornou 403 e o ZIP de `docs` retornou 403.
Entretanto, cópia, movimento e remoção recursiva de `docs` foram encaminhados
ao node pelo mesmo proxy. Nesses três casos o diagnóstico usa um node simulado:
confirma a passagem indevida pela autorização, não uma remoção em dados reais.

A API lógica de transferência também foi exercitada com `deny` no arquivo
exato `private/secret.txt`: a prévia entre nodes retornou 200 e chamou o plano
do node. `resolveLogicalTransferRequest` autoriza os mounts, sem incorporar
`source.paths` e o caminho efetivo do destino. Policies restritas somente a
uma subpasta também podem ser recusadas indevidamente por essa exigência sobre
a raiz do mount.

**Pontos de entrada:**

- `control/internal/httpapi/server.go`: `proxyNode`, `subtreeReadResource`,
  `nodeAuthorizationRequirements`, `resolveLogicalTransferRequest`,
  `transferMountRequirements` e descoberta de destinos.
- `node/backend/internal/services/jobs/service.go`: execução de cópia/movimento
  e expansão em itens; o node não conhece as policies do usuário do control.

**Entrega:** calcular autorização a partir dos caminhos reais de origem e
destino; aplicar negações a descendentes de operações recursivas e ao resultado
da expansão. Uma implementação conservadora pode recusar o lote quando houver
negação interna, como já ocorre com ZIP/busca. Cobrir API lógica e proxy legado;
não basta alterar a visibilidade dos botões.

**Aceite:** leitura direta, prévia, criação, cópia/movimento/remoção recursivos e
destino com descendente negado falham antes de acessar dados protegidos. Incluir
operator e service account, subpasta permitida, múltiplas raízes, deny em origem
e destino, conflito/rename e retomada após mudança de autorização. Definir e
testar a política de revogação para jobs já enfileirados/em execução.

### R02 — Confinar symlinks ao escopo autorizado e preservar o alvo ao remover

**Prioridade: P0.**

Reprodução com **imagens reais em containers Linux**:

1. Mount contém `public/` e `private/secret.txt` com conteúdo fictício.
2. `public/alias.txt` é symlink para `../private/secret.txt`.
3. Admin compartilha somente a pasta `public`.
4. Um visitante sem sessão solicita o conteúdo de `alias.txt` pelo link público.
5. A resposta é 200 com os bytes de `private/secret.txt`, fora da pasta compartilhada.

Em diagnóstico adicional do serviço de filesystem, remover `public/alias.txt`
apagou o arquivo alvo e deixou o symlink. O resolvedor segue o link antes de
`Delete`. O confinamento ao mount existe, mas é insuficiente para o novo RBAC
por subpasta e para o limite de um compartilhamento público.

**Cadeia:** `publicShareContent` → `resolveSharePath` → `streamShareResource` →
download do node → `filesystem.Open` → `resolve`/`EvalSymlinks`.
Também revisar `filesystem.Delete`, `Move` e os acessos por grants.

**Entrega:** decidir uma semântica única de symlinks. Para a primeira release,
recusar seguir links nos caminhos de acesso a conteúdo autorizado por subpasta
é uma opção conservadora. Se forem suportados, validar o destino canônico contra
o escopo efetivo e usar operações ancoradas em diretório, evitando nova corrida
entre validação e uso. Remover/mover um link deve operar sobre a entrada prevista,
sem apagar/mover silenciosamente o alvo.

**Aceite:** cobrir links no componente final e intermediário, alvo dentro/fora
do mount, dentro/fora da pasta permitida, raiz compartilhada que seja link,
symlink trocado durante a operação, ZIP/busca, grants e destino de escrita.
O cenário anônimo acima precisa falhar sem servir nenhum byte protegido.

### R03 — Completar o fluxo de upload e vincular autorização à sessão persistida

**Prioridade: P0 funcional e de autorização.**

Em container, criar sessão pela Control Tower retornou 201. O primeiro
`PATCH .../files/uploads/{id}` retornou **404 `resource_not_found`**, inclusive
para admin. O mesmo chunk enviado diretamente ao node retornou 200; completar
diretamente e baixar pelo control funcionou. A rota PATCH existe no node e no
cliente, mas falta no mapeamento de requisitos do proxy.

Há uma segunda lacuna: leitura, conclusão e cancelamento por ID não resolvem
o destino persistido antes de autorizar. Um diagnóstico mostrou
`POST .../uploads/{id}/complete?path=public` sendo encaminhado com base nesse
caminho informado pelo cliente. O node usa o destino da sessão, ignorando esse
`path`. Corrigir apenas o PATCH deixaria essa divergência de autorização.

**Pontos:** `nodeAuthorizationRequirements` e `fileTargetsFromRequest` no
control; `node/backend/internal/infra/httpapi/uploads.go`;
`control/frontend/src/lib/api.ts`, `useResumableUploads.ts` e
`resumable-upload.ts`.

**Entrega:** mapear métodos explicitamente e carregar a sessão pelo node para
autorizar seu mount/destino verdadeiro. Revalidar cada leitura/mutação, inclusive
após mudança de policy; filtrar a listagem de sessões por acesso efetivo. Não
confiar em um `?path=` suplementar para autorizar um upload por ID.

**Aceite:** navegador real envia arquivo vazio, pequeno e vários chunks através
do control; interrupção/retomada, cancelamento, sessão expirada, overwrite e
usuário restrito à subpasta funcionam. Outro usuário sem acesso ao destino não
pode inspecionar, completar ou abortar a sessão. Testar revogação durante envio.

### R04 — Tornar `overwrite=false` uma garantia atômica

**Prioridade: P0 de integridade dos dados.**

Diagnóstico determinístico: iniciar `filesystem.Upload(..., overwrite=false)`
com destino ausente; criar esse destino durante a leitura do corpo; concluir o
envio. O upload substituiu o arquivo recém-criado e não retornou conflito.
Há checagem anterior ao envio seguida de `os.Rename`, que pode sobrescrever.
O upload retomável repete uma checagem antes do rename, mas ela também não é uma
publicação atômica sem substituição.

**Pontos:** `node/backend/internal/services/filesystem/service.go` (`Upload`,
`Move`, cópias locais e receivers) e `uploads.go` (`CompleteUpload`).

**Entrega:** primitive de publicação com garantia de não substituição, adequada
às plataformas suportadas. Revisar todos os caminhos que publicam arquivos e o
tratamento de erro da UI. Uma segunda chamada a `Lstat` não fecha a corrida.

**Aceite:** concorrentes sobre o mesmo destino produzem um vencedor e conflito
para os demais, preservando bytes e nome do arquivo vencedor. Repetir com destino
criado por processo externo, streaming, retomável, cópia e transferência remota.
Overwrite explícito continua funcionando com as garantias documentadas.

### R05 — Atualizar e qualificar a cadeia de dependências

**Prioridade: P0 para sinalizações alcançáveis sem tratamento.**

- Os dois scans Go apontaram [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809),
  de `crypto/x509`, no toolchain efetivo 1.26.9, com correção indicada em 1.26.10.
  Atualizar de forma coordenada `toolchain` dos dois módulos, imagens e CI;
  confirmar o advisory e repetir os scans. Não deduzir exploração do Jolt somente
  a partir das trilhas conservadoras exibidas pelo scanner.
- O npm apontou 10 pacotes, incluindo `vite`, `source-map-js`, `shadcn`,
  `@modelcontextprotocol/sdk`, `hono` e a cadeia de glob/AST. `npm explain`
  confirmou SDK MCP como dependência do CLI `shadcn`, e `hono` nessa cadeia.
  O Docker entrega somente o `dist` do frontend, sem o servidor Node/CLI.
  Isso exige separar risco de desenvolvimento/build de código servido ao usuário.
- Há alertas do Vite associados ao servidor de desenvolvimento/editor e outros
  dependentes de Windows; não classificá-los automaticamente como execução remota
  no servidor Go de produção. Atualizar o lockfile e avaliar aplicabilidade.
- Não aplicar cegamente a sugestão automática de downgrade de `shadcn` para
  `1.0.0`. Separar ferramentas do frontend, remover dependências realmente
  desnecessárias e escolher versões corrigidas compatíveis.
- O binding `github.com/mutecomm/go-sqlcipher/v4@v4.4.2` embute SQLite **3.33.0**
  no código C verificado localmente. `govulncheck` não certifica essa camada.
  Inventariar SQLite/SQLCipher/crypto nativos e bibliotecas das imagens, avaliar
  advisories aplicáveis e definir atualização ou aceitação fundamentada.

**Aceite:** nenhum alerta alcançável high/critical sem correção ou análise
documentada de inaplicabilidade; build, migração e restore com o conjunto final
de dependências; SBOM e scan das imagens publicáveis. Escanear novamente o RC,
mesmo que o commit tenha CI verde histórica.

## Condições adicionais para publicar

### R06 — Orçamento de disco e limites de uploads

**P1, necessário para a distribuição self-hosted proposta.** O upload streaming
usa `io.Copy` sem teto de bytes; o retomável limita ao total declarado pelo
cliente, sem teto operacional global. Não foi encontrada checagem de espaço
livre nem reserva para sessões concorrentes. TTL e limpeza existem, mas não
evitam encher o disco antes da expiração.

Definir limite configurável por arquivo, orçamento/sessões concorrentes e margem
de disco; validar na criação e durante escrita, com comportamento explícito em
filesystem cheio, inclusive na publicação e gravação de checkpoints. Expor os
limites efetivos à UI. Testar ENOSPC por injeção ou filesystem temporário limitado,
sem encher o disco do operador. Não depender apenas do proxy HTTP, pois upload
retomável divide o envio e o node também tem API direta.

### R07 — Distribuição, versão e rastreabilidade

**P1, necessário para chamar o resultado de release.** Hoje há apenas
`.github/workflows/ci.yml`, sem evento de tag/publicação; os builds Docker usam
`push: false`. O Compose é orientado a build local, sem imagens versionadas.

Entregar:

- Versão, commit e data de build nos dois binários/API diagnóstica e identificação
  da UI; etiquetas OCI correspondentes.
- Workflow para tags SemVer, incluindo RC; gates concluídos antes da publicação,
  permissões mínimas e actions fixadas por SHA revisado.
- Duas imagens versionadas em registry definido (proposta: GHCR), com digest,
  proveniência e SBOM; smoke por arquitetura anunciada.
- Compose de distribuição que consuma imagens imutáveis, `.env.example` sem
  credenciais reais, instrução para gerar segredos e changelog da primeira versão.
- Registro da correspondência tag → SHA → digests → evidências. A promoção do RC
  deve reutilizar os digests aprovados, sem rebuild silencioso.
- Proteção de `main` e do fluxo de tags, com os checks relevantes exigidos antes
  de promoção. Ajustes no GitHub devem ser feitos na execução do plano.

Não é necessário criar instalador nativo, auto-update ou publicar em múltiplos
registries para 0.1.0.

### R08 — Instalação, rede e configuração operável

**P1.** O smoke confirmou boot de imagens, mas não a experiência de instalar o
produto em dois hosts. O Compose fixa `MTLS_PUBLIC_ENDPOINT` em
`https://jolt-node:8443`, nome interno inadequado para anunciar a outros hosts.
Também não encaminha vários knobs recentes, como tokens de métricas, para os
containers. Certificados/CA precisam de bind mounts correspondentes aos caminhos
configurados; definir só a variável não disponibiliza o arquivo.

Entregar um caminho documentado de instalação em um host e um exemplo de node
adicional, endpoint peer anunciado configurável, API privada/TLS, HTTPS do control,
probes e métricas utilizáveis. Explicar `PUID`/`PGID`, root-squash e que
`JOLT_OWNED_PATHS` faz `chown -R` sobre caminhos configurados; o operador precisa
conseguir optar por preservar ownership já preparado. Não executar esse exemplo
sobre dados existentes durante testes.

Separar liveness de readiness se os probes forem usados para declarar o serviço
pronto para operar: hoje `/health` do control devolve `ok` sem diagnóstico de
dependências. A readiness do control não deve exigir todos os nodes online.
Validar comportamento esperado com banco indisponível, frontend ausente e mount
ausente, mantendo diagnósticos acionáveis.

### R09 — Testes de integração, navegador e escala

**P1.** Acrescentar à CI um fluxo real control → node e testes de navegador dos
caminhos essenciais. Os 31 testes atuais do frontend não passam pelo backend;
por isso o PATCH ausente passou pelo gate existente.

Matriz mínima:

| Fluxo | Cenário de aceite |
| --- | --- |
| Primeiro uso | Instalação limpa, login HTTPS, cadastrar dois nodes, criar mounts e visualizar arquivos |
| Acesso | Admin, operator restrito a subpasta e service account com/sem grupo; deny em descendente |
| Upload | Vazio, pequeno, vários chunks, cancelamento, perda de conexão, retomada e substituição explícita |
| Arquivos | Busca, ZIP, texto e preview; nomes UTF-8, espaços, caracteres de URL; conflito sem perda de arquivo |
| Transferência | Arquivo/pasta/múltiplas raízes; cópia e move nos dois sentidos; conflito e checksum |
| Confiança | Parear, revogar com um lado offline, reportar parcial, tentar novamente; validar persistência e UI após reload |
| Recuperação | Reiniciar durante chunk e após checkpoint; peer/mount ausente; validação explícita de job restaurado |
| Público | Senha errada/rate limit, expiração, revogação do link/criador, cota, Range e symlink fora da pasta |
| UI | Desktop e viewport mobile; dialogs e seleção de destino sem controles escondidos/inacessíveis |

Executar `acceptance-full` em infraestrutura descartável Linux representativa
com ≥220 GiB livres e registrar tamanho, filesystem, arquitetura, duração, hashes
e uso de recursos. O teste atual amplia cópias locais; adicionar ensaio direto
entre **dois nodes/hosts** para qualificar mTLS, rede e interrupção em escala.
O sucesso histórico de `half` em APFS não substitui essa evidência.

Se a release não certificar 10 GiB/100 GiB, declarar explicitamente o escopo
validado e ajustar as promessas de capacidade; não rotular o perfil pendente como
aprovado.

### R10 — Backup, upgrade, rollback e contratos atuais

**P1.** Snapshots offline, lock exclusivo, integridade, manifests e diagnósticos
já existem e seus testes passaram. Falta o ensaio operacional com os artefatos
finais: backup → restauração em diretório vazio → diagnóstico → login e operação
entre nodes preservando identidade, policies, grants e estado dos jobs.

Especificar uma matriz de compatibilidade node/control. Para a primeira versão,
suportar o par da mesma release é suficiente, desde que a limitação seja clara.
Planejar upgrade a partir de um snapshot do commit pré-release, incluindo bancos
plaintext legados somente se forem anunciados como suportados. Alteração de
binding/chave/schema exige testar compatibilidade antes de prometer downgrade.

Rollback seguro deve usar a imagem anterior junto ao backup compatível quando
o schema não suportar retorno; não assumir que trocar a tag do container reverte
o banco. Backups do node incluem chaves privadas e não incluem os arquivos dos
mounts. A chave externa do banco e os dados dos mounts exigem backup separado.

Atualizar documentação corrente:

- `IMPLEMENTATION.md` ainda é de julho e lista upload retomável como pendência;
  `THREAT_MODEL.md` não inclui links públicos na superfície e ainda diz que não
  há rate limit no login. O código já tem lockout persistido.
- `ROADMAP.md` e `REMEDIATION.md` contêm achados históricos. Reclassificar cada
  candidato pelo código atual; não transformar toda a lista antiga em bloqueio.
- README ainda diz Go 1.24 e SQLite no node em trechos que divergem do código.
- Node tem OpenAPI embutido e teste textual das rotas de arquivos; transferências
  têm contrato separado. Falta cobertura completa da API do control e validação
  semântica de schemas/respostas/SSE. Garantir ao menos os fluxos públicos da
  release e exemplos executáveis de autenticação, erros e idempotência.

## Pontos que precisam de decisão ou investigação delimitada

Estes itens não foram todos reproduzidos como exploração; não devem ser
apresentados como falhas confirmadas adicionais.

| Tema | Evidência e próximo passo | Tratamento proposto |
| --- | --- | --- |
| Cota de link e Range | `isResumeRange` isenta qualquer range iniciando depois de zero, sem comprovar download anterior. Teste existente mantém contador zero após repetidas requisições assim | Antes do RC, vincular retomada a um download/ticket contado ou definir e documentar outra semântica sem prometer limite estrito burlável |
| Retomar upload após reload | Hook mantém arquivo/sessão em memória; não foi demonstrada recuperação da UI após fechar a página | Qualificar retomada na mesma página; decidir recuperação com reseleção do arquivo. Não prometer persistência da UI sem teste |
| Substituição de upload | Hook dispara abort e inicia nova sessão sem aguardar a exclusão da anterior | Investigar corrida `upload_in_progress`; corrigir e cobrir no fluxo de conflito de R03 |
| Crash na conclusão de upload | Rename precede remoção da linha da sessão; confirmar retry se o processo parar entre os dois | Incluir em R03/R04; conclusão repetida deve ter resultado recuperável e não exigir reenvio indevido |
| Rotação de token | Duas fases existem; control persiste novo token antes do commit. Há testes do sucesso e do node | Injetar queda/erro entre prepare, persistência e commit e testar retry/recuperação; evitar refatoração especulativa |
| Banco cifrado | Passphrase é reduzida por SHA-256; não há KDF lento específico para esse caminho | Para 0.1.0, instruir chave aleatória de 32 bytes e backup seguro; mudança de KDF requer desenho de migração separado |
| SQLite serializado | `SetMaxOpenConns(1)` nos dois produtos | Medir no acceptance; aumentar pool apenas se houver gargalo demonstrado e testes de locking |
| Limitador de banda | Reserva de tempo com mutex e espera cancelável; não há garantia demonstrada de justiça entre jobs | Medir cancelamento, baixa banda e concorrência; não bloquear só pela escolha do algoritmo |
| Revogação bilateral na UI | Existe tratamento `revoke_incomplete` e reconciliação; não houve ensaio visual nesta rodada | Verificar backend e tela recarregada em R09, sem afirmar que o sintoma histórico continua presente |

## Sequência de execução

| Etapa | Trabalho | Dependência / saída |
| --- | --- | --- |
| 1. Congelar escopo | Registrar estes itens e a matriz suportada; preservar o SHA auditado | Backlog atual e critérios acordados |
| 2. Segurança e dados | R01, R02 e R04, com testes que falham antes da correção | Nenhum escape de escopo nem overwrite involuntário conhecido |
| 3. Upload e dependências | R03, R05 e R06; decidir cota/retomada do link público | Fluxos reais funcionando e scans triados |
| 4. Entrega operável | R07, R08 e contratos/runbooks de R10 | Instalação por imagem versionada, rastreável e reproduzível |
| 5. Qualificação | R09, restore/upgrade/rollback de R10, Linux e arquiteturas anunciadas | `v0.1.0-rc.1` com relatório completo; repetir somente checks afetados por alterações posteriores |
| 6. Promoção | Revisar gates, aprovar o candidato e publicar os digests qualificados | `v0.1.0`, release notes, checksums/digests e limitações conhecidas |

As etapas indicam dependências, não datas prometidas. O caminho crítico é a
autorização por subpasta/symlink, seguido da validação integrada e da infraestrutura
de escala. Estimar calendário depois de fechar a abordagem de R01/R02 e de
reservar o host de aceitação; o estado atual não sustenta uma data confiável.

## Checklist final de go/no-go

- [ ] R01–R05 corrigidos ou, no caso de alertas de dependências, com
  inaplicabilidade fundamentada; regressões permanentes aprovadas.
- [ ] Limites de disco/upload e comportamento em ENOSPC definidos e testados.
- [ ] Node e control do SHA candidato passam build, vet, race, scans e aceitação rápida.
- [ ] Fluxos integrados e de navegador passam com usuários de privilégios diferentes.
- [ ] Compartilhamento público não escapa da pasta; cota e retomada têm contrato coerente.
- [ ] Arquiteturas e escala anunciadas possuem evidência em infraestrutura representativa.
- [ ] Instalação limpa e atualização/restauração/rollback ensaiados com os artefatos finais.
- [ ] Imagens identificadas por digest, SBOM/proveniência e scan; Compose sem build obrigatório.
- [ ] Segredos, endpoints externos, HTTPS, volumes e permissões têm instruções verificadas.
- [ ] Versão/commit visíveis, matriz node/control definida e docs atuais sem promessas não testadas.
- [ ] Nenhum P0 aberto; limitações restantes explícitas nas release notes.
- [ ] Tag aponta para o SHA aprovado e promoção utiliza os mesmos digests do RC.

## Depois da 0.1.0

Tracing distribuído, API de logs recentes, configuração dinâmica, webhooks,
agendamento, sync bidirecional, delta estilo rsync, multi-hop, backup online,
importação de certificado externo, i18n completa e otimização do bundle podem
ficar no backlog posterior. MFA e gestão avançada de sessões merecem avaliação
conforme o perfil de exposição, mas não substituem as correções de autorização
e integridade necessárias nesta primeira versão.
