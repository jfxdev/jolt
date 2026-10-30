# Qualificação da primeira versão estável

Estado desta avaliação: **maduro para release candidate; ainda não aprovado para
produção**. A primeira distribuição usa versões datadas `YYYY-MM-DD[.N]`, sem
prefixo `v` e sem SemVer. O diagnóstico histórico de `0.1.0` permanece em
[RELEASE_0.1.0.md](RELEASE_0.1.0.md); esta página é o gate corrente.

## Contrato da v1

Escopo suportado: administração de arquivos, uploads retomáveis, jobs duráveis,
cópia/movimento local e entre nodes, pareamento/grants, RBAC, service accounts,
shares públicos, métricas e recuperação offline.

Plataforma anunciada somente após evidência: Docker Linux/amd64, um Control
Tower single-instance e par node/control da mesma release. Instalações antigas
de node não possuem conversor; comece com estado novo. `/api/v1` e as versões
`info.version` dos documentos OpenAPI são versões de contrato, independentes da
versão datada do aplicativo.

Limitações deliberadas: sem HA, sync bidirecional/contínuo, backup online,
agendador de transferências, tracing, API de logs, configuração mutável, MFA ou
importação de certificado mTLS externo. Retomada de upload na UI exige reseleção
do mesmo arquivo após reload. Alteração de RBAC bloqueia novas chamadas, mas não
cancela retroativamente jobs já admitidos; cancele-os ou revogue grant/peer.

## Gates e evidências

`Pronto` significa código/documentação entregues e verificação correspondente
aprovada. `Pendente` é bloqueio para promoção, mesmo quando o automatismo existe.

| Gate | Evidência exigida | Estado |
| --- | --- | --- |
| Build, vet, testes e race | `make check`, race nos dois módulos, frontend | Pronto nesta working tree; teste ETag repetido 50 vezes com race |
| Contratos | OpenAPI parseável, rotas cobertas e typecheck | Pronto nesta working tree |
| Imagens amd64 | Build final, versão/commit e smoke por digest | Builds locais Linux/amd64 aprovados com versão `integration`; artefatos finais por digest pendentes |
| Smoke integrado | `scripts/container-smoke.py --expected-version VERSION` | Pronto local: oito grupos aprovados nas imagens locais |
| Navegador | `scripts/browser-integration.py --expected-version VERSION`, desktop/mobile | Pronto local: desktop e mobile aprovados (2/2) |
| Recuperação | snapshot → restore vazio → diagnósticos → operação | Pronto local: restore, diagnósticos, operação e upload retomado aprovados |
| Upgrade/rollback | lifecycle com as duas imagens anteriores, mesmo par de release | Fluxos com backup compatível aprovados localmente; release anterior real pendente |
| Escala | `make acceptance-full`, ≥100 GiB, Linux/amd64 representativo | Pronto local em macOS/ARM64 (4.842,680 s); Linux/amd64 representativo pendente |
| Dois hosts | instalação limpa, mTLS, rede, falha e retomada entre hosts físicos | Pendente de infraestrutura |
| Segurança | `govulncheck`, `npm audit`, Trivy HIGH/CRITICAL e triagem | Todos aprovados localmente; zero achados HIGH/CRITICAL no Trivy nas imagens locais |
| Inventário nativo/SBOM | artifact da release; análise C/SQLCipher e pacotes da imagem | Inventário local aprovado; artifact da release final pendente |
| Publicação | prerelease com tag→SHA→digests e evidências | Workflow implementado; nenhuma release criada localmente |
| Promoção | URL de evidências, environment `production`, mesmo tag/SHA/digests, sem rebuild | Workflow implementado; aguarda todos os gates |

Evidências locais de 2026-10-30: host macOS/arm64, Docker 29.9.1, imagens
Linux/amd64 executadas sob emulação e tags locais `jolt-node:smoke` e
`jolt-control:smoke`. O inventário confirmou Go 1.26.10, Alpine 3.22.7,
SQLCipher 4.4.2 e SQLite 3.33.0. Esses resultados qualificam esta working tree,
não os artefatos publicados, e não substituem a execução em Linux/amd64
representativo.

Resultados antigos em [ACCEPTANCE.md](ACCEPTANCE.md) são evidência histórica dos
perfis indicados, não substituem a execução no SHA e nas imagens finais.

## Sequência de release

1. Congelar o SHA candidato e concluir os gates pré-publicação de código,
   testes, contratos e segurança. Manter como pendentes os gates que dependem
   dos artefatos finais ou de infraestrutura representativa.
2. Publicar pelo workflow `Release` uma **prerelease** datada. Ele aloca a versão
   antes dos builds, executa scans, browser integration e lifecycle e só então
   cria a Release com digests e artifact de inventário.
3. Conferir as evidências de scan, inventário, browser e lifecycle dos mesmos
   digests e executar os gates que exigem infra representativa. Anexar nesta
   página ou em evidência versionada: data, SHA, comandos, ambiente, filesystem,
   duração, hashes e links dos runs.
4. Revisar limitações e scans. Uma vulnerabilidade HIGH/CRITICAL corrigível é
   no-go até correção ou análise fundamentada de inaplicabilidade.
5. Aprovar o environment `production` e executar `Promote dated release` com a
   versão e a URL das evidências. A promoção confere tag, digests e versão do app,
   repete smoke e apenas marca a mesma Release como estável.

Não reconstrua para “promover”, não mova tags e não use `latest` como evidência.
Se qualquer artefato mudar, é outro candidato e precisa de nova qualificação.

## Registro a preencher por candidato

```text
Versão:
SHA:
Digest node:
Digest control:
Run da prerelease:
Run de browser/lifecycle:
Host/filesystem do acceptance-full:
Ensaio entre dois hosts:
Scans e inventário:
Upgrade/rollback:
Aprovadores e data:
Pendências aceitas:
```

## Decisão de maturidade

Há uma base funcional e controles de engenharia suficientes para um RC: estado
durável/cifrado, autorização server-side, mTLS, limites de upload/disco,
testes de falhas, recuperação offline, imagens rastreáveis e promoção imutável.
Isso **não** é evidência suficiente para declarar a v1 production-ready enquanto
a qualificação dos artefatos publicados, o upgrade/rollback desde uma release
anterior, a escala e o ensaio entre dois hosts estiverem pendentes. A decisão
final deve ser tomada sobre os artefatos e resultados acima,
não sobre a quantidade de funcionalidades ou o histórico de testes unitários.
