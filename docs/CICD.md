# CI/CD e releases datadas

Toda alteração em `main` deve chegar por pull request. A CI valida workflows e
formatação, build/vet/testes Go com race, frontend e Playwright desktop/mobile,
aceitação rápida, `govulncheck`, build das imagens e smoke real entre containers.
O check **PR Gate** exige todos esses validadores.

## Candidata e artefatos

Após merge em `main`, a workflow de release aloca a versão **antes** dos builds,
em data de São Paulo: `YYYY-MM-DD`, depois `.1`, `.2` etc. Não há SemVer nem
prefixo `v`. App, labels OCI, imagens, tag e GitHub Release usam exatamente essa
versão. `/api/v1` e `info.version` dos contratos são independentes.

São construídas imagens `linux/amd64` com provenance/SBOM e tag candidata
`sha-<commit>`. Os gates de publicação executam:

- pull pelos digests e Trivy, bloqueando HIGH/CRITICAL;
- inventário de módulos Go, pacotes Alpine, bibliotecas ligadas e SQLite nativo;
- smoke HTTP real com `--expected-version`;
- snapshot/restore vazio/diagnósticos/operação pelo lifecycle;
- jornada real com dois nodes, proxy HTTPS e Playwright desktop/mobile.

Cada publicação cria uma **prerelease** com:

- `ghcr.io/jfxdev/jolt-node:<versão>`;
- `ghcr.io/jfxdev/jolt-control:<versão>`;
- tag anotada com commit e digests;
- notas e vínculo para a execução;
- artifacts `native-inventory-*` e SBOM/provenance associados às imagens.

A tag nunca é sobrescrita. Uma nova execução do mesmo commit reutiliza a versão
associada, mesmo após mudança de data. Se uma colisão fizer a versão mudar entre
`prepare` e `publish`, a execução falha em vez de publicar app e imagem com
versões divergentes. Uma publicação já concluída não refaz builds.

`govulncheck` não cobre C/SQLCipher. Trivy e o inventário não substituem a triagem
nativa nem os gates externos registrados em [RELEASE_V1.md](RELEASE_V1.md).

## Promoção estável sem rebuild

A prerelease não é automaticamente declarada production-ready. Depois de concluir
os gates de escala, dois hosts, upgrade/rollback e demais evidências, execute
manualmente **Promote dated release** com versão e URL de evidências. O job exige
aprovação do environment `production` e:

1. confirma que a Release é prerelease e resolve a tag anotada;
2. verifica que as tags de imagem ainda apontam para os digests aprovados;
3. faz pull por digest e repete smoke com a versão esperada;
4. marca a mesma Release como estável e anexa a evidência.

Tag, SHA e digests permanecem idênticos; nenhum rebuild ocorre. A primeira
versão não tem automaticamente uma imagem anterior: o gate de upgrade/rollback
precisa ser exercido com o par anterior explicitamente fornecido ao lifecycle
quando essa versão existir.

## Operação e incidentes de publicação

Use **Re-run jobs** para retomar falhas. Não crie, mova ou apague tags de release
manualmente. Para divergência, compare SHA da tag anotada e digests da Release;
a promoção falha fechado se eles não corresponderem ao candidato testado.

Os pacotes precisam permitir pull anônimo, verificado na publicação. Se falhar,
altere uma vez `jolt-node` e `jolt-control` para **Public** em GitHub Packages e
reexecute; tag e digests são reutilizados. Proteção de branch, rulesets,
permissions de actions e reviewers do environment `production` são configuração
externa obrigatória e devem ser auditadas antes da primeira publicação.
