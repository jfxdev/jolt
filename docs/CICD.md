# CI/CD e releases datadas

Toda alteração em `main` deve chegar por pull request. A CI executa validação de
workflows e formatação, build, vet e testes Go com race, testes e build do
frontend, cenários Playwright desktop/mobile, aceitação rápida, `govulncheck` e
smoke real entre os dois containers. O check **PR Gate** só passa quando todos
os validadores passam.

Após um merge, a execução na `main` cria imagens candidatas amd64 com a tag
`sha-<commit>`, executa o smoke pelos digests publicados e promove esses mesmos
digests para a versão pública. Nenhuma implantação é feita.

## Versões e artefatos

As versões usam a data de São Paulo: `YYYY-MM-DD`, depois `.1`, `.2` e assim
por diante no mesmo dia. Tags são anotadas, nunca sobrescritas, e registram o
commit e os digests publicados. Uma nova execução do mesmo commit reutiliza a
tag já associada a ele; uma execução parcialmente concluída pode continuar sem
gerar outra versão.

Cada publicação entrega:

- `ghcr.io/jfxdev/jolt-node:<versão>`
- `ghcr.io/jfxdev/jolt-control:<versão>`
- uma GitHub Release com notas, commit, digests e vínculo para a execução

As imagens são públicas e atendem `linux/amd64`. Para instalar uma versão,
prefira o digest indicado na release: ele identifica exatamente a imagem testada.

Antes da primeira publicação completa, após os pacotes candidatos terem sido
criados, altere uma vez a visibilidade de `jolt-node` e `jolt-control` para
**Public** em GitHub Packages. O GitHub não oferece uma API para essa alteração.
Se a execução parar na verificação anônima, faça esse ajuste e reexecute-a; a
tag e os digests serão reutilizados.

## Operação

Use **Re-run jobs** na execução de publicação para retomar uma falha. Não crie,
mova nem apague tags de release manualmente. Para investigar uma divergência,
compare o SHA da tag anotada e os digests da release; a publicação interrompe a
promoção se o digest publicado não corresponder ao candidato testado.
