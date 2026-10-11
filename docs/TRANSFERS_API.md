# API de transferências entre nodes

O contrato OpenAPI está em [`openapi/transfers.yaml`](openapi/transfers.yaml). As três rotas públicas usam caminhos lógicos de mounts; IDs de grants nunca aparecem no navegador, em respostas ou nos payloads.

`TRANSFER_MAX_SOURCE_PATHS` limita apenas as raízes recebidas em `source.paths`; o padrão é `1000` e o valor efetivo vem em `max_source_paths` na descoberta e prévia. Pastas podem expandir para mais itens. O corpo JSON continua limitado a 1 MiB.

Uma conta de serviço precisa estar em grupos com os dois nodes permitidos e ter `read` no mount de origem, `create` no mount de destino e `create` (prévia) ou `execute` (criação) em `nodes/{destination}/transfers`. Para `move`, precisa também de `delete` no mount de origem e o grant de envio precisa permitir remoção pós-move.

A confiança confirma a identidade dos nodes; ela não autoriza arquivos. É necessário um grant ativo de envio na origem e um grant ativo de recebimento com escrita no destino. A descoberta retorna `blocked_targets` com `source_grant_missing` e/ou `destination_grant_missing` quando faltam autorizações compatíveis com a seleção. O pareamento dos grants e o payload enviado ao node usam os IDs atuais autenticados dos peers; URLs e permissões continuam usando os IDs cadastrados na Control Tower.

As autorizações de arquivos são gerenciadas na área **Relacionamentos**. Cada cartão mostra as autorizações ativas de envio e recebimento em cada node, respeitando a permissão de listagem. **Abrir relação de confiança** apresenta o estado dos dois lados e os mounts, pastas, direções e permissões de cada autorização. A configuração usa os endpoints existentes de grants, respeita `create`/`update`/`delete` e consulta a identidade autenticada na visão de confiança; vínculos e URLs usam os IDs cadastrados.

A visualização usa badges para direção e permissões, switches para ativar autorizações e um grupo compacto de ações de edição. Conflitos e visibilidade ficam em **Ver detalhes**; a remoção fica no menu com confirmação. **Editar autorização** e **Adicionar** abrem um diálogo separado, mantendo a relação entre os nodes como contexto; cancelar ou fechar descarta a edição e retorna à relação. Na edição, **Ambos / Enviar / Receber** mantém as permissões obrigatórias de cada direção, enquanto **Mais opções** reúne switches adicionais e chips de conflitos permitidos. Alterações no formulário só são aplicadas ao salvar; o switch de ativação da autorização é aplicado diretamente.

Os componentes reutilizáveis de `components/transfers/TransferAccess.tsx` padronizam botões, badges e ícones: Ambos em roxo, Enviar/Leitura em azul, Receber/Escrita em verde, Renomear em âmbar e Remover após mover em rosa. O formulário, os cartões de autorização e a visualização de confiança por node usam a mesma paleta, com variações para tema claro e escuro. A ordem das opções não altera a direção salva ou as permissões.

Na janela de transferência, os destinos de `blocked_targets` continuam selecionáveis com o estado “Configurar acesso”. O botão **Abrir relação de confiança** abre a mesma janela centralizada para os dois nodes selecionados, preservando a seleção de arquivos. Uma nova autorização na origem sugere o mount e a pasta comum da seleção; no destino, o recebimento oferece mounts habilitados com escrita. As autorizações ficam ativas na pasta escolhida. Uma autorização na mesma pasta, mount, peer e direção é atualizada em vez de duplicada. Após salvar ou fechar a janela de confiança, a descoberta é refeita mantendo o node escolhido; prévia e execução continuam bloqueadas até que os dois lados estejam autorizados. A aba Confiança de cada node mantém a visualização e direciona a edição para o relacionamento correspondente.

Um envio com leitura pode autorizar cópia e bloquear movimento quando falta `delete` na origem. Para **Mover**, a janela indica explicitamente a necessidade de permitir a remoção dos arquivos de origem ao mover entre hosts. Quando um único grant ativo cobre toda a seleção com leitura, mas sem remoção, a relação oferece **Revisar permissão para mover**, abrindo esse grant no editor. O switch **Permitir remoção dos arquivos de origem ao mover entre hosts** fica visível fora de **Mais opções** nas direções Enviar e Ambos. Abrir o editor não amplia permissões; a alteração depende de salvar. A validação de autorização continua sendo feita pelo servidor.

**Copiar** e **Mover** mostram **Como ficará no destino**, com nome, caminho no mount e tamanho dos arquivos. Antes de gerar a prévia, a lista estima os nomes das raízes selecionadas dentro da pasta escolhida. Após gerar, usa os caminhos e ações retornados pelo servidor, incluindo conteúdo das pastas, nomes renomeados, sobrescritas, itens existentes mantidos e conflitos. Alterar o destino ou a política de conflito descarta a prévia calculada. A lista avisa quando os itens retornados foram limitados a 500; os totais incluem toda a seleção.

O campo **Pasta de destino** reúne o caminho editável, o botão **Subir** e as subpastas disponíveis em um único controle. A navegação consulta o mesmo caminho usado na transferência, com limite na raiz autorizada. A lista de arquivos não repete o destino no cabeçalho: cada linha mostra apenas o caminho final, com o nome original no tooltip e o resultado ao lado do tamanho. Itens ignorados ou em conflito têm o texto atenuado e riscado.

```sh
base=https://control.example.test
token="$JOLT_SERVICE_TOKEN"

# 1. Descobrir destinos. A resposta não contém grants.
curl -sS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"operation":"copy","source":{"node_id":"node-a","mount_id":"media","paths":["exports/release","exports/readme.txt"]}}' \
  "$base/api/v1/nodes/node-a/transfers/targets"

# 2. Prévia sem efeitos.
payload='{"operation":"copy","source":{"node_id":"node-a","mount_id":"media","paths":["exports/release","exports/readme.txt"]},"destination":{"mount_id":"archive","path":"incoming/2026"},"conflict_policy":"fail","verify_checksum":true}'
curl -sS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d "$payload" "$base/api/v1/nodes/node-b/transfers/plan"

# 3. Criar. Repetir a mesma chave e payload retorna o mesmo job; payload diferente retorna 409 idempotency_conflict.
curl -i -sS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: migration-2026-09-18-001' -d "$payload" \
  "$base/api/v1/nodes/node-b/transfers"

# 4. Acompanhar o Location recebido na criação.
curl -sS -H "Authorization: Bearer $token" \
  "$base/api/v1/nodes/node-b/jobs/JOB_ID"
```

Para `move`, os bytes são copiados e validados por SHA-256 antes da finalização. A origem só é removida por mTLS com a identidade exata do peer, confinada ao grant e condicionada ao ETag de cada arquivo. Cancelamento, falha ou conflito ignorado sem checksum preservam a origem.
