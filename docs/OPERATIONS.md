# Operação e observabilidade

## Credenciais de agentes

Contas `agent` permitem somente leitura, mesmo quando uma policy concede
escrita. Suas chaves expiram em até 30 dias; o tipo é escolhido na criação e
não pode ser alterado. Contas existentes permanecem `automation`.

Cada chave tem limites configuráveis de taxa, pico, concorrência, bytes por
resposta e bytes por dia UTC. Os padrões são 60 requisições/minuto, pico de 10,
duas requisições simultâneas, 16 MiB por resposta e 1 GiB por dia. O Control
Tower reserva a cota no banco cifrado antes de enviar a resposta. Em caso de
falha abrupta, reservas não devolvidas permanecem debitadas naquele dia.
Revogação, desativação e expiração interrompem as requisições em andamento.
Alterar os limites de uma chave também interrompe suas requisições ativas;
os novos limites entram em vigor na próxima autenticação.

Opcionalmente, uma credencial pode restringir `read_media_types` a tipos MIME
exatos, por exemplo `text/plain` e `application/pdf`. A lista vazia permite
qualquer formato. A classificação usa o `Content-Type` fornecido pelo node,
que pode depender da extensão e não garante o conteúdo real: há falsos
positivos e negativos. Enquanto a restrição estiver ativa, downloads ZIP e
respostas com múltiplas faixas são recusados, pois não permitem verificar com
segurança o tipo de cada conteúdo. Uma única faixa continua disponível.

Uma lista opcional de CIDRs restringe a origem de cada chave. Por padrão é usado
o endereço da conexão. Configure `CONTROL_TOWER_TRUSTED_PROXIES` com CIDRs de
proxies que substituam e validem `X-Forwarded-For`; cabeçalhos enviados por
outras origens são ignorados. Sem CIDRs na chave, qualquer origem é aceita.

O botão **Desativar agentes** desativa todas as contas de agente e interrompe
suas requisições. A reativação é individual. Para voltar a uma versão antiga do
Control Tower, use um backup compatível anterior à criação das contas: versões
antigas não conhecem nem aplicam esses limites.

A auditoria de requisições de agentes registra a chave, IP, status, faixa,
bytes enviados, duração e interrupções, sem registrar o conteúdo lido. A busca
não registra a consulta por padrão; `CONTROL_TOWER_AUDIT_SEARCH_QUERY=true`
habilita o registro truncado, que pode conter dados sensíveis. A retenção
`CONTROL_TOWER_AUDIT_RETENTION_DAYS` começa em `0` (manter tudo). Valores
positivos apagam eventos anteriores ao prazo no ciclo de limpeza.

Buscas de agentes são limitadas a 200 resultados, 10 mil entradas examinadas,
profundidade 16 e 10 segundos. O retorno informa quando a busca ficou parcial.
O Control Tower exige que o node anuncie e confirme suporte a esses limites;
atualize nodes antigos antes de usar busca por agentes. Chamadas bloqueadas do
filesystem podem demorar a retornar mesmo após o prazo da busca.

Listagens e buscas de agentes incluem `display_name`, com controles e marcas
bidirecionais substituídos por identificadores visíveis e nomes longos
truncados. Exiba esse campo; use `path` e `name` originais para navegar ou abrir
arquivos. Os campos originais podem conter caracteres não seguros para exibição
e não devem ser interpretados como instruções.

Antes de servir conteúdo a agentes, o node examina os primeiros 64 KiB de cada
arquivo, mesmo em leituras com `Range` e em ZIPs. Um achado é recusado com
`secret_detected`; a auditoria registra a categoria, sem o valor encontrado.
Atualize os nodes antes de habilitar leituras de agentes: versões sem essa
proteção são recusadas. A varredura é uma camada adicional, com falsos positivos
e negativos; ela não identifica necessariamente segredos após o prefixo,
ofuscados ou dentro de arquivos compactados. Mudanças externas durante a
leitura também podem ocorrer depois da verificação.

Policies temporárias podem ser concedidas a usuários e contas de serviço por
até uma hora; a sugestão é de 15 minutos. Elas começam imediatamente, expiram
automaticamente e podem ser removidas antes do prazo. A auditoria registra o
responsável, o sujeito, a policy e o vencimento. A concessão temporária não
remove outra concessão permanente ou herdada da mesma policy; agentes mantêm o
limite de somente leitura. Permissões são reavaliadas em novas requisições,
sem encerrar automaticamente uma transferência que já estava em andamento.

Um coletor autorizado pode consultar `/api/v1/control-tower/audit?format=ndjson&after=0`
e continuar pelo cursor `X-Jolt-Next-After`. Guarde a exportação fora do banco
se for necessário preservá-la após restauração ou término da retenção. As
métricas de agentes incluem requisições, bytes e limites; os rótulos por conta
ficam limitados a 1024 contas distintas por processo.

Opcionalmente, `CONTROL_TOWER_AUDIT_HASH_CHAIN=true` inicia uma cadeia SHA-256
para eventos novos; o histórico anterior não é retroativamente autenticado.
Depois de ativada, a cadeia continua ativa mesmo se a variável voltar a ser
`false`, inclusive nas operações de recuperação. Cada evento inclui
`chain_data` e `chain_hash`. A exportação NDJSON informa o último checkpoint nos
cabeçalhos `X-Jolt-Checkpoint-ID`, `X-Jolt-Checkpoint-Hash` e
`X-Jolt-Checkpoint-Reason`; a retenção remove apenas prefixos contíguos e
registra o hash do último evento removido.

Guarde regularmente os checkpoints e exportações em um destino externo
protegido. Um hash guardado apenas no mesmo banco não impede que alguém com
acesso ao banco reescreva tanto os eventos quanto a cadeia. Para verificar uma
exportação contínua a partir de um checkpoint previamente guardado:

```sh
python3 scripts/verify-audit-ndjson.py audit.ndjson --after-id CHECKPOINT_ID --previous-hash CHECKPOINT_HASH
```

O verificador compara os dados de cada evento, a sequência e os hashes. Exporte
eventos depois do ID do checkpoint e preserve o hash final para a próxima página.
O checkpoint de ativação usa 64 zeros como hash e indica o último evento que
antecede a cadeia. A configuração e a versão do binário devem ser preservadas
nas rotinas de backup e recuperação.

Arquivos de isca declarados em `canary_paths` geram evento de auditoria
`canary` e incrementam `jolt_control_canary_total`. Um alerta Prometheus pode
usar `increase(jolt_control_canary_total[5m]) > 0`.

Ao retomar, tentar novamente ou resolver conflitos de jobs locais pelo Control
Tower, as permissões atuais para os caminhos do job são verificadas novamente.
A retomada manual de jobs entre nodes é recusada enquanto não houver contexto
de autorização verificável nos dois lados. Essa recusa ainda não cobre a
continuidade automática de jobs existentes: para exigir revogação imediata de
permissões em transferências, interrompa esses jobs e desative os grants até
que a autorização renovável entre nodes esteja disponível.

O Jolt expõe logs estruturados no stdout dos containers, probes HTTP e métricas
Prometheus. Não há tracing distribuído, API de logs, notificações nativas ou HA.
Prometheus/Grafana/Alertmanager e o agendador de backups são componentes externos.

## Cópias locais protegidas

`CONTROL_TOWER_SIGNED_LOCAL_JOBS=true` faz o Control Tower criar as cópias de
`POST …/mounts/{id}/files/copy` como jobs vinculados à autorização do chamador.
A opção vem desativada, exige a chave de assinatura (`CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_*`)
e cobre cópia local, além de delete e move de pastas, que passam a exigir um plano.
Cópias e moves entre nodes também usam autorização renovável (veja abaixo).

**Antes de ativar**

- Atualize o node para uma versão que anuncie `signed_local_copy_execution_v1`
  e configure as chaves públicas em `authorization_public_keys`. Sem a
  capacidade, a criação responde `signed_job_unavailable` (503) e nada é criado.
- Confira o relógio do Control Tower e dos nodes: o lease dura até 30 segundos.
- Planeje o rollback antes: criar a primeira cópia protegida eleva a versão mínima
  de segurança gravada no banco, e binários antigos não a verificam. Fixe as imagens
  por digest e só volte a um backup anterior à primeira cópia protegida.

**Como funciona**

- O Control Tower renova a autorização de cada job ativo a cada 10 segundos,
  revalidando credencial, grupos e policies. Se um desses falhar, nenhum lease novo
  é emitido e o node interrompe a cópia em até 30 segundos, mantendo o progresso.
- O job interrompido fica em `waiting_validation` com fase `waiting_authorization`
  e retoma sozinho quando chega uma autorização mais nova. Jobs interrompidos por
  reinício do node ou pausados por um operador pedem retomada explícita.
- Entradas que o filtro oculta não são copiadas. O job termina como
  `completed_with_warnings` e informa apenas quantas foram omitidas.
- A política de conflito `ask` é recusada nessas cópias. Um job `failed` não é mais
  renovado: crie outra cópia em vez de tentar de novo.

**Apagar ou mover uma pasta**

Com a opção ligada, `DELETE …/files?recursive=true` e `POST …/files/move` de uma
pasta respondem `409 plan_required`. O fluxo é: `POST …/files/destructive-plans`
(o node conta arquivos, pastas e bytes e devolve um token de uso único válido por
5 minutos) e depois `POST …/destructive-plans/{planID}/confirm` com uma
`Idempotency-Key`. Arquivos e a remoção de pasta vazia mantêm a rota direta.

- A confirmação cria um job que aguarda a primeira autorização e, antes de alterar
  qualquer coisa, varre a pasta de novo. Se algo mudou desde o plano (inclusive um
  arquivo editado ou recriado, pois a identidade inclui datas), o job falha com
  `tree_changed` e nada é tocado: gere um novo plano.
- Uma remoção interrompida no meio, por cancelamento ou perda da autorização, **não
  é retomada nem desfeita**: a pasta parcial já não confere com o plano. Confira o
  que restou e planeje de novo.
- Mover para um destino existente exige `overwrite`; o plano fixa o conteúdo do
  destino e a confirmação falha se ele mudar.
- Se o usuário perdeu a permissão entre o plano e a confirmação, a confirmação
  responde 403 e o job é cancelado. Ações na auditoria: `plan_delete`,
  `plan_move`, `confirm_delete`, `confirm_move`.
- A varredura lê o conteúdo de todos os arquivos para calcular o digest: em pastas
  grandes, planejar e confirmar levam o tempo de uma leitura completa.
- Mover entre nodes (transferência com `operation: move`, pasta ou arquivo) também exige
  plano e confirmação: veja "Copiar e mover entre nodes".

**Copiar e mover entre nodes**

`POST /api/v1/nodes/{destino}/transfers` com `operation: copy` cria um job executado
pelo node de **destino**, sob a mesma autorização renovável. O destino busca o
manifesto do node de origem pelo canal mTLS e planeja só o que a policy do usuário
deixa listar e ler; o que ela esconde fica de fora e aparece apenas como contagem
(`completed_with_warnings`). Um destino que a policy não deixa escrever recusa o
plano inteiro. A cada item, e de novo logo antes de publicar um arquivo, o destino
reavalia a policy com o lease vigente.

- **Requisitos:** o node de destino precisa anunciar `signed_transfer_pull_v1`
  (além das capacidades de cópia protegida) e ter as chaves públicas em
  `authorization_public_keys`. O ID registrado de cada node no Control Tower precisa
  ser o que o node informa; se divergirem, a criação responde `node_identity_mismatch`
  (a policy nomeia os nodes pelo ID registrado).
- **Mover:** `operation: move` primeiro pede a prévia (`…/transfers/plan`), que calcula
  o plano sob a policy do usuário e devolve `move_plan` com um token de uso único válido
  por 5 minutos. Criar o move exige devolver esse `move_plan`; sem ele, `422 plan_required`.
  O plano guarda um digest do ator, dos dois lados, da policy e de cada entrada (tamanho,
  data, checksum e ação): se qualquer coisa mudou entre a prévia e a confirmação, a
  resposta é `409 tree_changed` e nada é consumido. Um move **recusa** (`409
  move_incomplete`) uma seleção com alguma entrada oculta para o usuário, porque a origem
  é apagada depois; uma cópia só conta as omissões. O usuário precisa de `read`, `update`
  e `delete` na origem, e a limpeza apaga item a item, com ETag, só o que o lease deixa
  apagar; sem `delete` a origem é preservada e o job falha depois de copiar. Uma cópia
  verificada que não pôde ser limpa deixa a origem intacta: confira os dois lados.
- **Pull direto bloqueado:** com a opção ligada, `POST …/transfers/pull`,
  `…/pull/directory` e `…/pull/batch` respondem `409 use_logical_transfer`; as
  prévias (`…/plan`) continuam.
- **O que o node de origem vê:** ele serve o manifesto completo ao destino, pelo
  grant, sem conhecer o usuário. O filtro por policy é aplicado no destino, então os
  nomes ocultos trafegam entre os dois nodes, mas nunca chegam ao usuário nem ao
  job. O grant segue sendo o limite que a origem impõe.
- **A prévia do plano** (`…/transfers/plan`) também roda sob a policy do usuário: o
  destino planeja com um lease descartável, lista só o que o usuário pode ver e
  informa `sources_omitted` (a interface avisa quantas entradas não serão copiadas).
  Sem a capacidade no destino a prévia responde 409, sem voltar à prévia sem filtro.
- Cópia interrompida por perda da autorização fica em `waiting_authorization` e
  retoma sozinha; o que já foi copiado permanece.

**O que observar**

- Auditoria: `bind_job_authorization`, `confirm_job_authorization`,
  `finish_job_authorization` e `resolve_expired_job_authorization`.
- Logs do Control Tower: `renew signed job authorization` com `node_id` e `job_id`
  indica uma renovação que falhou; várias seguidas antecedem a interrupção do job.
- Eventos do job no node: `job.sources_omitted` e `job.waiting_authorization`.
- Jobs presos em `waiting_authorization` por muito tempo: credencial revogada,
  node fora do ar ou policy removida. Cancele-os se não forem mais necessários.

**Reverter**

Desligar a opção e reiniciar o Control Tower interrompe as renovações: as cópias
em andamento páram em até 30 segundos e ficam aguardando. Elas não são retomadas
por outro caminho; cancele-as. Cópias criadas depois voltam a ser comuns, sem
filtro por policy. Este recurso ainda não foi validado sob carga nem entre hosts.

## Políticas por tipo de arquivo

Uma regra de policy pode trazer `file_types` (classes, extensões, nomes exatos) e
`visibility` (`hidden`, o padrão, ou `visible`). A API só as aceita com
`CONTROL_TOWER_TYPED_POLICIES=true`. A opção vem desativada e o Control Tower **não
inicia** com ela se `CONTROL_TOWER_SIGNED_LOCAL_READS`, `CONTROL_TOWER_SIGNED_UPLOADS`
e `CONTROL_TOWER_SIGNED_LOCAL_JOBS` não estiverem ligados, nem sem a chave de
assinatura: cada rota que alcança um arquivo precisa levar o contexto assinado, ou uma
regra tipada deixaria passar o que esconde. Os nodes precisam anunciar as capacidades
dos modos assinados; sem elas a operação falha fechada, não volta ao caminho sem filtro.

**Editor e navegador**

- Em Access → Policies cada regra tem “Restringir por tipo”: classes (vídeo, áudio,
  imagem, documento, compactado, executável, segredo), extensões sem ponto, nomes exatos
  e “Quando bloqueado” (ocultar ou mostrar bloqueado). O editor valida os mesmos limites
  do servidor e descreve a regra em uma frase. Editar uma policy preserva os campos
  tipados; antes da correção eles se perdiam no salvamento.
- O controle fica desativado quando o Control Tower não foi iniciado com
  `CONTROL_TOWER_TYPED_POLICIES`; `GET /api/v1/control-tower/about` informa isso em
  `features.typed_policies`.
- No navegador de arquivos, uma entrada `visible` negada aparece com cadeado, sem
  abrir, baixar, selecionar nem menu de ações. As `hidden` não aparecem.

**Acesso efetivo**

- Access → Acesso efetivo mostra, para uma identidade (usuário ou conta de serviço) e uma
  lista de caminhos, o que ela pode fazer em cada capability. Informe o tipo da entrada:
  uma regra por tipo trata arquivo e pasta de forma diferente (`key.pem` como arquivo é
  negado; uma pasta com esse nome continua navegável).
- Cada célula é *permitido*, *negado* (sem concessão ou negação por caminho), *oculto*
  (regra por tipo; o arquivo some e o acesso direto responde 404) ou *bloqueado* (aparece,
  mas responde 403). Passar o mouse mostra as policies envolvidas.
- Quem tem a role `admin` aparece como “administrador de fato”; uma conta de serviço em
  node fora dos seus grupos de acesso ativos é negada. Exige `sudo` em
  `control-tower/policies`, aceita até 50 caminhos por consulta e é auditada
  (`effective_access`).
- A consulta usa o mesmo avaliador do node, então é a resposta exata para o tipo informado.
  Não substitui um teste com a conta real quando houver teto de agente ou CIDR.

**Semântica**

- O **node** decide o tipo real de cada entrada. Negação tipada vale só para arquivos;
  permissão tipada vale para os arquivos que casam e mantém as pastas navegáveis.
  Uma negação tipada pode listar as capacidades que retira (`["deny","read"]` esconde o
  conteúdo mas mantém a listagem); uma negação por caminho continua sozinha.
- Onde o node filtra por entrada (leituras, uploads, cópia local e entre nodes, delete e
  move de pasta com plano, copia e move entre nodes, shares e as prévias), o Control Tower só recusa o que
  nenhum tipo de entrada poderia fazer e deixa o resto para o node, que responde 404
  para o escondido (`hidden`) ou 403 (`visible`).
- Onde o node **não** filtra (delete e move direto de um arquivo), o Control Tower exige
  que todo tipo possível seja permitido. Pastas nessas rotas já exigem plano.
- Uma **negação por caminho** dentro de uma pasta continua recusando a operação inteira
  sobre ela (`deny_rule_within_scope`); as negações tipadas não.
- Desligar a opção não apaga as regras: uma negação tipada já gravada volta a negar
  tudo no caminho, como antes da opção existir.

**Casos dourados**

Quatro conjuntos travam o comportamento. Mudar uma semântica exige mudar o caso de propósito:

- `testdata/filetype-selectors.json` e `testdata/filetype-context-cases.json`, carregados pelos testes dos dois módulos: extensão em maiúsculas, ponto final, espaços, nome só com ponto, dupla extensão, homógrafos, `\`, NUL, `.`/`..`, barra final, mount em maiúsculas.
- `testdata/typed-operation-cases.json`, executado pelo Control Tower contra um node de mentira (`TestTypedOperationGoldenCases`): leitura, listagem, busca, ZIP, uso de disco, envio, criação de pasta, apagar, mover e copiar com nomes disfarçados (`./`, `//`, `..`, `%2E`, `%252E`, parâmetro repetido). O que importa: ou recusa aqui, ou adia ao node numa cópia protegida, ou chega ao node com contexto assinado. Nada chega sem assinatura quando uma regra tipada cobre o caminho, exceto o que o Control Tower decidiu sozinho.
- O mesmo arquivo traz perfis de node antigos: sem nenhuma capacidade, sem leitura de árvore, sem confirmação do filtro (`X-Jolt-Access-Applied`) e com a consulta de capacidades falhando. Todos falham fechados e nunca entregam a resposta do node.
- `TestSignedReadRefusesEveryTamperedEnvelope` (node): 34 variações de um envelope válido (assinatura, payload, regra de negação removida, validade estendida, chave desconhecida, versão, JSON duplicado ou com campo extra, cabeçalho duplicado, replay em outro arquivo, operação, mount, node ou raiz) devem ser recusadas sem servir o arquivo nem responder como se o filtro tivesse sido aplicado. `TestPlanCopyFilteredDestinationNamesCannotEvadeATypeDenial` faz o mesmo para o nome do destino de uma cópia.

Cada conjunto foi conferido por mutação: enfraquecer a verificação de assinatura, validade, duração máxima, campos desconhecidos, chaves duplicadas, as checagens de capacidade ou a confirmação do node faz algum caso falhar.

**O que ainda não existe**

- Não há conferência automática contra o que cada credencial de agente permite (teto de
  capabilities por token, CIDR): a matriz abaixo não os considera.
- Não houve validação sob carga nem entre hosts. Trate o recurso como experimental.

## Lixeira

Com `trash: {enabled: true, retention_days: 30}` em um mount `read_write` do `node.yaml` (ver
[`NODE_YAML.md`](NODE_YAML.md)), apagar um arquivo ou uma pasta (`recursive`) **move** a entrada para
`.jolt-trash` dentro do mount, com um único `rename` atômico no mesmo filesystem, em vez de remover. O
node guarda um registro no estado cifrado e a apaga sozinho depois da retenção (padrão 30 dias, até 365;
varredura a cada dez minutos).

**Uso**

- No navegador de arquivos, o botão **Lixeira** lista o que foi apagado no mount, com a pasta de origem e
  o tempo restante. **Restaurar** devolve a entrada ao caminho original e **nunca sobrescreve**: recusa se
  o nome foi ocupado (409), se a pasta onde ela estava não existe mais (404) ou se o nome passou a ser
  oculto por configuração (422). **Apagar de vez** remove na hora, depois de uma confirmação.
- A confirmação de apagar diz se o item vai para a lixeira e por quantos dias, ou que a ação não pode ser
  desfeita. Uma pasta vazia apagada sem `recursive` é removida de verdade; apagada com `recursive`, como faz a interface, vai para a lixeira.
- Quem pode ver, restaurar ou apagar de vez é decidido pelo **caminho que a entrada tinha**, com as mesmas
  regras do arquivo: `read` para listar, `create` para restaurar, `delete` para apagar de vez, inclusive
  regras por tipo. Uma entrada que o chamador não poderia ler responde como se não existisse. Agentes não
  acessam a lixeira. Uma concessão de `delete` que exige aprovação humana é recusada ao apagar de vez.

**Garantias e limites**

- A pasta é interna: não aparece em listagens, buscas, ZIPs, uso de disco nem em leitura direta pelo nome.
- Um registro é gravado **antes** do `rename` e removido **depois** que a entrada some. Após uma queda, o
  node termina ou desfaz o passo interrompido na inicialização. Um mount que não pode ser lido (disco
  desmontado) mantém seus registros intactos até voltar.
- Uma entrada que o `rename` não consegue mover (outro filesystem, como um mount point aninhado) faz o
  delete **falhar**; nunca apaga de verdade em silêncio. Uma pasta `.jolt-trash` que não seja um diretório
  comum (um link plantado no host) também faz falhar, sem seguir o link.
- O estado cifrado do node sobe para a versão 7 ao gravar o primeiro registro; um node anterior se recusa a
  abri-lo. Faça rollback só com backup anterior à ativação. O Control Tower exige a capacidade `trash_v1`
  do node e responde 409 `node_upgrade_required` sem ela.
- A lixeira ocupa disco até a retenção, e um arquivo com hardlinks não libera espaço até lá. **Não é
  backup**: quem acessa o host a vê e a esvazia, e o que foi apagado de vez ou passou da retenção se foi.
- Move entre nodes e a limpeza da origem depois de uma cópia também passam pelo delete do node e, portanto,
  pela lixeira da origem.
- `trash.max_bytes` (opcional) limita o que a lixeira guarda. Passar do teto **recusa o delete**
  (507 `trash_full`, e o job falha dizendo quanto caberia) em vez de apagar algo mais cedo: a retenção
  prometida vale mesmo cheia, e quem precisa de espaço apaga de vez ou restaura. Uma pasta conta os bytes
  dos arquivos dentro dela; o cálculo percorre a árvore uma vez ao apagar.
- Métricas por mount e dois alertas de referência (perto do teto e item além da retenção) estão na
  seção de métricas e na de alertas. Sem teto, a lixeira só é limitada pelo disco.

## Aprovação humana

Uma regra de policy pode conceder `delete` ou `update` **somente com a aprovação de uma pessoa**
(`needs_approval: ["delete"]`, na interface “Exigir aprovação para…”). A opção vem desativada:
`CONTROL_TOWER_APPROVALS=true` liga as aprovações e `CONTROL_TOWER_APPROVAL_WEBHOOK_URL`
(https, sem credenciais; `http` só em loopback) avisa um webhook de cada pedido novo.

**Como funciona**

- Pedido: apagar, mover ou copiar arquivos pela API de arquivos (corpo JSON de até 16 KiB) em um
  caminho cuja concessão exige aprovação não executa. O Control Tower guarda o pedido exatamente como
  veio e responde `202` com `pending_operation_id` e a validade de **cinco minutos**. Um pedido idêntico
  ainda aguardando devolve o mesmo id; cada identidade tem até 20 pedidos abertos.
- Decisão: em Access → Aprovações (ou `POST …/pending-operations/{id}/approve|reject`), uma **pessoa**
  autenticada com `sudo` em `control-tower/approvals`. Chave de API, conta de serviço e agente não
  decidem. Quem tem a role `admin` decide sem regra.
- Execução: ao aprovar, o Control Tower **reexecuta o pedido guardado como o aprovador**, com as
  permissões atuais dele; só os requisitos aprovados passam pela porta da aprovação. Antes disso confere
  de novo se quem pediu ainda pode (conta ativa, policies atuais, node no grupo). Aprovar não dá mais
  poder a ninguém: se o aprovador não pode apagar aquilo, o pedido falha e nada muda.
- Aprovar o próprio pedido exige confirmação explícita (`acknowledge_self_approval`).
- Repetir a aprovação devolve o resultado guardado (`replayed: true`) e não executa de novo. A cópia
  reexecutada usa a chave `approval-<id>`, então nem um nó que cria jobs por chave cria dois.
- Se o Control Tower reiniciar durante a execução, o pedido vira `indeterminate`: não se sabe se chegou
  ao node, e ele **nunca** é reexecutado sozinho.
- Cada passo (pedido, aprovação, rejeição, execução) vai para a auditoria. O webhook leva só o tipo da
  operação, node, mount, quem pediu e a validade: nunca caminhos, corpo ou credenciais.

**Falha fechada**

- Onde o Control Tower não consegue guardar o pedido (envio com sobrescrita, mover ou copiar entre nodes,
  plano de pasta, share), uma concessão marcada é **recusada** (`approval_unsupported`), nunca concedida.
- Com as aprovações desligadas, a marca continua valendo: a concessão é recusada. Desligar a opção não
  afrouxa nada. Uma policy que carrega marcas não pode ser editada com a opção desligada.
- O marcador de versão mínima do banco sobe para 8 ao gravar a primeira marca, para que um binário que
  não as conhece não leia a concessão como comum. Faça rollback só com backup anterior à ativação.
- A marca vale só em regras por caminho; uma regra por tipo não pode pedi-la.

**Pastas, transferências e agentes**

- **Pasta** (apagar ou mover): o plano é permitido, pois não muda nada, mas o pedido de **confirmação** fica
  guardado com os números que o node contou, e quem pediu nunca recebe o token. Quem aprova **planeja de novo
  como ele mesmo**, precisa encontrar os mesmos números (arquivos, pastas, bytes; se mudaram, nada roda e
  o pedido se refaz) e confirma na hora, então o job é dele e sua autorização renova com as permissões dele.
  Uma confirmação de plano antigo de uma concessão que passou a exigir aprovação cancela o job.
- **Transferência entre nodes** (move, ou cópia que sobrescreve): a prévia é permitida; a criação fica
  guardada com os números da prévia. Quem aprova faz a prévia de novo, confere os números e cria com a
  confirmação da própria prévia. A chave de criação deriva do pedido, então repetir a aprovação não cria um
  segundo job.
- **Efeito do tempo**: um acesso que só existe por concessão temporária (JIT) termina com ela, também no
  meio de um download ou de um stream: o pedido é cortado quando a mais cedo das concessões temporárias de que
  dependeu expira. Se algo permanente também dá o acesso, ou se é administrador, nada o limita. Leases de
  jobs e de transferências já nunca passam da concessão temporária e não se renovam depois de revogada.
- **Agentes**: uma credencial de agente com `request_deletes` pode enviar um `DELETE` de arquivo. Ela continua
  sem apagar: o pedido só é guardado quando uma regra **da conta** que exige aprovação cobre o caminho, uma
  concessão comum segue recusada, e qualquer outra coisa além do teto de leitura também. Só apagar um arquivo
  pode ser pedido (nem mover, copiar, enviar nem a lixeira). Quem decide vê que foi um agente. O pedido é
  encerrado se a credencial for revogada ou perder o direito antes da decisão.
- Onde nada disso se aplica (envio com sobrescrita, share, apagar de vez da lixeira), a concessão marcada
  continua **recusada** (`approval_unsupported`).
- A conferência SHA-256 do corpo guardado fica no estado cifrado e é recusada na hora de tomar o pedido
  (`pending_operation_corrupt`), com teste que adultera o banco.

## Certificados e chaves gerenciados

> **Status:** fases 1, 2 e 4 de [`proposals/certificados-gerenciados.md`](proposals/certificados-gerenciados.md). O
> Control Tower é a autoridade, serve o próprio HTTPS e enrola nodes com um token de uso único; o node recebe o
> pacote de confiança e o certificado da API e os renova sozinho. Um node pode ser posto em `managed-only` (só o
> certificado do Control Tower o autentica), e há revogação, rotação da intermediária e da raiz e raiz fora do
> banco. Validado com processos reais em loopback (`scripts/managed-tls-smoke.py` e
> `scripts/managed-rotation-smoke.py`), não entre hosts nem sob carga. O `jolt-mcp trust` guarda a raiz para os agentes.

`CONTROL_TOWER_TLS_MODE=managed` faz o Control Tower manter uma autoridade própria e dispensa `openssl`,
certificado externo e reverse proxy. O padrão, `manual`, não muda nada.

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `CONTROL_TOWER_TLS_MODE` | `manual` | `managed` liga a autoridade. |
| `CONTROL_TOWER_TLS_NAMES` | vazio | Nomes DNS e IPs extras no certificado HTTPS, separados por vírgula. O host de `CONTROL_TOWER_PUBLIC_BASE_URL`, `localhost`, `127.0.0.1` e `::1` entram sempre. |
| `CONTROL_TOWER_CERTIFICATE_VALIDITY_DAYS` | `90` | Vida dos certificados folha, de 7 a 180. Renovam aos 2/3. |
| `CONTROL_TOWER_CA_ADDRESS` | `:8091` | Página HTTP simples que serve só a raiz pública. `off` a desliga. |
| `CONTROL_TOWER_ENROLLMENT_APPROVAL` | `auto` | `auto`: um token válido enrola o node sem mais nada. `manual`: uma pessoa aprova cada adesão. Um token pode pedir `manual` com o padrão `auto`; nenhum token afrouxa um `manual`. |

As quatro últimas só valem no modo `managed`; usá-las no `manual` é erro de configuração. `managed` também
recusa `CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_ID` e `_FILE`: a chave de assinatura passa a ser gerada.

### O que existe

- **Raiz** (10 anos, ECDSA P-256): assina só intermediárias. Fica no banco, selada com uma chave derivada de
  `CONTROL_TOWER_DB_ENCRYPTION_KEY` para esse fim, e só é lida para emitir uma intermediária.
- **Intermediária** (2 anos): assina todo certificado folha. Renova sozinha aos 2/3, e a antiga fica no pacote
  até expirar, porque os certificados que ela emitiu continuam válidos.
- **Certificado HTTPS** do Control Tower (90 dias): fica só na memória, é refeito a cada início e renovado a
  quente, sem reiniciar. Cobre os nomes configurados.
- **Chave de assinatura de contextos** (Ed25519, 90 dias): a mesma que `signed reads/uploads/jobs` já usavam,
  agora gerada, selada no banco e rotacionada. Aos 60 dias nasce a sucessora, publicada no pacote **assinado
  pela antiga**; aos 67 dias (7 dias depois) ela passa a assinar; aos 74 dias (14 dias após ser criada) a antiga
  sai do pacote. Nada precisa reiniciar.
- **Pacote de confiança** (`GET /api/v1/control-tower/crypto/trust-bundle`): raiz, intermediárias, chaves e
  seriais revogados, assinado. Só muda quando algo que os nodes confiam muda.

### Instalar a raiz uma vez

Num navegador novo, abra `http://HOST:8091/ca`: a página mostra o fingerprint SHA-256 e como instalar em cada
sistema. **Compare o fingerprint com o de Access > Certificados** (ou com `GET /api/v1/control-tower/crypto/ca`)
por outro canal, porque essa página chega por HTTP simples. A raiz também sai em
`https://HOST:8090/.well-known/jolt/ca.pem`. Scripts usam o arquivo diretamente, por exemplo
`curl --cacert jolt-root-ca.pem`.

Um agente que usa o `jolt-mcp` faz o mesmo uma vez, com o fingerprint conferido por outro canal:

```sh
jolt-mcp trust http://HOST:8091 --fingerprint AB:CD:...
```

O comando baixa a raiz, confere o SHA-256 e **não grava nada se ele não bater**. Depois disso o servidor MCP
confia **só** nas raízes guardadas (nada do repositório do sistema) e relê o arquivo quando ele muda, então não há
mais nada a configurar. Em [`MCP.md`](MCP.md#confiar-na-raiz-do-jolt) estão o local do arquivo, `--next` para uma
troca de raiz e `--replace`.

A raiz não muda quando a intermediária ou um certificado é renovado: o dispositivo que a instalou não precisa
de nada depois.

### Healthcheck e portas

Com HTTPS no listener, o healthcheck do Compose precisa de `CONTROL_HEALTHCHECK_URL=https://127.0.0.1:8090/health`
(ou `/readyz`); o `wget` já roda com `--no-check-certificate` dentro do container. Publique a porta `8091` só
para quem precisa baixar a raiz.

### Enrolar um node

Com `CONTROL_TOWER_PUBLIC_BASE_URL` em `https://` (o endereço que os nodes alcançam; o certificado já cobre o host
dele), em **Access > Certificados > Adesão de nodes**:

1. Crie um token: nome do node, aprovação (automática ou por uma pessoa) e validade (15 minutos por padrão, até 24 h).
   Ele aparece **uma vez**. O Control Tower guarda só um hash.
2. No node, ponha `JOLT_JOIN_TOKEN=<token>` (ou `JOLT_JOIN_TOKEN_FILE`) no ambiente e, no `node.yaml`:

   ```yaml
   tls_mode: managed
   api_public_endpoint: https://ENDEREÇO-DESTE-NODE:8080
   ```

   Sem `api_tls_*` (o modo gerenciado os recusa) e sem `CONTROL_TOWER_TOKEN`: o node escolhe o próprio token
   operacional e o entrega ao Control Tower na adesão.
3. Inicie o node. Ele baixa a raiz **sem confiar na conexão**, só segue se o SHA-256 for o do token, e então envia
   o segredo por uma conexão que precisa encadear nessa raiz. Recebe o certificado da API e o primeiro pacote de
   confiança, guarda tudo no estado cifrado e passa a servir HTTPS. O Control Tower o cadastra sozinho.

Nos Compose de exemplo (`docker-compose.yml`, `deploy/docker-compose*.yml`) o `CONTROL_TOWER_TOKEN` é declarado como
obrigatório. Para um node gerenciado, use um override que o troque pelo token de adesão, por exemplo no
`deploy/docker-compose.node.yml`: remova `CONTROL_TOWER_TOKEN_FILE`, monte o token como secret e defina
`JOLT_JOIN_TOKEN_FILE: /run/secrets/join_token`. O `node.yaml` montado precisa trazer `tls_mode` e
`api_public_endpoint`.

Depois disso o token pode sair do ambiente (um reinício o ignora: `this node is already enrolled`).

**O que o node confere antes de guardar:** o pacote traz uma raiz com o fingerprint do token e é assinado por uma
chave dele; o certificado é para a chave que o próprio node gerou, encadeia nessa raiz e serve para servidor. Se
algo falha, nada é gravado.

**Aprovação por uma pessoa:** o node fica esperando (até 15 minutos, sem aceitar operações) e escreve o seu
fingerprint de identidade no log. O administrador vê o pedido em *Aguardando aprovação*, **compara** esse
fingerprint com o do log e aprova ou rejeita (o motivo chega ao node). Só `sudo` em
`control-tower/enrollments` decide; agentes e contas de serviço não.

**Se a resposta se perder:** o node repete o mesmo pedido e recebe a mesma resposta, sem token novo. Um pedido
diferente com o mesmo token é recusado.

**Travas:** todo token errado (desconhecido, expirado, usado, de outro nome de node) responde o mesmo 401. Cinco
falhas do mesmo endereço o travam por tempo crescente (o endereço vê um `429`); atrás de um NAT, isso vale para
todos os nodes por ele. No máximo 20 adesões esperando ao mesmo tempo.

### Renovação e pacote nos nodes enrolados

A cada minuto o Control Tower olha cada node enrolado:

- se o node está atrás no pacote de confiança, envia o atual. O **node decide sozinho**: só adota um pacote mais novo,
  que mantenha uma raiz que ele já tinha e esteja assinado por uma chave que o pacote anterior listava. Estar
  autenticado no canal não basta;
- aos 2/3 da vida do certificado da API (60 de 90 dias), pede um pedido de assinatura ao node (a chave nova nasce
  nele e nunca sai), emite o certificado e o instala. Se o certificado não for para essa chave ou não encadear, o
  node mantém o atual.

Um node fora do ar fica com o erro registrado (`last_error` do node enrolado) e os outros seguem. As chaves de
assinatura do pacote entram no que o node aceita **junto** com as do `node.yaml`; em caso de mesmo `id`, vale a do
YAML.

O Control Tower fala com os nodes enrolados confiando só na raiz da autoridade (e no que o operador já tinha
configurado) e apresenta o seu certificado de cliente. Ele confere o certificado do node **ele mesmo**, para que a
lista de revogados valha: um certificado cuja cadeia tenha qualquer serial revogado é recusado. A única exceção é o
certificado **exato** que a própria autoridade emitiu para aquele node (a impressão digital fica no registro): se
ele expirou com o node fora do ar, ou se a intermediária que o assinou foi trocada, o Control Tower ainda alcança o
node, que prova ser o dono pela chave, e o renova. O serial do próprio certificado ainda precisa estar fora da
lista, e o nome do endereço tem de constar nele.

### Só certificado: `managed-only`

No `node.yaml`, `tls_mode: managed-only` faz o node autenticar o Control Tower **só** pelo certificado de cliente
dele e **recusar** o token operacional, mesmo o correto. O certificado é conferido a cada requisição contra o pacote
em uso, então uma revogação vale também numa conexão que já estava aberta. As rotas de rotação do token
(`/api/v1/crypto/operational-token/{prepare,commit}`) respondem `409 operational_token_disabled`. `/metrics` segue
com o próprio token de métricas e `/health` com `public_health`, como antes.

Para migrar um node que já está em `managed`: troque `tls_mode` para `managed-only` e reinicie. Em Access >
Certificados cada node mostra **Certificado** ou **Token compartilhado**, e um aviso conta quantos ainda aceitam o
token. Para voltar, `tls_mode: managed` e reiniciar: o node volta a aceitar o token que escolheu na adesão.

Roubar o canal exige então a chave de cliente do Control Tower (que fica na memória dele) **e**, para assinar
contextos, a chave de assinatura. Um node que vaze sua própria chave não dá acesso a nenhum outro.

### Revogar um certificado

`POST /api/v1/control-tower/crypto/revocations` (`sudo`), com `{"node_id": "..."}` ou `{"serial": "..."}` e um
`reason`, ou o botão **Revogar certificado** do node em Access > Certificados. O serial entra no próximo pacote
assinado, que o Control Tower envia a cada node no ciclo de um minuto. Depois disso:

- o Control Tower **deixa de falar** com aquele node, e os outros passam a recusar o certificado dele;
- um certificado do próprio Control Tower (HTTPS, cliente) que seja revogado é reemitido no mesmo ciclo;
- o serial sai do pacote um dia depois de o certificado vencer de qualquer jeito, para a lista não crescer.

Para o node revogado voltar, enrole-o de novo: um token novo e um `data_dir` limpo no host (o estado cifrado que
guarda o certificado revogado não é reaproveitado). **A intermediária em uso não se revoga assim**; use a rotação abaixo. Uma raiz nunca se revoga.

### A chave da intermediária vazou

`POST /api/v1/control-tower/crypto/ca/intermediate/rotate` com `{"revoke_previous": true}` (ou o botão **Girar e
revogar** em Access > Certificados). A intermediária atual é revogada e sai do pacote na hora; uma nova, assinada pela
raiz, passa a emitir; o Control Tower reemite os próprios certificados e, no próximo ciclo, **troca o certificado de
cada node** sem que ninguém seja enrolado de novo. Navegadores e nodes não instalam nada, porque confiam na raiz.
Isto pede a chave da raiz no banco (ou o arquivo dela, veja abaixo).

Sem `revoke_previous` a rotação é a planejada: a nova assina e a antiga fica no pacote até vencer. Cabem duas
intermediárias no pacote; uma terceira só entra depois de a mais antiga sair ou de ser revogada.

### Trocar a raiz

Em três passos, sem parada e sem re-enrolar ninguém. É o único caso em que **cada navegador e agente instala uma
raiz nova**, porque o certificado HTTPS passa a ser assinado por ela.

1. **Começar** (`POST .../crypto/ca/root/rotate`, ou **Começar a troca da raiz**). A raiz nova nasce e vai para o
   pacote ao lado da atual; nada é assinado por ela ainda. Os nodes a recebem no ciclo seguinte. A página `/ca`
   oferece a raiz nova em `/ca/next.pem`, com o fingerprint, para instalar nos dispositivos agora.
2. **Promover** (`POST .../crypto/ca/root/promote`, ou **Promover a raiz nova**). O Control Tower **recusa** enquanto
   algum node não confirmou o pacote que traz a raiz nova (`409 nodes_behind`), porque esse node deixaria de confiar
   nele. `force` promove assim mesmo, e os nodes que ficaram para trás precisam ser enrolados de novo. Promovido, a
   raiz nova assina uma intermediária nova, o certificado HTTPS e o de cliente passam a ser dela e cada node recebe
   um certificado da cadeia nova no ciclo seguinte. `/.well-known/jolt/ca.pem` passa a servir a raiz nova.
3. **Aposentar**: sozinho. Quando todo node tem o pacote atual, sem erro de sincronização, e um certificado assinado
   sob a cadeia nova, a raiz antiga e as intermediárias dela saem do banco e do pacote. Com nenhum node enrolado,
   isso acontece no ciclo seguinte à promoção.

Um node cujo certificado foi **revogado** não conta nessas esperas: ele não é mais alcançado e não segura a troca.

Tokens de adesão criados depois da promoção fixam a raiz nova. **Um token criado antes dela deixa de servir**: o
Control Tower passa a publicar a raiz nova e o node, que confere o fingerprint do token, recusa sem enviar nada.
Crie outro.

### Raiz fora do banco (opcional)

Sem HSM ou segundo host, a raiz fica no mesmo banco que a intermediária. O endurecimento é tirá-la de lá. Com o
**Control Tower parado** (os comandos abrem o banco direto e usam o mesmo travamento de instância):

```sh
export JOLT_ROOT_KEY_PASSWORD_FILE=/run/secrets/jolt-root-password   # 16 caracteres ou mais
jolt-control ca export-root --data-dir /data --out /seguro/jolt-root.json --confirm-remove-from-database
```

O arquivo é cifrado com Argon2id e AES-256-GCM e **nunca sobrescreve** outro. A chave só sai do banco depois de o
arquivo gravado ser relido e abrir com a senha. **Guarde o arquivo fora deste host e a senha longe dele**: sem os
dois a intermediária não pode ser renovada e a autoridade precisa ser refeita (todos os nodes e dispositivos de
novo). `jolt_root_key_in_database` passa a 0.

Sem a chave o Control Tower continua trabalhando normalmente: emite folhas, renova o HTTPS, gira a chave de
assinatura. Só falha o que pede a raiz: renovar a intermediária (a cada 2 anos, aos 2/3 da vida) e girá-la. O aviso
é o log `the intermediate certificate is due for renewal and the root key is not in the database`, o alerta abaixo
e a métrica. Com o Control Tower parado:

```sh
jolt-control ca renew-intermediate --data-dir /data --root-file /seguro/jolt-root.json
# chave vazada:  ... --revoke-previous --reason "chave copiada"
jolt-control ca import-root --data-dir /data --in /seguro/jolt-root.json   # devolve a chave ao banco
jolt-control ca status --data-dir /data                                    # raiz, intermediárias, onde está a chave
```

A chave da raiz **nunca** volta ao banco em `renew-intermediate`. Um arquivo legível por outros (`chmod` diferente de
600) é recusado. A troca de raiz funciona com a antiga fora do banco: só a raiz nova precisa estar nele.

### Quando algo sai do normal

| Situação | O que acontece | O que fazer |
| --- | --- | --- |
| Node fora do ar além de 60 dias (certificado vence antes de renovar) | O Control Tower o alcança pelo certificado exato que emitiu e o renova ao voltar | Nada |
| Node com a chave vazada | | Revogar; enrolar de novo |
| Chave da intermediária vazada | | Girar e revogar; nada nos nodes |
| Chave da raiz vazada | A autoridade inteira está comprometida | Refazer a autoridade; veja `DISASTER_RECOVERY.md` |
| Node recusa o pacote (`last_error` no node) | O node não adota pacote que não seja mais novo, não mantenha uma raiz que tinha ou não esteja assinado por chave que conhecia | Investigar; um pacote legítimo nunca cai aqui |
| Restore de um snapshot antigo do Control Tower | Os nodes não aceitam um pacote mais velho que o deles | `DISASTER_RECOVERY.md`: o intervalo entre snapshots importa |

### Observabilidade

- `jolt_certificate_expiry_seconds{kind}`: segundos até o fim do que está **em uso** de cada tipo (`root`,
  `intermediate`, `https`, `signing_key`). Chave que está saindo ou publicada e ainda sem assinar não conta,
  para uma despedida planejada não parecer problema.
- `jolt_trust_bundle_version`: versão do pacote publicado.
- `jolt_root_key_in_database`: 1 enquanto a chave da raiz está no banco, 0 depois de `ca export-root`.
- `jolt_managed_nodes`, `jolt_managed_node_bundle_lag` (quantas versões o node mais atrasado está atrás) e
  `jolt_managed_node_certificate_expiry_seconds` (o certificado de API que vence primeiro).
- No node: `jolt_node_api_certificate_expiry_seconds` e `jolt_node_trust_bundle_version`.
- Access > Certificados lista tudo, com datas e fingerprint, e avisa quando algo em uso está perto do fim.
  Nenhuma chave privada sai pela API.

```yaml
      - alert: JoltCertificateEndsSoon
        expr: jolt_certificate_expiry_seconds{kind=~"https|signing_key"} < 14 * 24 * 3600
        for: 1h
        labels: {severity: warning}
        annotations:
          summary: "{{ $labels.kind }} do Control Tower perto do fim; a renovação automática não ocorreu"
      - alert: JoltIntermediateEndsSoon
        expr: jolt_certificate_expiry_seconds{kind="intermediate"} < 60 * 24 * 3600
        for: 1h
        labels: {severity: critical}
        annotations:
          summary: "A intermediária do Control Tower não foi renovada"
      - alert: JoltRootKeyNeededSoon
        # Com a raiz fora do banco, a intermediária só é renovada por uma pessoa, com o arquivo e a senha.
        expr: jolt_root_key_in_database == 0 and jolt_certificate_expiry_seconds{kind="intermediate"} < 90 * 24 * 3600
        for: 1h
        labels: {severity: critical}
        annotations:
          summary: "Renove a intermediária: jolt-control ca renew-intermediate (o Control Tower precisa estar parado)"
      - alert: JoltNodeBundleBehind
        expr: jolt_managed_node_bundle_lag > 0
        for: 1h
        labels: {severity: warning}
        annotations:
          summary: "Há node enrolado com um pacote de confiança antigo; veja last_error em Access > Certificados"
      - alert: JoltNodeCertificateEndsSoon
        expr: jolt_managed_node_certificate_expiry_seconds < 14 * 24 * 3600
        for: 1h
        labels: {severity: warning}
        annotations:
          summary: "O certificado de API de um node enrolado não foi renovado"
```

### Limites

- **Raiz e intermediária no mesmo banco** por padrão. Quem tem o banco e `CONTROL_TOWER_DB_ENCRYPTION_KEY` tem a
  autoridade; `ca export-root` separa a raiz, mas não protege contra quem já tem o processo em execução.
- **Restore de um snapshot antigo** do Control Tower pode deixá-lo com um pacote e uma chave de assinatura que os
  nodes já substituíram. Os nodes não aceitam pacote mais velho. Mantenha snapshots com menos de 14 dias de idade em
  relação à última rotação da chave de assinatura (veja `DISASTER_RECOVERY.md`).
- Uma troca de raiz exige que **cada navegador e agente instale a raiz nova**; só a intermediária e as folhas são
  invisíveis para eles.
- O certificado de cliente do Control Tower fica na memória dele: um `managed-only` com o Control Tower fora do ar
  não deixa ninguém operar o node.
- `ca export-root`, `import-root` e `renew-intermediate` exigem o Control Tower parado.
- `jolt-mcp trust` baixa a raiz por HTTP simples e só a aceita se o fingerprint informado bater. Um fingerprint copiado da própria página `/ca` não prova nada: confira-o em Access > Certificados ou com o administrador.
- Depois de uma troca de raiz, o agente precisa rodar `jolt-mcp trust --next` antes da promoção (ou `trust` de novo depois, pela porta HTTPS ou HTTP).
- Exercitado com processos reais em loopback e com nodes simulados; **não** entre hosts, com relógios divergentes
  (a folga de `NotBefore` é de 5 minutos), sob carga nem com os navegadores de cada sistema.

## Rotinas

**Diária**

- conferir `up`, `/readyz`, taxa de 5xx, jobs falhos e capacidade dos mounts;
- revisar nodes `offline`/`untrusted`, mounts indisponíveis e jobs em
  `waiting_validation`, `waiting_mount`, `waiting_peer` ou `waiting_user_decision`;
- confirmar que o backup agendado terminou e que alertas de login/compartilhamento
  foram triados.

**Semanal**

- revisar auditoria administrativa e service accounts sem grupo ativo;
- verificar crescimento dos volumes de estado, duração de jobs e uploads ativos
  antigos; uploads expirados são limpos pelo node;
- avaliar atualizações de segurança de Go, npm, imagem base e da camada C nativa.

**Mensal e antes de cada release**

- ensaiar restore em diretórios vazios, sem tocar nos volumes ativos;
- revisar secrets, acessos admin, políticas `sudo`, grants e endpoints públicos;
- registrar versão, SHA e digests em produção e comparar com a Release aprovada.

Os comandos de backup exigem parada e são detalhados em
[DISASTER_RECOVERY.md](DISASTER_RECOVERY.md). Faça backup independente dos mounts:
os snapshots não contêm os arquivos publicados.

## Logs e probes

```sh
docker compose --env-file .env -f docker-compose.yml logs --since=1h jolt-control
docker compose --env-file .env -f docker-compose.node.yml logs --since=1h jolt-node
curl --fail http://127.0.0.1:8090/livez
curl --fail http://127.0.0.1:8090/readyz
```

`/health` permanece como alias de liveness. Não use `/livez` para disparar
restores nem `/readyz` como garantia de que peers/mounts estejam saudáveis.
Envie logs a um coletor externo com rotação e retenção; não grave tokens,
conteúdo de secrets ou URLs de share em alertas.

## Prometheus

`/metrics` só existe quando o token dedicado está configurado e exige
`Authorization: Bearer`. Não use token operacional, sessão ou API key. Restrinja
o scrape por rede/TLS e armazene os tokens no secret store do Prometheus.

```yaml
scrape_configs:
  - job_name: jolt-control
    scheme: https
    authorization:
      credentials_file: /run/secrets/jolt_control_metrics_token
    static_configs:
      - targets: [control.internal.example:8090]
  - job_name: jolt-node
    scheme: https
    authorization:
      credentials_file: /run/secrets/jolt_node_metrics_token
    static_configs:
      - targets: [node-a.internal.example:8080, node-b.internal.example:8080]
```

Adapte scheme/porta à API TLS e à rede real. Não exponha `/metrics` na Internet.
Labels usam padrões de rota, não caminhos de arquivos ou tokens de share.

### Métricas úteis

- Control Tower: `jolt_control_info`, `jolt_control_http_requests_total`,
  `jolt_control_http_request_duration_seconds`, `jolt_control_logins_total`,
  `jolt_control_login_failures_total`, `jolt_control_login_lockouts_total`,
  `jolt_control_authorization_denied_total`, `jolt_control_node_proxy_total`,
  `jolt_control_shares_created_total`, `jolt_control_shares_revoked_total`,
  `jolt_control_share_downloads_total`,
  `jolt_control_share_unlock_failures_total` e, com certificados gerenciados,
  `jolt_certificate_expiry_seconds` e `jolt_trust_bundle_version`.
- Node: `jolt_node_info`, `jolt_http_requests_total`,
  `jolt_http_request_duration_seconds`, `jolt_http_response_bytes_total`,
  `jolt_jobs_total`, `jolt_jobs_active`, `jolt_job_bytes_total`,
  `jolt_max_concurrent_jobs`, `jolt_uploads_started_total`,
  `jolt_uploads_completed_total`, `jolt_uploads_failed_total`,
  `jolt_uploads_aborted_total`, `jolt_uploads_active`,
  `jolt_upload_bytes_total` e, da lixeira, `jolt_trash_entries`, `jolt_trash_bytes` e
  `jolt_trash_oldest_age_seconds` (por `mount`, atualizados a cada minuto) e
  `jolt_trash_purged_total`.
- Ambos exportam métricas de runtime Go com prefixo `go_`/`process_` conforme o
  registro nativo. Counters só aumentam; use `rate()`/`increase()`.

## Alertas de referência

Os limiares abaixo são iniciais e precisam ser calibrados com carga real. Um job
falho pode ser decisão de conflito ou autorização; correlacione com UI/auditoria
antes de reiniciar serviços.

```yaml
groups:
  - name: jolt-availability
    rules:
      - alert: JoltTargetDown
        expr: up{job=~"jolt-control|jolt-node"} == 0
        for: 5m
        labels: {severity: critical}
        annotations:
          summary: "Jolt não está sendo coletado: {{ $labels.instance }}"
      - alert: JoltControlServerErrors
        expr: sum(rate(jolt_control_http_requests_total{status=~"5.."}[5m])) > 0.1
        for: 10m
        labels: {severity: warning}
      - alert: JoltNodeServerErrors
        expr: sum(rate(jolt_http_requests_total{status=~"5.."}[5m])) > 0.1
        for: 10m
        labels: {severity: warning}
      - alert: JoltNodeProxyFailures
        expr: sum(rate(jolt_control_node_proxy_total{result!="success"}[5m])) > 0.1
        for: 10m
        labels: {severity: warning}
      - alert: JoltLoginFailures
        expr: sum(rate(jolt_control_login_failures_total[5m])) > 0.2
        for: 10m
        labels: {severity: warning}
      - alert: JoltTrashNearCap
        # Só faz sentido com `trash.max_bytes`; ajuste o teto ao do mount.
        expr: jolt_trash_bytes > 0.8 * 50 * 1024 * 1024 * 1024
        for: 30m
        labels: {severity: warning}
        annotations:
          summary: "A lixeira de {{ $labels.mount }} passou de 80% do teto"
      - alert: JoltTrashEntryPastRetention
        # A varredura roda a cada 10 min; um item bem além da retenção indica falha ao purgar.
        expr: jolt_trash_oldest_age_seconds > (30 * 86400) + 3600
        for: 1h
        labels: {severity: warning}
      - alert: JoltSharePasswordFailures
        expr: sum(rate(jolt_control_share_unlock_failures_total[5m])) > 0.2
        for: 10m
        labels: {severity: warning}
```

Antes de ativar o alerta de proxy, confira os valores de `result` no ambiente e
exclua resultados esperados de política, se necessário. Adicione alertas de disco
e filesystem por `node_filesystem_*` do node_exporter: as métricas Jolt não
substituem telemetria do host nem informam peers/mounts individualmente.

## Dashboard Grafana de referência

Crie uma linha por produto, com variável `instance`, e use estes painéis:

| Painel | Consulta principal |
| --- | --- |
| Disponibilidade | `jolt_control_info` ou `jolt_node_info` |
| Requisições/s | `sum by (route,status) (rate(jolt_http_requests_total[5m]))` (prefixo `jolt_control_` no Control) |
| Latência p95 | `histogram_quantile(0.95, sum by (le,route) (rate(jolt_http_request_duration_seconds_bucket[5m])))` |
| Jobs ativos/capacidade | `jolt_jobs_active` e `jolt_max_concurrent_jobs` |
| Jobs terminais | `sum by (type,state) (rate(jolt_jobs_total[1h]))` |
| Bytes de jobs/s | `sum by (type) (rate(jolt_job_bytes_total[5m]))` |
| Uploads | `jolt_uploads_active` e `sum(rate(jolt_uploads_completed_total[1h]))` |
| Falhas de upload | `sum(rate(jolt_uploads_failed_total[1h]))` |
| Autenticação | `rate(jolt_control_login_failures_total[5m])`, lockouts e logins |
| Autorização | `sum by (capability) (rate(jolt_control_authorization_denied_total[5m]))` |
| Proxy de nodes | `sum by (node_id,result) (rate(jolt_control_node_proxy_total[5m]))` |
| Shares | criação, revogação, downloads e falhas de senha por hora |
| Runtime | heap/goroutines/CPU e espaço de disco do host |

Latência de streaming inclui duração do download/upload; não trate p95 alto como
erro sem segmentar rota. `jolt_node_info` e `jolt_control_info` indicam scrape da
aplicação, não readiness ou integridade de dados.

## Resposta a incidentes

1. Preserve logs, métricas, auditoria, versão e digests; não exponha secrets.
2. Para conter escrita, pause/cancele jobs ou revogue grants/peers conforme o caso.
3. Para credencial comprometida, use a recuperação offline documentada e atualize
   token no node e Control Tower de forma coordenada.
4. Para inconsistência de estado, pare o serviço, preserve evidências e restaure
   em local separado. Não execute comandos de recovery sobre instância ativa.
5. Antes de voltar, execute readiness, diagnóstico e uma transferência pequena;
   registre impacto e ações no relatório de release/incidente.

Vulnerabilidades devem ser reportadas por GitHub Security Advisory privada, sem
issue pública com segredo, dados pessoais ou prova contendo arquivos reais.
Inclua versão/SHA/digest, arquitetura, configuração redigida, impacto e passos
mínimos de reprodução. Não há neste repositório promessa de SLA de resposta.
