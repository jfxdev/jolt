# jolt - Requisitos do Sistema

## 1. Visao Geral

O `jolt` e um sistema distribuido, dockerizado, para gerenciar arquivos e diretorios montados em hosts diferentes. Cada node e um node API-only, enquanto a Control Tower oferece a interface web amigavel a mobile para operacao centralizada.

O diferencial principal do sistema e permitir que varias instancias independentes se comuniquem diretamente entre si, formando grupos logicos chamados `clusters`, sem depender de um centralizador obrigatorio. Cada host roda uma instancia propria do `jolt`, publica diretorios autorizados e pode copiar arquivos ou pastas inteiras de/para outros hosts confiaveis com poucos cliques.

O sistema tambem deve funcionar como um filesystem por API: uma camada distribuida e controlada para navegar, consultar metadados e executar operacoes de arquivo sem conceder acesso direto ao filesystem dos servidores. Esse contrato deve permitir uso futuro por automacoes, CLIs, integracoes e agentes de IA com escopo limitado, auditavel e revogavel.

O sistema deve ser especialmente robusto para:

- transferencia de arquivos grandes, como filmes de aproximadamente 10 GB;
- transferencia de diretorios grandes, como bibliotecas de jogos ou torrents com milhares de arquivos e aproximadamente 100 GB ou mais;
- retomada de transferencias interrompidas;
- funcionamento parcial quando algum host da rede estiver indisponivel.

## 2. Terminologia

- **Node**: uma instancia do `jolt` rodando em um host.
- **Cluster**: grupo logico de nodes confiaveis.
- **Nest**: conjunto de diretorios publicados por um node.
- **Mount**: referencia logica cadastrada em um node para um caminho local de diretorio ou arquivo que pode participar de operacoes.
- **API Filesystem**: contrato de API que representa mounts, diretorios, arquivos, metadados e operacoes como recursos logicos, sem expor acesso direto ao filesystem do servidor.
- **Peer**: outro node conhecido e autorizado.
- **Control Tower**: superficie web de operacao centralizada que permite visualizar nodes conhecidos e iniciar operacoes neles usando as APIs dos proprios nodes.
- **User**: identidade humana autenticada na Control Tower.
- **Service Account**: identidade nao humana autenticada na Control Tower para automacao.
- **Control Tower Policy**: regra de RBAC aplicada a paths de nodes, semelhante ao modelo de policies do HashiCorp Vault.
- **Role**: agrupador reutilizavel de Control Tower Policies que pode ser associado a usuarios para conceder um conjunto coerente de permissoes.
- **Node Path**: caminho logico usado pela Control Tower para autorizar acesso a recursos e operacoes de um node.
- **Pairing Invite**: convite de pareamento que descreve identidade, expiracao, cluster opcional e operacao esperada entre os nodes.
- **Transfer Mode**: modo operacional esperado para a relacao de confianca, como `one_sided` ou `dual_channel`.
- **Transfer Path Grant**: declaracao explicita dos mounts ja cadastrados que um node autoriza para transferencias com outro node.
- **Transfer Job**: tarefa de copia ou transferencia entre origem e destino.
- **Transfer Item**: arquivo individual dentro de um job.
- **Manifest**: lista estruturada de arquivos de uma pasta, com metadados necessarios para planejar uma transferencia.
- **Chunk**: bloco de bytes de um arquivo usado para transferencias retomaveis.

## 3. Objetivos

### 3.1 Objetivos do Produto

- Permitir navegar arquivos e diretorios dos nodes pela Control Tower.
- Permitir publicar diretorios montados em containers Docker.
- Permitir parear varias instancias do `jolt`.
- Permitir copiar arquivos entre hosts confiaveis sem servidor central obrigatorio.
- Permitir copiar diretorios inteiros entre hosts.
- Permitir acompanhar progresso, velocidade, falhas e historico das transferencias.
- Oferecer uma experiencia simples em desktop e mobile pela Control Tower.
- Manter o sistema resiliente quando nodes individuais ficarem offline.
- Permitir operar multiplos nodes por uma Control Tower web, sem transformar essa UI em centralizador obrigatorio da rede.
- Oferecer um filesystem distribuido por API para automacoes e agentes de IA acessarem arquivos de forma controlada, sem credenciais de sistema operacional ou acesso direto ao disco dos servidores.

### 3.2 Objetivos Tecnicos

- Ser simples de instalar via Docker.
- Ter backend preferencialmente em Go.
- Ter frontend da Control Tower preferencialmente em Vue 3 com shadcn-vue.
- Usar armazenamento local leve, preferencialmente SQLite.
- Separar comunicacao de controle da transferencia de dados.
- Suportar evolucao futura para protocolos como `rsync`, `SSH/SFTP` ou outros backends de transferencia.
- Definir um contrato estavel de API Filesystem com permissoes, auditoria, idempotencia e limites operacionais.

## 4. Fora de Escopo Inicial

Os itens abaixo nao sao obrigatorios no MVP, mas podem ser considerados em versoes futuras:

- sincronizacao continua automatica no estilo Syncthing;
- resolucao avancada de conflitos entre arquivos;
- relay publico obrigatorio para hosts atras de NAT;
- armazenamento em nuvem como backend primario;
- edicao de arquivos na interface web;
- indexacao global de conteudo;
- organizacoes, times e governanca avancada alem do RBAC basico da Control Tower;
- cliente desktop nativo;
- aplicativo mobile nativo.

## 5. Requisitos Funcionais

### 5.1 Inicializacao e Configuracao

- RF-001: O sistema deve iniciar como uma aplicacao Docker.
- RF-002: O sistema deve permitir configurar o nome do node.
- RF-003: O sistema deve permitir configurar a porta HTTP da API do node.
- RF-004: O sistema deve permitir configurar a porta mTLS usada para transferencia node-to-node.
- RF-005: O node deve receber por variavel de ambiente, preferencialmente `CONTROL_TOWER_TOKEN`, um token operacional da Control Tower e somente deve aceitar chamadas de API autenticadas com esse token, exceto endpoints explicitamente publicos de healthcheck quando habilitados.
- RF-006: O node nao deve expor interface web propria para operacao ou administracao; deve expor Swagger ou OpenAPI para documentar a API na porta HTTP da API, e qualquer chamada interativa pelo Swagger deve usar o mesmo token operacional.
- RF-007: O sistema deve permitir configurar diretorios montados por variaveis de ambiente, arquivo de configuracao, API autenticada ou Control Tower.
- RF-008: O sistema deve persistir configuracoes locais entre reinicios do container.
- RF-009: No primeiro boot, o sistema deve inicializar banco local, diretorio interno de dados e identidade criptografica quando ainda nao existirem.
- RF-010: Em boots seguintes, o sistema deve reutilizar identidade e configuracoes persistidas.
- RF-011: O sistema deve permitir bootstrap por variaveis de ambiente, arquivo de configuracao ou API autenticada.

### 5.2 Gerenciamento de Mounts e Nests

- RF-012: O sistema deve listar os diretorios locais configurados como mounts.
- RF-013: O sistema deve permitir navegar arquivos e subdiretorios dentro de cada mount autorizado.
- RF-014: O sistema deve exibir metadados basicos dos arquivos, incluindo nome, caminho relativo, tamanho, tipo e data de modificacao.
- RF-015: O sistema deve impedir acesso a caminhos fora dos mounts autorizados.
- RF-016: O sistema deve proteger contra path traversal em todas as operacoes de arquivo.
- RF-017: O sistema deve permitir renomear, criar diretorios e remover arquivos apenas quando o mount possuir permissao de escrita.
- RF-018: O sistema deve permitir definir mounts como somente leitura ou leitura/escrita e oculta-los da publicacao remota sem remove-los da configuracao local.

### 5.3 Gestao Local de Arquivos

- RF-019: O sistema deve permitir gestao de arquivos locais dentro dos mounts autorizados.
- RF-020: O sistema deve permitir copiar arquivos locais entre diretorios autorizados do mesmo node.
- RF-021: O sistema deve permitir copiar diretorios locais entre diretorios autorizados do mesmo node.
- RF-022: O sistema deve permitir colar arquivos ou diretorios copiados em destino autorizado.
- RF-023: O sistema deve permitir recortar arquivos ou diretorios dentro de mounts com permissao de escrita.
- RF-024: O sistema deve permitir mover arquivos ou diretorios entre destinos autorizados do mesmo node.
- RF-025: O sistema deve permitir renomear arquivos e diretorios em mounts com permissao de escrita.
- RF-026: O sistema deve permitir criar novos diretorios em mounts com permissao de escrita.
- RF-027: O sistema deve permitir remover arquivos e diretorios em mounts com permissao de escrita.
- RF-028: O sistema deve permitir upload de arquivos para diretorios autorizados.
- RF-029: O sistema deve suportar upload de arquivos grandes por streaming, sem carregar o arquivo inteiro em memoria.
- RF-030: Uploads devem usar arquivo temporario e finalizacao segura antes de publicar o arquivo final.
- RF-031: Operacoes locais de copia, recorte, movimento, remocao, renomeacao e upload devem passar pela API.
- RF-032: Operacoes locais devem respeitar permissoes do mount e regras de path traversal.
- RF-033: Operacoes locais de longa duracao devem ser representadas como jobs.
- RF-034: Operacoes locais devem oferecer politicas de conflito equivalentes as usadas em transferencias entre nodes.

### 5.4 Interface Web da Control Tower

- RF-035: A Control Tower deve fornecer uma interface responsiva e amigavel para mobile.
- RF-036: A Control Tower deve permitir navegar arquivos dos nodes autorizados.
- RF-037: A Control Tower deve permitir navegar arquivos de peers autorizados pelos nodes.
- RF-038: A Control Tower deve permitir selecionar um arquivo como origem de transferencia.
- RF-039: A Control Tower deve permitir selecionar uma pasta como origem de transferencia.
- RF-040: A Control Tower deve permitir selecionar um mount ou subdiretorio de destino.
- RF-041: A Control Tower deve mostrar progresso de transferencias em tempo real ou quase real.
- RF-042: A Control Tower deve mostrar historico de transferencias consultando os nodes responsaveis.
- RF-043: A Control Tower deve mostrar o estado dos peers conhecidos, incluindo online, offline, erro ou desconhecido.
- RF-044: A Control Tower deve permitir pausar, retomar e cancelar transferencias quando tecnicamente possivel.
- RF-045: A Control Tower deve apresentar erros de transferencia de forma compreensivel.
- RF-046: A Control Tower deve permitir filtrar ou buscar arquivos no diretorio atualmente navegado.
- RF-047: A Control Tower deve permitir copiar, colar, recortar, mover, renomear, remover, criar diretorio e fazer upload de arquivos quando o mount permitir.

### 5.5 Pareamento entre Nodes

- RF-048: O sistema deve permitir adicionar peers manualmente por endereco.
- RF-049: O sistema deve permitir gerar um convite de pareamento.
- RF-050: O sistema deve permitir aceitar um convite de pareamento.
- RF-051: O pareamento deve trocar identidades criptograficas ou credenciais seguras entre nodes.
- RF-052: O sistema deve permitir remover um peer conhecido.
- RF-053: O sistema deve permitir bloquear comunicacao com um peer removido ou revogado.
- RF-054: O sistema deve persistir a lista de peers conhecidos localmente.
- RF-055: O sistema deve permitir agrupar peers em clusters.
- RF-056: O sistema deve continuar operando localmente quando nao houver peers online.
- RF-057: Cada node deve gerar uma identidade criptografica propria na primeira inicializacao.
- RF-058: A identidade criptografica principal do node deve ser estavel e nao deve expirar automaticamente.
- RF-059: O sistema deve exibir uma fingerprint curta da identidade do node para conferencia humana durante pareamento.
- RF-060: Convites de pareamento devem ter expiracao configuravel.
- RF-061: Convites de pareamento devem ser revogaveis.
- RF-062: Convites de pareamento devem ser de uso unico por padrao.
- RF-063: Sessoes, tokens temporarios ou credenciais operacionais entre peers devem expirar.
- RF-064: O sistema deve permitir rotacionar manualmente a identidade de um node.
- RF-065: Quando a identidade de um peer conhecido mudar, o sistema deve tratar o evento como suspeito e exigir confirmacao manual antes de confiar novamente.
- RF-066: A chave privada de identidade do node nunca deve ser transmitida para outros nodes.
- RF-067: A confianca entre peers nao deve ser transitiva: se A confia em B e B confia em C, A nao deve confiar automaticamente em C.

### 5.6 Descoberta e Estado de Peers

- RF-068: O sistema deve consultar periodicamente a disponibilidade de peers conhecidos.
- RF-069: O sistema deve exibir a ultima vez em que um peer esteve online.
- RF-070: O sistema deve permitir atualizar o endereco de um peer.
- RF-071: O sistema pode suportar descoberta local via mDNS em versoes futuras.
- RF-072: O sistema deve tratar peers offline sem bloquear a operacao dos demais peers.

### 5.7 Transferencia de Arquivos Individuais

- RF-073: O sistema deve permitir copiar um arquivo local para um peer.
- RF-074: O sistema deve permitir copiar um arquivo remoto para o node local.
- RF-075: O sistema deve permitir copiar um arquivo entre dois diretorios do mesmo node.
- RF-076: O sistema deve transferir arquivos grandes por streaming, sem carregar o arquivo inteiro em memoria.
- RF-077: O sistema deve suportar transferencia de arquivos de pelo menos 10 GB.
- RF-078: O sistema deve gravar arquivos recebidos em um arquivo temporario antes de substituir ou publicar o arquivo final.
- RF-079: O sistema deve permitir retomar arquivos parcialmente transferidos.
- RF-080: O sistema deve validar tamanho final do arquivo apos a transferencia.
- RF-081: O sistema deve suportar verificacao opcional por checksum.
- RF-082: O sistema deve registrar falhas de transferencia com mensagem de erro.

### 5.8 Transferencia de Diretorios Grandes

- RF-083: O sistema deve permitir copiar uma pasta inteira entre nodes.
- RF-084: O sistema deve gerar um manifest antes de transferir diretorios.
- RF-085: O manifest deve conter caminho relativo, tipo, tamanho e data de modificacao dos itens.
- RF-086: O manifest pode conter checksums quando a politica de verificacao exigir.
- RF-087: O sistema deve comparar o manifest da origem com o estado existente no destino.
- RF-088: O sistema deve criar um plano de transferencia antes de iniciar a copia de diretorios.
- RF-089: O sistema deve permitir pular arquivos ja existentes no destino.
- RF-090: O sistema deve permitir sobrescrever arquivos existentes, conforme politica escolhida.
- RF-091: O sistema deve permitir renomear arquivos em caso de conflito, conforme politica escolhida.
- RF-092: O sistema deve suportar diretorios com milhares de arquivos.
- RF-093: O sistema deve suportar diretorios com pelo menos 100 GB de dados totais.
- RF-094: O sistema deve acompanhar progresso agregado por bytes e por quantidade de arquivos.
- RF-095: O sistema deve continuar um job de diretorio a partir dos arquivos restantes apos interrupcao.
- RF-096: O sistema deve registrar falhas por arquivo individual dentro de um job de diretorio.
- RF-097: O sistema deve permitir tentar novamente apenas os itens com falha.

### 5.9 Chunks e Retomada

- RF-098: O sistema deve dividir arquivos grandes em chunks para permitir retomada eficiente.
- RF-099: O tamanho do chunk deve ser configuravel.
- RF-100: O sistema deve persistir quais chunks ou ranges ja foram concluidos.
- RF-101: O sistema deve suportar requisicoes parciais de arquivo por range.
- RF-102: O sistema deve validar se o arquivo de origem mudou durante uma transferencia.
- RF-103: O sistema deve definir uma politica para arquivos modificados durante a copia: falhar, tentar novamente ou copiar mesmo assim.
- RF-104: O sistema deve permitir retentativas automaticas em chunks ou arquivos que falharem.
- RF-105: O sistema deve limitar o numero maximo de retentativas por item.

### 5.10 Fila e Execucao de Jobs

- RF-106: O sistema deve tratar jobs como operacoes rastreaveis, persistentes e observaveis.
- RF-107: O sistema deve suportar jobs curtos e jobs de vida longa.
- RF-108: O sistema deve representar como jobs operacoes como copiar arquivo, copiar diretorio, gerar manifest, comparar manifest, validar transferencia, limpar parciais e tentar novamente itens com falha.
- RF-109: O sistema deve manter uma fila local de jobs.
- RF-110: O sistema deve persistir a fila em armazenamento local.
- RF-111: O sistema deve permitir executar multiplos jobs em paralelo, respeitando limites configuraveis.
- RF-112: O sistema deve permitir configurar numero maximo de arquivos paralelos por job.
- RF-113: O sistema deve permitir configurar numero maximo de chunks paralelos por arquivo.
- RF-114: O sistema deve permitir configurar limite de banda por node ou por job.
- RF-115: O sistema deve permitir pausar jobs de vida longa quando tecnicamente possivel.
- RF-116: O sistema deve permitir retomar jobs pausados.
- RF-117: O sistema deve permitir cancelar jobs.
- RF-118: O sistema deve limpar arquivos temporarios de jobs cancelados conforme politica configurada.
- RF-119: O sistema deve manter historico de jobs concluidos, falhos e cancelados.
- RF-120: O sistema deve rastrear fase atual do job, como validacao, planejamento, transferencia, verificacao, finalizacao e limpeza.
- RF-121: O sistema deve registrar validacoes executadas antes, durante e depois de um job.
- RF-122: O sistema deve permitir retries por chunk, por arquivo, por peer e por job.
- RF-123: O sistema deve aplicar backoff e jitter em retries para evitar repeticoes agressivas.
- RF-124: O sistema deve separar timeouts de conexao, leitura ociosa, chunk, validacao e job.
- RF-125: Jobs de vida longa nao devem ter timeout global obrigatorio por padrao.
- RF-126: Jobs devem detectar ausencia de progresso por janela configuravel.
- RF-127: O sistema deve calcular estimativa de tempo de conclusao quando houver dados suficientes.
- RF-128: Estimativas de tempo devem indicar grau de confianca quando possivel.
- RF-129: Jobs de diretorio devem expor progresso por bytes, por arquivos e por fase.
- RF-130: Jobs devem poder terminar como `completed_with_warnings` quando parte dos itens falhar sem invalidar todo o resultado.
- RF-131: Jobs devem poder entrar em `waiting_user_decision` quando uma decisao de conflito ou override for necessaria.
- RF-132: O sistema deve permitir aplicar uma decisao de override a um arquivo especifico ou aos conflitos seguintes do mesmo job.

### 5.11 Processo Idle dos Nodes

- RF-133: O node deve manter API HTTP autenticada, Swagger/OpenAPI e porta mTLS disponiveis quando estiver idle.
- RF-134: O sistema deve executar heartbeat leve com peers conhecidos durante idle.
- RF-135: O heartbeat deve validar identidade do peer antes de atualizar seu estado como online.
- RF-136: O sistema deve classificar peers conhecidos em estados como `unknown`, `online`, `offline`, `untrusted`, `identity_changed` e `degraded`.
- RF-137: O sistema deve evitar marcar um peer como offline apos uma unica falha temporaria.
- RF-138: O sistema deve usar tolerancia a falhas consecutivas ou janela de tempo antes de marcar peer como offline.
- RF-139: O sistema deve usar backoff para peers offline ou instaveis.
- RF-140: O sistema deve limpar convites expirados durante idle.
- RF-141: O sistema deve expirar ou invalidar sessoes temporarias vencidas durante idle.
- RF-142: O sistema deve verificar mounts configurados de forma leve durante idle.
- RF-143: A verificacao idle de mounts deve identificar indisponibilidade, falta de permissao e possivel modo read-only.
- RF-144: A verificacao idle de mounts nao deve calcular tamanho total de diretorios nem varrer arvores grandes.
- RF-145: O sistema deve detectar quando um peer aguardado por jobs pendentes volta a ficar online.
- RF-146: Jobs em estado `waiting_peer` devem voltar para a fila quando o peer necessario ficar online e as validacoes forem aprovadas.
- RF-147: Antes de retomar job pendente, o sistema deve revalidar identidade do peer, permissao, estado local e metadados necessarios.
- RF-148: O sistema deve emitir eventos de idle relevantes para a Control Tower, como peer online/offline, identidade alterada, mount indisponivel e job pronto para retomar.
- RF-149: O sistema deve evitar checksums, indexacao global ou varreduras pesadas durante idle.
- RF-150: O sistema deve tratar desligamento do processo de forma ordenada, persistindo estado e marcando jobs em execucao como interrompidos quando necessario.

### 5.12 Politicas de Conflito

- RF-151: O sistema deve oferecer politica de pular arquivo existente.
- RF-152: O sistema deve oferecer politica de sobrescrever arquivo existente.
- RF-153: O sistema deve oferecer politica de renomear arquivo em conflito.
- RF-154: O sistema deve oferecer politica de falhar o item quando houver conflito.
- RF-155: O sistema deve oferecer politica de perguntar ao usuario quando houver conflito.
- RF-156: O sistema deve oferecer politica de decidir por checksum quando ativada.
- RF-157: O sistema deve oferecer comparacao por tamanho.
- RF-158: O sistema deve oferecer comparacao por tamanho e data de modificacao.
- RF-159: O sistema deve oferecer comparacao por checksum quando ativada.
- RF-160: O sistema deve mostrar uma pre-visualizacao do plano de copia antes de iniciar jobs de diretorio grandes.
- RF-161: O sistema deve permitir configurar politica de conflito por job.
- RF-162: O sistema deve permitir override manual por item em jobs de diretorio.
- RF-163: O sistema deve permitir aplicar uma decisao manual aos proximos conflitos do mesmo job.
- RF-164: O sistema nao deve apagar ou substituir o arquivo de destino antes de validar o arquivo temporario recebido.

### 5.13 Protocolos de Comunicacao

- RF-165: O sistema deve possuir uma API de controle para listar peers, mounts, arquivos, jobs e estados.
- RF-166: O sistema deve possuir um mecanismo de transferencia de dados separado das operacoes de controle.
- RF-167: O MVP deve poder usar HTTP proprio com streaming e suporte a range requests.
- RF-168: O sistema deve permitir evolucao futura para backends alternativos de transferencia.
- RF-169: O sistema deve avaliar suporte futuro a `rsync` para copias incrementais eficientes.
- RF-170: O sistema deve avaliar suporte futuro a `SSH/SFTP` para integracao com ambientes Linux existentes.
- RF-171: O sistema deve suportar operacao atras de reverse proxy para Control Tower e API HTTP autenticada.
- RF-172: O sistema deve documentar configuracao de reverse proxy para uploads, downloads e streams grandes.
- RF-173: Para comunicacao node-to-node autenticada por certificado, o sistema deve preferir conexao direta ou TLS passthrough.
- RF-174: Quando um reverse proxy terminar TLS para comunicacao entre nodes, esse modo deve ser tratado como configuracao avancada e explicita.
- RF-175: O sistema deve permitir configurar endpoints separados para API HTTP autenticada do node, Swagger/OpenAPI e peer/data API mTLS quando necessario.
- RF-176: O sistema deve documentar que proxies para transferencia devem evitar limite de body, buffering de request/response e timeouts curtos.

### 5.14 API e Eventos

- RF-177: O backend deve expor endpoints para operacoes de arquivos, peers, clusters, mounts e transferencias.
- RF-178: O backend deve expor eventos de progresso por WebSocket, Server-Sent Events ou mecanismo equivalente.
- RF-179: A API deve retornar erros estruturados.
- RF-180: A API deve validar permissao antes de qualquer operacao de leitura ou escrita.
- RF-181: A API deve suportar paginacao ou streaming para listagens muito grandes.
- RF-182: Todo processo de listagem de arquivos e diretorios deve ser executado por API.
- RF-183: Todo processo de escrita, remocao, renomeacao, criacao de diretorio, copia ou transferencia deve ser executado por API.
- RF-184: A Control Tower deve consumir a mesma API publica ou interna disponivel para automacao.
- RF-185: A CLI futura deve consumir a mesma API publica ou interna disponivel para automacao.
- RF-186: O sistema deve permitir instrumentacao por orquestradores externos via API.
- RF-187: Operacoes iniciadas por orquestrador devem passar pelas mesmas validacoes de permissao, trust, path e conflito usadas pela Control Tower.
- RF-188: Operacoes mutaveis via API devem aceitar chave de idempotencia ou mecanismo equivalente quando houver risco de repeticao.
- RF-189: Operacoes via API devem produzir eventos observaveis e auditaveis.
- RF-190: Operacoes via API devem aceitar ou gerar identificadores de correlacao para rastrear fluxos entre nodes.
- RF-191: O sistema deve expor contrato de API documentado, preferencialmente OpenAPI ou especificacao equivalente.

### 5.15 Persistencia Local

- RF-192: O sistema deve persistir configuracoes locais.
- RF-193: O sistema deve persistir peers conhecidos.
- RF-194: O sistema deve persistir clusters.
- RF-195: O sistema deve persistir mounts configurados.
- RF-196: O sistema deve persistir jobs e itens de transferencia.
- RF-197: O sistema deve persistir estado necessario para retomar jobs apos reinicio.
- RF-198: O sistema deve manter metadados em banco local, preferencialmente SQLite.
- RF-281: O node deve carregar configuracao a partir de valores padrao, variaveis de ambiente, arquivo de configuracao e banco local persistido, com precedencia documentada.
- RF-282: Configuracoes operacionais mutaveis devem ser lidas e alteradas por API autenticada, Swagger/OpenAPI ou Control Tower.
- RF-283: Configuracoes imutaveis em runtime, como portas, paths internos de dados e token operacional recebido por ambiente, devem exigir reinicio do processo para mudanca.
- RF-284: O sistema deve distinguir configuracao desejada, configuracao efetiva e estado observado.
- RF-285: A API deve expor endpoint para leitura da configuracao efetiva sem revelar segredos.
- RF-286: A API deve expor endpoint para atualizar configuracoes mutaveis com validacao, auditoria, idempotencia e mascaramento de segredos.
- RF-287: Alteracoes de configuracao devem ser persistidas atomicamente ou rejeitadas sem deixar estado parcial.
- RF-288: Segredos como `CONTROL_TOWER_TOKEN`, chaves privadas e tokens de peers nao devem ser retornados em claro por API, Swagger, logs ou exportacoes de diagnostico.

### 5.16 Logs e Auditoria

- RF-199: O sistema deve registrar eventos importantes de transferencia.
- RF-200: O sistema deve registrar erros de comunicacao entre peers.
- RF-201: O sistema deve registrar alteracoes de configuracao relevantes.
- RF-202: O sistema deve permitir consultar logs recentes pela API e pela Control Tower.
- RF-203: O sistema deve evitar registrar segredos, tokens ou chaves privadas em logs.

### 5.17 Docker e Operacao

- RF-204: O sistema deve fornecer Dockerfile oficial.
- RF-205: O sistema deve fornecer exemplo de `docker-compose.yml`.
- RF-206: O sistema deve permitir montar diretorios do host no container.
- RF-207: O sistema deve permitir configurar volume persistente para banco local e arquivos internos.
- RF-208: O sistema deve funcionar sem privilegios elevados sempre que possivel.
- RF-209: O sistema deve ter healthcheck HTTP.
- RF-210: O container deve suportar configuracao de UID do processo por variavel `PUID`.
- RF-211: O container deve suportar configuracao de GID do processo por variavel `PGID`.
- RF-212: O container pode aceitar `UID` e `GID` como aliases ou fallback para `PUID` e `PGID`.
- RF-213: O container deve suportar configuracao de `UMASK`.
- RF-214: Arquivos e diretorios criados pelo `jolt` devem usar o UID/GID efetivo configurado.
- RF-215: Uploads, copias locais, transferencias recebidas, diretorios criados e arquivos temporarios devem respeitar UID/GID e `UMASK`.
- RF-216: O processo principal do `jolt` deve evitar rodar como root permanente.
- RF-217: O sistema deve diagnosticar quando um mount configurado como escrita nao e gravavel pelo UID/GID efetivo.
- RF-218: O sistema deve expor por API informacoes de diagnostico de permissao do mount quando disponiveis, como gravavel, somente leitura, owner, group e modo, para uso por Swagger, automacao e Control Tower.

### 5.18 Control Tower

- RF-219: O sistema deve oferecer uma Control Tower como superficie web para centralizar a operacao de nodes conhecidos.
- RF-220: A Control Tower deve listar nodes conhecidos, incluindo o node local e peers autorizados.
- RF-221: A lista de nodes deve exibir estado operacional resumido, incluindo online, offline, degraded, untrusted, identity_changed e setup_required quando aplicavel.
- RF-222: A Control Tower deve permitir selecionar um node e visualizar seus mounts, arquivos, jobs, historico, diagnosticos e configuracoes permitidas.
- RF-223: A Control Tower deve iniciar operacoes usando as mesmas APIs expostas pelos nodes, sem acessar filesystem, banco local ou motor de transferencia diretamente.
- RF-224: Operacoes iniciadas pela Control Tower devem seguir as mesmas validacoes de permissao, trust, path traversal, conflito, idempotencia e auditoria usadas por clientes autenticados da API do node e por orquestradores externos.
- RF-225: A Control Tower deve permitir criar jobs de copia, transferencia, upload, remocao, renomeacao, criacao de diretorio, pausa, retomada, cancelamento e retry quando o node de destino expuser permissao para essas operacoes.
- RF-226: A Control Tower deve permitir acompanhar progresso de jobs de multiplos nodes em tempo real ou quase real por eventos de API.
- RF-227: A Control Tower deve preservar identificadores de correlacao para rastrear operacoes entre requisicao da Control Tower, node, jobs, chamadas entre nodes e logs.
- RF-228: A Control Tower deve permitir filtrar ou buscar nodes por nome, estado, cluster, endereco ou capacidade quando houver muitos nodes conhecidos.
- RF-229: A Control Tower deve exibir capacidades declaradas por node, como streaming HTTP, range requests, manifest de diretorio, resume e backends opcionais.
- RF-230: A Control Tower deve tratar nodes offline ou indisponiveis sem bloquear a operacao dos demais nodes.
- RF-231: A Control Tower deve indicar claramente quando uma operacao nao esta disponivel por falta de permissao, node offline, identidade alterada, capacidade ausente ou mount indisponivel.
- RF-232: A Control Tower nao deve conceder confianca transitiva entre nodes; operar por ela nao deve fazer um node confiar automaticamente em outro.
- RF-233: A Control Tower do MVP deve ser distribuida como imagem apartada, atuando como orquestrador opcional para centralizar operacoes do dia a dia sem remover a autonomia de cada node.
- RF-234: Quando a Control Tower coordenar operacoes entre dois nodes remotos, a transferencia de dados deve preferir conexao direta entre origem e destino sempre que tecnicamente possivel.
- RF-235: A Control Tower deve degradar graciosamente para operacao local quando nao houver peers online ou quando a conectividade com outros nodes estiver indisponivel.
- RF-236: A Control Tower nao deve persistir jobs de transferencia; jobs devem ser criados, persistidos e executados pelos nodes envolvidos.
- RF-237: A Control Tower deve autenticar chamadas de controle para nodes usando o token operacional configurado no node, preferencialmente via `CONTROL_TOWER_TOKEN`.

### 5.19 Convites e Escopo Operacional

- RF-238: Todo convite de pareamento deve declarar a operacao esperada entre os nodes antes da relacao de confianca ser criada.
- RF-239: O convite deve indicar o modo de transferencia esperado, usando no minimo `one_sided` ou `dual_channel`.
- RF-240: No modo `one_sided`, o convite deve declarar qual lado podera enviar, receber ou solicitar copia apos o pareamento.
- RF-241: No modo `dual_channel`, o convite deve declarar que ambos os nodes poderao enviar e receber dados, sempre limitados aos paths autorizados por cada lado.
- RF-242: O convite deve permitir descrever uma intencao operacional humana, como backup para NAS, importacao de midia, compartilhamento temporario ou sincronizacao manual futura.
- RF-243: O convite deve separar identidade de permissao: aceitar um convite estabelece confianca entre identidades, mas nao concede acesso irrestrito a arquivos.
- RF-244: Apos a confianca ser estabelecida, cada node deve elencar explicitamente os mounts e paths permitidos para transferencias com o outro node.
- RF-245: Cada Transfer Path Grant deve declarar path, mount, permissao de leitura, permissao de escrita, visibilidade remota e politicas permitidas de conflito.
- RF-246: Um node nao deve conseguir listar, ler, escrever ou transferir paths que nao tenham sido declarados e autorizados pelo node dono do filesystem.
- RF-247: Alteracoes em Transfer Path Grants devem ser persistidas, auditaveis e aplicadas imediatamente a novas operacoes.
- RF-248: A Control Tower deve permitir revisar, aceitar, negar ou ajustar o modo operacional e os paths propostos antes de finalizar o pareamento.
- RF-249: Quando os dois lados propuserem escopos diferentes, o sistema deve aplicar apenas a intersecao segura entre modo operacional, permissoes e paths efetivamente concedidos.
- RF-250: A Control Tower deve respeitar os Transfer Path Grants de cada node e nao deve exibir ou oferecer operacoes fora do escopo autorizado.

### 5.20 Mounts e Relacoes de Confianca

- RF-251: Mounts devem ser cadastrados diretamente no node como referencias logicas para caminhos locais de diretorios ou arquivos.
- RF-252: Mounts devem existir independentemente de conexoes, peers, nodes, clusters ou relacoes de confianca.
- RF-253: Um mount deve possuir identificador estavel, nome amigavel, caminho local referenciado, tipo de alvo, permissao logica, estado e diagnosticos.
- RF-254: Transfer Path Grants e listas de caminhos confiaveis somente podem referenciar mounts ja cadastrados no node dono do filesystem.
- RF-255: O sistema nao deve permitir adicionar a uma relacao de confianca um path arbitrario que nao esteja contido em um mount cadastrado.
- RF-256: O sistema nao deve criar mount automaticamente ao aceitar convite, criar peer ou configurar uma relacao de confianca.
- RF-257: Propostas de paths recebidas por convite ou peer devem ser tratadas como sugestoes e somente podem virar grants apos o usuario escolher um mount local ja cadastrado.
- RF-258: Um mount associado a qualquer Transfer Path Grant, peer, cluster ou relacao de confianca ativa nao deve poder ser deletado.
- RF-259: Para remover um mount associado, o usuario deve primeiro remover, revogar ou migrar todas as relacoes e grants que dependem dele.
- RF-260: O sistema pode permitir desabilitar ou ocultar um mount associado, mas deve preservar a referencia logica necessaria para auditoria, historico e jobs existentes.
- RF-261: Jobs existentes que referenciem um mount removido, desabilitado ou indisponivel devem falhar ou aguardar correcao com erro estruturado, sem cair para outro path automaticamente.
- RF-262: A Control Tower deve indicar quando um mount esta bloqueado para exclusao por estar associado a relacoes de confianca ou jobs persistidos.

### 5.21 Disaster Recovery

- RF-263: O sistema deve oferecer estrategia documentada de disaster recovery para nodes e Control Tower.
- RF-264: Cada node deve ser tratado como fonte de verdade para sua identidade, mounts, grants, peers, clusters, jobs, historico, parciais e configuracoes locais.
- RF-265: A Control Tower nao deve ser fonte de verdade para jobs ou relacoes entre nodes; sua perda nao deve apagar jobs, grants ou historico persistidos nos nodes.
- RF-266: O node deve permitir backup consistente do volume persistente contendo banco local, identidade criptografica, configuracoes, peers, clusters, mounts, grants, jobs e estado de retomada.
- RF-267: O backup do node deve preservar a identidade criptografica para evitar quebra de confianca com peers conhecidos.
- RF-268: O restore de um node com identidade preservada deve manter `node_id`, fingerprint, peers, grants e jobs retomaveis quando os mounts referenciados estiverem disponiveis.
- RF-269: O restore de um node sem identidade preservada deve ser tratado como novo node, exigindo novo pareamento e nova autorizacao de grants.
- RF-270: O node deve detectar inconsistencia entre banco restaurado e paths reais de mounts, marcando mounts ausentes ou divergentes como unavailable/degraded sem remapear automaticamente.
- RF-271: Jobs em andamento no momento de backup, crash ou restore devem ser reabertos em estado seguro como `interrupted`, `waiting_validation`, `waiting_mount` ou `waiting_peer`, conforme o motivo.
- RF-272: Antes de retomar jobs restaurados, o node deve revalidar identidade dos peers, grants, mounts, arquivos parciais, tamanhos, ranges, checksums quando configurados e politicas de conflito.
- RF-273: Arquivos parciais restaurados devem permanecer como parciais ate validacao explicita; o sistema nao deve promover parciais para arquivos finais automaticamente apos restore.
- RF-274: O sistema deve oferecer diagnostico de disaster recovery pela API e Control Tower, incluindo identidade restaurada, mounts ausentes, grants afetados, jobs aguardando validacao e parciais encontrados.
- RF-275: A Control Tower deve poder ser reconstruida a partir de configuracao propria e redescoberta/reconexao aos nodes usando tokens operacionais configurados.
- RF-276: A Control Tower pode persistir preferencias de exibicao, lista de nodes cadastrados e metadados operacionais, mas esses dados devem ser reconstruiveis a partir dos nodes e de configuracao externa.
- RF-277: O backup da Control Tower deve incluir apenas configuracao propria, tokens/segredos necessarios, preferencias e cadastro de endpoints dos nodes, nunca jobs como fonte de verdade.
- RF-278: A perda da Control Tower deve degradar a experiencia operacional centralizada, mas nao deve impedir nodes de continuar executando jobs ja criados ou aceitando operacoes pela API autenticada.
- RF-279: A rotacao do `CONTROL_TOWER_TOKEN` deve ser suportada como parte de recuperacao de credenciais comprometidas, exigindo atualizacao coordenada no node e na Control Tower.
- RF-280: O sistema deve documentar procedimentos de restore de node, restore de Control Tower, perda de volume persistente, troca de host, restauracao de mount em novo caminho e rotacao emergencial de tokens.

### 5.22 Chaves e mTLS

- RF-289: O node deve suportar um diretorio dedicado para material criptografico, configuravel por variavel de ambiente e montado como volume separado.
- RF-290: O diretorio de keys deve armazenar identidade do node, chaves privadas, certificados mTLS, CAs confiaveis, certificados em rotacao e metadados de versao.
- RF-291: O node deve criar arquivos de chave com permissoes restritivas, preferencialmente `0600` para arquivos e `0700` para diretorios, respeitando UID/GID efetivo quando possivel.
- RF-292: O node deve recusar iniciar ou entrar em modo degraded quando o diretorio de keys estiver ausente, permissivo demais, ilegivel, nao gravavel quando necessario ou pertencente a UID/GID inesperado.
- RF-293: O diretorio de keys nao deve ser cadastrado automaticamente como mount de transferencia nem aparecer em Transfer Path Grants.
- RF-294: O sistema deve permitir usar chaves geradas automaticamente no primeiro boot ou chaves/certificados preprovisionados no diretorio de keys.
- RF-295: A API deve expor metadados seguros das chaves, como fingerprint, validade, emissor, versao e estado de rotacao, sem expor material privado.
- RF-296: O sistema deve suportar rotacao planejada de certificados mTLS com janela de sobreposicao entre certificado atual e proximo certificado.
- RF-297: A rotacao mTLS deve permitir publicar novo certificado publico para peers antes de promover a nova chave como ativa.
- RF-298: Durante a janela de rotacao, peers autorizados devem poder confiar no certificado atual e no proximo certificado quando ambos estiverem vinculados a mesma identidade confiavel do node.
- RF-299: A promocao de novo certificado mTLS deve ser atomica, auditavel e reversivel enquanto o certificado anterior ainda estiver dentro da janela de grace.
- RF-300: Transferencias em andamento nao devem ser derrubadas apenas pela criacao de uma nova chave; novas conexoes devem usar o material ativo mais recente apos promocao.
- RF-301: O sistema deve suportar revogacao emergencial de certificado mTLS comprometido, bloqueando novas conexoes com o certificado revogado e exigindo confirmacao manual quando necessario.
- RF-302: O backup e restore do diretorio de keys deve preservar identidade e cadeia de confianca; perda desse diretorio deve ser tratada como perda de identidade do node.

### 5.23 Autenticacao e RBAC da Control Tower

- RF-303: A Control Tower deve exigir login para usuarios humanos antes de exibir nodes, mounts, jobs, configuracoes ou operacoes.
- RF-304: A Control Tower deve criar um usuario admin no boot da aplicacao quando ainda nao existir nenhum usuario administrativo.
- RF-305: O bootstrap do usuario admin deve aceitar credenciais por variaveis de ambiente, arquivo de configuracao seguro ou fluxo inicial protegido.
- RF-306: Senhas de usuarios da Control Tower devem ser armazenadas usando Argon2id com parametros configuraveis e seguros por padrao.
- RF-307: A Control Tower deve autenticar usuarios humanos usando cookies de sessao HTTP-only, Secure quando HTTPS estiver ativo, SameSite e expiracao configuravel.
- RF-308: Sessoes devem ser persistidas no SQLite da Control Tower e poder ser revogadas individualmente ou globalmente.
- RF-309: O SQLite da Control Tower deve ser criptografado usando encryption key fornecida por variavel de ambiente ou arquivo secreto montado.
- RF-310: A Control Tower nao deve iniciar em modo normal se a encryption key obrigatoria estiver ausente, invalida ou incapaz de abrir o banco existente.
- RF-311: A Control Tower deve permitir criar, editar, desabilitar e remover usuarios, preservando auditoria.
- RF-312: A Control Tower deve permitir criar, editar, desabilitar e remover service accounts para automacao.
- RF-313: Service accounts devem autenticar por token proprio ou credencial equivalente, armazenada apenas em formato seguro ou irreversivel quando aplicavel.
- RF-314: Service accounts nao devem usar cookies de sessao de navegador por padrao.
- RF-315: A Control Tower deve implementar RBAC por policies aplicadas a Node Paths.
- RF-316: O modelo de RBAC deve ser semelhante ao HashiCorp Vault, com paths e capabilities.
- RF-317: Capabilities minimas devem incluir `read`, `list`, `create`, `update`, `delete`, `write`, `execute`, `sudo` e `deny`.
- RF-318: A capability `deny` deve ter precedencia sobre permissoes concedidas por outras policies.
- RF-319: A capability `sudo` deve ser exigida para operacoes administrativas sensiveis, como gerenciar usuarios, service accounts, policies, tokens de nodes e rotacao de credenciais.
- RF-320: Policies devem poder ser associadas a usuarios e service accounts.
- RF-321: A avaliacao de RBAC deve ocorrer antes de qualquer chamada da Control Tower para a API de um node.
- RF-322: Node Paths devem representar recursos e operacoes de nodes de forma previsivel, usando dominios separados para cadastro de mounts, gerenciamento de arquivos, transferencias, jobs, grants e recursos administrativos, sem RBAC por subdiretorio interno do mount.
- RF-323: A Control Tower deve ocultar ou desabilitar acoes para as quais o usuario nao possua capability suficiente.
- RF-324: Toda negacao de permissao deve retornar erro compreensivel e gerar evento de auditoria sem expor segredos.
- RF-325: A Control Tower deve registrar auditoria de login, logout, falhas de login, criacao de sessao, revogacao de sessao, alteracao de usuario, service account, policy e tentativas negadas por RBAC.
- RF-326: O admin inicial deve receber policy administrativa completa, mas policies futuras devem seguir principio de menor privilegio.
- RF-327: O token operacional usado pela Control Tower para chamar nodes nao deve substituir autenticacao de usuario nem RBAC da Control Tower.
- RF-328: Em operacoes iniciadas por service account, eventos, jobs e logs devem registrar a service account como ator original.
- RF-329: As rotas da API da Control Tower devem ser desenhadas para mapear diretamente para Node Paths de RBAC.
- RF-330: A Control Tower deve autorizar acesso a arquivos no nivel do mount inteiro; subpaths informados em query/body nao devem alterar a decisao de RBAC.
- RF-331: Operacoes de arquivo dentro de um mount devem receber subpath como parametro de operacao, nao como segmento de RBAC.
- RF-332: Rotas administrativas da Control Tower devem usar prefixo separado de rotas de nodes, por exemplo `/api/v1/control-tower/...`.
- RF-333: Rotas que instrumentam nodes devem usar prefixo estavel com `node_id`, por exemplo `/api/v1/nodes/{node_id}/...`.
- RF-334: O dominio `files` do RBAC deve cobrir gerenciamento de arquivos dentro de mounts, como listar, baixar, enviar, criar diretorio, renomear, mover, copiar localmente e remover.
- RF-335: O dominio `transfers` do RBAC deve cobrir criacao, planejamento, execucao e controle de transferencias entre nodes.
- RF-336: Permissoes concedidas no dominio `files` nao devem autorizar automaticamente operacoes no dominio `transfers`.
- RF-337: Iniciar uma transferencia pela Control Tower deve exigir permissao no dominio `transfers` e tambem permissao compativel nos mounts de origem e destino no dominio `files`.
- RF-338: O sistema deve expor um conceito de API Filesystem para acesso distribuido e controlado a arquivos e diretorios via API.
- RF-339: O API Filesystem deve permitir que usuarios, service accounts, automacoes e agentes de IA acessem apenas mounts e operacoes autorizadas por RBAC, grants e configuracao local do node.
- RF-340: O API Filesystem nao deve expor caminhos absolutos reais do host para clientes nao administrativos; clientes devem operar com `node_id`, `mount_id` e `path` relativo.
- RF-341: Toda operacao do API Filesystem deve passar pelas mesmas validacoes de autenticacao, RBAC, path traversal, permissao real do filesystem, idempotencia quando mutavel e auditoria.
- RF-342: O API Filesystem deve oferecer respostas estruturadas com metadados suficientes para automacoes e agentes de IA, como tipo, tamanho, timestamps, checksum quando disponivel, permissao efetiva, limites e erros acionaveis.
- RF-343: A Control Tower deve permitir emitir credenciais de service account para automacoes e agentes de IA com policies restritas ao dominio `files` e/ou `transfers`.
- RF-344: O sistema deve permitir revogar ou rotacionar credenciais de automacao sem alterar mounts, grants ou identidade criptografica dos nodes.
- RF-345: A Control Tower deve permitir criar, listar, editar e remover roles com nome, descricao e conjunto de policies.
- RF-346: Uma role deve poder conter varias policies, e uma mesma policy deve poder participar de varias roles.
- RF-347: Um usuario deve poder receber varias roles e herdar a uniao das policies contidas nelas.
- RF-348: Policies associadas diretamente ao usuario e policies herdadas por roles devem ser avaliadas em conjunto, sem duplicar efeitos, mantendo `deny` com precedencia global.
- RF-349: Criacao, alteracao, remocao e associacao de roles devem exigir `sudo` e gerar auditoria.

## 6. Requisitos Nao Funcionais

### 6.1 Disponibilidade e Resiliencia

- RNF-001: O sistema nao deve depender de um servidor central obrigatorio para operacoes entre peers conhecidos.
- RNF-002: A indisponibilidade de um node nao deve impedir o funcionamento dos demais.
- RNF-003: Jobs envolvendo nodes offline devem ficar pausados, falhos ou aguardando reconexao sem travar a aplicacao.
- RNF-004: O sistema deve recuperar estado de jobs apos reinicio do processo ou container.
- RNF-005: O sistema deve tolerar quedas de rede durante transferencias grandes.
- RNF-006: O sistema deve evitar corrupcao de arquivos por meio de arquivos temporarios e finalizacao atomica quando suportada pelo sistema de arquivos.
- RNF-007: Jobs de vida longa devem ser duraveis e retomaveis quando tecnicamente possivel.
- RNF-008: Falhas parciais devem ser isoladas no menor nivel viavel, como chunk ou arquivo, evitando reiniciar jobs inteiros sem necessidade.
- RNF-009: Jobs devem registrar causa de parada ou falha de forma suficiente para retomada, diagnostico e exibicao ao usuario.

### 6.2 Performance

- RNF-010: O backend nao deve carregar arquivos grandes inteiros em memoria.
- RNF-011: O sistema deve conseguir transferir arquivos de pelo menos 10 GB usando memoria limitada.
- RNF-012: O sistema deve conseguir planejar e transferir diretorios de pelo menos 100 GB e milhares de arquivos.
- RNF-013: Listagens de diretorios grandes devem ser paginadas, limitadas ou transmitidas de forma incremental.
- RNF-014: A geracao de manifest deve evitar uso excessivo de memoria.
- RNF-015: Checksums completos devem ser opcionais para evitar custo alto em massas grandes de dados.
- RNF-016: O sistema deve permitir configurar paralelismo para equilibrar velocidade, disco, CPU e rede.
- RNF-017: A Control Tower deve manter a interface responsiva durante jobs longos.
- RNF-018: O processo idle deve manter baixo consumo de CPU, disco e rede.
- RNF-019: O processo idle nao deve varrer diretorios grandes nem calcular checksums automaticamente.

### 6.3 Seguranca

- RNF-020: A comunicacao entre peers deve ser autenticada.
- RNF-021: A comunicacao entre peers deve ser criptografada quando trafegar fora de ambientes explicitamente confiaveis.
- RNF-022: Transferencias entre nodes devem usar mTLS; controle operacional da Control Tower deve usar o token operacional configurado no node, evitando senhas compartilhadas simples.
- RNF-023: O sistema deve permitir revogar acesso de peers.
- RNF-024: O sistema deve isolar acesso aos caminhos configurados como mounts.
- RNF-025: O sistema deve validar e normalizar caminhos antes de acessar o sistema de arquivos.
- RNF-026: O sistema deve proteger contra path traversal.
- RNF-027: Segredos locais devem ser armazenados de forma segura dentro do volume persistente.
- RNF-028: Operacoes destrutivas devem exigir permissao explicita.
- RNF-029: A Control Tower e a API HTTP autenticada dos nodes devem exigir autenticacao quando expostas em rede nao confiavel.
- RNF-030: A chave principal de identidade do node nao deve expirar automaticamente, para evitar quebra inesperada de pareamentos confiaveis.
- RNF-031: Convites de pareamento devem expirar em prazo curto, com padrao recomendado entre 10 e 30 minutos.
- RNF-032: Credenciais operacionais temporarias devem ter tempo de vida limitado.
- RNF-033: A rotacao de identidade principal deve ser uma acao explicita e auditavel.
- RNF-034: Mudancas inesperadas na identidade de um peer conhecido devem gerar alerta de seguranca.
- RNF-035: A revogacao de peer deve ter efeito imediato sobre novas operacoes autenticadas.

### 6.4 Integridade de Dados

- RNF-036: Arquivos recebidos devem ser gravados inicialmente como parciais/temporarios.
- RNF-037: Arquivos finais nao devem ser publicados como completos antes da validacao minima.
- RNF-038: O sistema deve validar tamanho final dos arquivos.
- RNF-039: O sistema deve oferecer checksum opcional por arquivo.
- RNF-040: O sistema pode oferecer checksum opcional por chunk.
- RNF-041: O sistema deve detectar mudancas no arquivo de origem durante a transferencia quando possivel.
- RNF-042: O sistema deve preservar estrutura de diretorios em copias de pasta.
- RNF-043: O sistema deve tratar nomes de arquivo com espacos, caracteres especiais e diretorios profundos.
- RNF-044: Sobrescritas devem evitar perda de dados quando a nova copia ainda nao foi validada.
- RNF-045: Overrides de arquivos devem ser registrados de forma auditavel.

### 6.5 Usabilidade

- RNF-046: A interface da Control Tower deve ser mobile-first.
- RNF-047: Operacoes comuns devem exigir poucos cliques.
- RNF-048: A Control Tower deve comunicar claramente origem, destino e impacto de uma transferencia.
- RNF-049: Jobs longos devem mostrar progresso, velocidade e estimativa de tempo quando possivel.
- RNF-050: Falhas parciais em diretorios grandes devem ser visiveis e acionaveis.
- RNF-051: A Control Tower deve permitir retomar ou tentar novamente sem exigir recriar todo o job.
- RNF-052: A Control Tower deve evitar termos excessivamente tecnicos em fluxos comuns.
- RNF-053: A interface da Control Tower deve funcionar bem em telas pequenas e com toque.

### 6.6 Portabilidade

- RNF-054: O sistema deve rodar em Linux via Docker.
- RNF-055: O sistema deve ser compativel com hosts comuns como NAS, servidores domesticos, desktops e VPS.
- RNF-056: O backend deve evitar dependencias externas obrigatorias quando possivel.
- RNF-057: Protocolos opcionais como `rsync` ou `SSH/SFTP` nao devem ser requisitos obrigatorios do MVP.
- RNF-058: A imagem Docker deve ser pequena o suficiente para uso domestico e em servidores modestos.

### 6.7 Observabilidade

- RNF-059: O sistema deve expor healthcheck.
- RNF-060: O sistema deve produzir logs estruturados ou minimamente parseaveis.
- RNF-061: O sistema deve registrar metricas basicas de transferencias, como bytes enviados, bytes recebidos, duracao e falhas.
- RNF-062: O sistema deve permitir diagnosticar peers offline ou inacessiveis.
- RNF-063: Erros devem conter contexto suficiente para suporte sem expor segredos.
- RNF-064: O sistema deve expor estado resumido do node local, incluindo idle, transferring, degraded e setup_required.
- RNF-065: O sistema deve expor estado resumido de peers conhecidos sem exigir operacoes pesadas.

### 6.8 Manutenibilidade

- RNF-066: O backend deve separar modulos de API, persistencia, filesystem, peers e transferencias.
- RNF-067: O motor de transferencia deve ser projetado para aceitar backends alternativos no futuro.
- RNF-068: O frontend da Control Tower deve separar componentes de navegacao, selecao, jobs, configuracoes e administracao de nodes.
- RNF-069: O projeto deve incluir testes automatizados para logica critica de paths, permissoes e transferencias.
- RNF-070: O projeto deve documentar configuracao, deploy e fluxo de pareamento.

## 7. Requisitos de Arquitetura

### 7.1 Componentes Principais

#### 7.1.1 Backend

- O backend deve ser implementado preferencialmente em Go.
- O backend deve expor API HTTP autenticada para Control Tower, Swagger/OpenAPI e automacao, alem da porta mTLS para peers.
- O backend deve possuir um modulo de transferencia capaz de streaming, ranges, chunks e retomada.
- O backend deve possuir nodes para executar jobs em fila.
- O backend deve persistir estado em SQLite ou banco local equivalente.
- O backend deve usar acesso ao filesystem com validacao rigorosa de paths.

#### 7.1.2 Estrutura de Diretorios do Backend

O backend deve seguir uma estrutura simples, orientada por responsabilidade e dominio, evitando acoplamento direto entre handlers de API, regras de negocio, persistencia, filesystem e SDKs externos.

Estrutura recomendada:

```text
backend/
  cmd/
    jolt-node/
      main.go
  internal/
    services/
      foo/
    infra/
      db/
      filesystem/
      http/
      mtls/
      config/
      crypto/
    models/
    schemas/
    mappers/
    repositories/
      foo/
    constants/
    entities/
    contracts/
```

Responsabilidades:

- `cmd/jolt-node`: ponto de entrada do binario do node; deve montar configuracao, dependencias, rotas, nodes e processo de shutdown.
- `internal/services`: logica de dominio e casos de uso do sistema. Deve coordenar operacoes como mounts, peers, grants, jobs, manifest, transferencias, path validation, politicas de conflito, configuracao e auditoria. Subpastas por dominio, como `services/mounts`, `services/transfers`, `services/jobs` ou `services/foo`, devem agrupar regras proximas.
- `internal/infra`: adaptadores tecnicos e detalhes externos ao dominio, como filesystem, SQLite, HTTP clients, servidor HTTP, mTLS, leitura de variaveis de ambiente, chaves criptograficas, logs e SDKs. Codigo nessa camada nao deve conter regra de negocio central.
- `internal/infra/db`: conexao SQLite, migracoes, transacoes, helpers de query e configuracao do banco local.
- `internal/models`: structs ligadas a armazenamento, chamadas externas ou representacoes persistidas. Exemplos: registros de banco, payloads de SDK, modelos de tabela e structs usados por repositories.
- `internal/schemas`: structs de entrada e saida da API com validacoes de transporte. Exemplos: request/response de HTTP, query params, payloads de criacao de job, patch de configuracao e filtros.
- `internal/mappers`: conversoes explicitas entre schemas, models e entities. Deve concentrar transformacoes de DTOs, mascaramento de segredos e montagem de respostas de API.
- `internal/repositories`: acesso a dados e integracoes consultivas, como chamadas ao banco, chamadas HTTP entre nodes ou storage tecnico. Repositories devem depender de `models` e retornar dados para services sem embutir decisao de dominio.
- `internal/repositories/foo`: repositorios agrupados por dominio quando houver volume suficiente, como `jobs`, `mounts`, `peers`, `audit` ou `foo`.
- `internal/constants`: constantes globais do sistema, nomes de estados, defaults, headers, nomes de capabilities, limites padrao e chaves de contexto. Deve evitar virar deposito de regra de negocio.
- `internal/entities`: structs do fluxo principal do sistema, usadas como DTOs internos de dominio. Exemplos: `Node`, `Mount`, `Peer`, `TransferJob`, `TransferItem`, `Manifest`, `PathGrant`, `Capability` e `AuditEvent`.
- `internal/contracts`: interfaces e contratos do sistema. Deve declarar portas consumidas pelos services, como repositories, filesystem, clock, event bus, job queue, transfer backend, authorizer e key store.

Diretrizes de dependencia:

- `services` podem depender de `entities`, `contracts`, `constants` e `mappers`, mas nao devem depender diretamente de detalhes de `infra`.
- `infra` e `repositories` implementam interfaces de `contracts`.
- `schemas` representam a borda da API; nao devem ser usados como modelo principal de dominio.
- `models` representam persistencia ou integracao; nao devem escapar para handlers quando uma `entity` ou `schema` for mais adequada.
- `mappers` devem ser preferidos a conversoes espalhadas em handlers, services e repositories.
- regras criticas de path traversal, permissao, grants, conflito, idempotencia e auditoria devem ficar em `services` ou helpers de dominio chamados por `services`, nunca apenas em handlers.

Exemplo conceitual de fluxo:

```text
HTTP schema -> mapper -> service -> contract -> repository/infra -> model
                       -> entity  -> mapper   -> HTTP response schema
```

### 7.2 API-first e Orquestracao

O `jolt` deve ser API-first. A API deve ser a fronteira oficial para qualquer operacao de leitura, escrita, listagem, transferencia, validacao ou administracao.

Clientes suportados devem usar o mesmo caminho de execucao:

- Control Tower;
- Swagger/OpenAPI do node;
- CLI futura;
- chamadas entre peers;
- orquestradores externos;
- automacoes locais;
- integrações futuras.

A Control Tower e demais clientes nao devem acessar filesystem, banco local ou motor de transferencia diretamente. Eles devem consumir a API autenticada e assinar eventos de progresso ou estado.

Um orquestrador externo deve conseguir:

- listar nodes conhecidos;
- listar mounts autorizados;
- listar arquivos e diretorios;
- criar jobs;
- acompanhar progresso;
- pausar, retomar ou cancelar jobs;
- fornecer decisoes de conflito;
- consultar historico;
- consultar estado de peers;
- consultar eventos e logs permitidos;
- iniciar operacoes contra um node especifico quando possuir permissao.

Operacoes iniciadas por orquestrador devem ser indistinguiveis das operacoes iniciadas pela Control Tower do ponto de vista de seguranca, validacao, auditoria e persistencia.

Operacoes mutaveis devem suportar idempotencia. Quando um orquestrador repetir uma requisicao por timeout ou falha de rede, o sistema deve evitar criar jobs duplicados ou aplicar a mesma escrita duas vezes.

#### 7.2.1 API Filesystem Distribuido

O `jolt` deve oferecer um API Filesystem: uma representacao logica, distribuida e controlada de arquivos e diretorios acessiveis pelos nodes. Ele deve existir para evitar que usuarios, automacoes, integracoes e agentes de IA precisem de SSH, SMB, NFS, credenciais do sistema operacional ou acesso direto ao disco dos servidores.

Principios:

- o node dono do filesystem real continua sendo a fonte de verdade;
- clientes enxergam apenas `node_id`, `mount_id`, metadados e paths relativos;
- paths absolutos reais do host ficam encapsulados no node e so aparecem em diagnosticos administrativos quando permitido;
- toda operacao passa por API autenticada;
- toda decisao de acesso passa por RBAC, grants aplicaveis, validacao de path e permissao real do filesystem;
- toda operacao relevante gera auditoria com ator, tipo de ator, origem da credencial, Node Path, mount, path relativo e resultado;
- o contrato deve ser previsivel o bastante para automacoes e agentes de IA planejarem acoes sem descobrir detalhes internos do servidor;
- respostas devem ser estruturadas, com erros estaveis e acionaveis.

O API Filesystem deve cobrir no minimo:

- descoberta de nodes e capabilities;
- listagem de mounts autorizados;
- navegacao de diretorios por `mount_id` e `path` relativo;
- leitura de metadados de arquivos e diretorios;
- download e upload controlados;
- criacao de diretorio;
- rename, move, copia local e delete;
- planejamento de transferencias entre nodes;
- observabilidade de jobs criados por operacoes de filesystem ou transferencia.

Automacoes e agentes de IA devem ser tratados como clientes de baixa confianca por padrao. Eles devem usar service accounts com policies explicitas, escopo minimo, expiracao ou rotacao configuravel e auditoria detalhada. Uma automacao nunca deve receber permissao implicita por estar rodando no mesmo host da Control Tower.

O API Filesystem nao deve prometer consistencia global forte entre nodes. Cada operacao deve declarar o node e o mount alvo, e respostas devem refletir o estado observado naquele node no momento da chamada. Quando um node estiver offline, degradado ou com mount indisponivel, a API deve retornar estado estruturado em vez de tentar acessar o filesystem por outro caminho.

Todas as operacoes relevantes devem produzir eventos com identificadores de correlacao para permitir rastreamento entre:

- requisicao original;
- job criado;
- itens processados;
- chamadas entre peers;
- eventos de progresso;
- logs de auditoria.

O contrato da API deve ser documentado, preferencialmente em OpenAPI, para permitir clientes e orquestradores externos.

#### 7.2.2 Modelo de Configuracao

Cada node deve montar uma configuracao efetiva a partir de camadas bem definidas.

Camadas de leitura, da menor para a maior precedencia:

- valores padrao compilados no binario;
- arquivo de configuracao montado no container;
- variaveis de ambiente;
- banco local persistido;
- overrides temporarios de runtime quando existirem.

Precedencia recomendada:

- valores padrao existem apenas como fallback;
- arquivo de configuracao define bootstrap declarativo;
- variaveis de ambiente sobrescrevem arquivo para facilitar Docker/Compose;
- banco local persiste alteracoes feitas por API autenticada ou Control Tower;
- configuracoes marcadas como locked por ambiente nao podem ser sobrescritas pelo banco.

Tipos de configuracao:

- **Bootstrap imutavel em runtime**: porta HTTP da API, porta mTLS, path do volume interno, path do banco, `CONTROL_TOWER_TOKEN`, modo de exposicao e endpoints publicos base. Alteracoes exigem reinicio.
- **Configuracao operacional mutavel**: nome amigavel do node, mounts cadastrados, permissao logica de mounts, grants, politicas padrao, limites de paralelismo, timeouts, retries e preferencias de limpeza. Alteracoes passam por API autenticada e sao persistidas no banco.
- **Estado observado**: disponibilidade de mounts, espaco em disco, permissao real do filesystem, estado de peers, jobs ativos, eventos idle e diagnosticos. Nao deve ser editado diretamente.
- **Segredos**: identidade criptografica, chaves privadas, tokens operacionais e credenciais temporarias. Devem ser persistidos separadamente ou marcados como secretos no banco, nunca retornados em claro.
- **Material criptografico em arquivo**: identidade, chaves privadas, certificados mTLS e CAs confiaveis devem ficar em diretorio de keys dedicado, fora dos mounts de transferencia.

Modelo conceitual:

```text
defaults -> config file -> environment -> persisted database -> effective config
                                                     |
                                                     v
                                            observed runtime state
```

Leitura pela API:

- `GET /config/effective`: retorna configuracao efetiva sem segredos.
- `GET /config/sources`: informa de onde veio cada campo, sem revelar valores secretos.
- `GET /config/schema`: retorna schema de configuracao e campos mutaveis/imutaveis.
- `GET /diagnostics/config`: retorna inconsistencias, campos ausentes, conflitos e avisos.

Escrita pela API:

- `PATCH /config`: altera apenas campos mutaveis.
- `PUT /mounts/{mount_id}` ou endpoint equivalente altera mounts.
- `PUT /policies/defaults` altera politicas padrao.
- `POST /config/reload` pode reler arquivo de configuracao quando tecnicamente seguro, mas nao deve alterar portas ou tokens sem reinicio.

Toda escrita de configuracao deve:

- exigir token operacional valido;
- validar schema e regras de dominio antes de persistir;
- gravar em transacao;
- emitir evento de auditoria;
- incluir identificador de correlacao;
- indicar se a alteracao aplica imediatamente ou exige restart;
- mascarar segredos em resposta, logs e eventos.

Armazenamento recomendado no node:

- SQLite para configuracoes mutaveis, peers, clusters, mounts, grants, jobs, eventos e diagnosticos.
- Arquivos no volume de keys para identidade criptografica, certificados mTLS, chaves privadas e CAs confiaveis.
- Arquivos no volume persistente de dados para banco, estado de jobs, metadados, diagnosticos e artefatos grandes quando apropriado.
- Arquivo de configuracao opcional para bootstrap declarativo e reprodutibilidade.

Exemplo conceitual de volumes:

```yaml
services:
  jolt-node:
    image: jolt/node:latest
    environment:
      - NODE_NAME=nas-home
      - API_PORT=8080
      - MTLS_PORT=8443
      - CONTROL_TOWER_TOKEN=change-me
      - JOLT_DATA_DIR=/var/lib/jolt
      - JOLT_KEYS_DIR=/var/lib/jolt-keys
      - PUID=1000
      - PGID=1000
      - UMASK=077
    volumes:
      - ./jolt-data:/var/lib/jolt
      - ./jolt-keys:/var/lib/jolt-keys
      - /srv/media:/mnt/media:rw
```

O volume `jolt-keys` deve ser tratado como material sensivel. Ele nao deve ser registrado automaticamente como mount, nao deve ser navegavel por peers e nao deve aparecer em grants.

A Control Tower deve ler e alterar configuracoes apenas pelas APIs dos nodes. Ela pode manter cache ou preferencias locais, mas o node permanece fonte de verdade da propria configuracao.

Conflitos entre camadas:

- se um campo estiver definido por ambiente e tambem no banco, a politica deve indicar se ambiente bloqueia o campo ou apenas define valor inicial;
- para o MVP, campos sensiveis e estruturais definidos por ambiente devem ser tratados como locked;
- a API deve mostrar que o campo esta bloqueado, mas nao deve retornar o valor secreto;
- tentativas de alterar campo locked devem retornar erro estruturado.

### 7.3 Permissionamento e Identidade de Arquivos

O `jolt` deve separar permissionamento em duas camadas:

- permissao logica da aplicacao;
- permissao real do filesystem.

A permissao logica define o que um usuario, peer, cluster ou operacao pode tentar fazer. A permissao real do filesystem define o que o sistema operacional permite que o processo faca com o UID/GID efetivo.

As duas camadas devem permitir a operacao para que ela seja executada.

#### 7.3.1 UID, GID e UMASK

O container deve seguir o formato de configuracao popularizado por imagens LinuxServer:

```yaml
environment:
  - PUID=1000
  - PGID=1000
  - UMASK=002
```

`PUID` define o usuario efetivo usado para criar arquivos. `PGID` define o grupo efetivo. `UMASK` define as permissoes padrao de arquivos e diretorios criados.

Aliases `UID` e `GID` podem ser aceitos como fallback, mas a documentacao oficial deve preferir `PUID` e `PGID`.

Exemplos de `UMASK`:

- `022`: arquivos geralmente `644`, diretorios geralmente `755`.
- `002`: arquivos geralmente `664`, diretorios geralmente `775`.
- `077`: arquivos geralmente `600`, diretorios geralmente `700`.

#### 7.3.2 Processo no Container

O container pode iniciar com privilegios suficientes para preparar usuario, grupo e diretorios internos, mas o processo principal do `jolt` deve rodar sem root permanente sempre que possivel.

Todos os arquivos criados pelo sistema devem usar o UID/GID efetivo configurado:

- uploads;
- arquivos recebidos de outro node;
- copias locais;
- diretorios criados;
- arquivos temporarios `.jolt.partial`;
- arquivos gerados por jobs internos.

#### 7.3.3 Modelo e Permissoes de Mount

Mounts sao referencias logicas locais do node para caminhos de diretorios ou arquivos. Eles devem ser cadastrados, validados e persistidos no node antes de poderem ser usados por peers, clusters, Control Tower ou jobs.

Um mount nao pertence a uma conexao com outro node. Relacoes de confianca, nodes e grants apenas referenciam mounts existentes por `mount_id`.

Cada mount deve possuir:

- `mount_id` estavel;
- nome amigavel;
- caminho local referenciado;
- tipo de alvo, como diretorio ou arquivo;
- permissao logica, como somente leitura ou leitura/escrita;
- estado operacional;
- diagnosticos de permissao e disponibilidade.

Essa permissao logica nao substitui a permissao real do filesystem. Se um mount estiver configurado como leitura/escrita, mas o UID/GID efetivo nao conseguir escrever, o sistema deve bloquear a escrita e mostrar diagnostico claro.

Nenhum Transfer Path Grant deve apontar diretamente para caminho absoluto do host. Grants devem apontar para `mount_id` cadastrado e, quando necessario, para subpath relativo dentro desse mount.

Um mount com relacoes, grants ou jobs persistidos associados nao deve ser deletado diretamente. A exclusao deve exigir primeiro a remocao, revogacao ou migracao dessas dependencias.

Durante setup e idle, o sistema deve verificar de forma leve:

- caminho existe;
- caminho e diretorio;
- leitura permitida;
- escrita permitida quando aplicavel;
- criacao e remocao de arquivo temporario quando o mount for leitura/escrita;
- owner, group e modo quando a plataforma permitir.

#### 7.3.4 Preservacao de Permissoes

No MVP, o sistema nao deve preservar owner, group ou mode originais por padrao ao copiar arquivos entre hosts.

Padrao recomendado:

- owner: UID efetivo do processo `jolt`;
- group: GID efetivo do processo `jolt`;
- mode: resultado do `UMASK` configurado.

Preservar metadados Unix pode ser adicionado em modo avancado futuro:

```yaml
filesystem:
  preserve_mode: false
  preserve_owner: false
  preserve_group: false
```

`preserve_owner` e `preserve_group` nao devem exigir que o container rode como root permanente.

#### 7.3.5 Diagnostico de Permissao

A Control Tower e a API devem conseguir explicar erros comuns:

- mount existe, mas nao e legivel;
- mount configurado como escrita, mas filesystem esta somente leitura;
- UID/GID efetivo nao tem permissao de escrita;
- arquivo temporario nao pode ser criado;
- arquivo temporario nao pode ser removido;
- destino nao pode ser sobrescrito;
- owner/group/mode sugerem configuracao incorreta de `PUID`, `PGID` ou `UMASK`.

### 7.4 Persistencia Segura de Chaves e Rotacao mTLS

O node deve separar dados operacionais de material criptografico. O banco e estado operacional ficam no volume de dados; identidade, chaves privadas, certificados e CAs confiaveis ficam no volume de keys.

#### 7.4.1 Diretorio de Keys

Variavel recomendada:

```text
JOLT_KEYS_DIR=/var/lib/jolt-keys
```

Estrutura conceitual:

```text
/var/lib/jolt-keys/
  identity/
    node.key
    node.pub
    fingerprint
  mtls/
    active/
      tls.key
      tls.crt
      ca.crt
      metadata.json
    next/
      tls.key
      tls.crt
      metadata.json
    previous/
      tls.crt
      metadata.json
    trust/
      peers/
        node_abc.crt
        node_xyz.crt
      revoked/
        serials.json
```

Permissoes recomendadas:

- diretorios: `0700`;
- chaves privadas: `0600`;
- certificados publicos: `0644` ou mais restritivo;
- owner/group: UID/GID efetivo do processo `jolt`;
- `UMASK` recomendado para keys: `077`.

O node deve validar esse diretorio no boot:

- existe;
- e diretorio;
- pertence ao UID/GID esperado quando a plataforma permitir;
- nao e world-writable;
- chaves privadas nao estao world-readable;
- possui espaco suficiente para escrita de rotacao;
- permite escrita atomica de arquivos temporarios.

Se a validacao falhar, o node deve entrar em `setup_required` ou `degraded`, conforme severidade. Falhas que exponham chave privada devem bloquear mTLS ate correcao.

#### 7.4.2 Criacao de Mount para Keys no Docker

O mount de keys e um volume Docker operacional, nao um Mount do dominio `jolt`.

Exemplo:

```yaml
services:
  node:
    image: jolt/node:latest
    environment:
      - JOLT_DATA_DIR=/var/lib/jolt
      - JOLT_KEYS_DIR=/var/lib/jolt-keys
      - CONTROL_TOWER_TOKEN=change-me
      - PUID=1000
      - PGID=1000
      - UMASK=077
    volumes:
      - ./data:/var/lib/jolt
      - ./keys:/var/lib/jolt-keys
      - /srv/media:/mnt/media
```

O diretorio `./keys` deve ser criado no host com acesso restrito ao usuario/grupo que executara o container. Ele nao deve ser incluido em `mounts` de transferencia.

#### 7.4.3 Estados do Material mTLS

Estados conceituais de certificado/chave mTLS:

- `active`: usado para novas conexoes.
- `next`: gerado ou importado, distribuido para peers, ainda nao ativo.
- `previous`: certificado antigo aceito durante janela de grace.
- `revoked`: certificado explicitamente bloqueado.
- `expired`: certificado fora da validade.

Metadados minimos:

- `key_id`;
- fingerprint;
- serial;
- not_before;
- not_after;
- issuer;
- subject;
- estado;
- criado_em;
- ativado_em;
- revogado_em quando aplicavel;
- motivo de revogacao quando aplicavel.

#### 7.4.4 Rotacao Planejada de mTLS

Fluxo recomendado:

- gerar novo par chave/certificado em `next` no MVP; importacao de material
  externo fica reservada ao roadmap pos-MVP;
- validar permissao e formato do material novo;
- publicar fingerprint e certificado publico novo para peers confiaveis;
- peers registram o certificado novo como proximo certificado aceito para o mesmo node;
- Control Tower mostra a janela de rotacao e peers ainda nao atualizados;
- operador promove `next` para `active`;
- certificado anterior passa para `previous`;
- novas conexoes usam `active`;
- conexoes existentes podem concluir com o certificado anterior;
- apos grace period, `previous` deixa de ser aceito para novas conexoes.

Durante a janela de sobreposicao, a confianca deve continuar vinculada a identidade estavel do node. Um certificado novo nao deve ser aceito se nao estiver associado ao mesmo node confiavel ou a uma aprovacao manual explicita.

#### 7.4.5 Revogacao Emergencial

Se uma chave mTLS for comprometida:

- marcar certificado/chave como `revoked`;
- bloquear novas conexoes que usem o certificado revogado;
- publicar evento de seguranca;
- exigir geracao/importacao de novo material;
- exigir redistribuicao de trust para peers;
- manter logs de auditoria sem expor chave privada;
- permitir que jobs afetados entrem em `waiting_peer`, `waiting_validation` ou `failed`.

Revogacao emergencial pode interromper transferencias em andamento se o risco de compromisso for maior que o custo operacional.

#### 7.4.6 APIs Conceituais de Keys

APIs devem retornar apenas metadados seguros:

- `GET /keys/status`;
- `GET /keys/mtls`;
- `POST /keys/mtls/next`;
- `POST /keys/mtls/promote`;
- `POST /keys/mtls/revoke`;
- `GET /keys/diagnostics`.

Nenhum endpoint deve retornar chave privada. Exportacao de certificado publico e CA confiavel pode ser permitida quando necessaria para pareamento ou rotacao.

### 7.5 Frontend da Control Tower

- O frontend deve existir na Control Tower, nao nos nodes.
- O frontend da Control Tower deve ser implementado preferencialmente em Vue 3.
- O frontend da Control Tower deve usar Vite.
- O frontend da Control Tower deve usar TypeScript.
- O frontend da Control Tower deve usar shadcn-vue como base de componentes.
- O frontend da Control Tower deve ser responsivo e mobile-first.
- O frontend da Control Tower deve consumir eventos de progresso em tempo real ou quase real a partir das APIs dos nodes.

#### 7.5.1 Estrutura de Diretorios do Frontend

O frontend da Control Tower deve usar uma estrutura por funcionalidades, inspirada em feature-sliced design, mas sem complexidade excessiva. A separacao deve favorecer telas e fluxos reais da Control Tower: navegacao de arquivos, nodes, jobs, pareamento, configuracoes, usuarios e policies.

Estrutura recomendada:

```text
frontend/
  src/
    app/
      App.vue
      router/
      providers/
      layouts/
    pages/
      nodes/
      files/
      transfers/
      jobs/
      pairing/
      settings/
      admin/
      login/
    features/
      node-status/
      file-browser/
      transfer-create/
      job-monitor/
      pairing-invite/
      mount-management/
      rbac-policy-editor/
      auth-session/
    entities/
      node/
      mount/
      file-entry/
      transfer-job/
      peer/
      policy/
      user/
    shared/
      api/
      ui/
      composables/
      lib/
      constants/
      types/
      stores/
      styles/
```

Responsabilidades:

- `src/app`: inicializacao da aplicacao, providers globais, roteamento, layouts base, tratamento de sessao e configuracao visual global.
- `src/pages`: composicao de telas roteaveis. Cada page deve combinar features e entidades sem concentrar regra complexa.
- `src/features`: fluxos acionaveis pelo usuario, como criar transferencia, navegar arquivos, acompanhar job, gerenciar mount, aceitar convite, editar policy ou encerrar sessao.
- `src/entities`: modelos de interface e pequenos componentes ligados a conceitos do dominio, como card de node, linha de arquivo, badge de peer, resumo de job ou permissao efetiva de mount.
- `src/shared/api`: cliente HTTP, tipagem de contratos gerados ou manuais, tratamento de erro estruturado, idempotency key e correlacao.
- `src/shared/ui`: componentes genericos reutilizaveis, preferencialmente baseados em shadcn-vue e Tailwind, sem conhecimento direto de dominio.
- `src/shared/composables`: composables genericos ou transversais, como `usePagination`, `useEventStream`, `useConfirmDialog` e `useResponsive`.
- `src/shared/lib`: funcoes utilitarias puras, formatadores, normalizacao de erros, datas, bytes e duracoes.
- `src/shared/constants`: constantes do frontend, como rotas, estados visuais, labels de capabilities e limites de UI.
- `src/shared/types`: tipos compartilhados quando nao pertencem claramente a uma entidade especifica.
- `src/shared/stores`: stores globais pequenas, como autenticacao, preferencias locais e estado de conexao. Estado de tela deve permanecer perto da page ou feature quando possivel.
- `src/shared/styles`: estilos globais, tokens, tema e integracao com Tailwind/shadcn-vue.

Diretrizes para o frontend:

- pages compoem; features executam fluxos; entities representam conceitos; shared fornece base tecnica e visual.
- A Control Tower deve consumir apenas APIs da Control Tower e dos nodes; nenhum componente deve assumir acesso direto a filesystem, banco ou motor de transferencia.
- Tipos de request/response devem ficar em `shared/api` ou ser gerados a partir do OpenAPI quando disponivel.
- Componentes de `shared/ui` nao devem importar stores, rotas ou APIs de dominio.
- Features podem usar entities e shared, mas devem evitar dependencias circulares entre features.
- Cada fluxo importante deve ter estados de loading, erro estruturado, vazio, sucesso, permissao negada e indisponibilidade de node.
- A organizacao deve continuar leve no MVP: uma feature so deve virar pasta propria quando possuir componentes, composables ou regras suficientes para justificar a separacao.

### 7.6 Docker

- O node deve ser empacotado em uma imagem Docker.
- A imagem do node deve conter um unico binario Go servindo API HTTP e Swagger/OpenAPI no MVP, sem frontend operacional.
- A Control Tower deve ser empacotada em uma imagem Docker apartada.
- O container do node deve expor uma porta HTTP configuravel.
- O container do node deve expor uma porta mTLS configuravel para transferencia node-to-node.
- O container do node deve receber o token operacional da Control Tower por variavel de ambiente.
- O container do node deve usar volume persistente para dados internos.
- Diretorios gerenciados devem ser fornecidos ao node como volumes montados.

### 7.7 Comunicacao Distribuida

- Cada node deve ser capaz de operar de forma autonoma.
- Nodes devem conversar diretamente entre si quando possivel.
- O sistema deve permitir peers com enderecos diferentes por rede local, VPN ou internet.
- Um relay futuro pode existir, mas nao deve ser requisito para o funcionamento basico entre peers diretamente alcancaveis.
- Transferencias node-to-node devem usar mTLS como modelo de autenticacao e criptografia do canal de dados.
- Operacoes de controle iniciadas pela Control Tower devem usar o token operacional configurado no node.

### 7.8 Reverse Proxy e TLS

O `jolt` deve funcionar atras de reverse proxies como Nginx e Traefik para exposicao da Control Tower e, quando necessario, da API HTTP autenticada dos nodes.

Para comunicacao node-to-node autenticada por certificado, a recomendacao padrao deve ser:

- conexao direta entre nodes; ou
- TLS passthrough no proxy.

Se o proxy terminar TLS, o `jolt` nao recebe diretamente o certificado TLS do peer. Portanto, autenticacao mTLS ponta a ponta deixa de funcionar nesse formato, a menos que o sistema esteja usando outro mecanismo de identidade assinado na camada da aplicacao.

#### 7.8.1 Separacao de Endpoints

O sistema deve permitir separar endpoints quando necessario:

- Control Tower atras de reverse proxy HTTP comum;
- API HTTP autenticada do node atras de reverse proxy HTTP comum quando explicitamente exposta;
- peer/data API mTLS por conexao direta ou TLS passthrough.

Exemplo conceitual:

```text
control.example.com         -> Control Tower via reverse proxy HTTP
node-api.example.com        -> API HTTP autenticada do node via reverse proxy HTTP
peer.jolt.example.com       -> peer/data API mTLS via TLS passthrough
```

#### 7.8.2 Nginx para Control Tower/API e Streams Grandes

Configuracao recomendada para proxy HTTP quando houver upload/download grande:

```nginx
server {
    listen 443 ssl http2;
    server_name jolt.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    client_max_body_size 0;
    client_body_timeout 1h;
    send_timeout 1h;

    location / {
        proxy_pass http://jolt:8080;
        proxy_http_version 1.1;

        proxy_request_buffering off;
        proxy_buffering off;
        proxy_max_temp_file_size 0;

        proxy_read_timeout 1h;
        proxy_send_timeout 1h;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Decisoes importantes:

- `client_max_body_size 0` remove limite de tamanho do corpo no Nginx.
- `proxy_request_buffering off` evita que o Nginx leia o upload inteiro antes de encaminhar.
- `proxy_buffering off` evita buffering de resposta para downloads e streams.
- `proxy_http_version 1.1` ajuda streaming e conexoes longas.
- timeouts devem ser compativeis com transferencias grandes.

#### 7.8.3 Nginx TLS Passthrough para Peer API

Para preservar mTLS ponta a ponta entre nodes, o Nginx deve operar em modo TCP stream:

```nginx
stream {
    upstream jolt_peer {
        server jolt:8443;
    }

    server {
        listen 443;
        proxy_pass jolt_peer;
        proxy_connect_timeout 10s;
        proxy_timeout 24h;
    }
}
```

Nesse modo, o Nginx nao termina TLS. O proprio `jolt` recebe e valida o certificado do peer.

#### 7.8.4 Traefik para Control Tower/API e Streams Grandes

Para rotas HTTP de Control Tower ou API autenticada, o Traefik pode ser usado normalmente, mas nao deve aplicar middleware de buffering em rotas de upload ou transferencia.

Se o middleware de buffering for usado, os limites devem ser explicitamente ilimitados:

```yaml
http:
  middlewares:
    jolt-buffering:
      buffering:
        maxRequestBodyBytes: 0
        maxResponseBodyBytes: 0
```

Configuracao de entrypoint para evitar timeouts inadequados em uploads grandes:

```yaml
entryPoints:
  websecure:
    address: ":443"
    transport:
      respondingTimeouts:
        readTimeout: "0s"
        writeTimeout: "0s"
        idleTimeout: "0s"
```

`readTimeout` deve ser configurado com cuidado, pois cobre a leitura da requisicao incluindo o corpo.

#### 7.8.5 Traefik TLS Passthrough para Peer API

Exemplo conceitual com labels Docker:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.tcp.routers.jolt-peer.rule=HostSNI(`peer.example.com`)"
  - "traefik.tcp.routers.jolt-peer.entrypoints=websecure"
  - "traefik.tcp.routers.jolt-peer.tls.passthrough=true"
  - "traefik.tcp.services.jolt-peer.loadbalancer.server.port=8443"
```

#### 7.8.6 Principios de Reverse Proxy

- Reverse proxy e suportado.
- Control Tower e API HTTP autenticada do node podem usar reverse proxy HTTP.
- Peer/data API com certificado deve preferir conexao direta ou TLS passthrough.
- Terminar TLS antes do `jolt` deve ser modo avancado e explicito.
- Proxies nao devem impor limite de tamanho para uploads e downloads grandes.
- Proxies nao devem bufferizar request/response de transferencias grandes.
- Timeouts devem ser configurados para streams longos.

### 7.9 Bootstrap

O bootstrap do `jolt` deve ser dividido em duas fases:

- bootstrap local do node;
- bootstrap de entrada em um cluster ou pareamento com peers.

#### 7.9.1 Bootstrap Local

No primeiro boot, o node deve:

- carregar configuracoes de ambiente, arquivo local e valores padrao;
- criar o diretorio interno de dados caso ele nao exista;
- inicializar o banco local;
- gerar identidade criptografica propria caso ainda nao exista;
- derivar o `node_id` a partir da identidade publica;
- gerar ou carregar a fingerprint curta exibida ao usuario;
- detectar mounts configurados;
- subir API HTTP autenticada;
- subir endpoint Swagger/OpenAPI;
- subir porta mTLS para transferencias node-to-node quando configurada.

Se o volume persistente ja possuir uma identidade, o node deve reutilizar essa identidade e nao deve gerar outra automaticamente.

#### 7.9.2 Setup Inicial

A primeira configuracao deve solicitar ou aceitar apenas informacoes essenciais por variaveis de ambiente, arquivo de configuracao, API autenticada ou Control Tower:

- nome amigavel do node;
- token operacional da Control Tower;
- confirmacao dos mounts detectados;
- permissao inicial dos mounts;
- modo de exposicao desejado: local, LAN, VPN/internet manual.

O node nao deve depender de navegador local para setup.

#### 7.9.3 Criacao de Cluster

Um node deve poder criar um novo cluster localmente.

Ao criar um cluster:

- o node atual deve ser registrado como membro inicial;
- nenhuma permissao total deve ser concedida automaticamente a futuros peers;
- mounts devem continuar usando politicas explicitas por peer ou por cluster;
- o cluster deve funcionar como agrupamento logico, nao como autoridade central permanente.

#### 7.9.4 Entrada em Cluster Existente

Um node deve poder entrar em um cluster existente por convite de pareamento.

O convite deve conter, no minimo:

- endereco do node emissor;
- identificador do convite;
- identidade publica ou fingerprint do emissor;
- expiracao;
- modo de transferencia esperado: `one_sided` ou `dual_channel`;
- papel operacional proposto para cada lado;
- identificador do cluster, quando aplicavel.

O convite pode conter:

- nome amigavel do emissor;
- permissoes sugeridas;
- paths ou mounts sugeridos para publicacao apos pareamento, tratados apenas como rascunho de configuracao;
- politicas de conflito sugeridas;
- capacidades esperadas, como manifest de diretorio, range requests ou resume;
- descricao humana da finalidade do pareamento;
- uso unico;
- metadados para QR code ou link `jolt://`.

#### 7.9.4.1 Modos Operacionais do Convite

O modo operacional define a direcao esperada das transferencias depois que os nodes criarem uma relacao de confianca.

Modos minimos:

- `one_sided`: apenas um lado deve expor paths para envio ou recebimento, conforme o papel declarado no convite.
- `dual_channel`: ambos os lados podem expor paths e realizar transferencias de envio e recebimento, respeitando os grants declarados por cada node.

Exemplos de `one_sided`:

- notebook envia backups para NAS domestico;
- camera ou servidor de midia envia arquivos para um node de arquivo;
- node de ingestao recebe uploads de outro node, mas nao permite leitura remota.

Exemplos de `dual_channel`:

- desktop e NAS podem copiar arquivos entre si;
- dois servidores confiaveis podem trocar bibliotecas autorizadas;
- dois nodes de um mesmo cluster podem enviar e receber jobs manuais.

O convite deve declarar papeis operacionais de forma explicita, por exemplo:

```json
{
  "transfer_mode": "one_sided",
  "issuer_role": "receiver",
  "invitee_role": "sender",
  "purpose": "backup-notebook-to-nas"
}
```

Para `dual_channel`, os papeis podem ser simetricos:

```json
{
  "transfer_mode": "dual_channel",
  "issuer_role": "sender_receiver",
  "invitee_role": "sender_receiver",
  "purpose": "manual-library-exchange"
}
```

Esses campos indicam intencao e ajudam a Control Tower a guiar o usuario, mas nao substituem grants explicitos de paths.

#### 7.9.4.2 Transfer Path Grants

Apos a relacao de confianca ser aprovada, cada node deve declarar os paths que aceita usar com o peer. Essa declaracao deve referenciar apenas mounts ja cadastrados no proprio node.

Um grant conceitual pode conter:

```json
{
  "grant_id": "grant_movies_rw",
  "mount_id": "movies",
  "path": "/incoming",
  "direction": "receive",
  "permissions": {
    "read": false,
    "write": true,
    "delete": false,
    "rename": false
  },
  "conflict_policies": ["skip_existing", "rename", "ask"],
  "visible_to_peer": true
}
```

Campos importantes:

- `mount_id`: mount local ao node dono do filesystem;
- `path`: path relativo ao mount, nunca caminho absoluto do host;
- `direction`: `send`, `receive` ou `send_receive`;
- `permissions`: operacoes permitidas nesse path;
- `conflict_policies`: politicas aceitas para jobs que usem esse path;
- `visible_to_peer`: se o peer pode listar esse grant remotamente.

Cada node e autoridade apenas sobre seus proprios grants. Em uma relacao `dual_channel`, os dois nodes devem declarar seus grants separadamente.

Um grant nao deve criar mount. Se o usuario quiser autorizar um caminho ainda nao cadastrado, deve primeiro criar o mount no node dono do filesystem e depois associar esse mount a relacao de confianca.

No MVP, grants devem suportar tanto mount inteiro quanto subdiretorio relativo dentro de um mount.

Um node pode aceitar o convite e ainda nao publicar nenhum path. Nesse caso, a relacao de confianca existe, mas nenhuma transferencia de arquivo deve ser possivel ate que grants sejam configurados.

#### 7.9.5 Handshake de Pareamento

O handshake de pareamento deve seguir este fluxo conceitual:

- o node entrante usa o convite para conectar ao node emissor;
- o node entrante valida endereco, expiracao e identidade do emissor;
- o node entrante revisa modo operacional, papeis esperados e finalidade do convite;
- a Control Tower mostra a fingerprint do emissor para conferencia humana;
- o node entrante envia sua identidade publica e metadados basicos;
- o node entrante pode enviar uma proposta inicial de Transfer Path Grants;
- o node emissor mostra a solicitacao pendente;
- o usuario do node emissor revisa identidade, modo operacional, papeis e grants propostos;
- o usuario do node emissor aprova, rejeita ou ajusta o pareamento;
- ambos persistem o peer conhecido apos aprovacao;
- cada node persiste apenas os grants que ele proprio concedeu;
- os grants efetivos sao divulgados ao peer pela API apos o pareamento;
- o convite e consumido quando for de uso unico;
- permissoes de mounts sao aplicadas explicitamente.

Para o MVP, o pareamento deve exigir confirmacao humana no minimo no lado que emitiu o convite. Quando possivel, a Control Tower deve permitir conferencia de fingerprint nos dois lados.

#### 7.9.6 Bootstrap por CLI ou Configuracao

O sistema deve ser projetado para permitir bootstrap sem depender exclusivamente da Control Tower.

Comandos ou operacoes equivalentes devem ser considerados:

- exibir fingerprint do node;
- criar convite;
- revogar convite;
- aceitar convite;
- listar peers;
- remover peer;
- exportar diagnostico basico.

Mesmo que a CLI nao seja entregue integralmente no MVP, o backend deve expor as capacidades necessarias para automacao futura.

#### 7.9.7 Descoberta Local

A descoberta local por mDNS pode ser adicionada apos o MVP.

Quando existir, a descoberta deve servir apenas para localizar nodes na rede local. Ela nao deve criar confianca automaticamente.

Um node descoberto por mDNS deve continuar exigindo pareamento, convite, fingerprint ou outro mecanismo explicito de confianca.

#### 7.9.8 Rebootstrap e Perda de Identidade

Se o volume persistente for apagado ou a identidade local for perdida, o node deve ser tratado como uma nova identidade, mesmo que use o mesmo nome amigavel.

Peers antigos devem tratar essa situacao como mudanca suspeita de identidade e exigir confirmacao manual antes de restaurar confianca.

O sistema deve deixar claro para o usuario que:

- apagar o volume persistente remove a identidade do node;
- uma nova identidade invalida pareamentos anteriores;
- restaurar identidade por backup deve ser uma operacao protegida.

#### 7.9.9 Principios de Bootstrap

- O bootstrap local nao deve depender de internet.
- Um node deve poder operar sozinho.
- A identidade deve ser criada uma vez por volume persistente.
- Convite nao substitui confirmacao de identidade.
- Descoberta nao implica confianca.
- Cluster nao implica permissao total.
- Apagar o volume persistente cria uma nova identidade.
- Reentrada com nova identidade exige confirmacao manual.
- Nenhum node deve virar autoridade central permanente por padrao.

### 7.10 Processo Idle dos Nodes

O estado idle e o modo normal de baixo consumo do `jolt`. Um node idle nao esta executando transferencias ativas, mas deve continuar disponivel, seguro e pronto para retomar ou iniciar jobs.

Durante idle, o node deve:

- manter API HTTP autenticada, Swagger/OpenAPI e porta mTLS disponiveis;
- acompanhar estado dos peers conhecidos;
- limpar convites e sessoes expiradas;
- verificar mounts de forma leve;
- observar jobs pendentes que dependem de peers offline;
- emitir eventos para a Control Tower;
- evitar varreduras pesadas em disco, checksums completos ou indexacao global.

#### 7.10.1 Estados do Node

O sistema deve considerar os seguintes estados conceituais para o node local:

- `starting`: processo iniciando.
- `setup_required`: identidade ou configuracao inicial ainda nao concluida.
- `ready`: node pronto para operar.
- `idle`: node pronto, sem transferencias ativas.
- `transferring`: node possui jobs em execucao.
- `degraded`: node opera parcialmente, mas algum recurso local esta com problema.
- `shutting_down`: node encerrando de forma ordenada.

Exemplos de estado `degraded`:

- mount configurado indisponivel;
- mount esperado como escrita esta somente leitura;
- volume persistente quase cheio;
- banco local com problema;
- falha recorrente na comunicacao com peers;
- credencial ou sessao operacional invalida.

#### 7.10.2 Estados dos Peers

O sistema deve considerar os seguintes estados conceituais para peers conhecidos:

- `unknown`: estado ainda nao determinado.
- `online`: peer respondeu heartbeat valido.
- `offline`: peer nao responde dentro da politica configurada.
- `untrusted`: peer nao possui confianca valida.
- `identity_changed`: peer conhecido apresentou identidade diferente da esperada.
- `degraded`: peer respondeu, mas informou problema operacional.

Um peer nao deve ser marcado como offline por uma unica falha. O sistema deve usar falhas consecutivas, janela de tempo ou combinacao das duas.

#### 7.10.3 Heartbeat

O heartbeat deve ser leve e nao deve carregar listagens de arquivos, manifests ou metadados pesados.

A resposta conceitual de heartbeat pode conter:

```json
{
  "node_id": "node_abc",
  "name": "nas-home",
  "fingerprint": "K9P4-M2Q7-L8XA",
  "status": "idle",
  "version": "0.1.0",
  "capabilities": ["http-range", "directory-manifest"],
  "active_jobs": 0
}
```

O node receptor deve validar a identidade do peer antes de atualizar seu estado como online.

Se um peer conhecido responder com mesmo endereco ou nome amigavel, mas identidade diferente, o estado deve ser alterado para `identity_changed`, a comunicacao deve ser bloqueada e a Control Tower deve exigir confirmacao manual.

#### 7.10.4 Intervalos Padrao

Valores padrao sugeridos:

```yaml
idle:
  peer_heartbeat_interval: 30s
  peer_offline_after: 3m
  mount_check_interval: 60s
  pending_job_check_interval: 15s
  expired_invite_cleanup_interval: 60s
  partial_cleanup_interval: 6h
  history_compaction_interval: 24h
```

Peers offline ou instaveis devem usar backoff progressivo, por exemplo:

- peer online: heartbeat a cada 30 segundos;
- primeira falha: tentar novamente em aproximadamente 10 segundos;
- falhas repetidas: aumentar para 30 segundos, 1 minuto e 5 minutos;
- peer offline por longo periodo: manter tentativas leves e espaçadas.

#### 7.10.5 Jobs Pendentes Durante Idle

Jobs que dependem de peer offline devem ficar em estado como `waiting_peer`.

Quando o peer voltar a ficar online, o sistema deve:

- validar identidade do peer;
- validar permissoes atuais;
- validar se mounts locais e remotos necessarios estao disponiveis;
- validar estado persistido de arquivos, chunks ou manifest;
- mover o job para `queued` quando for seguro retomar.

Retomar um job nao deve ignorar alteracoes de confianca, permissoes ou identidade ocorridas enquanto o peer esteve offline.

#### 7.10.6 Mounts Durante Idle

A verificacao de mounts em idle deve ser leve.

Ela pode verificar:

- existencia do caminho;
- se o caminho e diretorio;
- permissao de leitura;
- permissao de escrita quando aplicavel;
- espaco disponivel quando a plataforma permitir de forma barata.

Ela nao deve:

- calcular tamanho total de diretorios;
- gerar manifests automaticamente;
- calcular checksums;
- varrer arvores grandes;
- modificar arquivos de mounts sem job explicito.

#### 7.10.7 Eventos de Idle

Eventos relevantes para Control Tower e logs:

- `peer.online`;
- `peer.offline`;
- `peer.identity_changed`;
- `peer.degraded`;
- `mount.available`;
- `mount.unavailable`;
- `mount.read_only`;
- `job.ready_to_resume`;
- `invite.expired`;
- `session.expired`;
- `node.degraded`;

#### 7.10.8 Encerramento Ordenado

Ao receber sinal de encerramento, o node deve:

- parar de aceitar novos jobs;
- concluir ou interromper com seguranca operacoes em andamento;
- persistir estado dos jobs;
- marcar jobs em execucao como `interrupted` quando nao puder conclui-los;
- fechar conexoes com peers;
- encerrar o processo sem corromper banco ou arquivos parciais.

#### 7.10.9 Principios de Idle

- Idle deve ser leve.
- Idle deve ser seguro.
- Idle deve usar backoff para peers offline.
- Idle nao deve gerar carga pesada de disco ou rede.
- Idle nao deve criar confianca automaticamente.
- Idle deve preparar retomada de jobs, nao forcar retomada insegura.
- Transferencia e evento; vigilancia leve e a rotina.

### 7.11 Modelo de Jobs e Execucao

Jobs sao o modelo central para operacoes rastreaveis do `jolt`. Uma transferencia e um tipo de job, mas o conceito tambem deve cobrir operacoes de validacao, planejamento, verificacao, limpeza e retentativa.

Todo job deve saber:

- o que pretende fazer;
- qual fase esta executando;
- o que ja concluiu;
- por que parou;
- se pode retomar;
- o que precisa do usuario;
- quais itens falharam;
- qual politica de conflito e override esta ativa.

#### 7.11.1 Tipos de Jobs

Jobs curtos:

- validar destino;
- checar espaco disponivel;
- testar conexao com peer;
- criar ou revogar convite;
- listar metadados leves;
- validar permissao.

Jobs de vida longa:

- copiar arquivo grande;
- copiar diretorio grande;
- gerar manifest;
- comparar manifest;
- verificar checksum pos-transferencia;
- limpar arquivos parciais antigos;
- tentar novamente itens com falha.

Jobs curtos podem ser exibidos como operacoes imediatas na Control Tower, mas ainda devem gerar erro estruturado e log quando falharem. Jobs de vida longa devem ser persistidos, exibidos no historico e suportar acompanhamento de progresso.

#### 7.11.2 Estados de Job

Estados conceituais:

- `created`: job criado, ainda sem validacao completa.
- `validating`: validacoes iniciais em execucao.
- `planning`: manifest, comparacao ou plano de execucao em andamento.
- `queued`: pronto para executar.
- `running`: executando.
- `paused`: pausado pelo usuario ou por politica.
- `waiting_peer`: aguardando peer voltar.
- `waiting_space`: aguardando espaco disponivel.
- `waiting_user_decision`: aguardando decisao do usuario.
- `verifying`: validando resultado.
- `finalizing`: promovendo temporarios, preservando metadados e encerrando.
- `completed`: concluido sem erros relevantes.
- `completed_with_warnings`: concluido com falhas parciais ou avisos.
- `failed`: falhou sem conclusao aceitavel.
- `cancelled`: cancelado pelo usuario ou politica.
- `interrupted`: interrompido por queda, reinicio ou shutdown.

Jobs de diretorio devem poder concluir como `completed_with_warnings` quando a maioria dos itens foi processada, mas alguns arquivos falharam.

#### 7.11.3 Fases de Job

Fases conceituais:

- `validate_source`;
- `validate_target`;
- `estimate`;
- `plan`;
- `transfer`;
- `verify`;
- `finalize`;
- `cleanup`.

A Control Tower deve conseguir mostrar a fase atual para jobs de vida longa.

#### 7.11.4 Validacoes

Validacoes antes de iniciar:

- peer online quando aplicavel;
- identidade do peer valida;
- permissao de leitura na origem;
- permissao de escrita no destino;
- mounts disponiveis;
- espaco em disco suficiente ou aviso ao usuario;
- politica de conflito definida;
- arquivo ou diretorio de origem existente;
- destino permitido pelas regras de mount.

Validacoes durante o job:

- peer continua confiavel;
- arquivo de origem nao mudou, quando essa protecao estiver ativa;
- destino continua disponivel;
- espaco em disco continua suficiente;
- chunk recebido possui tamanho esperado;
- ausencia de progresso nao excedeu limite configurado;
- permissao nao foi revogada.

Validacoes depois do job:

- tamanho final bate com o esperado;
- checksum bate quando ativado;
- arquivo temporario foi promovido corretamente;
- estrutura de diretorios foi preservada;
- metadados configurados foram aplicados quando possivel;
- manifest final confere quando aplicavel.

#### 7.11.5 Retries

Retries devem existir em niveis diferentes:

- chunk retry;
- file retry;
- peer retry;
- job retry.

Valores padrao sugeridos:

```yaml
retries:
  chunk_max_attempts: 5
  file_max_attempts: 3
  peer_reconnect_max_attempts: 0
  retry_backoff: exponential
  retry_jitter: true
```

`peer_reconnect_max_attempts: 0` significa sem limite fixo para jobs de vida longa, desde que o job possa ficar em `waiting_peer` com backoff e sem consumir recursos excessivos.

Falhas transientes devem preferir retry ou estado de espera. Falhas de permissao, identidade alterada ou path invalido devem bloquear o job ate correcao ou decisao explicita.

#### 7.11.6 Timeouts

Timeouts devem ser separados por tipo de operacao.

Valores padrao sugeridos:

```yaml
timeouts:
  connect_timeout: 10s
  idle_read_timeout: 60s
  chunk_timeout: 5m
  file_timeout: 0
  job_timeout: 0
  validation_timeout: 2m
  manifest_timeout: 0
```

`file_timeout: 0`, `job_timeout: 0` e `manifest_timeout: 0` significam sem timeout global fixo por padrao. Para arquivos grandes e diretorios enormes, o sistema deve preferir detectar ausencia de progresso em vez de limitar duracao total.

#### 7.11.7 Estimativa de Tempo

Estimativa de conclusao deve ser tratada como informacao aproximada, nao como promessa.

Campos sugeridos:

- `total_bytes`;
- `completed_bytes`;
- `total_files`;
- `completed_files`;
- `failed_files`;
- `skipped_files`;
- `current_speed`;
- `average_speed`;
- `moving_average_speed`;
- `eta_seconds`;
- `eta_confidence`.

`eta_confidence` deve usar valores como:

- `low`;
- `medium`;
- `high`;
- `unknown`.

Antes de concluir manifest ou planejamento, a Control Tower deve poder mostrar estado como `Estimando...`. Depois do planejamento, deve mostrar bytes planejados, arquivos planejados, progresso e ETA quando houver dados suficientes.

#### 7.11.8 Overrides e Conflitos

Politicas de conflito por job:

- `skip_existing`: pular arquivo existente.
- `overwrite`: substituir arquivo existente.
- `rename`: manter ambos usando novo nome.
- `fail`: falhar item em conflito.
- `ask`: pedir decisao ao usuario.
- `checksum_then_decide`: comparar checksum antes de decidir.

Criterios de comparacao:

- `same_size`;
- `same_size_and_modtime`;
- `checksum`;
- `always`.

Quando `ask` for usado em jobs de diretorio, o job deve entrar em `waiting_user_decision` e permitir:

- decidir apenas para o item atual;
- aplicar a mesma decisao aos proximos conflitos;
- cancelar o job;
- pausar o job;
- revisar o plano.

#### 7.11.9 Arquivos Temporarios e Sobrescrita

Arquivos recebidos devem ser escritos em arquivo temporario, por exemplo:

```text
file.ext.jolt.partial
```

Finalizacao segura:

- escrever arquivo parcial;
- validar tamanho e checksum quando aplicavel;
- aplicar metadados quando configurado;
- promover o parcial para arquivo final por rename atomico quando suportado;
- registrar resultado do item.

Ao sobrescrever, o sistema nao deve apagar o arquivo existente antes de validar o novo arquivo parcial. Politicas futuras podem adicionar backup temporario antes da substituicao.

#### 7.11.10 Principios de Jobs

- Jobs devem ser persistentes.
- Jobs devem ser retomaveis quando tecnicamente possivel.
- Jobs devem ter estados explicitos.
- Jobs devem separar validacao, planejamento, execucao e verificacao.
- Retries devem ocorrer no menor nivel viavel.
- Timeouts globais nao devem prejudicar operacoes grandes.
- Estimativas devem expor incerteza.
- Overrides devem ser explicitos e auditaveis.
- Falhas parciais devem ser recuperaveis sem recriar todo o job.

### 7.12 Control Tower

A Control Tower deve ser uma camada de experiencia e orquestracao sobre nodes conhecidos, usando o contrato de API dos nodes como unica fronteira operacional.

Ela nao deve ser requisito para a rede funcionar. Cada node deve continuar capaz de operar sozinho, parear peers, navegar mounts autorizados e executar jobs pela propria API autenticada.

Responsabilidades principais:

- manter uma visao consolidada dos nodes autorizados na Control Tower;
- exibir estado, capacidades, clusters, endpoints, fingerprints e diagnosticos permitidos;
- permitir navegar mounts e arquivos de qualquer node autorizado;
- iniciar operacoes contra o node selecionado usando a API dele;
- instrumentar a criacao de jobs nos nodes envolvidos;
- acompanhar jobs que envolvam um ou mais nodes;
- agregar eventos de progresso e logs permitidos em uma linha do tempo unica;
- preservar idempotencia, correlacao, auditoria e validacoes de seguranca.

Limites arquiteturais:

- a Control Tower nao deve acessar diretamente arquivos ou banco de outro node;
- a Control Tower nao deve substituir pareamento, trust ou autorizacao entre nodes;
- a Control Tower nao deve criar confianca transitiva;
- a Control Tower nao deve persistir jobs;
- a Control Tower nao deve ser dona da fila de jobs dos nodes;
- jobs devem ser persistidos nos nodes responsaveis por executa-los;
- a logica de execucao deve permanecer nos nodes dos nodes;
- transferencia de dados deve ocorrer entre os nodes participantes quando possivel, com a Control Tower apenas coordenando controle e visualizacao.

Modelo conceitual de UI da Control Tower:

- `Nodes`: lista de nodes com estado, cluster, endereco, fingerprint curta e capacidades.
- `Explorer`: navegacao de mounts e arquivos do node selecionado.
- `Operations`: acoes disponiveis para selecao atual, respeitando permissoes e capacidades.
- `Jobs`: fila e historico consolidado, filtravel por node, estado, cluster e tipo.
- `Activity`: eventos recentes, logs permitidos e diagnosticos.
- `Settings`: configuracoes locais da Control Tower e preferencias de exibicao.

Fluxo conceitual para uma operacao:

- usuario escolhe node de origem ou destino na Control Tower;
- Control Tower consulta estado, capacidades e permissoes via API;
- usuario seleciona arquivos, destino e politica de conflito;
- Control Tower envia requisicao mutavel com chave de idempotencia e identificador de correlacao;
- node responsavel valida permissao, trust, paths, mounts, conflito e disponibilidade;
- job e criado e persistido no node responsavel;
- Control Tower acompanha progresso por eventos ou consultas periodicas;
- logs, eventos e resultado final ficam rastreaveis pelo mesmo identificador de correlacao.

Para o MVP, a Control Tower deve ser uma imagem apartada. Ela deve existir para usuarios que queiram centralizar operacoes sem entrar node por node no dia a dia, mantendo a singularidade operacional de cada node.

#### 7.12.1 Autenticacao da Control Tower

A Control Tower deve ter autenticacao propria para usuarios humanos e service accounts. Essa autenticacao e separada do token operacional usado pela Control Tower para chamar nodes.

Componentes:

- SQLite criptografado para persistir usuarios, service accounts, policies, sessoes, auditoria e preferencias.
- Encryption key obrigatoria, preferencialmente por `CONTROL_TOWER_DB_ENCRYPTION_KEY` ou arquivo secreto montado.
- Hash de senha com Argon2id.
- Cookies de sessao para usuarios humanos.
- Tokens ou credenciais dedicadas para service accounts.

Bootstrap do admin:

- no primeiro boot, se nao existir usuario admin, a Control Tower deve criar um admin inicial;
- credenciais iniciais podem vir de variaveis de ambiente, arquivo secreto ou fluxo inicial protegido;
- apos bootstrap, a credencial inicial deve ser marcada como consumida quando aplicavel;
- o admin inicial recebe policy administrativa completa;
- a Control Tower deve alertar quando credenciais iniciais padrao ou inseguras forem detectadas.

Parametros recomendados de Argon2id:

```yaml
auth:
  argon2id:
    memory: 64MiB
    iterations: 3
    parallelism: 2
    salt_length: 16
    key_length: 32
```

Cookies de sessao:

- `HttpOnly`;
- `Secure` quando HTTPS estiver ativo;
- `SameSite=Lax` por padrao;
- expiracao absoluta configuravel;
- expiracao por inatividade configuravel;
- rotacao do identificador de sessao apos login;
- revogacao por usuario, por sessao ou global.

O cookie deve conter apenas identificador opaco de sessao. Dados de usuario, policies e estado de autenticacao devem ser resolvidos no servidor a partir do SQLite criptografado.

#### 7.12.2 Service Accounts

Service accounts existem para automacao e integracoes.

Requisitos:

- nao devem usar cookies de navegador por padrao;
- devem ter nome, descricao, status, policies associadas e metadados de auditoria;
- devem poder ter credenciais rotacionadas;
- devem poder ser desabilitadas sem remover historico;
- devem registrar `actor_type=service_account` nos eventos;
- devem respeitar o mesmo RBAC por Node Path aplicado a usuarios.

Tokens de service account devem ser exibidos apenas no momento de criacao ou rotacao. Depois disso, a Control Tower deve armazenar somente hash/derivacao segura ou material protegido pelo banco criptografado, conforme o tipo de token.

#### 7.12.3 RBAC por Node Path

O RBAC da Control Tower deve seguir modelo semelhante ao HashiCorp Vault: policies atribuem capabilities a paths.

Formato conceitual:

```hcl
path "nodes/node_nas/files/mounts/media" {
  capabilities = ["read", "list"]
}

path "nodes/node_nas/transfers/*" {
  capabilities = ["read", "list", "create", "execute"]
}

path "nodes/node_nas/jobs/*" {
  capabilities = ["read", "list", "update"]
}

path "nodes/node_nas/admin/*" {
  capabilities = ["deny"]
}
```

Capabilities:

- `read`: ler metadados ou conteudo permitido.
- `list`: listar colecoes, diretorios, mounts, jobs ou nodes.
- `create`: criar novos recursos, jobs ou grants.
- `update`: alterar recursos existentes.
- `delete`: remover recursos permitidos.
- `write`: alias operacional amplo para criar ou atualizar quando a API usar verbo generico.
- `execute`: executar acoes como pausar, retomar, cancelar, retry, promover chave ou iniciar transferencia.
- `sudo`: executar operacoes administrativas sensiveis.
- `deny`: negar explicitamente, com precedencia sobre allow.

Exemplos de Node Paths:

```text
nodes/*
nodes/{node_id}
nodes/{node_id}/mounts
nodes/{node_id}/mounts/{mount_id}
nodes/{node_id}/files
nodes/{node_id}/files/mounts/{mount_id}
nodes/{node_id}/transfers
nodes/{node_id}/transfers/{transfer_id}
nodes/{node_id}/jobs
nodes/{node_id}/jobs/{job_id}
nodes/{node_id}/grants
nodes/{node_id}/keys/mtls
nodes/{node_id}/admin/*
control-tower/users/*
control-tower/service-accounts/*
control-tower/policies/*
```

O RBAC deve separar dois dominios operacionais que usam os mesmos mounts como referencia:

- `files`: gerenciamento direto de arquivos dentro de mounts, como listar, baixar, enviar, criar diretorio, renomear, mover, copiar localmente e remover.
- `transfers`: planejamento, criacao, execucao e controle de transferencias entre nodes.

Permissao no dominio `files` nao deve conceder automaticamente permissao no dominio `transfers`. Uma pessoa pode ter acesso para navegar e baixar arquivos de um mount sem poder iniciar transferencias entre nodes.

O RBAC nao deve ser granular por subdiretorio ou arquivo dentro de um mount. Para arquivos, o menor escopo de autorizacao da Control Tower e:

```text
nodes/{node_id}/files/mounts/{mount_id}
```

Subpaths como `Movies/2026/file.mkv` podem aparecer em query string ou corpo da requisicao, mas nao devem virar path de policy.

Regras de avaliacao:

- policies de usuario e grupos futuros sao combinadas;
- service accounts avaliam apenas suas policies associadas;
- path mais especifico deve prevalecer quando houver conflito de allow;
- `deny` prevalece sempre;
- `sudo` deve ser exigido para administrar Control Tower e operacoes sensiveis de nodes;
- RBAC deve ser avaliado antes de a Control Tower chamar qualquer node;
- falhas de RBAC devem ser auditadas.

Mapeamento minimo de operacoes:

- listar nodes: `list` em `nodes/*`;
- ver estado de node: `read` em `nodes/{node_id}`;
- listar mount: `list` em `nodes/{node_id}/mounts`;
- navegar arquivos dentro de mount: `list` em `nodes/{node_id}/files/mounts/{mount_id}`;
- ler ou baixar arquivo dentro de mount: `read` em `nodes/{node_id}/files/mounts/{mount_id}`;
- copiar arquivo ou diretorio localmente: `read` no mount de origem e `create`/`write` no mount de destino, sempre no dominio `files`;
- upload: `create` ou `write` no mount de destino no dominio `files`;
- remover arquivo: `delete` no mount no dominio `files`;
- planejar transferencia: `read` nos mounts de origem, `create`/`write` nos mounts de destino e `create` em `nodes/{node_id}/transfers`;
- iniciar transferencia: `execute` em `nodes/{node_id}/transfers` ou `nodes/{node_id}/transfers/{transfer_id}`, alem das permissoes de origem/destino no dominio `files`;
- criar job: `create` em `nodes/{node_id}/jobs`;
- pausar/retomar/cancelar job: `execute` em `nodes/{node_id}/jobs/{job_id}`;
- rotacionar mTLS: `sudo` e `execute` em `nodes/{node_id}/keys/mtls`;
- gerenciar usuarios/policies: `sudo` em `control-tower/*`.

#### 7.12.4 Rotas Amigaveis para RBAC

As rotas da Control Tower devem favorecer paths estaveis e previsiveis. O objetivo e que a decisao de RBAC possa ser calculada a partir da rota principal, sem depender de interpretar paths de filesystem.

Prefixos principais:

```text
/api/v1/nodes
/api/v1/control-tower
/api/v1/auth
/api/v1/audit
```

Rotas de nodes:

```text
GET    /api/v1/nodes
POST   /api/v1/nodes
GET    /api/v1/nodes/{node_id}
PATCH  /api/v1/nodes/{node_id}
DELETE /api/v1/nodes/{node_id}

GET    /api/v1/nodes/{node_id}/status
GET    /api/v1/nodes/{node_id}/capabilities
GET    /api/v1/nodes/{node_id}/diagnostics

GET    /api/v1/nodes/{node_id}/mounts
POST   /api/v1/nodes/{node_id}/mounts
GET    /api/v1/nodes/{node_id}/mounts/{mount_id}
PATCH  /api/v1/nodes/{node_id}/mounts/{mount_id}
DELETE /api/v1/nodes/{node_id}/mounts/{mount_id}

GET    /api/v1/nodes/{node_id}/files/mounts/{mount_id}/entries?path=...
GET    /api/v1/nodes/{node_id}/files/mounts/{mount_id}/download?path=...
POST   /api/v1/nodes/{node_id}/files/mounts/{mount_id}/upload
POST   /api/v1/nodes/{node_id}/files/mounts/{mount_id}/actions/copy
POST   /api/v1/nodes/{node_id}/files/mounts/{mount_id}/actions/move
POST   /api/v1/nodes/{node_id}/files/mounts/{mount_id}/actions/rename
POST   /api/v1/nodes/{node_id}/files/mounts/{mount_id}/actions/mkdir
DELETE /api/v1/nodes/{node_id}/files/mounts/{mount_id}/entries
```

O parametro `path` representa o caminho relativo dentro do mount. Ele deve passar por validacao de path traversal no node, mas nao deve compor o Node Path de RBAC.

Rotas de transferencias:

```text
GET    /api/v1/nodes/{node_id}/transfers
POST   /api/v1/nodes/{node_id}/transfers/plan
POST   /api/v1/nodes/{node_id}/transfers
GET    /api/v1/nodes/{node_id}/transfers/{transfer_id}
POST   /api/v1/nodes/{node_id}/transfers/{transfer_id}/actions/start
POST   /api/v1/nodes/{node_id}/transfers/{transfer_id}/actions/pause
POST   /api/v1/nodes/{node_id}/transfers/{transfer_id}/actions/resume
POST   /api/v1/nodes/{node_id}/transfers/{transfer_id}/actions/cancel
POST   /api/v1/nodes/{node_id}/transfers/{transfer_id}/actions/retry
```

As rotas de `transfers` devem representar a intencao operacional de transferir entre nodes. Elas nao substituem a validacao dos Transfer Path Grants nem as permissoes `files` dos mounts de origem e destino.

Rotas de jobs:

```text
GET    /api/v1/nodes/{node_id}/jobs
POST   /api/v1/nodes/{node_id}/jobs
GET    /api/v1/nodes/{node_id}/jobs/{job_id}
POST   /api/v1/nodes/{node_id}/jobs/{job_id}/actions/pause
POST   /api/v1/nodes/{node_id}/jobs/{job_id}/actions/resume
POST   /api/v1/nodes/{node_id}/jobs/{job_id}/actions/cancel
POST   /api/v1/nodes/{node_id}/jobs/{job_id}/actions/retry
POST   /api/v1/nodes/{node_id}/jobs/{job_id}/decisions
```

Jobs continuam sendo o modelo persistido de execucao no node. O dominio `transfers` representa a intencao e o controle de transferencias; o dominio `jobs` representa observabilidade e ciclo de vida generico de jobs ja criados, incluindo jobs de transferencia, manifest, validacao, limpeza e retry.

Rotas de grants, peers, keys e configuracao:

```text
GET    /api/v1/nodes/{node_id}/grants
POST   /api/v1/nodes/{node_id}/grants
PATCH  /api/v1/nodes/{node_id}/grants/{grant_id}
DELETE /api/v1/nodes/{node_id}/grants/{grant_id}

GET    /api/v1/nodes/{node_id}/peers
POST   /api/v1/nodes/{node_id}/peers
DELETE /api/v1/nodes/{node_id}/peers/{peer_id}

GET    /api/v1/nodes/{node_id}/keys/mtls
POST   /api/v1/nodes/{node_id}/keys/mtls/next
POST   /api/v1/nodes/{node_id}/keys/mtls/promote
POST   /api/v1/nodes/{node_id}/keys/mtls/revoke

GET    /api/v1/nodes/{node_id}/config/effective
PATCH  /api/v1/nodes/{node_id}/config
GET    /api/v1/nodes/{node_id}/logs
```

Rotas da propria Control Tower:

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/session

GET    /api/v1/control-tower/users
POST   /api/v1/control-tower/users
PATCH  /api/v1/control-tower/users/{user_id}
DELETE /api/v1/control-tower/users/{user_id}

GET    /api/v1/control-tower/service-accounts
POST   /api/v1/control-tower/service-accounts
PATCH  /api/v1/control-tower/service-accounts/{account_id}
DELETE /api/v1/control-tower/service-accounts/{account_id}

GET    /api/v1/control-tower/policies
POST   /api/v1/control-tower/policies
PATCH  /api/v1/control-tower/policies/{policy_id}
DELETE /api/v1/control-tower/policies/{policy_id}

GET    /api/v1/control-tower/roles
POST   /api/v1/control-tower/roles
PATCH  /api/v1/control-tower/roles/{role_id}
DELETE /api/v1/control-tower/roles/{role_id}
GET    /api/v1/control-tower/users/{user_id}/roles
PUT    /api/v1/control-tower/users/{user_id}/roles

GET    /api/v1/audit/events
```

Mapeamento rota -> Node Path:

```text
/api/v1/nodes/{node_id}/files/mounts/{mount_id}/entries
  -> nodes/{node_id}/files/mounts/{mount_id}

/api/v1/nodes/{node_id}/files/mounts/{mount_id}/download
  -> nodes/{node_id}/files/mounts/{mount_id}

/api/v1/nodes/{node_id}/transfers
  -> nodes/{node_id}/transfers

/api/v1/nodes/{node_id}/transfers/{transfer_id}/actions/cancel
  -> nodes/{node_id}/transfers/{transfer_id}

/api/v1/nodes/{node_id}/jobs/{job_id}/actions/cancel
  -> nodes/{node_id}/jobs/{job_id}

/api/v1/control-tower/users/{user_id}
  -> control-tower/users/{user_id}
```

Esse mapeamento deve ser documentado no OpenAPI da Control Tower.

#### 7.12.5 Persistencia da Control Tower

O SQLite da Control Tower deve armazenar:

- usuarios;
- hashes Argon2id;
- service accounts;
- hashes ou metadados protegidos de tokens;
- policies;
- roles e associacoes role-policy;
- associacoes usuario-role;
- associacoes usuario-policy e service-account-policy;
- sessoes;
- eventos de auditoria;
- endpoints de nodes;
- preferencias de exibicao.

O banco deve ser criptografado em repouso usando encryption key externa ao banco. A perda da encryption key deve tornar o banco irrecuperavel sem backup da chave.

Backups da Control Tower devem incluir o banco criptografado e a forma segura de recuperar a encryption key, sem imprimir a chave em logs ou diagnosticos.

### 7.13 Disaster Recovery

Disaster recovery deve seguir o principio de que nodes sao fontes de verdade operacionais, enquanto a Control Tower e uma camada reconstruivel de instrumentacao e experiencia.

#### 7.13.1 Fontes de Verdade

Fonte de verdade do node:

- identidade criptografica;
- `node_id` e fingerprint;
- token operacional aceito para Control Tower;
- configuracoes locais;
- peers conhecidos;
- clusters;
- mounts cadastrados;
- Transfer Path Grants concedidos pelo node;
- jobs e itens de transferencia;
- estado de chunks/ranges/parciais;
- historico e logs locais permitidos.

Fonte de verdade da Control Tower:

- configuracao propria;
- endpoints de nodes cadastrados;
- token operacional necessario para acessar cada node, quando armazenado nela;
- preferencias de exibicao;
- filtros, agrupamentos visuais e metadados de experiencia.

A Control Tower nao deve ser fonte de verdade para:

- jobs;
- estado de chunks;
- grants concedidos por nodes;
- identidade de nodes;
- mounts de nodes;
- historico autoritativo de transferencias.

#### 7.13.2 Backup de Node

O backup minimo de um node deve incluir o volume persistente do node.

Esse volume deve conter:

- banco local;
- identidade criptografica privada e publica;
- configuracoes;
- peers e clusters;
- mounts e grants;
- fila de jobs;
- itens de transferencia;
- estado de retomada;
- metadados de parciais;
- logs locais dentro da politica de retencao.

Mounts em si podem apontar para dados externos ao volume persistente. O backup do node nao substitui backup dos arquivos gerenciados nos mounts.

Ao restaurar em outro host, o operador deve garantir que:

- mounts referenciados existem;
- paths montados apontam para os dados esperados;
- UID/GID/UMASK continuam compativeis;
- espaco disponivel e permissao real do filesystem foram revalidados;
- endpoints e portas foram atualizados quando necessario.

#### 7.13.3 Restore de Node com Identidade Preservada

Quando a identidade criptografica for restaurada:

- o `node_id` e fingerprint devem permanecer iguais;
- peers conhecidos devem continuar reconhecendo o node;
- grants podem continuar validos apos revalidacao;
- jobs podem ser retomados apenas apos validacao;
- mounts ausentes devem ficar em estado `unavailable` ou `degraded`;
- arquivos parciais devem permanecer parciais ate validacao.

Fluxo recomendado:

- parar o container antigo quando possivel;
- restaurar volume persistente;
- montar os paths esperados;
- iniciar o node;
- validar identidade e fingerprint;
- executar diagnostico de mounts;
- revalidar peers e grants;
- colocar jobs restaurados em estado seguro;
- retomar jobs apenas apos validacoes aprovadas.

#### 7.13.4 Restore de Node sem Identidade Preservada

Quando a identidade criptografica for perdida:

- o node deve ser tratado como novo;
- mesmo nome amigavel nao deve restaurar confianca;
- peers antigos devem marcar a situacao como identidade alterada ou node desconhecido;
- pareamentos devem ser refeitos;
- grants devem ser recriados explicitamente;
- jobs antigos de outros nodes que dependiam da identidade anterior nao devem confiar automaticamente no novo node.

Esse fluxo deve ser apresentado como recuperacao parcial, nao como restore completo.

#### 7.13.5 Jobs e Arquivos Parciais em DR

Jobs restaurados nunca devem retomar cegamente.

Antes de retomar, o node deve verificar:

- identidade e estado do peer;
- existencia e permissao dos mounts;
- validade dos grants;
- existencia da origem e destino;
- metadados esperados do arquivo;
- ranges/chunks ja gravados;
- tamanho dos parciais;
- checksum quando configurado;
- politica de conflito ainda aplicavel.

Estados seguros apos restore:

- `interrupted`: job existia, mas precisa de revalidacao;
- `waiting_mount`: mount necessario ausente ou sem permissao;
- `waiting_peer`: peer necessario indisponivel;
- `waiting_validation`: parciais ou metadados precisam ser conferidos;
- `failed`: estado inconsistente sem retomada segura.

#### 7.13.6 Disaster Recovery da Control Tower

A Control Tower deve ser recuperavel sem impactar a execucao dos nodes.

Backup minimo:

- configuracao da Control Tower;
- endpoints de nodes;
- tokens operacionais ou referencias seguras para obtencao desses tokens;
- preferencias de exibicao;
- agrupamentos visuais e filtros.

Restore da Control Tower:

- restaurar configuracao propria;
- restaurar ou reinformar tokens;
- reconectar aos nodes;
- consultar estado, mounts, grants e jobs diretamente nas APIs dos nodes;
- reconstruir dashboards e historico consolidado a partir dos nodes.

Se a Control Tower for perdida sem backup:

- nodes continuam operando;
- jobs ja criados continuam sob responsabilidade dos nodes;
- uma nova Control Tower pode ser criada;
- o operador deve cadastrar endpoints dos nodes e tokens novamente;
- a visao historica consolidada pode ser reconstruida parcialmente a partir dos historicos de cada node.

#### 7.13.7 Segredos e Rotacao em DR

Backups que contenham identidade de node ou tokens da Control Tower devem ser tratados como sensiveis.

Requisitos:

- backups devem evitar exposicao acidental de chaves privadas e tokens;
- restore deve permitir rotacionar `CONTROL_TOWER_TOKEN`;
- rotacao emergencial deve invalidar o token antigo no node;
- Control Tower deve suportar atualizar token por node;
- logs de restore nao devem imprimir tokens ou chaves privadas.

#### 7.13.8 Objetivos Operacionais Sugeridos

Valores iniciais sugeridos:

- RPO de configuracao de node: ultimo backup do volume persistente.
- RPO de arquivos gerenciados: definido pelo backup externo dos mounts.
- RTO de node: tempo de restaurar volume, mounts e revalidar jobs.
- RTO de Control Tower: tempo de subir nova imagem, restaurar configuracao e reconectar nodes.

O documento deve deixar claro que `jolt` gerencia transferencias, mas nao substitui uma estrategia de backup dos dados armazenados nos mounts.

## 8. Avaliacao de Protocolos

### 8.1 HTTP Proprio com Streaming

Vantagens:

- Integracao direta com backend Go e Control Tower.
- Simples de empacotar em Docker.
- Permite controle detalhado de progresso.
- Permite implementar range requests, chunks e resume.
- Bom para copy-on-demand.

Desvantagens:

- Exige implementar corretamente retomada, checksums, retries e controle de concorrencia.
- Nao possui delta copy nativo.
- Pode ser menos eficiente que rsync quando o destino ja possui partes parecidas dos arquivos.

Uso recomendado:

- MVP.
- Transferencia direta de arquivos e diretorios.
- Base comum para experiencia do produto.

### 8.2 rsync

Vantagens:

- Muito eficiente para sincronizacao incremental.
- Maduro para diretorios grandes.
- Economiza banda quando arquivos ja existem parcialmente no destino.
- Bom para bibliotecas grandes e atualizacoes recorrentes.

Desvantagens:

- Integracao com Control Tower e progresso detalhado pode ser mais complexa.
- Dependencia externa no container ou no host.
- Modelo de autenticacao/configuracao pode ser menos amigavel.
- Pode complicar portabilidade.

Uso recomendado:

- Backend opcional futuro.
- Modo avancado para sincronizacao incremental.

### 8.3 SSH/SFTP

Vantagens:

- Seguro e amplamente conhecido.
- Boa compatibilidade com servidores Linux.
- Pode reaproveitar infraestrutura de chaves SSH existente.

Desvantagens:

- Gerenciamento de chaves pode ser dificil para usuarios menos tecnicos.
- Containers podem complicar acesso a chaves e usuarios do host.
- SFTP nao resolve por si so manifest, fila, resume sofisticado e UX.

Uso recomendado:

- Integracao futura com hosts externos.
- Modo avancado para ambientes que ja usam SSH.

### 8.4 gRPC

Vantagens:

- Contratos tipados.
- Streaming eficiente.
- Bom para comunicacao entre servicos.

Desvantagens:

- Mais complexo para depurar e integrar diretamente com navegadores.
- Pode ser excesso para o MVP.

Uso recomendado:

- Possivel evolucao interna entre nodes se REST/HTTP se tornar limitante.

## 9. Politicas Padrao Sugeridas

### 9.1 Transferencias

- Tamanho de chunk padrao: 16 MiB.
- Arquivos paralelos por job: 4.
- Chunks paralelos por arquivo: 4.
- Retentativas por item: 5.
- Verificacao padrao: tamanho e data de modificacao.
- Checksum completo: opcional.
- Sufixo temporario: `.jolt.partial`.

### 9.2 Conflitos

- Politica padrao para arquivo existente: pular se tamanho e data forem iguais.
- Politica alternativa: sobrescrever.
- Politica alternativa: renomear destino.
- Politica alternativa: falhar item.
- Politica alternativa: perguntar ao usuario.
- Politica alternativa: validar por checksum antes de decidir.
- Decisao manual pode ser aplicada apenas ao item atual ou aos proximos conflitos do job.

### 9.3 Arquivos Modificados Durante a Copia

- Politica padrao: marcar como falha e tentar novamente ao final do job.
- Politica alternativa: copiar mesmo assim.
- Politica alternativa: ignorar arquivo modificado.

### 9.4 Confianca entre Hosts

- Chave de identidade do node: estavel, sem expiracao automatica.
- Transferencias node-to-node: autenticacao e criptografia por mTLS.
- Control Tower para controle operacional: token configurado no node, preferencialmente por `CONTROL_TOWER_TOKEN`.
- Diretorio de keys: configurado por `JOLT_KEYS_DIR`.
- Permissao recomendada para diretorios de keys: `0700`.
- Permissao recomendada para chaves privadas: `0600`.
- `UMASK` recomendado para volume de keys: `077`.
- Convite de pareamento: expiracao padrao de 15 minutos.
- Convite de pareamento: uso unico por padrao.
- Convite de pareamento: deve declarar `transfer_mode` e papeis operacionais.
- Grants de paths: nenhum path deve ser exposto automaticamente apenas por aceitar convite.
- Grants de paths: granularidade inicial deve suportar mount inteiro e subdiretorio relativo ao mount.
- Sessoes temporarias entre peers: expiracao obrigatoria.
- Rotacao de identidade: manual, explicita e auditavel.
- Mudanca inesperada de identidade conhecida: bloquear comunicacao ate confirmacao manual.
- Revogacao de peer: bloquear novas operacoes imediatamente.
- Rotacao mTLS planejada: usar `next` antes de promover para `active`.
- Certificado anterior: manter como `previous` durante grace period.
- Revogacao mTLS emergencial: bloquear novas conexoes imediatamente.

### 9.4.1 Autenticacao da Control Tower

- Admin inicial: criado no primeiro boot quando nao houver admin.
- Hash de senha: Argon2id.
- Sessao de usuario humano: cookie opaco, HTTP-only, SameSite=Lax.
- Cookie Secure: obrigatorio quando HTTPS estiver ativo.
- Banco da Control Tower: SQLite criptografado por encryption key externa.
- Service accounts: autenticacao sem cookie de navegador por padrao.
- RBAC: policies por Node Path.
- `deny`: precedencia maxima.
- `sudo`: necessario para administracao sensivel.

### 9.5 Jobs

- Jobs de vida longa: persistentes por padrao.
- Timeout global de job: desativado por padrao.
- Timeout de conexao: 10 segundos.
- Timeout de leitura ociosa: 60 segundos.
- Timeout de chunk: 5 minutos.
- Tentativas por chunk: 5.
- Tentativas por arquivo: 3.
- Retry de peer: backoff progressivo sem limite fixo para jobs retomaveis.
- ETA: calculado com media movel e exibido com confianca quando possivel.
- Falha parcial em diretorio: usar `completed_with_warnings` quando aplicavel.
- Conflito com politica `ask`: usar `waiting_user_decision`.
- Ausencia de progresso deve ser detectada por janela configuravel, nao por duracao total do job.

### 9.6 Filesystem e Permissoes

- Variaveis oficiais: `PUID`, `PGID` e `UMASK`.
- Aliases aceitos: `UID` e `GID`.
- `PUID` padrao: `1000`, quando nao configurado e quando seguro para o ambiente.
- `PGID` padrao: `1000`, quando nao configurado e quando seguro para o ambiente.
- `UMASK` padrao: `022`.
- Preservar mode original: desativado por padrao.
- Preservar owner original: desativado por padrao.
- Preservar group original: desativado por padrao.
- Arquivos criados devem pertencer ao UID/GID efetivo do processo.
- Permissoes logicas do app nao substituem permissoes reais do filesystem.

### 9.7 Reverse Proxy

- Control Tower e API HTTP autenticada do node: reverse proxy HTTP suportado.
- Peer/data API com mTLS: conexao direta ou TLS passthrough recomendado.
- TLS termination para peer/data API: modo avancado e explicito.
- Nginx para transferencias grandes: `client_max_body_size 0`, `proxy_request_buffering off`, `proxy_buffering off`.
- Traefik para transferencias grandes: evitar middleware de buffering ou configurar limites como `0`.
- Timeouts de proxy devem ser compativeis com transferencias longas.
- Endpoints de Control Tower, API HTTP autenticada do node e peer/data API podem ser separados.

## 10. Requisitos do MVP

O MVP deve incluir:

- Dockerfile.
- Exemplo de `docker-compose.yml`.
- Documentacao de reverse proxy para Nginx e Traefik.
- Suporte a configuracao de endpoint publico para Control Tower.
- Suporte a configuracao de endpoint separado para API HTTP autenticada do node e peer/data API quando necessario.
- Suporte a `PUID`, `PGID` e `UMASK`.
- Escrita de arquivos usando UID/GID efetivo configurado.
- Diagnostico de permissao de mounts.
- Container sem root permanente sempre que possivel.
- Node empacotado como unico binario Go servindo API HTTP autenticada e Swagger/OpenAPI, sem frontend operacional.
- Contrato de API documentado para operacoes principais.
- Listagem e escrita de arquivos sempre por API.
- Control Tower consumindo API dos nodes, sem acesso direto ao filesystem ou banco.
- Suporte basico a idempotencia em operacoes mutaveis.
- Identificadores de correlacao para jobs e eventos.
- Frontend Vue 3 responsivo na Control Tower.
- Control Tower empacotada como imagem apartada e opcional.
- SQLite criptografado para persistencia da Control Tower.
- Encryption key obrigatoria para abrir o banco da Control Tower, preferencialmente `CONTROL_TOWER_DB_ENCRYPTION_KEY`.
- Usuario admin criado no boot inicial da Control Tower.
- Login da Control Tower com senha armazenada por Argon2id.
- Cookies de sessao HTTP-only para usuarios humanos.
- Usuarios e service accounts gerenciaveis na Control Tower.
- RBAC basico por Node Path com policies e capabilities.
- Nodes sem interface web propria.
- Nodes expondo apenas porta HTTP da API/Swagger e porta mTLS de transferencia.
- Token da Control Tower recebido pelo node por variavel de ambiente.
- Diretorio de keys dedicado, configuravel por `JOLT_KEYS_DIR`.
- Volume Docker separado para keys, distinto do volume de dados e dos mounts de transferencia.
- Validacao de permissoes do diretorio de keys no boot.
- Rotacao mTLS planejada com estados `active`, `next` e `previous`.
- Revogacao emergencial de certificado mTLS comprometido.
- Modelo de configuracao por camadas: defaults, arquivo, ambiente, banco local e estado observado.
- Endpoint de leitura de configuracao efetiva sem segredos.
- Endpoint de alteracao de configuracoes mutaveis por API autenticada.
- Campos estruturais e secretos definidos por ambiente tratados como locked no MVP.
- Lista de nodes conhecidos na Control Tower.
- Visualizacao de estado, capacidades e diagnosticos resumidos por node.
- Operacoes da Control Tower executadas pelas mesmas APIs dos nodes.
- Operacoes da Control Tower autenticadas pelo token operacional configurado nos nodes.
- Control Tower sem persistencia de jobs, apenas instrumentacao e visualizacao.
- Disaster recovery documentado para nodes e Control Tower.
- Comandos offline de snapshot consistente para node e Control Tower.
- Comandos offline e somente leitura de diagnostico pos-restore para node e Control Tower.
- Backup e restore do volume persistente do node preservando identidade.
- Diagnostico pos-restore de mounts, grants, peers e jobs.
- Reconstrucao da Control Tower a partir de configuracao e APIs dos nodes.
- Rotacao do `CONTROL_TOWER_TOKEN`.
- Configuracao de node local.
- Configuracao de mounts.
- Mounts como referencias logicas locais antes de qualquer relacao de confianca.
- Navegacao de arquivos dos nodes pela API autenticada ou Control Tower.
- Gestao local de arquivos dentro dos mounts autorizados.
- Copiar, colar, recortar, mover, renomear, remover e criar diretorios localmente.
- Upload de arquivos para mounts com permissao de escrita.
- Upload de arquivos grandes por streaming.
- Identidade criptografica local persistente.
- Fingerprint visivel do node.
- Convites de pareamento temporarios.
- Convites declarando modo `one_sided` ou `dual_channel`.
- Pareamento manual entre dois nodes.
- Configuracao explicita de Transfer Path Grants apos pareamento.
- Transfer Path Grants vinculados apenas a mounts ja cadastrados.
- Transfer Path Grants por mount inteiro e por subdiretorio relativo.
- Bloqueio de exclusao de mounts associados a relacoes ou grants.
- Heartbeat leve entre peers conhecidos.
- Estados basicos de node e peers.
- Backoff para peers offline.
- Verificacao leve de mounts durante idle.
- Listagem de mounts remotos.
- Navegacao de arquivos remotos.
- Copia de arquivo unico entre nodes.
- Copia de diretorio entre nodes usando manifest.
- Autenticacao de transferencia node-to-node por mTLS.
- Transferencia por streaming sem carregar arquivo inteiro em memoria.
- Retomada basica de transferencia interrompida.
- Fila persistente de jobs.
- Estados e fases basicas de jobs.
- Validacoes antes, durante e depois de transferencias.
- Retries por chunk ou arquivo.
- Timeouts configuraveis para conexao, leitura ociosa e chunk.
- Estimativa basica de tempo de conclusao.
- Politicas de conflito por job.
- Override manual para conflitos de arquivo.
- Progresso de transferencia.
- Historico basico.
- Permissoes de mount somente leitura/leitura-escrita.

## 11. Requisitos Pos-MVP

Itens candidatos para evolucao:

- Importacao de certificados mTLS externos ou pre-provisionados.
- Descoberta LAN via mDNS.
- Checksums por chunk.
- Suporte opcional a rsync.
- Suporte opcional a SSH/SFTP.
- Limite de banda por peer.
- Agendamento de jobs.
- Sync recorrente.
- Busca global entre nodes.
- Capacidades avancadas da Control Tower para operar multiplos clusters.
- Preferencias avancadas de visualizacao e filtros da Control Tower.
- Politicas avancadas de retencao.
- Usuarios e permissoes avancadas.
- Compartilhamento temporario por link.
- Relay opcional para peers atras de NAT.
- Metricas Prometheus.
- Backup/exportacao avancada da configuracao local.

## 12. Criterios de Aceite Iniciais

- CA-001: Um usuario consegue subir uma instancia do `jolt` via Docker.
- CA-002: Um usuario consegue montar pelo menos um diretorio local no container.
- CA-003: A Control Tower lista arquivos do diretorio montado em um node autorizado.
- CA-004: Dois nodes conseguem ser pareados manualmente.
- CA-005: Um node consegue listar mounts publicados pelo outro.
- CA-006: Um usuario consegue copiar um arquivo de um node para outro.
- CA-007: Um arquivo grande deve ser transferido por streaming sem consumo de memoria proporcional ao tamanho do arquivo.
- CA-008: Uma transferencia interrompida deve poder ser retomada.
- CA-009: Um usuario consegue copiar uma pasta com subdiretorios preservando a estrutura.
- CA-010: Um job de diretorio mostra progresso por bytes e por arquivos.
- CA-011: Se um peer cair, os demais continuam operando.
- CA-012: O sistema impede acesso a arquivos fora dos mounts configurados.
- CA-013: Um convite expirado ou revogado nao permite pareamento.
- CA-014: Uma mudanca de identidade de peer conhecido exige confirmacao manual antes de nova confianca.
- CA-015: No primeiro boot, o sistema cria identidade local, banco e estrutura interna de dados.
- CA-016: Apos reinicio com o mesmo volume persistente, o node mantem o mesmo `node_id` e fingerprint.
- CA-017: Apos perda do volume persistente, o node recebe nova identidade e peers antigos nao confiam automaticamente nele.
- CA-018: Um node idle mantem API HTTP autenticada, Swagger/OpenAPI e porta mTLS disponiveis sem executar varredura pesada nos mounts.
- CA-019: Um peer nao e marcado como offline apos uma unica falha temporaria.
- CA-020: Um job aguardando peer offline volta para fila apenas apos o peer retornar e ter identidade/permissoes revalidadas.
- CA-021: Um job de vida longa persiste estado suficiente para continuar apos reinicio ou interrupcao.
- CA-022: Um job mostra fase atual, progresso e ETA quando houver dados suficientes.
- CA-023: Uma falha transiente de chunk ou arquivo gera retry sem reiniciar o job inteiro.
- CA-024: Um conflito de arquivo pode ser resolvido por politica do job ou decisao manual do usuario.
- CA-025: Um job de diretorio com falhas parciais pode terminar como `completed_with_warnings`.
- CA-026: Um timeout de conexao ou chunk nao implica timeout global automatico de um job longo.
- CA-027: A Control Tower lista arquivos e cria jobs usando API, sem acesso direto ao filesystem.
- CA-028: Um orquestrador consegue criar um job via API e acompanhar seu progresso por eventos ou consulta de estado.
- CA-029: Repetir uma requisicao mutavel com a mesma chave de idempotencia nao cria jobs duplicados.
- CA-030: Eventos e logs de um job possuem identificador de correlacao rastreavel.
- CA-031: Um usuario consegue copiar e colar arquivo ou diretorio entre caminhos autorizados do mesmo node.
- CA-032: Um usuario consegue recortar ou mover arquivo ou diretorio entre caminhos autorizados do mesmo node.
- CA-033: Um usuario consegue fazer upload de arquivo para mount com permissao de escrita.
- CA-034: Um upload grande e realizado por streaming e finalizado por arquivo temporario antes de publicar o destino.
- CA-035: Operacoes locais de escrita sao bloqueadas em mounts somente leitura.
- CA-036: Arquivos criados por upload, copia local ou transferencia recebida usam o UID/GID efetivo configurado por `PUID`/`PGID`.
- CA-037: Arquivos e diretorios criados respeitam o `UMASK` configurado.
- CA-038: Um mount configurado como escrita, mas sem permissao real no filesystem, e marcado com diagnostico claro.
- CA-039: O container nao exige modo privilegiado para operacoes normais de gestao e transferencia de arquivos.
- CA-040: A documentacao fornece exemplo de Nginx sem limite de body e sem buffering para uploads/downloads grandes.
- CA-041: A documentacao fornece exemplo de Traefik sem buffering ou com limites ilimitados para uploads/downloads grandes.
- CA-042: A documentacao explica que peer/data API com mTLS deve usar conexao direta ou TLS passthrough para manter autenticacao ponta a ponta.
- CA-043: O sistema permite configurar endpoints separados para Control Tower, API HTTP autenticada do node e peer/data API mTLS.
- CA-044: A Control Tower lista o node local e peers conhecidos com estado operacional resumido.
- CA-045: Um usuario consegue selecionar um node na Control Tower e navegar mounts autorizados usando API.
- CA-046: Uma operacao iniciada pela Control Tower cria job pelo mesmo caminho de API autenticada exposto pelo node.
- CA-047: Se um node listado estiver offline ou com identidade alterada, a Control Tower bloqueia operacoes inseguras nele sem bloquear os demais nodes.
- CA-048: Um convite informa claramente se a relacao esperada e `one_sided` ou `dual_channel`.
- CA-049: Apos aceitar um convite, nenhum path fica disponivel para transferencia ate que o node dono declare um Transfer Path Grant.
- CA-050: Em uma relacao `one_sided`, a Control Tower bloqueia operacoes que contrariem o papel operacional aceito.
- CA-051: Em uma relacao `dual_channel`, cada node consegue elencar seus proprios paths permitidos sem herdar paths do outro lado.
- CA-052: Um peer nao consegue listar nem transferir paths fora dos grants concedidos.
- CA-053: Um usuario nao consegue criar Transfer Path Grant para path que nao esteja dentro de um mount ja cadastrado no node.
- CA-054: Aceitar convite ou criar peer nao cria mount automaticamente.
- CA-055: Um mount associado a relacao de confianca ou grant nao pode ser deletado ate que as associacoes sejam removidas, revogadas ou migradas.
- CA-056: Um mount desabilitado ou indisponivel nao e substituido automaticamente por outro path em jobs existentes.
- CA-057: O node do MVP e distribuido como um unico binario Go capaz de servir API HTTP autenticada e Swagger/OpenAPI, sem interface web propria.
- CA-058: A Control Tower do MVP roda como imagem apartada e consegue operar nodes autorizados sem substituir a API propria de cada node.
- CA-059: A Control Tower nao persiste jobs; apos criar uma operacao, o job aparece e permanece no node responsavel.
- CA-060: Operacoes de controle feitas pela Control Tower exigem o token operacional configurado no node alvo.
- CA-061: Transferencias node-to-node usam canal autenticado por mTLS.
- CA-062: Um Transfer Path Grant pode ser criado para um mount inteiro ou para um subdiretorio relativo dentro de um mount.
- CA-063: Sem o token recebido por variavel de ambiente, chamadas para a API HTTP do node sao rejeitadas.
- CA-064: O node expoe portas separadas para API HTTP/Swagger e transferencia mTLS, e chamadas interativas pelo Swagger exigem o mesmo token operacional da API.
- CA-065: Restaurar o volume persistente de um node com identidade preservada mantem o mesmo `node_id` e fingerprint.
- CA-066: Apos restore de node, mounts ausentes ou sem permissao sao marcados como unavailable/degraded e nao sao remapeados automaticamente.
- CA-067: Jobs restaurados entram em estado seguro e so retomam apos revalidar peers, mounts, grants e parciais.
- CA-068: Restaurar um node sem identidade preservada faz com que peers antigos tratem o node como identidade nova ou suspeita.
- CA-069: Perder a Control Tower nao apaga jobs nem grants persistidos nos nodes.
- CA-070: Uma nova Control Tower consegue reconstruir a visao operacional consultando APIs dos nodes autorizados.
- CA-071: Rotacionar `CONTROL_TOWER_TOKEN` invalida chamadas com o token antigo e permite chamadas com o token novo.
- CA-072: O node monta configuracao efetiva respeitando precedencia entre defaults, arquivo, ambiente e banco local.
- CA-073: A API retorna configuracao efetiva sem expor `CONTROL_TOWER_TOKEN`, chaves privadas ou outros segredos.
- CA-074: Tentar alterar por API um campo locked por variavel de ambiente retorna erro estruturado.
- CA-075: Alterar configuracao mutavel por API persiste no banco local e sobrevive a reinicio.
- CA-076: Falha de validacao ao alterar configuracao nao deixa estado parcial persistido.
- CA-077: O node persiste identidade, chaves privadas e certificados mTLS em diretorio dedicado configurado por `JOLT_KEYS_DIR`.
- CA-078: O diretorio de keys nao aparece como mount de transferencia e nao pode ser usado em Transfer Path Grants.
- CA-079: O node recusa iniciar mTLS ou entra em degraded quando chaves privadas possuem permissoes inseguras.
- CA-080: A API de keys retorna fingerprint, validade, emissor e estado de rotacao sem expor chave privada.
- CA-081: Uma rotacao planejada permite registrar certificado `next`, promove-lo para `active` e manter o certificado anterior como `previous` durante grace period.
- CA-082: Revogar certificado mTLS comprometido bloqueia novas conexoes com esse certificado e registra evento auditavel.
- CA-083: A Control Tower cria um usuario admin no primeiro boot quando nao existir admin cadastrado.
- CA-084: Senhas de usuarios da Control Tower sao persistidas como hash Argon2id, nunca em texto claro.
- CA-085: Login bem-sucedido cria cookie de sessao HTTP-only e sessao persistida no SQLite criptografado.
- CA-086: A Control Tower nao inicia em modo normal sem encryption key valida para abrir o SQLite.
- CA-087: Um usuario sem `list` no Node Path de um node nao ve esse node na lista.
- CA-088: Um usuario com `read` mas sem `write` no dominio `files` consegue navegar arquivos permitidos, mas nao consegue iniciar upload ou copia local para aquele mount.
- CA-089: Uma policy com `deny` bloqueia acesso mesmo quando outra policy concede permissao ao mesmo path.
- CA-090: Uma service account consegue chamar APIs da Control Tower apenas dentro das capabilities associadas as suas policies.
- CA-091: Operacoes administrativas de usuarios, service accounts e policies exigem capability `sudo`.
- CA-092: Eventos de auditoria registram ator, tipo de ator, policies aplicadas, path avaliado e decisao allow/deny sem expor segredos.
- CA-093: Uma policy concedida em `nodes/{node_id}/files/mounts/{mount_id}` autoriza ou nega operacoes de gerenciamento de arquivos em qualquer subpath desse mount conforme capabilities, sem exigir policy por subdiretorio.
- CA-094: O parametro `path` de uma operacao de arquivo nao altera o Node Path usado na decisao de RBAC.
- CA-095: Rotas de arquivos da Control Tower usam `mount_id` no path da API e recebem subpath por query string ou corpo da requisicao.
- CA-096: O OpenAPI da Control Tower documenta o mapeamento entre rota e Node Path de RBAC.
- CA-097: Uma policy que concede `read`, `list` ou `write` em `nodes/{node_id}/files/mounts/{mount_id}` nao permite criar, planejar ou executar transferencias sem capability adequada em `nodes/{node_id}/transfers`.
- CA-098: Criar ou iniciar uma transferencia pela Control Tower exige permissao no dominio `transfers` e permissoes compativeis no dominio `files` para mounts de origem e destino.
- CA-099: Mesmo com RBAC permitido na Control Tower, uma transferencia entre nodes e negada quando os Transfer Path Grants dos nodes envolvidos nao autorizarem origem, destino, direcao ou modo operacional.
- CA-100: Rotas de transferencia da Control Tower usam o prefixo `/api/v1/nodes/{node_id}/transfers` e nunca sao confundidas com rotas de gerenciamento direto de arquivos.
- CA-101: Um cliente autenticado consegue navegar um mount autorizado usando apenas API, `node_id`, `mount_id` e `path` relativo, sem receber caminho absoluto do host.
- CA-102: Uma service account sem policy no dominio `files` nao consegue listar, baixar, enviar, mover, renomear ou remover arquivos, mesmo possuindo credencial valida.
- CA-103: Uma automacao ou agente de IA com policy restrita a um mount nao consegue acessar outro mount do mesmo node nem inferir paths absolutos fora do escopo permitido.
- CA-104: Toda operacao mutavel do API Filesystem registra auditoria com ator, tipo de ator, Node Path avaliado, `node_id`, `mount_id`, `path` relativo, decisao e identificador de correlacao.
- CA-105: Quando um node ou mount estiver indisponivel, o API Filesystem retorna erro ou estado estruturado sem tentar acessar o filesystem por canal alternativo.
- CA-106: Os binarios do node e da Control Tower oferecem comando offline de snapshot que recusa execucao concorrente com a instancia ativa, valida a integridade do SQLite e publica arquivo atomico com manifest e checksums.
- CA-107: O snapshot do node inclui dados e keys no mesmo conjunto, enquanto o snapshot da Control Tower exclui explicitamente a encryption key externa e registra essa exclusao no manifest.
- CA-108: O diagnostico offline de restore do node valida identidade, banco, mounts, peers, grants, jobs e parciais sem retomar jobs ou alterar o estado restaurado.
- CA-109: O diagnostico offline de restore da Control Tower valida a encryption key externa, administradores habilitados e credenciais criptografadas sem imprimir plaintext.

## 13. Decisoes Fechadas, Riscos e Decisoes em Aberto

### 13.1 Decisoes Fechadas

- O MVP do node tera um unico binario Go servindo API HTTP autenticada e Swagger/OpenAPI, sem frontend operacional.
- A Control Tower do MVP sera uma imagem apartada e opcional, usada como orquestrador de operacoes do dia a dia.
- A Control Tower deve preservar a singularidade de cada node: nodes continuam autonomos, donos dos seus nodes, jobs, mounts, permissoes e estado.
- A Control Tower nao persiste jobs. Ela apenas instrumenta operacoes e acompanha eventos; a logica e persistencia dos jobs ficam nos nodes envolvidos.
- Nodes nao terao interface web propria; devem expor Swagger/OpenAPI, porta HTTP da API autenticada e porta mTLS para transferencia.
- A autenticacao e criptografia de transferencias node-to-node sera por mTLS.
- A autenticacao de controle entre Control Tower e nodes sera por token recebido pelo node por variavel de ambiente, preferencialmente `CONTROL_TOWER_TOKEN`.
- Transfer Path Grants devem suportar mount inteiro e subdiretorio relativo ao mount.
- Disaster recovery do node depende principalmente do backup do volume persistente e dos mounts externos correspondentes.
- Node e Control Tower fornecerao comandos offline de snapshot consistente; o processo ativo mantera lock exclusivo para impedir captura concorrente.
- Node e Control Tower fornecerao diagnosticos offline e somente leitura antes da ativacao de um restore, com relatorio estruturado e falha de processo para inconsistencias bloqueantes.
- Control Tower e reconstruivel; nodes sao a fonte de verdade de jobs, grants, mounts e identidade.
- Restore sem identidade criptografica preservada deve ser tratado como novo node.
- Jobs restaurados nao retomam automaticamente sem revalidacao.
- Configuracao efetiva do node sera composta por defaults, arquivo, variaveis de ambiente, banco local e estado observado.
- Configuracoes mutaveis serao persistidas no banco local; configuracoes estruturais/secretas por ambiente ficam locked no MVP.
- Material criptografico do node ficara em diretorio de keys dedicado, separado do banco e dos mounts de transferencia.
- Rotacao mTLS usara janela de sobreposicao com estados `active`, `next`, `previous` e suporte a revogacao emergencial.
- Certificados mTLS serao gerados internamente no MVP; importacao de certificados externos ou pre-provisionados fica no roadmap pos-MVP.
- Control Tower tera autenticacao propria com usuarios humanos, service accounts, Argon2id e cookies de sessao.
- Control Tower persistira autenticacao, sessoes, policies e auditoria em SQLite criptografado por encryption key externa, preferencialmente `CONTROL_TOWER_DB_ENCRYPTION_KEY`.
- RBAC da Control Tower sera baseado em policies por Node Path, com capabilities semelhantes ao HashiCorp Vault.
- RBAC de arquivos na Control Tower sera granular ate o mount, nao ate subdiretorio ou arquivo dentro do mount.
- RBAC da Control Tower separara os dominios `files` e `transfers`; permissoes de gerenciamento de arquivos nao autorizam automaticamente transferencias.
- O sistema oferecera um API Filesystem distribuido para usuarios, automacoes e agentes de IA operarem arquivos por API controlada, sem acesso direto ao filesystem dos servidores.
- Rotas da Control Tower serao desenhadas para mapear diretamente para Node Paths estaveis.

### 13.2 Riscos e Decisoes em Aberto

- Definir o nivel inicial de operacoes permitidas entre dois nodes remotos coordenados por uma Control Tower.
- Definir se propostas de grants dentro do convite serao apenas sugestoes ou poderao virar rascunhos editaveis na Control Tower.
- Definir se `one_sided` deve distinguir submodos como `sender_only`, `receiver_only` e `requester_only`.
- Definir se mounts associados poderao ser arquivados logicamente ou apenas desabilitados quando houver historico de jobs.
- Definir formato de exportacao/importacao de configuracao e diagnostico de DR.
- Definir politica de retencao de backups recomendada.
- Definir como armazenar tokens da Control Tower em backup: segredo direto, referencia externa ou integracao futura com secret manager.
- Definir formato oficial do arquivo de configuracao: YAML, TOML ou JSON.
- Definir quais campos poderao usar reload sem restart apos o MVP.
- Definir duracao padrao da grace period para certificado mTLS anterior.
- Definir formato exato dos metadados de keys e lista de revogacao.
- Definir formato oficial das policies da Control Tower: HCL-like, YAML, JSON ou DSL propria.
- Definir parametros finais de Argon2id para ambientes pequenos e servidores modestos.
- Definir duracao padrao de sessao, idle timeout e politica de remember-me, se existir.
- Definir se service accounts usarao tokens opacos, JWT assinado, chave API prefixada ou outro formato.
- Definir se grupos de usuarios entram no MVP ou ficam para evolucao.
- Definir se a comparacao padrao usara apenas tamanho/data ou tambem checksum rapido.
- Definir como representar clusters na Control Tower e no modelo de permissao.
- Definir suporte inicial a copia local-local alem de copia peer-peer.
- Definir o comportamento padrao para arquivos modificados durante a transferencia.
- Definir estrategia de limpeza de arquivos `.jolt.partial`.
- Definir limites padrao de paralelismo para evitar saturar discos lentos ou redes domesticas.
