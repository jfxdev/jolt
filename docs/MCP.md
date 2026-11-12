# Jolt MCP

`jolt-mcp` usa o [SDK oficial de MCP para Go](https://github.com/modelcontextprotocol/go-sdk) e fala com o Control Tower em nome de um agente. Ele não decide permissões: cada ferramenta vira uma chamada à API do Control Tower, onde policies, grupos, cotas, aprovações, proteção de agentes e auditoria continuam sendo aplicados. Use uma conta de agente com as permissões mínimas necessárias.

Há dois transportes, no mesmo binário:

| | STDIO (`jolt-mcp`) | HTTP (`jolt-mcp serve`) |
| --- | --- | --- |
| Uso | um processo por agente, iniciado pelo cliente MCP | um serviço compartilhado, na porta 8092 |
| Credencial | arquivo `JOLT_MCP_CREDENTIAL_FILE` | o `Authorization: Bearer` de cada requisição |
| Toolsets padrão | `files` | `files,inspect,files_write,jobs` |

## STDIO

Configure o processo MCP com as variáveis `JOLT_MCP_CONTROL_URL` e `JOLT_MCP_CREDENTIAL_FILE`. O arquivo deve conter apenas uma credencial bearer, com uma quebra de linha final opcional, e ser legível pelo usuário que executa o processo. O conteúdo do arquivo é lido novamente em cada chamada, permitindo rotação por substituição do arquivo.

```json
{
  "command": "/usr/local/bin/jolt-mcp",
  "env": {
    "JOLT_MCP_CONTROL_URL": "https://jolt.example.internal",
    "JOLT_MCP_CREDENTIAL_FILE": "/run/secrets/jolt-agent-token"
  }
}
```

O servidor usa STDIO para o protocolo e stderr para erros de inicialização; não aceita a credencial em argumentos ou na URL. Para executá-lo por STDIO em um container, passe `jolt-mcp` como comando e monte o arquivo de credencial com acesso somente de leitura para o usuário do container.

## HTTP

`jolt-mcp serve` serve MCP por [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http) em `/mcp`, sem sessão (cada requisição é independente), e uma sonda de vida em `GET /health`. O serviço **não guarda credencial**: cada requisição precisa de `Authorization: Bearer <token do agente>`, que é repassado como está ao Control Tower em cada chamada de ferramenta. Assim cada agente aparece com a própria identidade na auditoria e é limitado pelas próprias policies. Sem token, ou com um token malformado, a resposta é `401`. `JOLT_MCP_CREDENTIAL_FILE` é ignorado nesse modo.

O binário já está na imagem do Control Tower. Os arquivos `docker-compose.yml` e `deploy/docker-compose.yml` têm o serviço `jolt-mcp`, que usa a mesma imagem com `entrypoint: jolt-mcp` e `command: serve`, roda como `PUID:PGID` sem capabilities, com sistema de arquivos somente leitura, e publica a porta só em `127.0.0.1` (`MCP_HTTP_BIND` muda isso).

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `JOLT_MCP_CONTROL_URL` | — (obrigatória) | URL do Control Tower. No compose, `http://jolt-control:8090`. |
| `JOLT_MCP_HTTP_ADDRESS` | `:8092` | Endereço de escuta (`--address` sobrepõe). |
| `JOLT_MCP_TOOLSETS` | `files,inspect,files_write,jobs` | Toolsets oferecidos, separados por vírgula. Nomes desconhecidos impedem a inicialização. |
| `JOLT_MCP_READ_ONLY` | `false` | Remove toda ferramenta que altera estado, em qualquer toolset. |
| `JOLT_MCP_INSECURE_CONTROL_URL` | `false` | Aceita `http://` fora do loopback para o Control Tower. Só para a rede privada do compose. |
| `JOLT_MCP_ALLOWED_ORIGINS` | vazio | Origens de navegador permitidas (`https://app.example.com`, separadas por vírgula). Elas recebem resposta ao preflight CORS (`OPTIONS`, sem token) e `Access-Control-Allow-Origin` nas respostas. Requisições com outro `Origin` recebem `403`; clientes sem `Origin` não são afetados. |
| `JOLT_MCP_TLS_CERT_FILE`, `JOLT_MCP_TLS_KEY_FILE` | vazio | Servem HTTPS diretamente. Sem eles o serviço avisa no início que os tokens trafegam em texto claro. |
| `JOLT_MCP_CA_FILE` | — | Raízes confiadas para o Control Tower (ver abaixo). |
| `MCP_HEALTHCHECK_URL` | `http://127.0.0.1:8092/health` | Só no compose: URL da sonda de saúde. Com TLS direto, use `https://127.0.0.1:8092/health`. |

Por padrão o Control Tower do compose escuta HTTP simples na rede interna, por isso o serviço vem com `JOLT_MCP_INSECURE_CONTROL_URL=true`. Com `CONTROL_TOWER_TLS_MODE=managed`, use `https://jolt-control:8090`, defina `JOLT_MCP_INSECURE_CONTROL_URL=false` e monte a raiz em `JOLT_MCP_CA_FILE` (ver abaixo). **Fora do loopback, publique a porta 8092 apenas atrás de um proxy TLS ou com TLS direto**: sem isso os tokens bearer trafegam em texto claro.

Cada chamada de ferramenta gera uma linha JSON em stderr com o nome da ferramenta, o resultado, a duração e o `subject` (um hash do token, nunca o token).

### Compose com TLS e CA

Os compose repassam `JOLT_MCP_TLS_CERT_FILE`, `JOLT_MCP_TLS_KEY_FILE`, `JOLT_MCP_CA_FILE` e `MCP_HEALTHCHECK_URL` ao container, mas os valores são caminhos **dentro** do container: os arquivos precisam ser montados por um override. Monte-os somente leitura, legíveis por `PUID` e não graváveis por outros usuários (o `jolt-mcp` recusa um arquivo de CA que outros possam alterar). Por exemplo, em `docker-compose.override.yml` ao lado do compose:

```yaml
services:
  jolt-mcp:
    environment:
      # TLS direto na porta 8092.
      JOLT_MCP_TLS_CERT_FILE: /run/secrets/mcp_tls_cert
      JOLT_MCP_TLS_KEY_FILE: /run/secrets/mcp_tls_key
      MCP_HEALTHCHECK_URL: https://127.0.0.1:8092/health
      # Control Tower com CONTROL_TOWER_TLS_MODE=managed.
      JOLT_MCP_CONTROL_URL: https://jolt-control:8090
      JOLT_MCP_INSECURE_CONTROL_URL: "false"
      JOLT_MCP_CA_FILE: /run/secrets/jolt_ca.pem
    volumes:
      - ./secrets/mcp_tls_cert.pem:/run/secrets/mcp_tls_cert:ro
      - ./secrets/mcp_tls_key.pem:/run/secrets/mcp_tls_key:ro
      - ./secrets/jolt_ca.pem:/run/secrets/jolt_ca.pem:ro
```

Use só a parte de que precisa: TLS direto e CA do Control Tower são independentes. O `jolt_ca.pem` pode ser o arquivo gravado por `jolt-mcp trust` (ver abaixo). Com TLS direto, `MCP_HTTP_BIND` pode sair do loopback; sem ele, coloque um proxy TLS na frente.

### Registrar no Claude Code

Não passe o token na linha de comando (`--header "Authorization: Bearer $(cat ...)"`): ele fica visível nos argumentos do processo e gravado fixo na configuração do cliente, e a rotação do arquivo não o atualiza. Use um `headersHelper`, que o Claude Code executa a cada conexão e que lê o arquivo protegido do token:

```sh
#!/bin/sh
# /usr/local/bin/jolt-mcp-headers: imprime o cabeçalho com o token atual.
IFS= read -r token < /run/secrets/jolt-agent-token
printf '{"Authorization":"Bearer %s"}\n' "$token"
```

```json
{
  "mcpServers": {
    "jolt": {
      "type": "http",
      "url": "http://127.0.0.1:8092/mcp",
      "headersHelper": "/usr/local/bin/jolt-mcp-headers"
    }
  }
}
```

`read` e `printf` são embutidos do shell, então o token não aparece em argumentos de processo. O helper roda de novo a cada nova conexão e quando o próprio `/mcp` responde `401`/`403` (token ausente ou malformado). Um token revogado ou expirado não gera esse `401`/`403`: o Control Tower recusa a chamada e a recusa volta como erro da ferramenta. Por isso, depois de substituir o arquivo do token, reconecte o servidor (`/mcp` no Claude Code) para que o helper leia o token novo.

## Ferramentas

Ferramentas com IDs (`node_id`, `mount_id`, `job_id`...) recusam `/`, `\`, `?`, `#`, `%` e espaços; `path` é sempre relativo ao mount e recusa `..`. Os paths canônicos retornados pelo servidor devem ser usados em chamadas seguintes. Argumentos desconhecidos são recusados antes de chegar ao Control Tower.

Respostas JSON têm limite de 2 MiB e texto de 1 MiB. Respostas que contenham a credencial em uso são recusadas. Quando o Control Tower recusa uma chamada, o erro traz o status HTTP, o `code`, a mensagem e o `correlation_id`; use este último em `search_audit`. Uma operação que espera aprovação retorna `pending_operation_id`, que se acompanha com `get_pending_operation`. Toda chamada que altera estado (inclusive `write_text`) envia um `Idempotency-Key` gerado; passe `idempotency_key` (o mesmo valor ao repetir a chamada) para que ela seja aplicada uma vez só.

As anotações MCP indicam ao cliente quais ferramentas pedem confirmação: leitura tem `readOnlyHint`, escrita só aditiva (`mkdir`, `restore_trash`, `pause`...) tem `destructiveHint: false`, e as destrutivas vão sem anotação, que pela especificação já significa destrutiva. Toda ferramenta que pode substituir dados existentes é destrutiva, como `write_text` (com `overwrite`) e `copy` (com `overwrite`, `checksum` ou `ask`).

### Custo em tokens

Todo agente paga pela lista de ferramentas em cada conversa, então ela é enxuta: as convenções comuns (IDs, paths relativos, erros, aprovações, `idempotency_key`) vão uma vez nas `instructions` do `initialize`, e argumentos óbvios como `node_id` não têm descrição. Ações raras ou simétricas sobre um mesmo recurso são uma ferramenta só, com o argumento `action` (`control_job`, `decide_pending_operation`, `manage_*`); a descrição lista cada ação com seus argumentos. A lista padrão do HTTP tem cerca de 16 KB (~4 mil tokens) e, com `admin`, cerca de 24 KB; `TestToolListingStaysSmall` falha se ela crescer além do orçamento. Ofereça só os toolsets que o agente usa: `files` sozinho custa ~400 tokens.

### `files` — leitura de arquivos

`list` (com `after`, o cursor da página anterior, até 200 itens), `search` (`query`), `disk_usage` e `read_text` (UTF-8 sem controles binários, até 1 MiB).

### `inspect` — diagnóstico (somente leitura)

| Ferramenta | Para quê |
| --- | --- |
| `whoami`, `about` | Identidade da credencial; versão e recursos do Control Tower. |
| `check_permissions` | Capabilities da credencial em até 100 Node Paths (`nodes/{node}/files/mounts/{mount}/{path}`). |
| `effective_access` | O que outra identidade pode fazer, com as regras que decidiram. Exige permissão de listar policies. |
| `diagnose_node` | Em uma chamada: o que o node reporta, trust e certificados, jobs por estado e mounts. Cada seção traz o próprio erro. |
| `diagnose_path` | Metadados de um path e as capabilities nele e em cada pasta acima, para achar por que uma chamada é recusada. |
| `list_nodes`, `node_info`, `node_trust` | Nodes, estado e certificados. |
| `list_mounts`, `get_mount`, `stat`, `archive_plan` | Mounts, metadados de uma entrada e estimativa de um archive. |
| `list_jobs`, `job_summary`, `get_job`, `list_job_items` | Jobs e itens por arquivo, para achar qual falhou e por quê. |
| `list_trash`, `get_trash_item` | Lixeira de um mount. |
| `list_peers`, `list_grants`, `list_connections` | Pareamento e conexões entre nodes. |
| `list_pending_operations`, `get_pending_operation` | Operações esperando aprovação. |
| `search_audit` | Auditoria filtrada por `correlation_id`, `action`, `actor_type`, `result`, paginada por `before_id`. |
| `list_certificates`, `get_trust_bundle`, `list_revocations` | Autoridades, bundle de trust e revogações. |

### `files_write` — alterar arquivos

`mkdir`, `write_text` (UTF-8 até 1 MiB; recusa sobrescrever sem `overwrite`), `plan_copy` (prévia, não altera nada), `copy` (`conflict_policy`: `skip`, `overwrite`, `rename`, `fail`, `checksum` ou `ask`; `ask` deixa cada conflito esperando `override_job_item` e é recusado com jobs assinados), `move`, `delete` (`recursive` para pastas não vazias; vai para a lixeira quando ela está ativa), `restore_trash` e `purge_trash` (definitivo).

Para apagar ou mover uma árvore, quando o Control Tower exige (`plan_required`), use `plan_destructive`: ele devolve `plan_id`, `token` e quantos arquivos e bytes serão afetados. Mostre isso ao usuário e só então chame `confirm_destructive`; se a árvore mudar no meio, nada é alterado.

### `jobs` — jobs, transferências e aprovações

`control_job` (`action`: `pause`, `resume`, `cancel`, `retry`), `override_job_item` (decide um conflito: `skip`, `overwrite`, `rename`, `fail`), `transfer_targets`, `plan_transfer` e `create_transfer` (cópia ou movimentação entre nodes, com as mesmas `conflict_policy` de `copy`; um move precisa do `move_plan` devolvido pelo plano) e `decide_pending_operation` (`action`: `approve`, `reject`).

### `admin` — identidades, policies e frota (opt-in)

Só aparece com `admin` em `JOLT_MCP_TOOLSETS`. Uma ferramenta por recurso, com `action`: `manage_users`, `manage_service_accounts` (inclui tokens, grupos, policies, políticas temporárias e workload identities), `manage_access_groups`, `manage_policies` (inclui roles), `manage_shares`, `manage_mounts` (inclui `browse_host_fs`), `manage_nodes` (inclui enrollments e join tokens) e `manage_peering` (conexões, grants e peers). Ações de criação e alteração recebem `body` com os campos da API, listados na descrição. Com `JOLT_MCP_READ_ONLY=true` cada uma oferece só as ações `list*`. Como uma ferramenta mistura leitura e escrita, ela é anotada como destrutiva.

> **Atenção:** com `admin`, um agente com permissão suficiente cria credenciais (o segredo volta na resposta uma única vez) e muda policies. Ofereça esse toolset só a agentes que precisam dele, de preferência num serviço `jolt-mcp` separado.

Ficam fora do MCP, só na interface: rotação e promoção de CA, revogação de certificados, rotação de token e identidade de nodes, distribuição de mTLS, pareamento, uploads em partes, download de archives, rotas públicas de share e login.

Isso não habilita autenticação federada: JWT/JWKS e JWT-SVID ainda dependem da implementação de provedores e mapeamentos no Control Tower.

## Confiar na raiz do Jolt

Com `CONTROL_TOWER_TLS_MODE=managed`, o HTTPS do Control Tower é assinado pela raiz do próprio Jolt, que o sistema operacional do agente não conhece. Em vez de instalar a raiz no sistema, guarde-a uma vez para o `jolt-mcp`:

```sh
jolt-mcp trust http://HOST:8091 --fingerprint AB:CD:EF:...
```

- A URL é a página pública da raiz (`CONTROL_TOWER_CA_ADDRESS`, HTTP simples) ou o próprio Control Tower em HTTPS. Nos dois casos o conteúdo é autenticado só pelo `--fingerprint`, que **é obrigatório** e deve vir de outro canal (Access > Certificados, ou o administrador). Se o SHA-256 da raiz não for o informado, nada é gravado. Aceita maiúsculas, minúsculas e dois-pontos.
- A raiz precisa ser um certificado de CA autoassinado e válido; qualquer outra coisa é recusada.
- O arquivo fica em `JOLT_MCP_CA_FILE` ou, sem a variável, em `ca.pem` dentro de `jolt-mcp` no diretório de configuração do usuário (`~/.config` no Linux, `~/Library/Application Support` no macOS). É gravado com permissão `0600`, por substituição atômica, e guarda até 8 raízes. `--ca-file` escolhe outro caminho.
- **O servidor MCP passa a confiar só nas raízes desse arquivo** e não no repositório do sistema. `JOLT_MCP_CA_FILE` aplica-se mesmo que o arquivo ainda não exista (um erro de digitação falha, em vez de cair para outra confiança); o arquivo padrão só vale depois de criado. O arquivo é relido quando muda, sem reiniciar o processo, e é recusado se outros usuários puderem escrever nele.
- Rodar `trust` de novo **acrescenta** a raiz e mantém as que ainda não expiraram, para que uma troca de raiz não deixe o agente sem nenhuma válida. `--replace` descarta as anteriores.

Numa troca de raiz do Control Tower, `jolt-mcp trust http://HOST:8091 --fingerprint <da raiz nova> --next` guarda a raiz nova (`/ca/next.pem`, que só existe durante a troca) ao lado da atual, antes da promoção. A raiz antiga só sai do arquivo quando expira; depois da aposentadoria dela, rode `trust --replace` com a raiz nova para limpá-lo.

Em container, monte o arquivo da raiz somente para leitura e aponte `JOLT_MCP_CA_FILE` para ele (no compose, com o override de [Compose com TLS e CA](#compose-com-tls-e-ca)). Isso vale para os dois transportes.
