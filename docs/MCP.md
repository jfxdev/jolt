# Jolt MCP via STDIO

`jolt-mcp` usa o [SDK oficial de MCP para Go](https://github.com/modelcontextprotocol/go-sdk) e oferece quatro ferramentas de leitura: `list`, `search`, `disk_usage` e `read_text`. Elas acessam o Control Tower com a credencial configurada; policies, grupos, cotas, proteção de agentes e auditoria continuam sendo aplicados pelo Control Tower.

Configure o processo MCP com as variáveis `JOLT_MCP_CONTROL_URL` e `JOLT_MCP_CREDENTIAL_FILE`. O arquivo deve conter apenas uma credencial bearer, com uma quebra de linha final opcional, e ser legível pelo usuário que executa o processo. O conteúdo do arquivo é lido novamente em cada chamada, permitindo rotação por substituição do arquivo. Use uma conta de agente com as permissões mínimas necessárias.

```json
{
  "command": "/usr/local/bin/jolt-mcp",
  "env": {
    "JOLT_MCP_CONTROL_URL": "https://jolt.example.internal",
    "JOLT_MCP_CREDENTIAL_FILE": "/run/secrets/jolt-agent-token"
  }
}
```

O servidor usa STDIO para o protocolo e stderr para erros de inicialização; não aceita a credencial em argumentos ou na URL. HTTPS é obrigatório fora do loopback, e redirecionamentos não são seguidos. `read_text` aceita apenas texto UTF-8 sem controles binários e limita a resposta a 1 MiB; resultados JSON têm limite de 2 MiB. As ferramentas de listagem e busca pedem no máximo 200 itens. Os resultados não incluem a credencial configurada; respostas que a contenham são recusadas.

Todas as ferramentas recebem `node_id`, `mount_id` e `path`, relativo ao mount. `list` aceita `after`, o cursor retornado pela página anterior. `search` recebe também `query`. Os paths canônicos retornados pelo servidor devem ser usados em chamadas seguintes.

O binário também é incluído na imagem do Control Tower. Para executá-lo por STDIO em um container, passe `jolt-mcp` como comando e monte o arquivo de credencial com acesso somente de leitura para o usuário do container. Isso não habilita autenticação federada: JWT/JWKS e JWT-SVID ainda dependem da implementação de provedores e mapeamentos no Control Tower.

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

Em container, monte o arquivo da raiz somente para leitura e aponte `JOLT_MCP_CA_FILE` para ele.
