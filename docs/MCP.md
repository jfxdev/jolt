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
