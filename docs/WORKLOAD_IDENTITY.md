# Provedores de identidade de workload

O suporte está em implementação: o Control Tower já valida a configuração de provedores na inicialização, mas **a autenticação por JWT e JWT-SVID ainda não está habilitada**. Não use esta configuração como substituta de API keys até a integração de mapeamentos, cotas e revogação estar concluída.

`CONTROL_TOWER_WORKLOAD_PROVIDERS_FILE` aponta para um arquivo JSON com `version: 1` e até 32 provedores. Na ausência da variável, nenhum provedor é carregado. O arquivo é lido na inicialização; para alterar os provedores ou bundles, reinicie o Control Tower.

```json
{
  "version": 1,
  "providers": [
    {
      "id": "issuer-local",
      "type": "jwt",
      "issuer": "https://issuer.example.internal",
      "audience": "jolt",
      "jwks_url": "https://issuer.example.internal/jwks",
      "algorithms": ["RS256"]
    },
    {
      "id": "workload-spiffe",
      "type": "jwt_svid",
      "trust_domain": "example.internal",
      "audience": "jolt-workloads",
      "bundle_file": "./jwt-bundle.json"
    }
  ]
}
```

O bundle SPIFFE é um JWKS com chaves públicas e seu caminho relativo é resolvido a partir do arquivo de provedores. URLs JWKS exigem HTTPS, exceto para emissores de teste em loopback. O carregador recusa campos desconhecidos, rotas duplicadas, algoritmos simétricos e configurações incompletas; a seleção ambígua entre provedores é recusada. Não inclua credenciais privadas no arquivo.

Na edição de uma conta de serviço, a seção **Identidades de workload** permite cadastrar, desativar, reativar e revogar mapeamentos para os provedores configurados. Para JWT, informe emissor, sujeito e audiência exatos; para JWT-SVID, deixe o emissor vazio e informe o SPIFFE ID completo como sujeito. Em contas de agente, o vínculo recebe os limites exibidos no formulário e pode ter esses limites atualizados. A rotação de uma API key estática não revoga os vínculos de workload. A identidade pode ser preparada agora, mas ainda não autentica requisições.
