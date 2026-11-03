# Provedores de identidade de workload

O suporte está em implementação. Contas de agente podem autenticar com JWT ou JWT-SVID de um provedor configurado e uma identidade explicitamente mapeada. Contas de automação ainda recusam essas credenciais enquanto expiração, revogação e compartilhamentos são integrados.

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

O validador SPIFFE usado nesta versão aceita JWT-SVID assinados com RSA, RSA-PSS ou ECDSA; EdDSA é suportado pelo provedor JWT genérico, mas não pelo validador JWT-SVID. O carregamento recusa bundles sem nenhuma autoridade utilizável; em bundles mistos, chaves incompatíveis são ignoradas.

Na edição de uma conta de serviço, a seção **Identidades de workload** permite cadastrar, desativar, reativar e revogar mapeamentos para os provedores configurados. Para JWT, informe emissor, sujeito e audiência exatos; para JWT-SVID, deixe o emissor vazio e informe o SPIFFE ID completo como sujeito. Em contas de agente, o vínculo recebe os limites exibidos no formulário e pode ter esses limites atualizados. A rotação de uma API key estática não revoga os vínculos de workload. Cada vínculo possui uma identidade de credencial estável: a troca do JWT não reinicia os limites de taxa ou a cota diária. A expiração do JWT limita cada requisição, e a desativação ou revogação cancela as requisições ativas. JWTs com expiração superior a 30 dias são recusados para agentes. O token não é persistido.
