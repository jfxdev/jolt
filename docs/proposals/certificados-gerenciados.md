# Proposta — Certificados e chaves com ciclo de vida gerenciado pelo Jolt

> **Status:** proposta aprovada; **fase 1 implementada** (ver §12), fases 2 a 4 não · **Data:** 6 de novembro de 2026 · **Origem:** o Jolt precisa funcionar **fechado**, sem depender de reverse proxy, ACME, CA externa ou operação manual de `openssl` · **Complementa:** [`plano-consolidado-seguranca.md`](plano-consolidado-seguranca.md) (contextos assinados) e [`../PRODUCTION.md`](../PRODUCTION.md) · **Código lido:** `node/backend/internal/infra/crypto/certificates.go`, `node/backend/internal/infra/config/config.go`, `control/internal/config/config.go`, `control/internal/store/store.go`, `docs/NODE_YAML.md`, `scripts/signed-read-smoke.py`.

## 1. Resumo

Hoje o operador precisa, com ferramentas de fora do Jolt:

- gerar a chave Ed25519 que assina os contextos de autorização e copiar a pública para `authorization_public_keys` em cada `node.yaml`;
- obter um certificado HTTPS para o Control Tower (ou pôr um reverse proxy na frente);
- se quiser TLS na API do node, montar uma CA, um certificado de servidor por node e um de cliente para o Control Tower;
- copiar um token compartilhado (`CONTROL_TOWER_TOKEN`) para cada node e cadastrá-lo no Control Tower.

Só o mTLS entre peers (porta 8443) já tem ciclo de vida próprio (criação, preparo, promoção, rollback, revogação).

A proposta é o Control Tower passar a ser a **autoridade de certificação interna** do conjunto, emitindo, renovando e revogando tudo sozinho, e um **enrollment de um passo** por node substituir a configuração manual. O operador e os agentes passam a tocar em três pontos, todos únicos: criar um token de adesão, entregá-lo ao node na implantação e, se quiser navegador sem aviso, instalar a raiz pública uma vez em cada dispositivo.

### Escopo

Dentro:

1. CA interna no Control Tower e distribuição de um pacote de confiança (*trust bundle*).
2. Certificado HTTPS do próprio Control Tower, servido por ele, sem proxy na frente.
3. Certificados da API do node (servidor) e do Control Tower (cliente), com renovação automática.
4. Chave de assinatura de contextos: geração, distribuição e rotação.
5. Enrollment de node por token de uso único.
6. Inventário, métricas e alertas de vencimento.

Fora (não-objetivos):

- **Reverse proxy.** Esta proposta não o usa nem o descreve. O Control Tower termina o próprio TLS. Quem quiser pôr um proxy continua podendo, pelo modo manual.
- ACME / Let's Encrypt e qualquer dependência de rede externa para emitir ou validar.
- PKI corporativa externa, HSM, OCSP e CRL públicas.
- Reprojetar o mTLS entre peers, que continua gerido pelo node.
- Certificados de cliente para login de pessoas no navegador.
- Alta disponibilidade do Control Tower.

## 2. Princípios

1. **Fechado por padrão.** Nenhum passo exige internet. Tudo que precisa ser verificado está num pacote que o Control Tower assina e distribui.
2. **Mínimo de contato.** Cada ator humano ou agente faz uma ação por vida do sistema, nunca uma por renovação.
3. **Chave privada nunca viaja.** Cada componente gera a própria chave e envia só um CSR. Isso inclui o node.
4. **Vida curta em vez de revogação pesada.** Sem OCSP/CRL, o que limita um vazamento é o prazo curto mais uma lista de seriais revogados dentro do pacote assinado.
5. **O canal não basta para trocar a raiz de confiança.** Chaves de assinatura e CA só mudam por mensagem assinada pela chave anterior, nunca só porque a conexão é autenticada (§6.2).
6. **Compatibilidade.** O modo manual de hoje continua existindo e é o padrão até o operador optar pelo gerenciado, node a node.

## 3. Inventário

| Item | Quem gera a chave | Quem assina | Prazo | Renovação |
| --- | --- | --- | --- | --- |
| Raiz da CA do Jolt | Control Tower | ela mesma | 10 anos | só assina intermediárias; rotação com sobreposição (§7) |
| Intermediária emissora | Control Tower | raiz | 2 anos | renovada sozinha aos 2/3 da vida (§3.1) |
| Certificado HTTPS do Control Tower | Control Tower | intermediária | 90 dias | aos 2/3 da vida (60 dias), recarregado a quente |
| Certificado de cliente do Control Tower (para nodes) | Control Tower | intermediária | 90 dias | aos 2/3 da vida |
| Certificado de servidor da API do node | node | intermediária, via CSR | 90 dias | CT dirige, node gera a chave (§5.3) |
| Chave de assinatura de contextos | Control Tower | n/a (Ed25519) | 90 dias | rotação com sobreposição (§6) |
| Certificado mTLS entre peers | node | o próprio node | já existe | já existe |
| Token do node (`CONTROL_TOWER_TOKEN`) | Control Tower | n/a | até o modo `managed-only` | removido na fase 4 |

Certificados voltados a TLS usam **ECDSA P-256**, que todo navegador, cliente HTTP e biblioteca TLS aceita. A chave de assinatura de contextos continua **Ed25519**, como o node já espera.

Todos os certificados folha são válidos por **90 dias** por padrão (configurável por tipo, entre 7 e 180 dias) e renovados aos 2/3 da vida. O prazo longo dispensa contato frequente entre o Control Tower e os nodes; o que limita um vazamento de chave folha é a lista de seriais revogados dentro do pacote assinado (§4), não o prazo.

### 3.1 Raiz e intermediária

A hierarquia tem dois níveis:

- A **raiz** é gerada uma vez, guardada no SQLCipher sob uma chave de envelope própria, derivada de `CONTROL_TOWER_DB_ENCRYPTION_KEY` (HKDF com contexto fixo), e **só é carregada em memória para assinar uma intermediária**: no primeiro start, a cada renovação (2 anos) e numa troca de emergência. Nunca assina certificado folha.
- A **intermediária emissora** é a chave de uso diário. Ela assina todas as folhas e fica disponível ao processo.
- Os nodes e o navegador confiam **na raiz**. O hash do token de adesão (§5.1) é o da raiz, então trocar a intermediária não obriga nenhum node a re-enrolar nem nenhum navegador a reinstalar nada.

Isto limita o dano de um vazamento da chave diária: o Control Tower revoga a intermediária (serial no pacote, §4), gera outra assinada pela raiz e reemite as folhas, sem tocar na confiança dos dispositivos.

Sem HSM ou segundo host, a raiz continua no mesmo banco que a intermediária, então o isolamento é de **exposição em memória e de operação**, não de armazenamento. Quem tem o banco e a chave de criptografia dele ainda tem a CA. Por isso há um endurecimento opcional, sem contato no caminho padrão:

- `jolt-control ca export-root` grava a raiz cifrada por senha, remove-a do banco e passa a exigir o arquivo apenas na renovação da intermediária. O Control Tower alerta 60 dias antes (§10). É a única operação do sistema que **exige** uma pessoa, e só ocorre a cada 2 anos.
- O padrão é a raiz ficar no banco, para que o ciclo de vida seja totalmente automático.

## 4. Pacote de confiança

O Control Tower publica um *trust bundle* assinado com a chave de assinatura vigente:

```json
{
  "version": 12,
  "issued_at": "2026-11-06T12:00:00Z",
  "roots": ["<PEM da raiz atual>", "<PEM da próxima, durante rotação>"],
  "intermediates": ["<PEM da intermediária emissora>"],
  "signing_keys": [{"id": "2026-11", "key": "<base64 32 bytes>", "not_after": "..."}],
  "revoked_serials": ["..."],
  "signature": {"key_id": "2026-11", "value": "..."}
}
```

Regras que o node aplica antes de aceitar um pacote novo:

- `version` é estritamente crescente. Pacote com versão menor ou igual é recusado, o que impede *rollback* para um conjunto de chaves antigo.
- A assinatura precisa ser de uma chave que **já está** no pacote anterior armazenado. Só o primeiro pacote, entregue no enrollment, é aceito por outra via (§5.2).
- No máximo 16 chaves de assinatura, 2 raízes e 2 intermediárias, o mesmo limite de hoje para as chaves.
- Cada intermediária precisa estar assinada por uma raiz já confiável no pacote anterior.
- Chave ou raiz removida deixa de ser aceita; a sobreposição durante a rotação é explícita no pacote.

O pacote é guardado no estado cifrado do node, que eleva a versão mínima autenticada do estado ao gravar o primeiro. `authorization_public_keys` no YAML continua válido e, quando presente junto com um pacote, vale a **união**, nunca a substituição, para que ninguém perca acesso numa migração.

O node expõe o pacote atual por `GET` e o Control Tower o empurra quando muda e a cada reconciliação. Perder uma entrega é seguro: o node continua com o pacote anterior, que tem prazo próprio.

## 5. Enrollment

### 5.1 Token de adesão

O administrador cria no Control Tower um token com nome do node esperado e validade. O formato segue a ideia do `kubeadm join`: o token carrega o endereço do Control Tower e o **hash da raiz**, para que o node não precise confiar em nada que ainda não conhece:

```
jolt-join:v1:<segredo-32-bytes>:<sha256-da-raiz>:<https://control:8090>
```

- uso único, validade padrão de 15 minutos, máxima de 24 horas;
- ligado ao nome do node, que o enrollment não pode alterar;
- guardado só como hash no Control Tower, exibido uma vez;
- aceito em `JOLT_JOIN_TOKEN_FILE` (mesmo padrão `NOME_FILE` dos outros segredos) ou como argumento do primeiro start.

Isto é o **único** passo manual por node.

### 5.2 Fluxo

1. O node sobe sem token do Control Tower e com `tls_mode: managed`. Ele gera chave de API e CSR, e a identidade Ed25519 que já tem.
2. Conecta ao endereço do token e valida a cadeia **contra o hash da raiz do token**, sem usar o repositório de CAs do sistema. Uma raiz diferente aborta o enrollment antes de enviar o segredo.
3. Envia o segredo do token, o CSR, sua identidade (`node_id`, fingerprint) e o endpoint da API que anuncia.
4. O Control Tower valida token, nome e validade, consome o token, emite o certificado de servidor da API e devolve: certificado, raiz, primeiro pacote de confiança e a identidade do Control Tower.
5. O Control Tower cadastra o node (`node_id`, endpoint, fingerprint da identidade e do certificado), sem passar pela digitação de endpoint e token que existe hoje.
6. O node passa a exigir certificado de cliente emitido pela CA nas rotas operacionais.

O padrão é `enrollment_approval: auto`: um token válido, dentro do prazo e com o nome certo **é** a autorização, e o node entra sem mais nenhum passo humano. A aprovação manual existe e está descrita em §5.4.

### 5.3 Renovação do certificado de API do node

Dirigida pelo Control Tower, como já é a rotação do mTLS entre peers, porque ele já se conecta a todo node:

1. Quando o certificado do node chega a 2/3 da vida, o Control Tower pede `POST /api/v1/crypto/api-cert/csr`.
2. O node gera um par novo, mantém o antigo e devolve o CSR assinado pela chave nova.
3. O Control Tower emite e envia o certificado. O node o promove e passa a apresentá-lo, sem reiniciar.
4. Se o node estiver fora do ar, o Control Tower repete com recuo. O alerta de vencimento (§10) dispara muito antes da expiração.

Node que expirou sem renovar não consegue mais autenticar o Control Tower e precisa de novo token de adesão; é o único caso em que a renovação exige contato, e o alerta existe para evitá-lo.

### 5.4 Aprovação manual (opcional)

Para ambientes em que um token vazado não pode, sozinho, criar um node, o administrador escolhe `enrollment_approval: manual`. O valor é definido ao criar o token e tem um padrão global em `CONTROL_TOWER_ENROLLMENT_APPROVAL` (`auto` se omitido). Um token pode pedir `manual` mesmo com o padrão global `auto`, mas nunca o contrário: nenhum token afrouxa a política global `manual`.

Com `manual`, o fluxo muda a partir do passo 4 de §5.2:

1. O Control Tower valida e consome o token, mas **não emite** o certificado. Registra o node como `pending_enrollment`, com `node_id`, fingerprint da identidade, endpoint anunciado, endereço de origem e horário.
2. O node recebe uma resposta `202` e repete a consulta do próprio pedido (recuo de 5 a 60 segundos) até a decisão ou o prazo. Enquanto espera, não aceita nenhuma operação.
3. O administrador vê o pedido em Segurança > Nodes pendentes e **compara o fingerprint** que o node mostra em seu log de inicialização com o que o Control Tower recebeu. Aprovar emite o certificado e o pacote; rejeitar descarta o pedido e registra o motivo.
4. O pedido expira em 15 minutos sem decisão. Um token consumido nunca volta a valer, então um pedido expirado exige um token novo.
5. Quem aprova precisa de `sudo` em `control-tower/enrollments`, a mesma capacidade das aprovações humanas de operação. Agentes e contas de serviço não aprovam.

A aprovação, a rejeição e a expiração entram na auditoria com o fingerprint, sem o segredo do token.

## 6. Chave de assinatura de contextos

### 6.1 Geração e rotação

- O Control Tower gera a Ed25519 no primeiro start com `managed`, guarda a privada no SQLCipher e deixa de ler `CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_FILE`. Quem ainda a usa continua funcionando.
- A cada 60 dias (de 90 de vida), gera a seguinte, publica um pacote com as duas e, depois da janela de sobreposição (14 dias), publica um sem a antiga.
- O pacote que acrescenta a chave nova é assinado pela **antiga**; só depois a nova passa a assinar contextos. Assim nenhum node vê uma chave sem ter vindo de quem já era confiável.

### 6.2 Por que não basta o canal autenticado

Uma ideia mais simples seria o Control Tower enviar a chave pública ao node pela mesma API que já o autentica. Isso enfraquece o que a assinatura protege: quem roubar a credencial que autentica o Control Tower instalaria a própria chave e assinaria qualquer contexto. Por isso:

- a primeira chave chega só no enrollment, validada pelo hash da raiz que veio no token;
- toda mudança posterior exige assinatura da chave anterior (§4);
- no modo `managed-only` (§9) o token compartilhado deixa de existir, então roubar o canal exige roubar a chave de cliente do Control Tower **e** a chave de assinatura.

## 7. Rotação e perda da raiz e da intermediária

- **Rotação planejada:** a nova raiz entra no pacote junto da antiga, assinada pela chave de assinatura vigente. Depois que todos os nodes confirmarem o pacote (o Control Tower sabe pela reconciliação), o emissor passa a usar a nova. A raiz antiga sai do pacote só ao fim da vida dos últimos certificados que emitiu.
- **Vazamento da intermediária:** o Control Tower coloca o serial no pacote, gera uma nova intermediária assinada pela raiz e reemite as folhas. Os nodes não re-enrolam e os navegadores não mudam. É um incidente de operação, não de confiança.
- **Vazamento da raiz:** é um incidente do Control Tower inteiro, como já é o vazamento de `CONTROL_TOWER_DB_ENCRYPTION_KEY`. O procedimento é recriar a CA e re-enrolar todos os nodes. Deve estar escrito em `DISASTER_RECOVERY.md` antes de a fase 2 ser habilitada.
- **Perda do banco do Control Tower:** idem. Sem a raiz, os nodes não conseguem validar um Control Tower novo, o que é o comportamento desejado.

## 8. Navegadores e agentes

Sem reverse proxy e sem CA pública, o certificado HTTPS do Control Tower só é confiável para quem confia na raiz do Jolt. Isso é inevitável num sistema fechado, então o objetivo é torná-lo **uma vez por dispositivo**:

- `GET /.well-known/jolt/ca.pem` e uma página `/ca` mostram o fingerprint e instruções por sistema. Nenhuma outra funcionalidade depende de a raiz estar instalada.
- Quem já tem uma CA corporativa instalada nos dispositivos pode fornecer o certificado do Control Tower pelos arquivos manuais, como hoje.
- Agentes e o MCP STDIO recebem o `ca.pem` e o hash por configuração. O `jolt-mcp` ganha `trust <url> --fingerprint <sha256>`, que baixa a raiz, confere o hash e a guarda; depois disso o agente não toca mais em certificados.
- Renovações do certificado HTTPS não pedem nada de ninguém: a raiz continua a mesma e o servidor recarrega o certificado novo a quente.

## 9. Modos e compatibilidade

`tls_mode` no node e `CONTROL_TOWER_TLS_MODE` no Control Tower:

| Modo | Comportamento |
| --- | --- |
| `manual` (padrão) | Igual a hoje. Nada desta proposta é ativado. |
| `managed` | CA, pacote, certificados e rotação automáticos. O token compartilhado ainda é aceito, para migrar sem parada. |
| `managed-only` | Só certificado de cliente da CA autentica o Control Tower. Token compartilhado recusado. |

A migração de um node existente usa o mesmo token de adesão, com o nome do node já cadastrado: o enrollment atualiza o registro em vez de criar outro. Reverter para `manual` é possível enquanto o node ainda tiver o token e o YAML antigos.

## 10. Observabilidade

- **Inventário** na tela de Segurança: cada certificado e chave, emissor, fingerprint, vencimento e última renovação, por node.
- **Métricas** `jolt_certificate_expiry_seconds{kind,subject}`, `jolt_certificate_renewal_failures_total` e `jolt_trust_bundle_version{node}`.
- **Alertas de referência** a 14, 7 e 2 dias de vencimento de cada folha, a 60 dias da intermediária (e, com a raiz fora do banco, da necessidade de apresentá-la), e para node cujo pacote ficou atrás da versão publicada por mais de uma hora.
- **Auditoria** de enrollment, emissão, renovação, revogação e rotação, sem nunca registrar chave privada, segredo de token ou CSR.

## 11. Modelo de ameaça

| Ameaça | Mitigação | Risco residual |
| --- | --- | --- |
| Token de adesão roubado antes do uso | uso único, 15 minutos, nome fixado, aprovação `manual` opcional (§5.4) | quem usar primeiro vira aquele node; o administrador vê a divergência no inventário |
| Control Tower falso no enrollment | o node valida a cadeia contra o hash da raiz que veio no token | token interceptado por inteiro revela esse hash, mas isso não dá a chave da raiz |
| Roubo do canal Control Tower → node | `managed-only` exige certificado de cliente de 90 dias, revogável pelo pacote, e mensagens assinadas | roubo simultâneo da chave de cliente e da de assinatura |
| Node comprometido | só tem a própria chave de API; não assina contextos nem emite certificados; o serial vai ao pacote de revogados | até o próximo pacote chegar aos peers |
| Rollback de pacote | versão estritamente crescente, armazenada de forma cifrada e autenticada | node restaurado de backup antigo aceita um pacote mais novo, mas nunca um mais velho |
| Relógio errado | `NotBefore` com folga de 5 minutos, como o certificado mTLS atual; a operação já manda conferir o relógio (`PRODUCTION.md`), mas não há alerta de desvio | desvio maior que a folga impede conexão e aparece como falha de renovação |
| Roubo do banco do Control Tower | a raiz está cifrada pela mesma chave que protege os tokens dos nodes | quem tem banco e chave tem a CA, igual a hoje para tokens |

O Control Tower comprometido já controlaria todos os nodes pelo token compartilhado que guarda. A proposta não aumenta esse risco; ela o concentra numa chave só e permite, com `managed-only`, impedir que o vazamento de um node afete outro.

## 12. Fases

**Fase 1: autoridade no Control Tower, sem tocar nos nodes.**
- Raiz, intermediária, certificado HTTPS do Control Tower servido por ele, geração e rotação da chave de assinatura, pacote de confiança, inventário e métricas.
- Rotas `GET /crypto/ca`, `GET /crypto/authorization-keys` e a página `/ca`.
- O trecho `authorization_public_keys` sai pronto para colar, o que já elimina o `openssl` do caminho.
- Critérios: `go test -race` limpo; teste de rotação com sobreposição; teste que adultera pacote (versão, assinatura, chave desconhecida, raiz extra) e vê recusa; mutação nas verificações.

**Fase 1 — implementada em 6 de novembro de 2026.** `CONTROL_TOWER_TLS_MODE=managed` liga a autoridade, o HTTPS próprio, a chave de assinatura gerada e rotacionada, o pacote de confiança, a página pública da raiz, o inventário (API, métricas e aba Access > Certificados) e o bloco de YAML pronto. Operação em [`../OPERATIONS.md`](../OPERATIONS.md#certificados-e-chaves-gerenciados). Verificada com testes, mutação e um binário real (HTTPS validado com a raiz baixada, raiz e chave estáveis entre reinícios, recusa de chave de banco errada). O que mudou em relação ao texto acima:

- A chave de assinatura chega ao resto do código por uma fonte (`config.SigningSource`), não mais por um campo fixo; sem ela os contextos já emitidos deixariam de verificar quando a chave rodasse.
- Uma chave publicada e ainda sem assinar (a sucessora) **não** é aceita para verificar contextos; só a ativa e as que estão na sobreposição.
- O certificado HTTPS não é gravado: nasce na memória a cada início. Menos uma chave privada no banco.
- Uma renovação de intermediária que depende de uma raiz ausente do banco **não derruba** o Control Tower enquanto a intermediária vigente não expirou: o passe termina o resto e devolve `ErrRootUnavailable`, que vira aviso. Só a expiração é falha dura.
- `managed` recusa `CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_*` em vez de ignorá-las em silêncio.
- A métrica `jolt_certificate_expiry_seconds` tem um rótulo `kind` e conta só o que está em uso, para uma despedida planejada não parecer defeito.
- Um defeito achado pelos testes e corrigido: uma raiz listada como intermediária passava na checagem do pacote, porque a raiz assina a si mesma.
- Fica de fora desta fase, e continua previsto: `ca export-root`, seriais revogados, rotação de raiz, aprovação de enrollment, certificados de cliente e de API do node, `jolt-mcp trust`.

**Fase 2: enrollment e pacote no node.**
- Token de adesão, endpoints de enrollment e de pacote, estado cifrado no node, certificado de servidor da API e renovação dirigida pelo Control Tower, certificado de cliente do Control Tower.
- Critérios: node de mentira cobre cada passo do §5.2; um teste de falha para cada linha da tabela do §11; teste com processo real de node (feito pelo mantenedor).

**Fase 3: ergonomia e agentes.**
- Página `/ca`, `jolt-mcp trust`, hot reload do certificado HTTPS, UI de inventário e enrollment.
- Critérios: jornadas Playwright (desktop e mobile) de criar token, ver pendente e aprovar; documentação operacional.

**Fase 4: endurecimento.**
- `managed-only`, rotação de raiz, lista de revogados no pacote, `DISASTER_RECOVERY.md`, alertas de referência.
- Critérios: ensaio de rotação de raiz com dois nodes; ensaio de perda da raiz e re-enrollment; ensaio de node que expirou.

Cada fase é útil sozinha e reversível enquanto o modo `manual` existir.

## 13. Decisões

1. **Raiz e intermediária.** Decidido: hierarquia de dois níveis (§3.1). A raiz fica no banco por padrão, só assina intermediárias, e pode ser tirada do banco como endurecimento opcional.
2. **Validade padrão dos certificados.** Decidido: 90 dias para as folhas (§3). A intermediária dura 2 anos e a raiz 10.
3. **Aprovação do enrollment.** Decidido: o padrão é `auto`, e a aprovação `manual` fica documentada em §5.4 como opção por token ou global.
4. **Quem hospeda a página `/ca`.** Decidido: HTTP simples numa porta separada, só com o certificado público e o fingerprint, para o usuário poder baixá-lo antes de confiar na raiz.

## 14. O que não está provado

Nada aqui foi executado. Os pontos que dependem de ambiente real e que ficam para o aceite do mantenedor: renovação em dois hosts com relógio divergente, expiração e re-enrollment, recarga a quente do certificado HTTPS sob carga, e comportamento dos navegadores e do `jolt-mcp` com a raiz instalada em cada sistema operacional.
