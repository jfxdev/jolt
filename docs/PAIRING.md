# Pareamento de nodes

Dois nodes só trocam arquivos depois de estabelecerem uma relação de confiança
(pareamento) e de cada um declarar, no seu `node.yaml`, o que o outro pode fazer.
São duas etapas separadas:

1. **Confiança.** Criada pelo Control Tower e guardada no estado criptografado de
   cada node. Prova identidade; não dá acesso a arquivo nenhum.
2. **Autorizações (grants).** Declaradas em `transfer_grants` no `node.yaml` de cada
   lado. Só valem depois da confiança e de um restart.

O pareamento nunca cria mounts nem grants.

## Antes de começar

- Os nodes estão no ar e o Control Tower alcança a API de cada um (`api_address`),
  com o token operacional (`CONTROL_TOWER_TOKEN`) ou, em modo gerenciado, pelo
  enrolamento descrito em [Operação](OPERATIONS.md).
- Cada node tem `node_name` e um listener mTLS (`mtls_address`). Defina
  `mtls_public_endpoint` com a URL `https://` pela qual **os outros nodes** chegam
  nele. Em contêineres ou atrás de NAT ela costuma diferir do endereço de escuta.
  Veja [node.yaml](NODE_YAML.md).
- Seu usuário no Control Tower pode criar nodes e conexões
  (`control-tower/nodes` e `control-tower/connections`).

## 1. Registrar os nodes

Pela interface: **Nodes → +**. Pela API:

```sh
CT=https://control.example/api/v1/control-tower
JAR=$(mktemp)
curl -s -c "$JAR" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<senha>"}' "$CT/auth/login"

curl -s -b "$JAR" -H 'Content-Type: application/json' "$CT/nodes" \
  -d '{"name":"Node A","endpoint":"https://node-a.example:8080","token":"<token do node A>"}'
```

A resposta traz o `node_id`. Ele vem da identidade do node (`keys/identity.json`) e
não muda enquanto essa pasta existir. Se `keys/` for apagada, o node ganha outro ID:
remova o registro antigo e registre de novo.

## 2. Criar a conexão

Pela interface: **Relacionamentos → Conectar**. Pela API:

```sh
curl -s -b "$JAR" -H 'Content-Type: application/json' "$CT/connections" -d '{
  "issuer_node_id": "<ID do node A>",
  "target_node_id": "<ID do node B>",
  "transfer_mode": "dual_channel",
  "issuer_role": "sender_receiver",
  "invitee_role": "sender_receiver",
  "purpose": "Replicação A↔B",
  "expiry_minutes": 20
}'
```

| Campo | Valores |
| --- | --- |
| `transfer_mode` | `dual_channel`: os dois lados enviam e recebem; ambos os papéis são `sender_receiver`. `one_sided`: um sentido só; os papéis são diferentes entre `sender`, `receiver` e `requester`. |
| `issuer_node_id` / `target_node_id` | Nodes diferentes, ambos já registrados. O emissor cria o convite; o alvo recebe o pedido. |
| `expiry_minutes` | De 5 a 1440. Padrão: 20. O convite é de uso único. |
| `purpose`, `cluster_id` | Opcionais. O cluster só agrupa; nunca cria confiança transitiva. |

Antes de criar a conexão, confira **os dois nodes**, o emissor e o alvo, por outro
canal: leia o `node_id` e o `fingerprint` direto em cada node (`GET /api/v1/node`, com o
token do node) e compare com o que o responsável por aquele node informa. Um registro
com endpoint ou token errado apontaria para um node que você não pretendia, e o
emissor passaria a confiar nele e a poder trocar arquivos, se houver grants.

Essa conferência é pontual. Ela não protege contra um node comprometido que informe um
fingerprint na conferência e outro na criação da conexão. Quando isso importa, use o
caminho com confirmação explícita do passo 3, em vez da aprovação automática.

Um pareamento é entre dois nodes. Para três nodes que precisam se enxergar, crie as
três conexões (A↔B, A↔C, B↔C).

## 3. Aprovar

O pedido chega ao alvo como `pending_review`. Há dois caminhos:

- **Usuário humano com permissão `sudo` em `nodes/<alvo>/admin/pairing`.** A conexão é
  aprovada na hora (`auto_approved: true`, `trust_established: true`). É o caso de um
  administrador usando a interface.
- **Qualquer outro caso**, como uma conta de serviço ou um usuário sem essa permissão.
  A conexão fica `pending_review` e alguém precisa aprovar confirmando o fingerprint
  do **emissor**:

  ```sh
  curl -s -b "$JAR" -H 'Content-Type: application/json' \
    "$CT/connections/<request_id>/approve" \
    -d '{"confirmed_fingerprint":"F8F2:723C:FB07:F4D7:BE65"}'
  ```

  Pegue o fingerprint por outro canal, direto no emissor
  (`GET /api/v1/node`, campo `fingerprint`), e não da própria resposta da conexão.
  O Control Tower compara a fingerprint confirmada com a que registrou ao criar o
  pedido; se diferirem, responde `409 fingerprint_mismatch` e não estabelece a
  confiança. É essa conferência que impede um node falso de se passar pelo emissor.
  Para recusar: `POST $CT/connections/<request_id>/reject`.

A aprovação automática **não** faz essa comparação independente: ela usa a fingerprint
que o próprio emissor reportou ao criar o pedido. Para pareamentos em que a identidade
do emissor precisa ser provada (nodes de terceiros, redes não confiáveis), crie a
conexão com uma sessão que não aprove sozinha, como uma conta de serviço, ou com um
usuário sem `sudo` em `nodes/<alvo>/admin/pairing`, e aprove com a fingerprint obtida
fora de banda.

Leia a resposta da criação. Se `trust_established` vier `false`, a aprovação automática
não terminou, por exemplo porque um dos nodes ficou indisponível no meio do handshake.
A conexão fica `pending_review` ou `partially_connected`: não assuma que há confiança.
Restabeleça a conexão com o node, confira o status em `GET $CT/connections` e então
aprove (`approve`) ou complete a metade que falta (`reconcile`, veja abaixo).

## 4. Conferir

```sh
curl -s -b "$JAR" "$CT/connections"                    # status das conexões
curl -s -b "$JAR" "$CT/nodes/<ID do node A>/trust"     # os dois lados de cada relação
curl -s -H "Authorization: Bearer <token do node A>" \
  https://node-a.example:8080/api/v1/peers             # peers do ponto de vista do node
```

Em cada node, o outro deve aparecer com `state: online`.

## 5. Autorizar o acesso

Com a confiança estabelecida, declare os grants em cada `node.yaml` e reinicie. Cada
lado autoriza o outro de forma independente.

Um grant aponta para um mount que já existe no mesmo `node.yaml`, e o diretório do
mount (`local_path`) precisa existir no disco e ser legível e gravável pelo usuário do
node. O node não cria esse diretório: se ele faltar, o mount fica indisponível e as
transferências são recusadas ou esperam o diretório voltar. Se o mount não
existir, ou não tiver o modo e a publicação que o grant exige, o node recusa a
configuração e **não sobe** no restart. Para trocar arquivos nos dois sentidos, o
mount precisa ser `read_write`, e `published: true` quando o grant usa
`visible_to_peer: true`:

```yaml
mounts:
  - id: files
    name: Files
    local_path: "/srv/jolt/files"
    mode: read_write
    published: true
    enabled: true

transfer_grants:
  - id: "nodeA-nodeB-files"
    peer_node_id: "<ID do node B>"
    mount_id: files
    path: "."
    direction: send_receive
    permissions: {read: true, write: true, delete: false, rename: false}
    conflict_policies: [fail, skip]
    visible_to_peer: true
    enabled: true
```

No node B, faça o espelho com o ID do node A. Esse `send_receive` vale para trocas
nos dois sentidos. Para um sentido só, os dois lados declaram grants **complementares**,
não iguais:

| Node | `direction` | Permissões | `conflict_policies` | Mount |
| --- | --- | --- | --- | --- |
| Origem | `send` | `read: true`; `write` e `rename` precisam ser `false`; `delete` é opcional | não se aplica (o node recusa se vier preenchida) | qualquer modo; `read_write` se `delete: true` |
| Destino | `receive` | `write: true` | opcional; padrão `[fail]` | `read_write` |

Se os dois lados declaram `send`, nenhum recebe. Se os dois declaram `receive`, nenhum
envia.

Não troque só o `direction` de um grant que já foi aplicado. Além de as permissões e
as políticas de conflito precisarem acompanhar a direção (senão o node recusa o grant e
não sobe), o ID fica ligado ao par peer, mount, path e direção: mudar qualquer um deles
exige um **ID novo**. Remover e readicionar o mesmo ID não apaga essa ligação.

Campos, regras e restrições estão em [node.yaml](NODE_YAML.md). Comece com o menor
acesso que resolve: `send` ou `receive` em vez de `send_receive`, e um `path` mais
restrito que `.`.

## Quando algo sai do normal

| Sintoma | O que fazer |
| --- | --- |
| Status `partially_connected` | Só um lado confia no outro. `POST $CT/connections/<request_id>/reconcile` completa a metade que falta. |
| `reconcile_requires_new_invite` | O convite já foi consumido. Crie uma nova conexão. |
| `502 issuer_unavailable` ou `request_delivery_failed` | O Control Tower não alcançou o node. Confira `endpoint`, token e rede. O convite é revogado sozinho se o pedido não chega ao alvo. |
| Peer `revoked_by_peer` | O outro lado revogou a confiança. Não é falha de rede. Crie uma nova conexão se quiser restabelecer. |
| Peer `identity_changed` | A identidade do outro node mudou (rotação de chaves ou `keys/` recriada). Veja a rotação de identidade em [Operação](OPERATIONS.md). |
| Heartbeat falha logo após subir | Costuma ser só ordem de inicialização: o peer ainda não abriu o listener mTLS. Passa sozinho. |

Para encerrar uma relação, use **Revogar** na interface ou
`POST $CT/connections/<request_id>/revoke`, que remove a confiança nos dois nodes.
Só é sucesso quando a resposta é `200` com `status: revoked`. Se um node estiver
indisponível, a revogação não termina: a resposta é `409 revoke_incomplete` (com o
resultado de cada lado em `sides`) ou `502`, quando o Control Tower nem consegue
confirmar os IDs atuais dos nodes. Nesse caso a confiança e os grants podem continuar
ativos num dos lados. Restabeleça a conexão com o node, repita a revogação e confira
com `GET $CT/nodes/<ID>/trust` e `GET /api/v1/peers` que **os dois** lados deixaram de
confiar um no outro antes de considerar o assunto encerrado.

Verifique também depois de um `200`. A revogação remove os IDs que cada node tem
**hoje**. Se um node foi recriado com outro ID no mesmo endpoint (por exemplo, com
`keys/` apagada), o outro node pode continuar confiando no ID antigo. Compare a lista de
`/api/v1/peers` de cada node com os IDs que foram pareados originalmente (guarde-os, o
`GET $CT/connections` traz `issuer_node_id` e `target_node_id`). Para cada ID antigo que
sobrar, revogue-o direto no node, com o token dele:

```sh
curl -s -X DELETE -H "Authorization: Bearer <token do node>" \
  https://node-b.example:8080/api/v1/peers/<ID antigo>
```

Os IDs de grant usados com um peer revogado ficam bloqueados para sempre. Ao parear
de novo, dê **IDs novos** aos grants (por exemplo `nodeA-nodeB-files-2`).
