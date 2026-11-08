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
  É essa conferência que impede um node falso de se passar pelo emissor. Para recusar:
  `POST $CT/connections/<request_id>/reject`.

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
lado autoriza o outro de forma independente. Este grant deixa o node A trocar
arquivos com o node B no mount `files`:

```yaml
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

No node B, faça o espelho com o ID do node A. Campos, regras e restrições estão em
[node.yaml](NODE_YAML.md). Comece com o menor acesso que resolve: `direction: send`
ou `receive`, e um `path` mais restrito que `.`.

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
Os IDs de grant usados com um peer revogado ficam bloqueados para sempre. Ao parear
de novo, dê **IDs novos** aos grants (por exemplo `nodeA-nodeB-files-2`).
