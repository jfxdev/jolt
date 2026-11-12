# Provider Terraform / OpenTofu

`terraform-provider-jolt` gerencia as policies RBAC do Control Tower como código
e lê os nodes por nome, para que a configuração não dependa de ids.
Ele fala com a mesma API da tela Access → Policies e valida cada policy com as
regras do próprio Control Tower (`control/internal/rbac` e `control/internal/filetypes`),
compiladas no binário. O provider não é publicado em registry: a imagem de IaC
compila o binário a partir deste repositório e o instala em um mirror local.

Por enquanto ele cobre:

| Tipo | Nome | O que faz |
|---|---|---|
| resource | `jolt_policy` | Cria, altera e remove uma policy; importa por id ou por nome |
| data source | `jolt_policy` | Lê uma policy por `id` ou `name` |
| data source | `jolt_node` | Lê um node por `id` ou `name`: endpoint, estado e configuração |

A atribuição de policies a usuários, API keys e grupos continua na UI e na API.

## Credencial

O provider usa o token de uma API key (service account), enviado como
`Authorization: Bearer`. A key precisa estar em um grupo de acesso ativo, com uma
policy que dê `sudo` em `control-tower/policies`:

```json
{"name": "iac-policies", "rules": [
  {"path": "control-tower/policies", "capabilities": ["sudo"]},
  {"path": "nodes/*", "capabilities": ["list"]}
]}
```

A segunda regra só é necessária para o `jolt_node`. Uma API key só enxerga os
nodes do seu grupo de acesso, e só aqueles em que tem `list` em `nodes/<id>`:
inclua no grupo os nodes que a configuração cita. `nodes/*` cobre exatamente
`nodes/<id>`, sem arquivos, mounts ou nada abaixo; além da lista de nodes, ela só
mostra as conexões entre dois nodes visíveis.

**Atenção.** Quem tem `sudo` em `control-tower/policies` muda o que todos os
detentores de cada policy podem fazer: ampliar uma regra de uma policy já
atribuída amplia o acesso de quem a recebeu. Trate o token como credencial de
administrador e entregue-o à pipeline como secret, nunca no código. Não gerencie
pelo Terraform a policy que dá esse `sudo` à própria key do provider: um `apply`
que a altere ou remova tira o acesso da pipeline no meio do caminho. Se precisar
referenciá-la, use o data source.

## Imagem de IaC

O binário é compilado a partir da tag do repositório que corresponde ao Control
Tower em produção. Assim a validação embutida é a mesma do servidor.

```dockerfile
FROM golang:1.26.11-alpine AS jolt-provider
RUN apk add --no-cache git
ARG JOLT_REF=2026-11-12
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN git clone --depth 1 --branch "$JOLT_REF" https://github.com/jfxdev/jolt /src
WORKDIR /src/control
# 2026-11-12 -> 0.20261112.0; 2026-11-12.1 -> 0.20261112.1
RUN version="$(echo "$JOLT_REF" | sed -E 's/^([0-9]{4})-([0-9]{2})-([0-9]{2})(\.([0-9]+))?$/0.\1\2\3.\5/; s/\.$/.0/')" && \
    dir="/out/jolt.internal/jfxdev/jolt/$version/${TARGETOS}_${TARGETARCH}" && \
    mkdir -p "$dir" && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -buildvcs=false \
      -ldflags "-X main.version=$version" \
      -o "$dir/terraform-provider-jolt_v$version" ./cmd/terraform-provider-jolt

FROM <sua-imagem-de-iac>
COPY --from=jolt-provider /out/ /usr/share/terraform/plugins/
COPY terraformrc /etc/terraformrc
ENV TF_CLI_CONFIG_FILE=/etc/terraformrc
```

`terraformrc`, lido por Terraform e OpenTofu:

```hcl
provider_installation {
  filesystem_mirror {
    path    = "/usr/share/terraform/plugins"
    include = ["jolt.internal/*/*"]
  }
  direct {
    exclude = ["jolt.internal/*/*"]
  }
}
```

`jolt.internal` é só o nome do provider no mirror; nenhum dos dois CLIs tenta
resolvê-lo na rede. Prefira `filesystem_mirror` a `dev_overrides`, que avisa em
todo comando, pula o `init` e não gera lock file.

### Lock file

`terraform init` grava em `.terraform.lock.hcl` o hash do binário. O build acima
é reproduzível: a mesma tag com a mesma imagem Go produz o mesmo binário, e o CI
verifica isso. Trocar a tag muda a versão e o hash, e o lock é atualizado com
`terraform init -upgrade`. Se a pipeline roda em mais de uma plataforma, registre
os hashes de cada uma com `terraform providers lock -fs-mirror=/usr/share/terraform/plugins -platform=linux_amd64 -platform=linux_arm64`.
Mudar a imagem Go também muda o binário.

## Uso

```hcl
terraform {
  required_providers {
    jolt = {
      source  = "jolt.internal/jfxdev/jolt"
      version = "0.20261112.0"
    }
  }
}

provider "jolt" {
  control_url = "https://jolt.example.com" # ou JOLT_CONTROL_URL
  # token: JOLT_TOKEN
  # ca_file: JOLT_CA_FILE, quando o certificado do Control Tower vem da CA do Jolt
}

resource "jolt_policy" "media" {
  name        = "media-team"
  description = "Equipe de mídia"
  rules = [
    {
      path         = "nodes/node-a/files/mounts/media/**"
      capabilities = ["list", "read", "write"]
    },
    {
      path         = "nodes/node-a/files/mounts/media/**"
      capabilities = ["deny", "read"]
      file_types   = { classes = ["secret"], extensions = ["pem"] }
      visibility   = "visible"
    },
    {
      path           = "nodes/node-a/files/mounts/media/inbox/**"
      capabilities   = ["write", "delete"]
      needs_approval = ["delete"]
    },
  ]
}

data "jolt_policy" "admins" {
  name = "admins"
}

data "jolt_node" "backup" {
  name = "backup-01"
}

resource "jolt_policy" "backup" {
  name  = "backup-read"
  rules = [
    { path = "nodes/${data.jolt_node.backup.id}/files/**", capabilities = ["list", "read"] },
  ]
}
```

| Atributo do provider | Variável | |
|---|---|---|
| `control_url` | `JOLT_CONTROL_URL` | Esquema e host, sem caminho. HTTPS fora de loopback |
| `token` | `JOLT_TOKEN` | Token da API key |
| `ca_file` | `JOLT_CA_FILE` | PEM com as raízes que assinam o certificado do Control Tower; substitui a confiança do sistema |

Importar uma policy criada pela UI:

```sh
terraform import jolt_policy.media pol_0123456789abcdef01234567
terraform import jolt_policy.media name:media-team
```

## Validação

O `plan` recusa o que o Control Tower recusaria e também o que ele reescreveria,
porque um valor reescrito apareceria como mudança em todo plan:

- `path` só na forma canônica: sem `/` nas pontas e com `nodes/` no lugar do
  antigo `workers/`. A mensagem mostra a forma esperada.
- `capabilities` em minúsculas, entre `read`, `list`, `create`, `update`,
  `delete`, `write`, `execute`, `sudo` e `deny`. Uma regra de caminho com `deny`
  não leva outra capability.
- `description` sem espaços nas pontas, até 512 bytes.
- `file_types`, `visibility` e `needs_approval` com as mesmas regras do editor.

Duas validações dependem de como o Control Tower foi iniciado e só aparecem no
`apply`, como `400 invalid_policy`: `file_types` e `visibility` exigem
`CONTROL_TOWER_TYPED_POLICIES=true`, e `needs_approval` exige as aprovações
humanas ligadas. Toda recusa traz o `correlation_id`, que localiza a decisão na
auditoria.

## Comportamento

- `capabilities`, `needs_approval` e as listas de `file_types` são conjuntos: a
  ordem não importa. A ordem de `rules` é mantida.
- Não há controle de concorrência na API. Uma edição pela UI aparece como drift
  no próximo plan, e o `apply` a sobrescreve.
- Alterar ou remover uma policy interrompe os streams de agentes que dependiam
  dela, como acontece pela UI.
- Uma policy removida fora do Terraform é criada de novo no próximo `apply`, com
  outro id. As atribuições que ela tinha não voltam.
- Nomes de node não são únicos. Um `name` que mais de um node visível tenha é
  erro, com os ids de cada um; use `id` nesse caso. A comparação diferencia
  maiúsculas.
- Um node que não existe e um que a key não pode listar dão o mesmo erro.
- Cada leitura de `jolt_node` lista os nodes, e a lista sonda cada node visível
  (até 4 s por node, 4 em paralelo). `state`, `last_seen_at` e `configuration`
  vêm dessa sonda e mudam de um plan para o outro; não os use em atributos de
  recursos, ou o plan mostrará mudança a cada node que oscilar.

## Testes

```sh
cd control
go test ./internal/tfprovider/                     # cliente e validação, sem CLI
TF_ACC=1 TF_ACC_TERRAFORM_PATH="$(command -v tofu)" TF_ACC_PROVIDER_HOST=registry.opentofu.org \
  go test -run '^TestAcc' ./internal/tfprovider/   # com OpenTofu
TF_ACC=1 go test -run '^TestAcc' ./internal/tfprovider/   # com o terraform do PATH
```

Os testes de aceitação rodam o CLI de verdade contra um Control Tower em processo.
O CI os roda com OpenTofu 1.12.6, o CLI da pipeline de IaC.
