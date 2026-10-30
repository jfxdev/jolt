# Produção — instalação e ciclo de vida

Este é o caminho suportado para a primeira versão estável do Jolt: **containers
Docker em Linux/amd64**, um Control Tower por instalação e nodes operados um por
host ou por stack isolada. Node e Control Tower devem usar a **mesma versão
datada** `YYYY-MM-DD[.N]`; prefira os digests publicados na GitHub Release.
`/api/v1` é o contrato da API e não a versão da distribuição.

Não há alta disponibilidade, execução multi-réplica do Control Tower, atualização
automática ou backup online. O suporte a outras arquiteturas exige build e
qualificação próprios; um build local bem-sucedido não amplia essa matriz.

## 1. Arquitetura e rede

| Fluxo | Origem → destino | Exposição recomendada |
| --- | --- | --- |
| UI/API do Control Tower | navegador/automação → TCP 8090 | somente loopback; publicar por proxy HTTPS |
| API operacional do node | Control Tower → TCP 8080 | rede privada/VPN; nunca Internet pública |
| Peer/data plane | node destino → node origem, TCP 8443 | somente peers, por firewall; TLS 1.3 mTLS de ponta a ponta |
| Métricas | Prometheus → `/metrics` de cada API | rede de observabilidade e bearer token próprio |

O destino de uma transferência conecta-se diretamente ao endpoint mTLS anunciado
pela origem. Os bytes não atravessam o Control Tower. Configure DNS e firewall
para que **todo node destino alcance `mtls_public_endpoint` de cada origem**.
Não termine esse TLS no proxy; use encaminhamento TCP/TLS passthrough.

O proxy HTTPS do Control Tower deve preservar `Host`, permitir streaming e ter
timeouts compatíveis com uploads/downloads longos. Veja [REVERSE_PROXY.md](REVERSE_PROXY.md).

## 2. Preparação do host

Instale Docker Engine e Compose v2, sincronize o relógio e provisione espaço para
os mounts, dados operacionais, partials e snapshots. Os limites do Compose são
pontos de partida, não dimensionamento medido.

```sh
git clone https://github.com/jfxdev/jolt.git
cd jolt
git checkout YYYY-MM-DD
cd deploy
cp .env.example .env
install -d -m 700 secrets /srv/jolt/files /srv/jolt/backups
```

Edite `.env`:

- use as imagens e os digests da mesma Release, por exemplo
  `ghcr.io/jfxdev/jolt-node@sha256:...`;
- defina `CONTROL_TOWER_PUBLIC_BASE_URL=https://control.seu-dominio`;
- ajuste `JOLT_MOUNT_PATH`, `PUID`/`PGID`, endpoint peer e limites;
- mantenha `JOLT_OWNED_PATHS` vazio após preparar ownership no host. Um valor
  não vazio executa `chown -R` nos caminhos indicados a cada inicialização;
- mantenha `CONTROL_HTTP_BIND=127.0.0.1`. Não use `user:` no Compose: o
  entrypoint precisa preparar volumes antes de dropar privilégios.

Para filesystems com root-squash ou sem suporte a `chown`, prepare `PUID:PGID`
no host e não habilite `JOLT_OWNED_PATHS`. Os arquivos de configuração devem ser
legíveis pelo container e imutáveis em runtime; mudanças exigem restart.

## 3. Segredos

Gere valores independentes e aleatórios. Não reutilize senha, token ou chave:

```sh
umask 077
openssl rand -base64 36 > secrets/control_admin_password
openssl rand -base64 32 > secrets/control_db_key
openssl rand -base64 32 > secrets/control_tower_token
openssl rand -base64 32 > secrets/node_state_key
openssl rand -base64 32 > secrets/control_metrics_token
openssl rand -base64 32 > secrets/node_metrics_token
chmod 600 secrets/*
```

Todos os secrets devem ser legíveis pelo `PUID` selecionado, inclusive no node
remoto. Se criá-los como root com `umask 077`, ajuste o owner sem abrir as
permissões: com os padrões `PUID=1000` e `PGID=1000`, use
`sudo chown 1000:1000 secrets/*`; substitua esses números quando personalizar o
usuário de runtime. O `chmod 600` deve ser preservado.

`control_db_key` e `node_state_key` devem decodificar para 32 bytes. Faça backup
dessas chaves separadamente dos volumes e dos arquivos Compose. Perdê-las torna o
estado irrecuperável; alterá-las não é uma rotação suportada.

Cada segredo pode usar `NOME_FILE` ou `NOME`, nunca ambos com valores não vazios.
O conteúdo do arquivo tem whitespace externo removido; erro de leitura interrompe
o boot. Não coloque segredos reais em `.env.example`, YAML, URLs ou histórico do
shell. Os arquivos locais do exemplo são montados read-only; um secret manager
pode substituí-los sem alterar o contrato `*_FILE`.

## 4. Instalação local: Control Tower + primeiro node

Edite `node.yaml`:

- `node_name` único;
- `mtls_public_endpoint: https://node-a.seu-dominio:8443`;
- mounts com `local_path` no **namespace do container** (`/mnt/files`);
- grants vazios inicialmente. Pareamento não cria grants automaticamente.

Valide e suba:

```sh
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.yml pull
docker compose --env-file .env -f docker-compose.yml up -d
docker compose --env-file .env -f docker-compose.yml ps
curl --fail http://127.0.0.1:8090/readyz
```

Abra a URL HTTPS, autentique como `admin` e cadastre o node com endpoint
`http://jolt-node:8080` e o token de `control_tower_token`. A primeira senha de
admin vem do secret de bootstrap; troque-a pelo fluxo de administração e mantenha
uma recuperação offline testada. `/readyz` comprova o estado local, não a
disponibilidade de todos os nodes ou mounts.

## 5. Node adicional em outro host

Copie somente `docker-compose.node.yml`, `node.remote.yaml`, `.env.example` e o
esquema de secrets para o segundo host. Use a mesma release e crie **novos**
`node_state_key`, token operacional e tokens de métricas; nunca clone identidade
ou volumes do primeiro node.

Em `node.remote.yaml`, use outro `node_name` e um endpoint peer alcançável pelos
demais nodes. O Compose remoto mantém a API fora das portas publicadas por
padrão. Para um Control Tower em outro host, estabeleça uma das opções:

1. **VPN/rede privada (recomendada):** disponibilize TCP 8080 somente no IP do
   túnel, por meio de um override local, e cadastre `http://IP_PRIVADO:8080`.
2. **TLS na API:** configure `api_tls_cert_file`/`api_tls_key_file` no YAML,
   monte os arquivos read-only, publique 8080 apenas no IP privado e cadastre
   HTTPS. Se exigir certificado de cliente, configure também a CA e o par de
   certificados do Control Tower.

Exemplo de override, para criar somente no node remoto e não publicar em Git:

```yaml
services:
  jolt-node:
    ports:
      - "10.20.0.12:8080:8080"
```

Como `ports` é uma lista, confira o resultado com `docker compose config`; se o
Compose preservar entradas anteriores, deixe apenas os bindings pretendidos.
Restrinja 8080 por firewall aos endereços do Control Tower. HTTP simples só é
aceitável dentro de um túnel autenticado/cifrado. O certificado da API pode ser
recarregado sem restart; a porta mTLS continua obrigatoriamente mTLS.

Cadastre esse node no Control Tower, faça o pareamento com confirmação exata da
fingerprint e crie grants mínimos nos dois lados antes de transferir. Um ensaio
real entre dois hosts é gate de release; dois containers no mesmo host não o
substituem.

## 6. Atualização

Antes de mudar imagens, faça snapshots offline dos dois produtos e backup
separado dos mounts e chaves. Anote versões, digests, `node_id` e fingerprints.
Não atualize node e Control Tower para releases diferentes.

No host do Control Tower e do node local, use `docker-compose.yml`:

```sh
docker compose --env-file .env -f docker-compose.yml stop
# execute os snapshots descritos em DISASTER_RECOVERY.md
# atualize JOLT_NODE_IMAGE e JOLT_CONTROL_IMAGE para a nova mesma release
docker compose --env-file .env -f docker-compose.yml config --quiet
docker compose --env-file .env -f docker-compose.yml pull
docker compose --env-file .env -f docker-compose.yml up -d
curl --fail http://127.0.0.1:8090/readyz
```

Em cada node remoto, no diretório que contém o manifest copiado durante a
instalação, use somente `docker-compose.node.yml` e atualize `JOLT_NODE_IMAGE`:

```sh
docker compose --env-file .env -f docker-compose.node.yml stop
# execute o snapshot offline do node descrito em DISASTER_RECOVERY.md
docker compose --env-file .env -f docker-compose.node.yml config --quiet
docker compose --env-file .env -f docker-compose.node.yml pull
docker compose --env-file .env -f docker-compose.node.yml up -d
docker compose --env-file .env -f docker-compose.node.yml ps
```

Depois confira versão/commit na UI, login, mounts, jobs, peers, um upload e uma
transferência pequena. Jobs interrompidos podem exigir validação e resume
explícitos; isso é deliberado.

## 7. Rollback

Rollback não é apenas trocar a tag. Pare os serviços, restaure os snapshots
compatíveis criados **pela versão anterior** em diretórios/volumes vazios e rode
os diagnósticos antes de iniciar as imagens anteriores. Não restaure uma
identidade em dois nodes ativos. Dados dos mounts não são revertidos pelos
snapshots operacionais; avalie mudanças feitas durante a candidata.

`scripts/release-lifecycle.py` automatiza o ensaio descartável e, quando recebe
as duas imagens anteriores, valida upgrade e rollback com o snapshot correto.
Esse teste não substitui o procedimento nem um ensaio no armazenamento real.

## 8. Troubleshooting

- **Container reinicia:** `docker compose logs --tail=200 jolt-node jolt-control`;
  verifique secrets ausentes/duplicados, chave inválida e ownership.
- **`/livez` responde, `/readyz` falha:** não remova o container às cegas;
  investigue estado/banco local. Liveness não testa mounts nem peers.
- **Node offline no Control Tower:** teste DNS, rota, firewall, porta 8080, TLS e
  token. O health público não prova autenticação nem conectividade do Control.
- **Peer offline/untrusted:** teste 8443 de destino para origem e confira o
  endpoint anunciado, fingerprint, revogação e relógio. Não desabilite mTLS.
- **Job `waiting_mount`/`waiting_peer`:** corrija o recurso; o job aguarda sem
  consumir retry budget. Um mount presente no host pode estar ausente no container.
- **Job `waiting_validation`:** revise o diagnóstico e solicite resume explícito.
- **Upload não retoma após reload:** reselecione exatamente o mesmo arquivo; a UI
  não restaura sozinha o `File` do navegador.
- **Mudança de RBAC não para um job:** policies são verificadas na admissão e em
  novas chamadas; cancele o job já admitido ou revogue grant/peer quando exigido.

Logs recentes são obtidos no host/container; não existe API de logs, tracing
distribuído ou console remota de configuração. Consulte [OPERATIONS.md](OPERATIONS.md)
para métricas, alertas e rotinas e [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md)
para recuperação.
