# Plano consolidado — Segurança de agentes e restrições de arquivos

**Andamento em 3 de novembro de 2026:** implementação em andamento no branch `codex/agent-safety-file-restrictions`, com integração opcional de leituras e uploads retomáveis assinados. Este documento acompanha o plano aprovado e prevalece sobre as descrições históricas de [`agent-safety.md`](agent-safety.md) e [`file-type-restrictions.md`](file-type-restrictions.md). Código existente, inclusive com testes locais, não significa entrega validada de ponta a ponta ou publicada.

**Regra de ativação:** a API do Control Tower ainda recusa policies com `file_types` ou `visibility`. O node aplica contextos assinados nas rotas locais de leitura integradas; o proxy pode enviá-los quando `CONTROL_TOWER_SIGNED_LOCAL_READS=true`, após o provisionamento de chaves. O padrão é desativado e essa integração parcial **não representa proteção integral por policy**. Não habilitar a gravação dessas policies até proteger todos os caminhos afetados e validar a compatibilidade entre componentes.

## Checkpoint de implementação

| Entrega | Situação neste branch | Próximo passo principal |
| --- | --- | --- |
| 1. Mount e compatibilidade | Proteção por nome, árvores protegidas e provisionamento de chaves implementados em partes | Revisar todas as rotas, falhas e versões mistas |
| 2. Perfil de agente | Limites, interrupção e teto opcional de capabilities por credencial implementados em partes | Validar limites e revogação em jornadas e carga |
| 3. Auditoria e canary | Auditoria, exportação, cadeia opcional, canaries e métricas implementados em partes | Concluir aceite integrado, privacidade e alertas |
| 4. Regras por tipo | Persistência, avaliadores e leituras locais assinadas integradas opcionalmente ao proxy | Completar todas as operações antes de habilitar policies |
| 5. Shares, transferências e uploads | Uploads e shares assinados opcionais, reautorização e `exclude` por grant | Integrar consultas auxiliares e autorizações renováveis de transfers e jobs |
| 6. Segredos e apresentação | Varredura, limites de busca e `display_name` implementados em partes | Validar todos os fluxos e componentes desktop/mobile |
| 7. Lixeira, confirmação, aprovação e JIT | JIT implementado em partes; lixeira, planos e aprovações pendentes | Implementar fluxos destrutivos e revalidar jobs |
| 8. Identidade e MCP | MCP STDIO de leitura implementado; validadores JWT/JWKS e JWT-SVID internos | Integrar provedores e mapeamentos persistentes à autenticação e às cotas |

O objetivo continua sendo concluir as oito entregas neste branch em uma única rodada de implementação. Os commits existentes são etapas parciais, não marcos de entrega ou publicação.

Referências para retomada:

- `d376251`–`1992ccc`: fundação existente, teto de capabilities por credencial e persistência das regras por tipo.
- `0883a8d`–`c678ddc`: envelope e chaves, construção de contexto, uploads filtrados internos e compatibilidade de leitura/listagem.
- `f8676a9`–`30dad9a`: aplicação de contextos assinados nas leituras locais do node e recusa nas demais rotas.
- `3ad94bb`–`9da246d`: emissor interno no Control Tower, correção de privacidade em varreduras e testes adicionais de credenciais.

## Contratos aprovados

- `node.yaml` permanece a fonte de configuração do node, aplicada por reinício; o estado operacional do node continua em YAML cifrado e o Control Tower usa SQLCipher.
- Contas existentes permanecem `automation`. O tipo `agent` é imutável, limitado a `list` e `read` também pelo RBAC. Uma policy ou concessão temporária não concede escrita direta a agentes.
- Por credencial de agente, os padrões são 60 requisições/minuto, burst 10, duas simultâneas, 16 MiB por resposta, 1 GiB por dia UTC e expiração obrigatória da chave em até 30 dias. CIDRs são opcionais. A leitura aceita qualquer formato por padrão. Listagens e buscas têm até 200 resultados.
- Cada credencial de agente pode reduzir o teto para `list`, `read`, ambas ou nenhuma; a ausência da configuração preserva `list` e `read`, sempre sujeitos às policies.
- `hidden_patterns` usa globs de nome base, sem separadores e sem distinguir maiúsculas, em todos os componentes do caminho. Ocultos não entram em resultados ou totais; acesso direto responde 404 e criação de nome oculto responde 422 `hidden_name`.
- Restrições por tipo usam classes fixas, extensões e nomes exatos por união, até 64 seletores por regra; `visibility` padrão `hidden`. O node determina o tipo real. `deny` mantém precedência e regras legadas mantêm a semântica.
- Mover exige `read` e `update` na origem, `create` no destino e `update` na sobrescrita. Copiar exige `read` na origem e autorização no destino final. Exclusão e movimento de árvores protegidas são recusados antes da primeira alteração; cópias e ZIPs podem selecionar somente conteúdo autorizado.
- Delete e move de árvores exigirão plano e confirmação de uso único tanto na UI quanto na API. Um humano poderá aprovar sua própria solicitação mediante ação explícita e permissões atuais.
- Autorizações renováveis de jobs terão validade máxima de 30 segundos e renovação a cada 10 segundos; a execução aguardará em `waiting_validation` quando não conseguir renová-las. Isso ainda não está implementado.
- JWT/JWKS e JWT-SVID serão validados com provedores e bundles locais de teste; a configuração de um provedor real não faz parte deste branch.
- Trust e grants continuam necessários para transferências. Um marcador de versão mínima protege apenas binários que o verificam; binários antigos não passam a verificá-lo automaticamente. Fixar imagens por digest e fazer rollback apenas com backup compatível anterior à ativação.
- Uploads simples e retomáveis com sobrescrita exigem `create` e `update` no destino. Nas sessões existentes, o Control Tower usa o caminho e a opção de sobrescrita persistidos no node e reavalia as permissões; se o node não informar a opção, recusam-se chunks e conclusão com orientação de atualização. Filtros assinados são aplicados quando habilitados explicitamente.
- O Jolt limita acesso e consumo; não impede um agente de divulgar conteúdo que teve permissão de ler.

## 1. Proteção do mount e compatibilidade — em andamento

**Código existente**

- `hidden_patterns` e nomes internos protegidos no filesystem; filtros em acesso direto, listagem, busca, totais, ZIP, uploads, cópias e manifestos. Há pré-validação para impedir delete, move e sobrescrita de árvores com conteúdo protegido.
- A pré-validação de delete, move e sobrescrita recusa links simbólicos dentro das árvores; um link selecionado individualmente ainda pode ser removido ou movido sem seguir seu destino. A remoção recursiva observa cancelamento e verifica novamente nomes internos, padrões ocultos e links durante a operação. Se houver cancelamento ou alteração externa após o início, ela retorna erro e pode deixar remoção parcial; não promete rollback. Um move cancelado após guardar o destino tenta restaurá-lo e informa falha de restauração.
- O node anuncia capacidades específicas, incluindo `hidden_patterns_v1` e `protected_move_v1`; há verificações de compatibilidade para recursos já integrados.
- O `node.yaml` aceita chaves públicas de autorização identificadas para rotação, e o Control Tower pode carregar a chave privada de um arquivo PKCS#8. Provisionar as chaves, por si só, não faz o Control Tower enviar contextos nem habilita policies por tipo.
- Existem testes de nomes e árvores protegidas, inclusive caminhos de transferência e tráfego entre nodes.

**Falta**

- Completar a revisão de cobertura de todas as rotas, combinações de sobrescrita, falhas e versões antigas; executar a aceitação integrada antes de marcar a entrega concluída.
- Garantir orientação de atualização em todos os recursos que dependam de uma capacidade ainda não suportada. Alterações externas e falhas do filesystem após a pré-validação devem produzir resultado explícito.

## 2. Perfil de agente, cotas e interrupção — implementado em partes; aceite pendente

**Código existente**

- Perfil `agent`, limites por credencial, expiração, CIDRs opcionais e teto de leitura; contas antigas mantêm `automation`. Há interface e contratos para administração.
- A credencial pode restringir suas capabilities a `list`, `read`, ambas ou nenhuma; a ausência do campo mantém as duas possibilidades sujeitas às policies.
- Taxa e concorrência em memória; reservas transacionais no banco para orçamento de saída, reconciliação dos bytes enviados e cobrança conservadora após interrupção abrupta.
- Cancelamento de requisições por revogação, desativação, expiração e desligamento coletivo; reativação individual. Proxies confiáveis são configuráveis para interpretação de `X-Forwarded-For`.
- Marcador `minimum_security_version` e verificação em binários que o conhecem. Isso não modifica binários antigos.

**Falta**

- Revisar todos os caminhos de autorização, verificações auxiliares e fluxos de stream para comprovar que não há escrita direta ou ultrapassagem de limite.
- Validar limites exatos, `Range`, concorrência, desconexão, reinício, troca do dia UTC, cancelamento durante streams e migração de bancos em testes integrados e de carga.

## 3. Auditoria, detecção e canary — implementado em partes; aceite pendente

**Código existente**

- Auditoria de requisições de agentes, retenção configurável com padrão zero, captura opcional de busca, exportação incremental NDJSON com cursor e métricas com cardinalidade limitada.
- Cadeia opcional de hashes, checkpoints compatíveis com retenção e exportação e verificador; a cadeia não autentica retroativamente eventos anteriores à ativação.
- `canary_paths` por mount, eventos e métricas, além de exemplos operacionais em [`../OPERATIONS.md`](../OPERATIONS.md).

**Falta**

- Validar ponta a ponta campos, privacidade de nomes ocultos, interrupções, retenção, exportação e checkpoints; concluir a validação dos alertas e dos caminhos de acesso a canaries.
- **O pacote mínimo para agentes só será declarado concluído depois da aceitação integrada das entregas 1–3.**

## 4. Regras por tipo e filtragem no node — fundação interna; recurso desativado

**Código existente**

- Seletores e avaliadores de contexto versionado nos dois módulos, com casos dourados comuns, limites de tamanho e validação estrita.
- Ambos os módulos possuem um envelope Ed25519 com contexto limitado, validade máxima de 30 segundos, verificação de destinatário e vínculo da operação; os testes compartilham um vetor determinístico. No node, listagem, metadados, conteúdo, busca, uso de disco e ZIP aceitam contexto assinado para leitura local; outras rotas recusam explicitamente o contexto. Com chaves configuradas, o node anuncia `signed_local_read_v1` e `signed_local_tree_read_v1` para esses subconjuntos. O proxy pode emitir esses contextos por configuração explícita; não há renovação de jobs.
- O store do Control Tower já preserva seletores e visibilidade em migração aditiva; regras tipadas gravadas internamente elevam o marcador mínimo para a versão 2. O avaliador legado recusa permissões tipadas e trata negações tipadas de forma conservadora.
- O Control Tower consegue montar internamente um contexto completo para um mount, incluindo regras legadas e negações descendentes, rejeitando contextos inválidos ou acima dos limites. O proxy o envia para leituras locais quando a opção está habilitada e exige capacidade e confirmação do node.
- O emissor de autorizações para leituras locais revalida sessão ou API key, grupos ativos, policies, CIDRs e limites de agente, com validade limitada pela credencial e pelo prazo da requisição. Na preparação de leituras de árvores, negações por caminho continuam recusadas e negações por tipo podem ser encaminhadas no filtro. Shares usam um emissor próprio; jobs ainda não possuem renovação.
- O node e o proxy integram envelopes para upload simples e para criação, chunks, conclusão, cancelamento e reautorização de uploads retomáveis quando `CONTROL_TOWER_SIGNED_UPLOADS=true`. A criação da sessão vincula o corpo exato; os demais pedidos retomáveis vinculam ator, credencial, node, mount, destino e ID persistidos. O estado cifrado não expõe a identidade em JSON e recusa sua alteração ou atribuição automática a sessões antigas. Antes de gravar o primeiro vínculo, o cabeçalho autenticado é elevado à versão 2; a reautorização eleva-o à versão 3 para proteger a revisão contra replay. A retomada explícita reautoriza sessões antigas ou uma nova credencial do mesmo ator; outros fluxos seguem pendentes.
- Filtros internos no filesystem para leitura direta, listagem, busca, uso de disco, ZIP, criação de diretório, upload simples, cópia de arquivo e árvore, e pré-validação de delete e move. A implementação inclui testes focados de ocultação, destinos e sobrescritas.
- A filtragem interna distingue ausência de `read`/`list` de uma restrição explícita, preservando listagem sem leitura e leitura direta sem listagem para policies legadas.
- Uso de disco e ZIP recursivo não expõem nomes sem permissão de listagem; um arquivo conhecido e explicitamente selecionado ainda pode ser incluído quando há leitura direta.
- A API do Control Tower recusa `file_types` e `visibility` enquanto não há aplicação integral. As rotas locais de leitura do node só aplicam o filtro quando recebem um envelope assinado válido; isso ainda não equivale à aplicação integral de policies pelo Control Tower.

**Falta**

- Integrar e avaliar `file_types`/`visibility` nas policies, mantendo precedência, especificidade e expansão de regras legadas; atualizar diagnóstico, editor, matriz e navegador.
- Propagar contexto de autorização versionado e verificável do Control Tower ao node para **todas** as operações relevantes; validar escopo, tamanho, integridade, versões e capacidades, sem ignorar nem truncar filtros inválidos.
- Integrar os filtros às verificações auxiliares, cópia, move, delete, diretórios, uploads e retomadas. Validar as leituras locais já integradas em conjunto com o Control Tower e a aplicação durante varredura e publicação, inclusive falhas e mudanças externas.
- Preservar a recusa de operações sobre árvores com negações por caminho enquanto o novo contexto não as representar integralmente. Só habilitar as policies após cobrir shares e transferências da entrega 5.
- Atualizar OpenAPI, tipos do frontend e testes de contrato; executar casos dourados e testes contra adulteração, nodes antigos e contornos por caminho, rename e extensão.

## 5. Shares, transferências e uploads — parcialmente implementado

**Código existente**

- Shares reavaliam o criador também nos metadados e desbloqueio; listagem, conteúdo e ZIP podem usar contextos assinados quando `CONTROL_TOWER_SIGNED_LOCAL_READS=true`. A cota é reservada atomicamente após a confirmação do node e antes de enviar bytes, sem consumir downloads por falhas de capacidade ou autorização. A retomada manual entre nodes é recusada sem contexto verificável; isso ainda não garante revogação imediata na continuidade automática de jobs existentes.
- Shares novos de automação persistem o tipo do criador e a credencial emissora, revalidando conta, chave, expiração, grupos e políticas a cada acesso. A gravação eleva `minimum_security_version` do Control Tower para 3 na mesma transação. Shares antigos permanecem classificados como usuário; vínculos de automação antigos não são presumidos.
- `exclude` por grant possui validação, aplicação em origem/destino e capacidades específicas nos nodes. A inspeção opcional de uploads verifica MIME e assinaturas e remove parciais rejeitados.
- As rotas diretas de transferência verificam as capacidades `grant_exclude_send_v1` e `grant_exclude_receive_v1` quando os respectivos grants informam exclusões; recusam nodes incompatíveis com orientação de atualização, indisponibilidade de metadados e caminhos selecionados diretamente excluídos. Transferências em andamento ainda não possuem autorização renovável.
- Na descoberta, planejamento e criação de transferências, movimentos exigem `read`, `update` e `delete` na origem; políticas que podem sobrescrever exigem `create` e `update` no destino. A exigência se aplica também às rotas diretas de transferência, inclusive para políticas com letras maiúsculas ou espaços; `ask` autoriza o diretório pai quando pode renomear um arquivo.
- Retomada, nova tentativa e decisão manual de cópias locais revalidam conservadoramente `create` e `update` no diretório que contém o destino, pois decisões anteriores podem ter persistido ações de sobrescrita ou renomeação independentemente da política original. Isso pode exigir uma policy mais ampla até que os itens e a execução tenham autorização renovável integrada.
- Na inicialização do node, jobs herdados que estavam enfileirados, executando ou aguardando peer/mount passam a `waiting_validation`, preservando os checkpoints; reconexão de peer e recuperação do mount não os reativam automaticamente. Jobs remotos continuam sem retomada pelo Control Tower até existir autorização verificável. Isso não cobre revalidação contínua nem retries automáticos dentro da mesma execução do processo.
- Upload simples aplica contexto assinado quando `CONTROL_TOWER_SIGNED_UPLOADS=true`, vinculando destino, opções e chave de idempotência; o node revalida antes da publicação e interrompe streams expirados. A API de policies por tipo continua bloqueada.
- Upload retomável pode receber contextos assinados por configuração explícita. Admissão, chunks, publicação, cancelamento e reautorização usam o destino persistido; a publicação revalida create/update e preserva o destino existente se a permissão mudar ou surgir conflito.

**Falta**

- Completar a aplicação de regras por tipo às verificações auxiliares e aos fluxos de criação e diagnóstico dos shares, mantendo a recusa conservadora onde ainda houver divergência.
- Integrar emissão e validação das autorizações assinadas a transfers e jobs, vinculando ator, nodes, grants, raízes, operações e validade. As chaves já podem ser provisionadas; falta usá-las nesses fluxos e validar sua rotação ponta a ponta.
- Persistir o contexto necessário no estado cifrado, renovar antes de iniciar/retomar e durante jobs longos e aguardar quando não puder validar. Aplicar no manifesto, conteúdo, destino, sobrescrita e limpeza da origem, inclusive continuidade automática.
- Antes de ativar sessões com identidade persistida, validar o fluxo completo de atualização, recuperação e rollback com backup compatível, e assegurar que sessões antigas só recebam acesso após autorização explícita verificável. A versão 2 do cabeçalho do node é separada do marcador de versão mínima do Control Tower; binários muito antigos que não verificarem sua versão não são protegidos automaticamente.
- Integrar consultas auxiliares e exercitar interrupção, troca de permissão, rejeição, inspeção e retomada sem substituir destinos existentes indevidamente.

## 6. Segredos e apresentação — parcialmente implementado

**Código existente**

- Varredura do prefixo de 64 KiB para leituras de agentes, inclusive `Range` e arquivos em ZIP, com recusa em nodes sem capacidade anunciada.
- `read_media_types` opcional; buscas de agentes limitadas a 200 resultados, profundidade 16, 10 mil entradas e 10 segundos, com indicação de resultado incompleto.
- `display_name` saneado para listagem e busca, preservando caminhos canônicos. Documentação registra limitações e possíveis falsos positivos e negativos.
- As principais superfícies de arquivo no frontend usam `display_name` quando disponível e neutralizam controles e caracteres bidirecionais também no fallback para `name`, em breadcrumbs, diálogos, prévias, fila de uploads e share público. Caminhos e nomes canônicos continuam sendo enviados às APIs; caminhos editáveis não são alterados.

**Falta**

- Validar todos os fluxos de leitura e ZIP, auditoria sem valores de segredos, nomes em desktop/mobile e limites sob carga; conferir a apresentação em todos os componentes que exibem nomes.

## 7. Lixeira, confirmação, aprovação e JIT — parcial

**Código existente**

- Atribuições temporárias de policies a usuários e contas de serviço, com expiração, limite de uma hora, revogação, auditoria e interface. Agentes continuam sujeitos ao teto de leitura. Permissões são reavaliadas em novas requisições; isso não interrompe automaticamente transferências já em andamento.

**Falta**

- Lixeira opcional por mount gravável, retenção padrão de 30 dias, movimentação no mesmo filesystem, metadados e intenções no estado cifrado, recuperação após falhas e restauração com revalidação e recusa de conflitos.
- Planos para delete/move de árvores e confirmação de uso único por cinco minutos, vinculada ao sujeito, caminhos e identidade do plano; detectar alterações e exigir novo plano.
- `needs_approval` e solicitação de pequenas operações JSON por agentes, sem escrita direta. Aprovação humana na UI com permissões atuais e corpo guardado/revalidado; expiração em cinco minutos, execução idempotente e webhook somente para notificação.
- Validar JIT contra todas as rotas, expiração e interação com a autorização renovável de jobs.

## 8. Identidade de workload e MCP — parcial

- Existem validadores internos de JWT/JWKS e JWT-SVID, ainda **não ligados à autenticação**. O JWT verifica assinatura assimétrica, emissor, sujeito, audiência e expiração; o JWT-SVID usa o validador Go SPIFFE com bundle e trust domain próprios, além de expiração sem tolerância adicional. O JWKS limita resposta a 1 MiB e 64 chaves, usa timeout de três segundos, cache de cinco minutos e intervalo mínimo de dez segundos entre atualizações. Falha de atualização com cache expirado recusa a autenticação; rotação com o mesmo `kid` também é revalidada após o intervalo mínimo.
- O store possui mapeamentos internos de provider/emissor/sujeito/audiência para contas existentes, associados a um ID de credencial estável e à mesma infraestrutura de cota diária. Desativar e reativar um mapeamento preserva seu histórico; sua criação eleva `minimum_security_version` para 4 na mesma transação. O identificador sintético não é aceito como bearer estático. Esses métodos ainda não são expostos nem autenticam requisições: falta integrar a revalidação e o cancelamento dos streams em todos os pontos que usam credenciais.
- Implementar provedores JWT/JWKS com mapeamento explícito de contas e validação de assinatura, algoritmos, emissor, audiência e expiração; limitar atualização de chaves.
- Implementar JWT-SVID de acordo com trust domain/bundle e SPIFFE ID, respeitando sua validação própria.
- `jolt-mcp` usa o SDK oficial Go via STDIO, oferece apenas `list`, `search`, `disk_usage` e `read_text`, e consulta o Control Tower usando credencial relida de arquivo a cada chamada. O binário integra o build e a imagem; instruções em [`../MCP.md`](../MCP.md). A leitura de arquivos rotacionados não habilita JWT/SVID antes de sua integração no Control Tower.

## Validação e implantação pendentes

### Evidências locais já executadas

- Os validadores internos de workload passaram nos testes com emissor JWKS local e `-race`, cobrindo assinatura, algoritmos, claims, trust domain, bundle, rotação com e sem troca de `kid`, falhas e limites de atualização, tempo e tamanho. Esses testes não representam autenticação federada integrada nem comprovam cotas por identidade persistente.
- Os testes dos mapeamentos internos cobrem cota preservada após reinício e desativação, unicidade concorrente, auditoria e elevação atômica da versão. Um leitor compilado da revisão anterior, que suporta até a versão 3, aceitou estado legado e recusou o estado com mapeamento de versão 4. Ainda falta provar cotas com JWTs rotacionados através da autenticação HTTP.
- O MCP passou em `go test ./...`, `go vet ./...` e `go test -race -p 1 ./internal/mcpserver ./cmd/jolt-mcp` no Control Tower. O teste do processo STDIO cobre as quatro ferramentas, rotação de arquivo e recusa de escrita; uma jornada com node e Control Tower reais cobriu policy de agente e revogação da credencial. `docker build -f control/Dockerfile control` passou em Linux/arm64 e um container descartável confirmou as ferramentas por STDIO. O binário foi cross-compilado para Linux/amd64, sem execução nessa arquitetura; JWT/SVID e aceite entre hosts permanecem pendentes.
- Na recuperação de jobs herdados, passaram `CGO_ENABLED=0 go test ./...`, `go vet ./...` e `go test -race -p 1` nos pacotes de estado, jobs e transferências do node. Os testes conferem preservação dos itens, bloqueio de execução automática após reinício e retomada explícita, além da continuidade dos testes de peer/mount na mesma execução.
- A apresentação de nomes passou nos 47 testes do frontend, `npm run typecheck`, `npm run build` e em dois cenários Playwright de share público no Chromium desktop e mobile. As jornadas verificaram rótulos com controles neutralizados e o uso do caminho canônico no link e na navegação; outras jornadas de interface continuam pendentes.
- Após o ajuste de cancelamento e proteção de árvores, `CGO_ENABLED=0 go test ./...` e `go vet ./...` passaram no node; `go test -race -p 1` passou nos pacotes de filesystem, jobs e HTTP. Na primeira execução concorrente, `TestDirectoryJobUsesPersistedFileParallelism` excedeu o prazo de espera; o teste isolado e a suíte sequencial passaram. Os testes cobrem cancelamento antes e durante remoção, entrada protegida criada após a pré-validação, links em árvores e restauração do destino após cancelamento.
- Em 2026-11-03, `make acceptance` passou no macOS/ARM64 com o perfil `quick`: cópia de arquivo com interrupção e retomada, diretório de 1.024 arquivos e histórico cifrado. O teste do diretório levou aproximadamente 191 segundos; não é o perfil completo de carga nem validação entre hosts.
- Na correção das permissões de transferências, passaram `go test ./...`, `go test -race ./internal/httpapi` e `go vet ./...` no Control Tower. Os testes verificam as rotas lógicas e diretas, recusa antes do encaminhamento e permissões de atualização na origem e no destino.
- No Control Tower, `go test ./...` passou após a implementação do emissor; os testes de HTTP, store, RBAC e assinatura também passaram com `-race`. Após `9da246d`, o teste de HTTP com `-race` passou novamente.
- Na integração opcional do proxy posterior a `9da246d`, passaram `go test ./...`, `go test -race ./internal/httpapi ./internal/config` e `go vet ./...` no Control Tower. Os testes focados exercitam emissão por usuário e agente, vínculo de operação e caminho, recusa de node sem capacidade ou confirmação e interrupção de cliente lento.
- Uma jornada local entre processos reais do Control Tower e node passou para listagem, ocultação por nome, conteúdo com `Range`, metadados, busca, uso de disco, plano de ZIP e ZIP. Chave incompatível e ausência da capacidade produziram recusa. Reproduzir com `python3 scripts/signed-read-smoke.py --node-bin /caminho/jolt-node --control-bin /caminho/jolt-control`, após compilar os binários; exige OpenSSL com Ed25519 e portas de loopback. Essa jornada não habilita policies por tipo nem substitui a validação integrada das demais operações.
- Na correção de permissão de sobrescrita de uploads, passaram `go test ./...` e `go test -race ./internal/httpapi` no Control Tower. Os testes cobrem upload simples, criação e conclusão de sessão, chunks, destino persistido, metadado ausente e revogação de `update`; não substituem uma jornada de upload com filtros assinados.
- A verificação de envelopes para sessões de upload tem testes nos dois módulos para ator, credencial, corpo de admissão, operação, node, mount, caminho, ID da sessão, expiração e rejeição de contextos de transferência. Uma jornada local entre processos validou criação, chunk, publicação, cancelamento, troca de login, reautorização de sessão legada e recusa da credencial antiga. O ensaio opcional `scripts/signed-read-smoke.py --slow-expiry` confirmou a interrupção pelo proxy de uploads simples e em chunks ao expirar a autorização, preservação do destino existente e retomada do chunk pelo offset persistido. Isso não substitui testes sob carga ou entre hosts.
- Para essa integração de uploads retomáveis, passaram testes com `-race` nos pacotes HTTP e assinatura do Control Tower e nos pacotes HTTP, filesystem e assinatura do node, além de `go vet` nos dois módulos. A jornada local de processos executou também a confirmação de capacidade e a recusa de chave incompatível.
- Na reautorização, testes com `-race` cobriram troca de credencial, ator diferente, replay após ciclos de credencial, falhas ao elevar o estado à versão 3 e recusa por leitor da versão 2 compilado da revisão `c707bd1`. A jornada entre processos cobriu sessão legada, novo login e privacidade do vínculo. Passaram `go test ./...` e `go vet ./...` em ambos os módulos. Na interface, 45 testes e o build passaram; quatro cenários de retomada e recusa passaram em Chromium desktop e mobile.
- O upload simples assinado foi testado entre processos, inclusive repetição idempotente, e por HTTP real no node com expiração durante envio lento; o destino não foi publicado após a expiração. Os testes cobrem adulteração de opções, negação por tipo e isolamento da chave de idempotência por ator.
- Shares assinados foram exercitados entre processos para metadados, listagem, conteúdo com `Range`, última transferência permitida por cota e ZIP. Testes focados verificam revogação do criador, escopo, capacidade e confirmação do node; a habilitação integral de policies por tipo continua bloqueada.
- A criação e o acesso de um share por automação foram exercitados entre processos, incluindo revogação da chave. Testes cobrem remoção do node do grupo, desativação da conta ou grupo, remoção da policy, expiração de credencial e rejeição de datas inválidas; um leitor do Control Tower anterior recusou o estado de versão 3.
- No node, os testes do estado cifrado passaram com `-race`, cobrindo recuperação do vínculo após reinício, ausência de identidade em JSON e nos arquivos cifrados, imutabilidade e sessões antigas. A elevação do cabeçalho e as transações na versão 2 foram exercitadas em falhas de sincronização e rename; um leitor compilado da revisão `80e7980` aceitou estado legado e recusou o estado elevado. Passaram também `CGO_ENABLED=0 go test ./...` e `CGO_ENABLED=0 go vet ./...` do node no ambiente local.
- No node, `go test ./...` passou com acesso às portas locais durante a etapa que originou `f8676a9`, antes do ajuste final de canary. Nas alterações posteriores, os testes focados de filesystem e HTTP passaram com `-race`, incluindo leitura assinada, `Range` em HTTP real, ZIP, ocultação, conflitos e mudança de filtro durante upload; vet e build com `CGO_ENABLED=0` passaram. A revogação integrada durante um upload ainda precisa ser validada.
- No frontend, 43 testes e dois cenários Playwright de segurança de agente, em desktop e mobile, passaram na etapa `05d56d0`. Não houve mudanças posteriores no frontend até `9da246d`.
- Estes resultados são registros de execuções no ambiente local macOS/ARM64; cada item indica o escopo exercitado e nenhum constitui aceite integrado nem de release.

### Ainda necessário

- Executar novamente os testes dos dois módulos, detector de concorrência, contratos OpenAPI, frontend e jornadas de navegador desktop/mobile sobre a implementação completa; registrar resultados e lacunas por entrega.
- Validar migrações, containers, recuperação, integração entre versões e aceitação de carga conforme o processo do projeto. Registrar separadamente a validação representativa em Linux/amd64.
- Atualizar nodes antes de ativar recursos que dependam deles. Recusar operações afetadas quando o suporte completo estiver ausente.
- Preservar configurações, identidades e ambientes de teste locais. Não tratar os testes locais já executados como validação de release ou implantação.
