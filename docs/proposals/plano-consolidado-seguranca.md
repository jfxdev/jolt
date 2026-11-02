# Plano consolidado — Segurança de agentes e restrições de arquivos

**Andamento em 2 de novembro de 2026:** implementação em andamento no branch `codex/agent-safety-file-restrictions`, com integração opcional de leituras assinadas posterior ao commit `9da246d`. Este documento acompanha o plano aprovado e prevalece sobre as descrições históricas de [`agent-safety.md`](agent-safety.md) e [`file-type-restrictions.md`](file-type-restrictions.md). Código existente, inclusive com testes locais, não significa entrega validada de ponta a ponta ou publicada.

**Regra de ativação:** a API do Control Tower ainda recusa policies com `file_types` ou `visibility`. O node aplica contextos assinados nas rotas locais de leitura integradas; o proxy pode enviá-los quando `CONTROL_TOWER_SIGNED_LOCAL_READS=true`, após o provisionamento de chaves. O padrão é desativado e essa integração parcial **não representa proteção integral por policy**. Não habilitar a gravação dessas policies até proteger todos os caminhos afetados e validar a compatibilidade entre componentes.

## Checkpoint de implementação

| Entrega | Situação neste branch | Próximo passo principal |
| --- | --- | --- |
| 1. Mount e compatibilidade | Proteção por nome, árvores protegidas e provisionamento de chaves implementados em partes | Revisar todas as rotas, falhas e versões mistas |
| 2. Perfil de agente | Limites, interrupção e teto opcional de capabilities por credencial implementados em partes | Validar limites e revogação em jornadas e carga |
| 3. Auditoria e canary | Auditoria, exportação, cadeia opcional, canaries e métricas implementados em partes | Concluir aceite integrado, privacidade e alertas |
| 4. Regras por tipo | Persistência, avaliadores e leituras locais assinadas integradas opcionalmente ao proxy | Completar todas as operações antes de habilitar policies |
| 5. Shares, transferências e uploads | Filtros de upload internos, `exclude` por grant e verificações parciais | Integrar shares, publicação, autorizações renováveis e continuidade automática |
| 6. Segredos e apresentação | Varredura, limites de busca e `display_name` implementados em partes | Validar todos os fluxos e componentes desktop/mobile |
| 7. Lixeira, confirmação, aprovação e JIT | JIT implementado em partes; lixeira, planos e aprovações pendentes | Implementar fluxos destrutivos e revalidar jobs |
| 8. Identidade e MCP | Pendente | Implementar JWT/JWKS, JWT-SVID e `jolt-mcp` |

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
- Uploads simples e retomáveis com sobrescrita exigem `create` e `update` no destino. Nas sessões existentes, o Control Tower usa o caminho e a opção de sobrescrita persistidos no node e reavalia as permissões; se o node não informar a opção, recusam-se chunks e conclusão com orientação de atualização. A integração de filtros assinados ao upload ainda falta.
- O Jolt limita acesso e consumo; não impede um agente de divulgar conteúdo que teve permissão de ler.

## 1. Proteção do mount e compatibilidade — em andamento

**Código existente**

- `hidden_patterns` e nomes internos protegidos no filesystem; filtros em acesso direto, listagem, busca, totais, ZIP, uploads, cópias e manifestos. Há pré-validação para impedir delete, move e sobrescrita de árvores com conteúdo protegido.
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
- O emissor de autorizações para leituras locais revalida sessão ou API key, grupos ativos, policies, CIDRs e limites de agente, com validade limitada pela credencial e pelo prazo da requisição. Na preparação de leituras de árvores, negações por caminho continuam recusadas e negações por tipo podem ser encaminhadas no filtro. Ele ainda não está ligado aos shares ou jobs.
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

- Há revalidação de permissões em partes dos shares e das retomadas de jobs locais. A retomada manual entre nodes é recusada sem contexto verificável; isso ainda não garante revogação imediata na continuidade automática de jobs existentes.
- `exclude` por grant possui validação, aplicação em origem/destino e capacidades específicas nos nodes. A inspeção opcional de uploads verifica MIME e assinaturas e remove parciais rejeitados.
- Upload simples tem uma implementação filtrada interna com revalidação antes da publicação; **não está ligada às policies por tipo na API**.
- Upload retomável possui operações filtradas internas para verificar o destino da sessão, receber chunks, preparar e publicar. A publicação revalida create/update e preserva o parcial se a permissão mudar ou surgir conflito; os handlers ainda não fornecem contexto verificável.

**Falta**

- Recalcular a autorização completa do criador em cada acesso a shares, incluindo caminhos, listagem e ZIP, com regras por tipo.
- Integrar emissão e validação das autorizações assinadas a transfers e jobs, vinculando ator, nodes, grants, raízes, operações e validade. As chaves já podem ser provisionadas; falta usá-las nesses fluxos e validar sua rotação ponta a ponta.
- Persistir o contexto necessário no estado cifrado, renovar antes de iniciar/retomar e durante jobs longos e aguardar quando não puder validar. Aplicar no manifesto, conteúdo, destino, sobrescrita e limpeza da origem, inclusive continuidade automática.
- Integrar regras por tipo e revalidação à criação e publicação de uploads em chunks, usando o destino persistido da sessão. Exercitar interrupção, troca de permissão, rejeição, inspeção e retomada sem substituir destinos existentes indevidamente.

## 6. Segredos e apresentação — parcialmente implementado

**Código existente**

- Varredura do prefixo de 64 KiB para leituras de agentes, inclusive `Range` e arquivos em ZIP, com recusa em nodes sem capacidade anunciada.
- `read_media_types` opcional; buscas de agentes limitadas a 200 resultados, profundidade 16, 10 mil entradas e 10 segundos, com indicação de resultado incompleto.
- `display_name` saneado para listagem e busca, preservando caminhos canônicos. Documentação registra limitações e possíveis falsos positivos e negativos.

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

## 8. Identidade de workload e MCP — pendente

- Implementar provedores JWT/JWKS com mapeamento explícito de contas e validação de assinatura, algoritmos, emissor, audiência e expiração; limitar atualização de chaves.
- Implementar JWT-SVID de acordo com trust domain/bundle e SPIFFE ID, respeitando sua validação própria.
- Criar `jolt-mcp` via STDIO com o SDK oficial Go, somente `list`, `search`, `disk_usage` e `read_text`; manter credenciais fora dos resultados e respeitar os controles do Control Tower.

## Validação e implantação pendentes

### Evidências locais já executadas

- No Control Tower, `go test ./...` passou após a implementação do emissor; os testes de HTTP, store, RBAC e assinatura também passaram com `-race`. Após `9da246d`, o teste de HTTP com `-race` passou novamente.
- Na integração opcional do proxy posterior a `9da246d`, passaram `go test ./...`, `go test -race ./internal/httpapi ./internal/config` e `go vet ./...` no Control Tower. Os testes focados exercitam emissão por usuário e agente, vínculo de operação e caminho, recusa de node sem capacidade ou confirmação e interrupção de cliente lento.
- Uma jornada local entre processos reais do Control Tower e node passou para listagem, ocultação por nome, conteúdo com `Range`, metadados, busca, uso de disco, plano de ZIP e ZIP. Chave incompatível e ausência da capacidade produziram recusa. Reproduzir com `python3 scripts/signed-read-smoke.py --node-bin /caminho/jolt-node --control-bin /caminho/jolt-control`, após compilar os binários; exige OpenSSL com Ed25519 e portas de loopback. Essa jornada não habilita policies por tipo nem substitui a validação integrada das demais operações.
- Na correção de permissão de sobrescrita de uploads, passaram `go test ./...` e `go test -race ./internal/httpapi` no Control Tower. Os testes cobrem upload simples, criação e conclusão de sessão, chunks, destino persistido, metadado ausente e revogação de `update`; não substituem uma jornada de upload com filtros assinados.
- No node, `go test ./...` passou com acesso às portas locais durante a etapa que originou `f8676a9`, antes do ajuste final de canary. Nas alterações posteriores, os testes focados de filesystem e HTTP passaram com `-race`, incluindo leitura assinada, `Range` em HTTP real, ZIP, ocultação, conflitos e mudança de filtro durante upload; vet e build com `CGO_ENABLED=0` passaram. A revogação integrada durante um upload ainda precisa ser validada.
- No frontend, 43 testes e dois cenários Playwright de segurança de agente, em desktop e mobile, passaram na etapa `05d56d0`. Não houve mudanças posteriores no frontend até `9da246d`.
- Estes resultados são registros das execuções anteriores no ambiente local macOS/ARM64; não foram repetidos nesta atualização dos documentos e não constituem aceite integrado nem de release.

### Ainda necessário

- Executar novamente os testes dos dois módulos, detector de concorrência, contratos OpenAPI, frontend e jornadas de navegador desktop/mobile sobre a implementação completa; registrar resultados e lacunas por entrega.
- Validar migrações, containers, recuperação, integração entre versões e aceitação de carga conforme o processo do projeto. Registrar separadamente a validação representativa em Linux/amd64.
- Atualizar nodes antes de ativar recursos que dependam deles. Recusar operações afetadas quando o suporte completo estiver ausente.
- Preservar configurações, identidades e ambientes de teste locais. Não tratar os testes locais já executados como validação de release ou implantação.
