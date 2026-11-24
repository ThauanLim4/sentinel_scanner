# PROGRESSO — Sentinel Scanner

Atualizado em: 2026-11-24
Etapa atual: **3 — interface gráfica com PySide6**
Interface gráfica: **em desenvolvimento por fases (Fases A, B, C, D, E e F concluídas)**
Executável: **fora do escopo desta etapa**

## Estado real

- O núcleo é importável e executável no ambiente de desenvolvimento (Python 3.14, Windows).
- A suíte automatizada passa: **145 testes, OK (3 ignorados)** na última execução.
- Nenhum teste usa malware real, limpeza real do sistema, alteração real do Registro, de serviços,
  de tarefas agendadas ou de exclusões do Defender.
- O projeto **não** está pronto para uso real/produção. A validação em cenários reais e em uma
  matriz de Windows 10/11 com e sem administrador ainda é necessária.

## Etapa 3 — Fase A (concluída)

Fundação da interface: tema, componentes reutilizáveis, janela principal, sidebar e navegação.

- [x] Tema escuro/claro parametrizado por paleta, com QSS único e tokens corrigidos.
- [x] Componentes: cartões, métricas, status de proteção, tabela ordenável, estado vazio,
      confirmação explícita, detalhes, notificações (histórico + toast) e ícones SVG próprios.
- [x] Sidebar com as 10 seções, ícones, agrupamento visual e indicação da página ativa.
- [x] Cabeçalho com título da página, estado do sistema, notificações e versão.
- [x] Contexto da aplicação com banco, configurações, quarentena e fábricas do núcleo.
- [x] Infraestrutura assíncrona `QThread`/`QObject` com progresso, cancelamento, erro e
      encerramento controlado; nenhuma atualização de widget fora da thread principal.
- [x] Janela principal com navegação sem recarregar a aplicação, adaptação a resoluções e
      confirmação ao fechar durante operação.
- [x] Ponto de entrada único: `python -m sentinel` (`gui/app.py` + `sentinel/__main__.py`).
- [x] Validação offscreen: criação do banco, 10 telas registradas, navegação e troca de tema.
- [x] Suíte existente preservada: **145 testes, OK (3 ignorados)**.

Arquivos criados nesta fase: `gui/context.py`, `gui/main_window.py`, `gui/app.py`,
`gui/workers/base.py` e `gui/workers/{scan,process,network,cleanup}_worker.py`,
`gui/components/{common,sidebar,header,status_card,metric_card,data_table,confirmation_dialog,detail_dialog,notification}.py`,
`gui/views/{base_view,placeholder_view}.py`, `sentinel/{__init__,__main__}.py`.
As telas ainda são placeholders e serão substituídas nas fases seguintes.

## Etapa 3 — Fase B (concluída)

Dashboard funcional integrado ao banco local, ao Windows Defender e ao analisador de processos.

- [x] `evaluate_protection()` puro e testável: só declara **protegido** quando a última
      varredura terminou sem detecções **e** o Defender respondeu com tempo real ativo e
      definições atualizadas. Informação ausente rebaixa para **Verificando**.
- [x] Dados locais reais: resumo agregado, varredura mais recente, detecções e auditoria.
- [x] Consulta ao Defender e contagem de processos em threads próprias, com *cache* curto,
      proteção contra sondas duplicadas e atualização apenas na thread principal.
- [x] Cartão de proteção com estado, motivo, última varredura, ameaças, quarentena e Defender.
- [x] Métricas de varreduras, arquivos verificados, detecções, quarentena e processos ativos.
- [x] Tabelas de detecções e atividade recente, com estado vazio explícito e detalhes por linha.
- [x] Ações de varredura rápida, atualização, quarentena e histórico; banner de erro/aviso.
- [x] Nenhuma operação destrutiva é executada pelo Dashboard; nenhum resultado é inventado.
- [x] Validação offscreen com banco temporário e serviços simulados (Defender e processos):
      estados protegido/atenção/risco/verificando, métricas, tabelas, banner e troca de tema.

Arquivos criados nesta fase: `gui/views/dashboard_view.py`, `gui/workers/defender_worker.py`.
`gui/workers/process_worker.py` ganhou a contagem rápida usada pelo Dashboard.

## Etapa 3 — Fase C (concluída)

Tela de Scanner com execução assíncrona, progresso real, cancelamento e resultados auditáveis.

- [x] Varreduras rápida, completa e personalizada (pastas selecionadas e persistidas em JSON).
- [x] Execução em `QThread`; progresso (fase, arquivo atual, contadores e tempo), cancelamento
      cooperativo e encerramento sem atualizar widgets fora da thread principal.
- [x] Resultados lidos do banco após a confirmação do núcleo; nada é exibido como concluído
      antes disso. Falhas do núcleo viram banner, notificação e estado "Falhou".
- [x] Distinção explícita entre **heurística** e **assinatura confirmada** (hash na base local);
      assinatura Authenticode válida é mostrada como redutora de falso positivo, não como veredito.
- [x] O Scanner não remove arquivos automaticamente. A única ação destrutiva é "Isolar em
      quarentena", com confirmação explícita + reconhecimento e execução via `core/quarantine.py`.
- [x] Filtros por risco/origem e busca por caminho/categoria; detalhes com evidências.
- [x] Estados vazios, resultados parciais de varredura cancelada e aviso de que a ausência de
      detecções não garante proteção.
- [x] Validação offscreen com scanner e quarentena simulados: sucesso, filtro, quarentena,
      cancelamento, varredura personalizada sem pastas e erro do núcleo.

Arquivos criados nesta fase: `gui/views/scanner_view.py`, `gui/workers/quarantine_worker.py`.

## Etapa 3 — Fase D (concluída)

Telas de Processos, Rede e Inicialização, com leitura assíncrona e ações confirmadas.

- [x] **Processos**: lista com PID, nome, risco, CPU, RAM, usuário e caminho; análise rápida por
      padrão e **análise profunda opcional** (binários e assinaturas); busca e filtros por risco;
      detalhes com evidências; encerramento somente após confirmação + reconhecimento, executado
      por `ProcessAnalyzer.terminate(..., confirmed=True)`. Processos críticos têm a ação
      desabilitada e o núcleo ainda recusa serviços do Windows e PIDs reutilizados.
- [x] **Rede**: conexões ativas (processo, PID, protocolo, local, remoto, estado, destino externo)
      e indicadores do `NetworkAnalyzer` em abas separadas; métricas; busca; filtro de conexões
      externas e de risco; detalhes com as conexões correlacionadas. Nenhuma conexão é bloqueada
      automaticamente e a ausência de dados por falta de permissão é exibida explicitamente.
- [x] **Inicialização**: análise assíncrona de Registro, pastas, serviços, tarefas e drivers, com
      análise profunda e cancelamento cooperativo (o resultado é descartado ao final); filtros por
      tipo/risco; detalhes com evidências. Desativar/reativar sempre exige confirmação e executa
      via `StartupManager`; itens críticos usam `confirm_critical=True`, drivers são recusados e
      entradas RunOnce/políticas removidas do Registro não oferecem reativação.
- [x] Nenhum widget é atualizado fora da thread principal. Erros do núcleo viram banner,
      notificação e estado "Falhou"; estados vazios diferenciam ausência de dados de ausência de
      ameaças.
- [x] Validação offscreen com processos, rede e inicialização simulados: filtros, detalhes,
      encerramento confirmado, recusa de processo crítico, conexões externas, indicadores,
      desativação/reativação, confirmação crítica, remoção de RunOnce e erros do núcleo.
- [x] Suíte existente mantida: **145 testes, OK (3 ignorados)**.

Arquivos criados nesta fase: `gui/views/processes_view.py`, `gui/views/network_view.py`,
`gui/views/startup_view.py`, `gui/workers/startup_worker.py`. `gui/context.py` ganhou
`startup_manager()`; `gui/workers/process_worker.py` passou a aceitar modo rápido/profundo.

## Etapa 3 — Fase E (concluída)

Telas de Quarentena e Windows Defender com dados reais do núcleo e do banco.

- [x] **Quarentena**: listagem de todas as fases (`pending`/`ready`/`restoring`/`deleting`/
      `quarantined`/`restored`/`deleted`/`failed`) por uma extensão aditiva de
      `Quarantine.list_items(status=None)`; busca por nome/caminho/ID/hash, filtro por estado,
      ordenação por data/nome/tamanho, detalhes, métricas e atualização automática após operações.
- [x] Restauração e exclusão definitiva exigem confirmação na tela **e** `confirmed=True` na
      fábrica do worker; destino informado pelo usuário quando o original não está disponível,
      aviso explícito de sobrescrita e resultado anunciado somente após a resposta do núcleo.
      Nenhum arquivo `.qz`, chave ou journal é manipulado pela interface.
- [x] **Defender**: disponibilidade, antivírus, tempo real, adulteração (quando informado),
      versão/idade das definições, último scan rápido/completo, mensagens do núcleo, outros
      produtos, ameaças e histórico em abas separadas, exclusões somente leitura e aviso de
      acesso restrito. Lista vazia/resposta ausente é exibida como ausência de dados.
- [x] Ações permitidas: consultar estado, atualizar definições, verificações rápida/completa e
      consultar resultados/exclusões, todas em `QThread` com progresso e cancelamento.
      Nenhuma proteção é desativada e nenhuma exclusão é criada/removida.
- [x] Atualização e verificações são registradas em `actions` somente com o resultado real
      confirmado pelo núcleo; falha ao gravar é avisada sem alterar o resultado da operação.
- [x] Validação offscreen com quarentena e Defender simulados: 10 telas registradas (5 restantes
      ainda placeholders), filtros, confirmação recusada/aceita, restauração, exclusão, estado,
      atualização, scan rápido, resultados, exclusões restritas e troca de tema.
- [x] Suíte existente preservada: **145 testes, OK (3 ignorados)** (`py -3 -m unittest discover -s tests`).

Arquivos criados nesta fase: `gui/views/quarantine_view.py`, `gui/views/defender_view.py`.
Modificados: `gui/views/__init__.py`, `gui/workers/quarantine_worker.py`,
`gui/workers/defender_worker.py`, `gui/context.py`, `gui/formatting.py` e
`core/quarantine.py` (apenas assinatura aditiva de `list_items`).

## Etapa 3 — Fase F (concluída)

Telas de Limpeza e Histórico com prévia, confirmação e leitura incremental do banco.

- [x] **Limpeza**: categorias fornecidas por `cleanup.build_categories()`, estimativa por
      categoria, prévia individual com caminho/tamanho/idade/categoria e seleção de arquivos.
      A limpeza exige confirmação na tela e `confirmed=True` na fábrica; somente os caminhos
      marcados são enviados ao novo filtro aditivo `clean(..., only_paths=...)`, que mantém
      todas as revalidações do núcleo (raízes, links, arquivos pessoais e proteção).
- [x] Lixeira é uma categoria opcional, nunca incluída por padrão na execução; confirmar a
      limpeza com ela exige reconhecimento adicional e não há prévia individual dessa API.
- [x] Espaço estimado (antes) e bytes de arquivos removidos (depois) são exibidos em campos
      separados, com aviso de que não representam necessariamente o aumento de espaço livre.
      Cancelamento cooperativo, erros por categoria e resultados parciais são exibidos.
- [x] **Histórico**: varreduras, detecções, quarentena e ações reais do banco em uma tabela
      cronológica, com filtros de categoria/período/busca, carregamento incremental, detalhes
      e indicação de sucesso/falha/parcial. `Database` recebeu apenas parâmetros aditivos de
      limite/offset e `ts` derivado da varredura para detecções.
- [x] Limitação explícita na tela: consultas ao Defender não são gravadas pelo núcleo; só
      atualizações e verificações confirmadas aparecem como ações.
- [x] Validação offscreen com categorias/arquivos sintéticos, `cleanup` simulado (sem remoção
      real) e banco temporário: prévia, confirmação recusada/aceita, seleção individual,
      recusa sem confirmação, Lixeira, filtros, busca e incremental.
- [x] Suíte existente preservada: **145 testes, OK (3 ignorados)**.

Arquivos criados nesta fase: `gui/views/cleanup_view.py`, `gui/views/history_view.py`,
`gui/workers/history_worker.py`. Modificados: `gui/views/__init__.py`,
`gui/workers/cleanup_worker.py`, `gui/context.py`, `database/database.py` e
`core/cleanup.py` (filtro aditivo `only_paths`).

## Concluído na Etapa 2.2

### P0 — Quarentena

- [x] AES-256-GCM por item, com UUID como AAD.
- [x] Chave nunca em texto puro no SQLite.
- [x] DPAPI no Windows; fallback local apenas com ACL/modo restritivo comprovado.
- [x] Falha segura quando a chave mestra não pode ser protegida.
- [x] Journal *write-ahead* para criação, promoção, restauração e exclusão.
- [x] Temporário de restauração com ACL privada.
- [x] Backup do destino antes de substituição com `overwrite=True`.
- [x] Banco atualizado antes de remover o `.qz`; recuperação de operações interrompidas.
- [x] Verificação de tag GCM, SHA-256 e tamanho.
- [x] `capture_acl` libera buffers alocados pelo Windows com `LocalFree`.
- [x] Testes de falha: criptografia, verificação, promoção, remoção do original, banco indisponível,
      disco cheio, item corrompido, chave inválida e restauração/exclusão interrompidas.

### P1 — Testes e analisadores

- [x] Teste PE funciona com `pefile` instalado; sem a dependência a análise é limitada de forma
      explícita (o teste de PE real é ignorado apenas quando não há PE disponível).
- [x] Testes Windows: ACL NTFS, atributos somente-leitura, junction, symlink, DPAPI, restauração.
- [x] Testes de Registro/serviços/tarefas usando fakes e mocks (sem tocar no sistema real).
- [x] Testes do Defender: estado vazio, tempo real desligado, assinaturas antigas, exclusões
      restritas, falha do MpCmdRun e atualização não confirmada.
- [x] Encerramento em árvore não atinge processos filhos críticos.
- [x] Entradas de inicialização sob `%SystemRoot%` exigem confirmação extra.
- [x] Erros de Registro são convertidos em `RegistryError` (sem sucesso silencioso).
- [x] CPU de mineradores normalizada pelo número de CPUs lógicas; limiares documentados.
- [x] Limiar de CPU/GPU só conta com outra família de evidência e exige média acima do limiar.
- [x] Reuso de PID durante a amostragem não mistura histórico de CPU.

### P2 — Organização e documentação

- [x] `.gitignore` para `__pycache__`, logs, banco, chaves, backups, quarentena e relatórios.
- [x] `__pycache__` e `logs/sentinel.log` removidos do índice do Git (arquivos preservados no disco).
- [x] `requirements.txt` do núcleo; `requirements-dev.txt`; `requirements-gui.txt` (futuro).
- [x] `README.md` com instalação, arquitetura, segurança, uso e limitações.
- [x] `PROGRESS.md` com o estado real.
- [x] Proposta de arquitetura de assinaturas no relatório final (sem implementar download/updates).

## Pendente / não validado

- [ ] Matriz manual em Windows 10 e Windows 11, com usuário padrão e administrador.
- [ ] Validação manual das consultas reais ao Defender em máquina com outro antivírus ativo.
- [ ] Validação manual de serviços/tarefas reais em ambiente descartável (os testes usam mocks).
- [ ] Teste de symlink em ambiente com privilégio de criação (o ambiente atual ignora esse teste).
- [ ] Teste com disco realmente cheio e arquivo bloqueado por outro processo (simulados por mock).
- [ ] Revisão de desempenho em volumes grandes e em unidades de rede/nuvem.
- [ ] Implementação das telas de Limpeza, Histórico e Configurações (Fases F e G).
- [ ] Empacotamento em executável (etapa futura).
- [ ] Mecanismo de atualização de assinaturas (apenas proposto, não implementado).

## Próxima etapa recomendada

1. Validar manualmente o núcleo em VM Windows 10/11 descartável, com e sem administrador.
2. Revisar os tempos de varredura e a amostragem de CPU/GPU em hardware real.
3. Concluir as Fases F (Limpeza/Histórico), G (Configurações/integração) e H (auditoria/testes)
   da Etapa 3, consumindo a API do núcleo sem duplicar regras de segurança.
4. Definir e implementar o formato de assinaturas com assinatura digital e atualização segura,
   conforme a proposta do relatório.
