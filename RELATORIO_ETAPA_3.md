# RELATÓRIO — ETAPA 3 (Interface gráfica PySide6)

**Data:** 2026-11-24
**Status:** Etapa 3 concluída (Fases A–H)
**Ponto de entrada:** `python -m sentinel`
**Testes:** `python -m unittest discover -s tests -v` — 158 testes, `OK (skipped=3)`

## 1. Objetivo e escopo

Concluir a interface gráfica do Sentinel Scanner com dez telas reais, integrando-a **somente** ao
núcleo já existente (Etapa 2.2), sem duplicar regras de detecção, quarentena, limpeza,
inicialização, Defender ou manutenção. A GUI deve ser segura por construção: operações demoradas
assíncronas, ações destrutivas confirmadas, ausência de falsos vereditos e nenhuma mutação real de
Registro, serviços, tarefas, Defender ou arquivos do sistema durante os testes.

Fora do escopo: empacotamento em executável, atualização de assinaturas, uso de malware real e
validação manual em matriz Windows 10/11 com DPI real.

## 2. Auditoria prévia

Antes de qualquer alteração foram auditados: Git/working tree, `README.md`, `PROGRESS.md`,
`RELATORIO_ETAPA_2_2.md`, registro de telas, componentes, workers, `AppContext`, `Settings`, banco,
núcleo e testes existentes (145 testes). O diagnóstico identificou que:

- a GUI ainda não tinha tela de Configurações nem sinais de integração entre telas;
- telas concluídas nas Fases A–F não deveriam ser reconstruídas;
- operações reais já existiam no núcleo e precisavam ser apenas consumidas;
- `README.md` e `requirements-gui.txt` ainda descreviam a GUI como etapa futura;
- não havia `tests/test_gui.py` nem `RELATORIO_ETAPA_3.md`.

A linha de trabalho manteve commits pequenos e auditáveis após cada fase.

## 3. Fases executadas

### Fase A — Fundação

Tema, QSS único com paletas escura/clara, ícones SVG próprios, componentes reutilizáveis
(cabeçalho, sidebar, cartões, tabela, banner, diálogo de confirmação, notificações) e
`MainWindow` com navegação. Arquivos principais: `gui/main_window.py`, `gui/components/*`,
`gui/styles/*`, `gui/app.py`, `sentinel/__main__.py`.

### Fase B — Dashboard e Scanner

Dashboard com resumo real do banco, avaliação de proteção e sondas assíncronas do Defender e de
processos. Scanner com varredura rápida/completa/personalizada, progresso, cancelamento e
resultados. Classificação de evidências: `known_hash` = “Assinatura confirmada”; Authenticode
válido = “Heurística (assinado)”. Arquivos: `gui/views/dashboard_view.py`,
`gui/views/scanner_view.py`, `gui/workers/scan_worker.py`.

### Fase C — Processos e Rede

Leitura assíncrona de processos/conexões com indicadores e correlação. Encerramento de processo
passa pelo núcleo, exige confirmação e valida reuso de PID. Arquivos: `gui/views/processes_view.py`,
`gui/views/network_view.py`, `gui/workers/process_worker.py`, `gui/workers/network_worker.py`.

### Fase D/Fase E — Inicialização, Quarentena e Defender

Inicialização mostra Run/RunOnce, Startup, serviços e tarefas; alterações são reversíveis e
confirmadas, com backup quando aplicável, e drivers nunca são alterados. Quarentena oferece busca,
filtros por estado, ordenação, detalhes, restauração com destino/sobrescrita e exclusão definitiva
com reconhecimento; a GUI nunca toca `.qz` diretamente. Defender mostra disponibilidade, proteção,
tempo real, adulteração, definições, ameaças, exclusões somente leitura, outros produtos e
restrições; permite consultar estado, atualizar definições e executar verificações rápida/completa,
sem desativar proteções nem alterar exclusões. Arquivos: `gui/views/startup_view.py`,
`gui/views/quarantine_view.py`, `gui/views/defender_view.py`, `gui/workers/startup_worker.py`,
`gui/workers/quarantine_worker.py`, `gui/workers/defender_worker.py`.

Extensões aditivas do núcleo: `Quarantine.list_items(status=None)`.

### Fase F — Limpeza e Histórico

Limpeza usa `cleanup.build_categories()`, apresenta estimativa e prévia individual (caminho,
tamanho, idade, categoria) e envia ao núcleo somente os caminhos marcados, via
`clean(..., only_paths=...)`. Lixeira nunca é incluída por padrão e exige ack adicional. Espaço
estimado e bytes realmente removidos são exibidos separadamente. Histórico mostra varreduras,
detecções, quarentena, restaurações, exclusões, limpezas e ações de inicialização/processos/Registro,
com filtros por categoria/período/busca, ordem cronológica, detalhes e carregamento incremental.
Nenhum evento é inventado. Arquivos: `gui/views/cleanup_view.py`, `gui/views/history_view.py`,
`gui/workers/cleanup_worker.py`, `gui/workers/history_worker.py`.

Extensões aditivas do núcleo: `cleanup.list_files(...)`, `cleanup.clean(..., only_paths=...)`,
`Database.summary()`, `Database.list_findings(limit=...)`, `Database.list_actions(offset=...)`,
`Database.list_quarantine(limit=...)`.

### Fase G — Configurações e integração

Décima tela real (`gui/views/settings_view.py`) com tema, notificações não críticas, confirmação ao
fechar durante operações, `scan_workers`, `cpu_limit`, pastas da varredura, exclusões locais e
`log_level`. Todas as opções visíveis têm efeito verificável; idioma é fixo e não há opção
decorativa. Preferências são gravadas em `data/gui_settings.json` com escrita atômica, sem
Registro. `BaseView` passou a emitir `data_changed`/`settings_changed`; `MainWindow` aplica tema e
nível de log em tempo real e invalida o Dashboard após operações com efeito real. Scanner relê
pastas/exclusões ao abrir. `core/logger.py` ganhou `set_level()` aditivo. Notificações `success` e
`info` ficam apenas no log quando desligadas; `danger` e `warning` permanecem críticas.

### Fase H — Auditoria, testes e documentação

`tests/test_gui.py` foi criado com 13 testes versionados. A auditoria final cobriu threads, banco,
resoluções/escalas, confirmações, exclusões reais do Scanner, histórico, Defender com dublês e
entrypoint. Documentação final atualizada em `README.md`, `PROGRESS.md` e `requirements-gui.txt`.

## 4. Decisões de segurança

1. **Núcleo é a única fonte de verdade.** A GUI não implementa detecção, quarentena, limpeza,
   encerramento ou correção de Registro; ela apenas chama as APIs existentes via `AppContext`.
2. **Threads.** Toda operação demorada usa `QThread`/`QObject` com sinais Qt, progresso,
   cancelamento cooperativo e `TaskManager.shutdown()`. Widgets são atualizados somente na thread
   principal, por meio de sinais conectados a objetos da GUI.
3. **Confirmação.** Encerramento de processo, desativação/ativação de inicialização, restauração,
   exclusão definitiva, limpeza e fechamento durante operação exigem confirmação explícita. A
   fábrica das tarefas destrutivas também exige `confirmed=True`, impedindo chamada acidental.
4. **Defender somente leitura.** Consultas não são registradas no banco porque o núcleo não as
   registra; apenas atualização de definições e verificações confirmadas geram `actions`. Resposta
   vazia, lista vazia e `exclusions()["restricted"]` nunca são tratados como sucesso silencioso.
5. **Quarentena.** Nenhum arquivo `.qz` é lido/escrito pela GUI; metadados vêm do banco e operações
   passam por `core/quarantine.py`. ACLs/atributos no Windows são *best-effort* e não são anunciados
   como garantia absoluta.
6. **Limpeza.** A prévia é individual e somente os caminhos marcados entram em `only_paths`, que é
   um filtro aditivo: todas as proteções do núcleo (raízes, links, documentos, idade mínima)
   continuam valendo. Lixeira exige ack adicional e nunca é padrão.
7. **Dashboard.** “Protegido” exige varredura e Defender suficientes. Ausência de informação
   rebaixa o estado para “Verificando”; nenhum resultado parcial é apresentado como confirmação.
8. **Histórico.** Eventos são gerados apenas a partir de registros reais do banco. Consultas do
   Defender não gravadas são documentadas na própria tela.
9. **Preferências.** Opções sem efeito real foram proibidas. `language` permanece fixo e não é
   exibido. Listas persistentes são normalizadas e usadas pelo Scanner e pelo `AppContext`.

## 5. Testes e validação

Comandos executados no ambiente de desenvolvimento (Windows, Python 3.14 via `py -3`):

```powershell
py -3 -m compileall -q gui core database sentinel tests
py -3 -m unittest discover -s tests
py -3 -m unittest tests.test_gui -v
```

Resultado final da suíte completa:

```text
Ran 158 tests in 32.896s
OK (skipped=3)
EXITCODE=0
```

Os 13 testes da GUI cobrem:

- dez telas reais e nenhuma `PlaceholderView`;
- navegação nas resoluções 1366×768, 1280×720 e 1920×1080 com escalas aproximadas de 100/125/150%
  por fonte (o modo `offscreen` não mede o DPI real do Windows);
- gravação, recarga e normalização das preferências, incluindo valores inválidos;
- aplicação de tema e nível de log na mesma sessão;
- notificações críticas vs. não críticas;
- compartilhamento de pastas/exclusões com o Scanner e uso dos valores de desempenho;
- invalidação do Dashboard até que ele volte a ficar visível;
- sucesso, progresso, erro e cancelamento de `Worker`/`TaskManager`, com shutdown sem threads vivas;
- `exclude_paths` real do Scanner sobre arquivos sintéticos;
- confirmações obrigatórias de restauração/exclusão da quarentena e da limpeza;
- `only_paths` da limpeza repassado ao núcleo, sem limpeza real;
- filtros por categoria/período/busca e paginação incremental do histórico;
- Defender com dublê: consultas sem registro, operações confirmadas registradas e nenhuma tentativa
  de desativar proteções ou alterar exclusões;
- entrypoint `python -m sentinel` com `app.exec()` interceptado (sem loop real).

Nenhum teste executou limpeza real, malware real, alteração de Registro/serviços/tarefas/Defender
nem gravou fora de diretórios temporários.

## 6. Arquivos criados e modificados

**Criados na Etapa 3:** `gui/views/settings_view.py`, `tests/test_gui.py`,
`RELATORIO_ETAPA_3.md` e o ponto de entrada `sentinel/__main__.py`.

**Modificados/implementados na Etapa 3:** `gui/app.py`, `gui/main_window.py`, `gui/context.py`,
`gui/settings.py`, `gui/errors.py`, `gui/formatting.py`, `gui/components/*`, `gui/styles/*`,
`gui/views/*`, `gui/workers/*`, `core/cleanup.py`, `core/logger.py`, `core/quarantine.py`,
`core/scanner.py`, `database/database.py`, `README.md`, `PROGRESS.md` e `requirements-gui.txt`.

**Commits da Etapa 3:** `5190068` (Inicialização e infraestrutura de workers), `5531bf0`
(Quarentena e Defender), `bcaf07d` (Limpeza e Histórico), `51b583c` (Configurações e integração) e
o commit final de Fase H/documentação.

## 7. Limitações conhecidas

- Não há matriz manual em Windows 10/11 com usuário padrão/administrador.
- A escala DPI real (100/125/150%) não foi medida; os testes aproximam o efeito por fonte em
  modo `offscreen`.
- Consultas reais ao Defender em máquina com outro antivírus ainda precisam de validação manual.
- Serviços/tarefas reais e ACLs/junctions em privilégio elevado foram validados com mocks/saltas.
- Volumes grandes, unidades de rede/nuvem e disco cheio não foram medidos com carga real.
- Não há executável empacotado nem atualização automática de assinaturas.
- A GUI não substitui revisão humana: uma varredura sem achados não é declaração de sistema limpo.

## 8. Conclusão

A Etapa 3 está concluída: `python -m sentinel` abre uma aplicação PySide6 com dez telas reais,
integrada ao núcleo e ao banco existentes, com operações assíncronas, confirmações explícitas,
preferências persistentes e histórico fiel ao que foi realmente registrado. A suíte automatizada
passa com 158 testes (3 ignorados), preservando integralmente os 145 testes anteriores. Ainda são
necessárias validação manual em Windows real, medição DPI e decisão futura sobre empacotamento e
assinaturas antes de qualquer uso em produção.
