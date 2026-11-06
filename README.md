# Sentinel Scanner

Ferramenta defensiva em Python para **Windows**, com foco em análise de ameaças, monitoramento de
processos, detecção de persistência, análise de rede, quarentena criptografada e manutenção segura.
O projeto está na **Etapa 2.2 (hardening do núcleo)**.

> **Estado atual:** o núcleo é executável e a suíte automatizada passa no ambiente de
> desenvolvimento. **Não** é um produto pronto para uso real, não substitui um antivírus e **não**
> deve ser usado para limpezas amplas sem revisão. A interface gráfica e o executável **não** fazem
> parte desta etapa.

## Requisitos

- Windows 10 ou 11 (os testes automatizados também rodam em outros sistemas quando aplicável).
- Python 3.10+ (ambiente validado com Python 3.14).
- Dependências do núcleo: `psutil`, `cryptography`.
- `pefile` é opcional: sem ele o programa continua importável, mas a análise estática de PE fica
  limitada (sem seções, imports, entropia e fabricante).

## Instalação

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Dependências futuras de GUI e integrações opcionais estão em `requirements-gui.txt`; dependências
de desenvolvimento estão em `requirements-dev.txt` (a suíte usa apenas `unittest` da biblioteca
padrão).

## Executar os testes

```powershell
python -m unittest discover -s tests -v
```

Os testes usam somente arquivos sintéticos e diretórios temporários. Eles **não** alteram o
Registro real, serviços, tarefas agendadas, exclusões do Defender nem executam malware.

## Estrutura

```text
core/        núcleo: análise, quarentena, segurança, limpeza, registro, inicialização, Defender
database/    persistência SQLite (varreduras, achados, ações, cache, quarentena)
tests/       testes automatizados (unidade, integração, segurança e Windows)
data/        banco, chaves e listas locais (não versionar dados de execução)
quarantine/  arquivos .qz criptografados (conteúdo não versionado)
logs/        logs de execução (não versionados)
reports/     relatórios gerados (não versionados)
gui/         reservado para a etapa futura; não implementado nesta etapa
```

### Módulos principais

| Módulo | Responsabilidade |
|---|---|
| `core/quarantine.py` | Quarentena/restauração com journal, verificação e recuperação de interrupções |
| `core/quarantine_crypto.py` | AES-256-GCM, DPAPI e chave mestra com ACL/modo restritivo (fail-secure) |
| `core/win_security.py` | ACLs NTFS, atributos e verificação de permissões via ctypes |
| `core/file_analyzer.py` | Hash SHA-256, heurísticas, assinatura Authenticode e análise PE |
| `core/scanner.py` | Varredura paralela, incremental, sem seguir links/junctions |
| `core/process_analyzer.py` | Análise de processos e encerramento com confirmação/validação |
| `core/network_analyzer.py` | Conexões externas, portas e pools de mineração conhecidos |
| `core/miner_detector.py` | Detecção de mineradores por famílias independentes de evidência |
| `core/startup_analyzer.py` | Run/RunOnce, Startup, serviços, tarefas e drivers |
| `core/registry_analyzer.py` | Análise somente leitura e correções reversíveis com backup `.reg` |
| `core/malware_detection.py` | Correlação entre processos, rede, inicialização, registro e arquivos |
| `core/defender.py` | Integração somente leitura com o Microsoft Defender |
| `core/cleanup.py` | Limpeza conservadora com allowlist, idade mínima e proteção de documentos |

## Modelo de segurança

### Quarentena e restauração

- Conteúdo cifrado com **AES-256-GCM**; o UUID do item entra como AAD.
- A chave de cada item **nunca** é gravada em texto puro no SQLite.
- No Windows, a chave é embrulhada com **DPAPI** (escopo do usuário).
- O fallback local (`data/keys/master.key`) só é usado se a ACL/modo restritivo for comprovado;
  caso contrário a operação falha (`CryptoError`) em vez de usar uma chave exposta.
- A quarentena é *write-ahead*: o registro é criado antes da cópia, e o original só é removido
  depois de a cópia ser gravada, sincronizada e verificada.
- A restauração grava em temporário com ACL privada, valida tag GCM, SHA-256 e tamanho, preserva o
  destino anterior em backup e só remove o `.qz` depois de o banco confirmar `restored`.
- Interrupções em criação, criptografia, verificação, promoção, remoção, restauração e exclusão
  definitiva são reconciliadas por `Quarantine.recover()` na inicialização.

### Operações destrutivas

- Encerramento de processos exige confirmação explícita, validação de `create_time` (reuso de PID)
  e recusa de processos críticos, do próprio programa e de processos que hospedam serviços.
- Em `kill_tree`, processos filhos críticos são preservados.
- Correções de Registro exigem confirmação, lista de permissões e backup `.reg` antes da escrita.
- Desativação de inicialização é reversível (StartupApproved, backup `.reg`, `sc config` ou tarefa
  desabilitada); drivers nunca são alterados.
- A limpeza só remove arquivos, nunca segue links/junctions e não apaga documentos/mídia/fontes.

### Windows Defender

- Consulta estado, histórico, exclusões e produtos de segurança; executa verificações e atualização
  de definições via cmdlets oficiais.
- **Nunca** desativa proteções e **nunca** adiciona/remove exclusões.
- Saída vazia do PowerShell **não** é interpretada como “sistema limpo”.
- Algumas consultas e operações exigem privilégios administrativos; nesse caso o retorno é
  explícito (`restricted`, mensagem de erro) em vez de sucesso silencioso.

## Uso programático (exemplo)

```python
from core.quarantine import Quarantine
from database.database import Database

db = Database("data/sentinel.db")
q = Quarantine(db)

item_id = q.quarantine_file(r"C:\caminho\arquivo_sintetico.exe", allowed_roots=[r"C:\caminho"])
# ... inspeção ...
q.restore(item_id)              # restaura com verificação
# q.delete_permanently(item_id, confirmed=True)  # exige confirmação explícita
```

## Limitações conhecidas (por analisador)

- **Arquivos/PE:** heurísticas geram indícios, não veredito. Ausência de assinatura sozinha não é
  malware. `pefile` ausente limita a análise. Arquivos inacessíveis/em uso são ignorados.
- **Processos:** alguns campos podem exigir administrador; o nome do processo pode ser falsificado.
  Alto CPU/RAM isolado nunca é evidência.
- **Rede:** `psutil.net_connections` pode exigir privilégios; a resolução DNS de pools é
  *best effort* e depende da rede. Porta incomum é indicador fraco.
- **Mineradores:** CPU/GPU são normalizados pelo total de CPUs lógicas e só contam com outra
  família de evidência. A amostragem tem janela curta e pode não capturar picos.
- **Inicialização/Registro:** a análise é somente leitura por padrão; correções são limitadas por
  allowlist e podem exigir administrador. ACLs e permissões são preservadas em modo *best effort*
  e não devem ser tratadas como garantia absoluta.
- **Defender:** depende do PowerShell/Defender instalados; outro antivírus pode assumir a proteção.
  Não há verificação de malware real nesta etapa.
- **Limpeza:** conservadora por projeto; pode deixar resíduos em vez de arriscar arquivos do usuário.

## Inteligência de assinaturas

`data/signatures/` está vazio. A arquitetura proposta (sem baixar amostras reais e sem inventar
hashes) está descrita no `RELATORIO_ETAPA_2_2.md`, seção 7: hashes SHA-256 com metadados, origem e
confiabilidade, versionamento, atualização assinada, verificação de integridade e desativação de
listas obsoletas. Nenhum mecanismo de atualização externa foi implementado nesta etapa.

## Aviso

Segurança e integridade dos dados têm prioridade sobre velocidade. Use o projeto apenas em ambiente
controlado, com backup e revisão humana. Não declare o sistema “limpo” apenas porque uma varredura
não encontrou achados.
