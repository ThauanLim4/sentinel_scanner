# RELATÓRIO — ETAPA 2.2

**Projeto:** Sentinel Scanner
**Etapa:** 2.2 — hardening de segurança, validação do núcleo e documentação
**Data:** 2026-11-06
**Ambiente de validação:** Windows, Python 3.14.3, `psutil 7.2.2`, `cryptography 50.0.2`, `pefile 2024.8.26`
**Escopo:** núcleo (`core/`, `database/`), testes e documentação. **GUI e executável ficaram fora desta etapa.**

> Este relatório descreve o que foi efetivamente alterado e testado. Ele **não** declara o produto
> pronto para uso real. As validações feitas usam arquivos sintéticos, diretórios temporários, fakes e
> mocks; nenhuma limpeza real, alteração real de Registro, serviço, tarefa agendada ou Defender foi
> executada.

---

## 1. Objetivo

Concluir a Etapa 2.2 com foco em:

1. **P0 — Quarentena/restauração:** chave mestra protegida, criptografia autenticada, restauração
   verificada, proteção contra interrupções e falha segura.
2. **P1 — Analisadores e testes:** corrigir o teste de PE, ampliar a cobertura Windows e de falhas e
   auditar analisadores, detecção de mineradores, processos críticos, inicialização/Registro e Defender.
3. **P2 — Organização:** `.gitignore`, limpeza de `__pycache__`, dependências separadas, `README`,
   `PROGRESS` e documentação de limitações.
4. **Seção 7 — Assinaturas:** apenas **propor** a arquitetura, sem baixar amostras reais, sem aprovar
   amostras e sem criar hashes fictícios.

---

## 2. Problemas encontrados na auditoria

### 2.1 Quarentena e criptografia (P0)

| # | Problema | Risco |
|---|---|---|
| 1 | Chave mestra local podia ser usada sem comprovar ACL/modo restritivo | Chave legível por outros usuários/processos |
| 2 | Fallback de embrulho de chave podia mascarar falha do DPAPI | Perda de garantia de proteção sem erro explícito |
| 3 | Restauração não tinha journal *write-ahead* completo | Interrupção podia deixar destino parcial ou `.qz` órfão |
| 4 | Temporário de restauração era criado com permissões padrão | Conteúdo restaurado exposto durante a operação |
| 5 | Sobrescrita do destino não preservava o arquivo anterior | Perda de dados do usuário em caso de falha |
| 6 | `.qz` podia ser removido antes de o banco confirmar `restored` | Item perdido e banco inconsistente |
| 7 | Exclusão definitiva não registrava estado transitório | Interrupção deixava estado ambíguo |
| 8 | `capture_acl` não liberava o buffer SDDL alocado pelo Windows | Vazamento de memória |

### 2.2 Analisadores (P1)

| # | Problema | Risco |
|---|---|---|
| 9 | `kill_tree` podia encerrar processos filhos críticos | Derrubar serviço/processo essencial do Windows |
| 10 | `update_signatures` retornava `True` sem confirmação do cmdlet | Falso sucesso de atualização do Defender |
| 11 | Saída vazia do Defender não gerava mensagem explícita | Usuário podia interpretar como “sistema limpo” |
| 12 | `quarantined_items` não validava `returncode` do `MpCmdRun` | Falha silenciosa tratada como lista vazia |
| 13 | Entradas de inicialização sob `%SystemRoot%` não exigiam confirmação extra | Desativação acidental de componente legítimo |
| 14 | Erros genéricos de `OSError` no Registro escapavam como erro bruto | Falha sem tipo claro e sem tratamento consistente |
| 15 | `backup_key` não validava colmeia nem falhas do `reg.exe` | Backup ausente antes de escrita |
| 16 | CPU de minerador não era normalizada pelo total de CPUs lógicas | Um núcleo ocupado podia parecer 100% do sistema |
| 17 | Histórico de CPU podia ser misturado quando um PID era reutilizado | Evidência incorreta contra processo inocente |
| 18 | Limiar de CPU/GPU usava só a fração de amostras | Média abaixo do limiar ainda podia gerar alerta |
| 19 | `scanner.inaccessible` era incrementado sem lock | Corrida em varredura paralela |
| 20 | Variável `hits` sem uso em `file_analyzer` | Código morto/ruído |

---

## 3. Correções aplicadas

### 3.1 P0 — Quarentena e criptografia

**`core/quarantine_crypto.py`**

- `_load_master_key()` agora:
  - cria a chave com permissões restritivas;
  - **verifica** a ACL/modo depois de criar;
  - tenta **remediar** quando a verificação falha;
  - se ainda assim não for possível comprovar a proteção, lança `CryptoError`.
- `wrap_key()` não usa mais fallback inseguro silencioso: DPAPI é preferencial no Windows; o fallback
  local só é aceito com a chave mestra comprovadamente protegida.
- AES-256-GCM mantido para o conteúdo; o UUID do item é usado como AAD, impedindo troca de arquivos
  entre itens.

**`core/win_security.py`**

- `verify_private_file()`: exige DACL protegida e somente SIDs permitidos (SYSTEM, Administrators e o
  usuário atual).
- `secure_private_file()`: aplica SDDL restritiva e confirma o resultado.
- `capture_acl()`: libera o buffer SDDL com `LocalFree`.
- `restore_acl()`/`apply_attributes()`/`apply_mode()`: retornam falha explícita em vez de assumir
  sucesso.

**`core/quarantine.py`**

- Estados *write-ahead*: `pending` → `ready` → `quarantined`.
- Estados transitórios: `restoring`, `deleting`.
- Estados finais/erro: `restored`, `deleted`, `failed`.
- Journal em `meta["restore"]` com destino, temporário, backup, fase e hash.
- Restauração:
  1. grava journal e status `restoring`;
  2. descriptografa para temporário `.sentinel-restore-<qid>-<rand>.tmp`;
  3. aplica ACL privada no temporário;
  4. verifica tag GCM, SHA-256 e tamanho;
  5. com `overwrite=True`, move o destino anterior para
     `.sentinel-restore-backup-<qid>-<rand>.tmp`;
  6. promove o temporário com `os.replace`;
  7. atualiza o banco para `restored`;
  8. só então remove o `.qz` e o backup.
- Falhas após a promoção mantêm o `.qz` e o journal para conclusão posterior.
- `recover()`:
  - promove cópias `ready` válidas;
  - descarta cópias quando o original continua intacto;
  - conclui ou reverte `restoring` e `deleting`;
  - marca `failed` quando não há como reconciliar com segurança;
  - migra itens legados (XOR) quando aplicável.
- `delete_permanently()` grava `deleting` antes do `unlink`; a recuperação conclui ou reverte.
- `CryptoError` é convertido em `QuarantineError` nas operações públicas, sem expor detalhes internos.

### 3.2 P1 — Analisadores

**`core/process_analyzer.py`**
- `kill_tree` preserva filhos críticos e filhos cujo nome não pôde ser lido.
- Retorna `children_skipped` para transparência.

**`core/defender.py`**
- `update_signatures()` só retorna `True` com confirmação explícita do cmdlet.
- Saída vazia vira mensagem explícita (“não retornou o estado…”).
- `quarantined_items()` valida `returncode` e converte falhas em `DefenderUnavailable`.

**`core/startup_analyzer.py`**
- `is_critical()` cobre qualquer entrada cujo executável esteja sob `%SystemRoot%`, inclusive entradas
  criadas manualmente que não passaram por `evaluate()`.
- Tarefas sob `\Microsoft\Windows\` continuam protegidas.
- Drivers permanecem sempre recusados.

**`core/registry_analyzer.py`**
- `set_value()`/`delete_value()` convertem `OSError`, `AttributeError` e `ValueError` em
  `RegistryError`.
- `backup_key()` valida a colmeia e converte falhas de `reg.exe` em `RegistryError`; a escrita não
  ocorre sem backup.

**`core/miner_detector.py`**
- CPU normalizada pelo número de processadores lógicos (0–100% do total do sistema).
- Histórico de CPU não é misturado quando o PID é reutilizado (`create_time` diferente).
- CPU/GPU só contam com outra família independente de evidência e exigem **média acima do limiar**,
  além da fração de amostras.
- Falha de GPU desabilita a amostragem em vez de inventar dados.

**`core/scanner.py`**
- `inaccessible` incrementado sob lock.

**`core/file_analyzer.py`**
- Removida variável `hits` sem uso.

### 3.3 P2 — Organização

- `.gitignore` cobre `__pycache__`, `.pyc`, logs, banco, chaves, backups, quarentena, relatórios,
  ambientes virtuais e empacotamento.
- `__pycache__` e `logs/sentinel.log` removidos **do índice Git** com `git rm --cached`; os arquivos
  continuam no disco.
- Dependências separadas:
  - `requirements.txt` — núcleo (`psutil`, `cryptography`; `pefile` opcional);
  - `requirements-dev.txt` — desenvolvimento/testes;
  - `requirements-gui.txt` — GUI futura (`PySide6`) e integração opcional.
- `README.md` com instalação, arquitetura, modelo de segurança, uso e limitações.
- `PROGRESS.md` com estado real, pendências e próxima etapa.

---

## 4. Arquivos modificados e criados

### Modificados

| Arquivo | Mudança |
|---|---|
| `core/quarantine.py` | Journal de restauração/exclusão, temporário privado, backup do destino, recuperação, conversão de erros |
| `core/quarantine_crypto.py` | Verificação/remediação da chave mestra, fail-secure, sem fallback silencioso |
| `core/win_security.py` | ACL privada, verificação, `capture_acl` com `LocalFree`, atributos/modo |
| `core/process_analyzer.py` | `kill_tree` preserva críticos |
| `core/defender.py` | Estado vazio explícito, atualização confirmada, validação do `MpCmdRun` |
| `core/startup_analyzer.py` | Criticidade por `%SystemRoot%` e tarefas da Microsoft |
| `core/registry_analyzer.py` | Erros tipados, validação de colmeia e do backup |
| `core/miner_detector.py` | Normalização por CPUs lógicas, reuso de PID, média no limiar |
| `core/scanner.py` | Contador `inaccessible` sob lock |
| `core/file_analyzer.py` | Remoção de código morto |
| `tests/test_quarantine_security.py` | 31 testes de segurança, falhas e interrupções |
| `requirements.txt` | Dependências do núcleo separadas |

### Criados

| Arquivo | Conteúdo |
|---|---|
| `tests/test_windows_security.py` | 34 testes Windows/falhas (ACL, DPAPI, Defender, Registro fake, inicialização, processos, mineração, restauração) |
| `.gitignore` | Exclusões de artefatos e dados de execução |
| `requirements-dev.txt` | Dependências de desenvolvimento |
| `requirements-gui.txt` | Dependências futuras de GUI |
| `README.md` | Documentação de instalação, arquitetura, segurança e limitações |
| `PROGRESS.md` | Estado real e pendências |
| `RELATORIO_ETAPA_2_2.md` | Este relatório |

**Nenhum commit, `git reset`, `git clean` ou `git checkout` foi executado.** As alterações estão no
working tree para revisão.

---

## 5. Justificativas técnicas

- **Falhar fechado:** uma chave que não pode ser comprovadamente protegida é pior que uma operação
  recusada. Por isso `CryptoError` interrompe a operação em vez de cair para um armazenamento exposto.
- **Journal antes da ação:** o banco registra a intenção antes de cada etapa destrutiva; a recuperação
  consegue distinguir “não começou”, “começou e falhou” e “terminou”. Isso evita tanto perda de dados
  quanto itens órfãos.
- **Temporário privado + promoção atômica:** o conteúdo restaurado nunca fica exposto no diretório de
  destino antes de estar completo e verificado; `os.replace` evita destino parcial.
- **Backup do destino:** sobrescrever sem preservar o anterior transformaria uma falha de restauração
  em perda definitiva de dados do usuário.
- **AAD por item:** impede que um `.qz` válido seja trocado por outro e “autentique” no lugar errado.
- **Processos críticos:** encerrar árvore é útil contra malware, mas não pode derrubar `lsass`,
  `services` ou serviços do Windows. A verificação é feita no filho, não só no processo raiz.
- **Defender honesto:** ausência de resposta não é ausência de ameaça. A ferramenta prefere reportar
  indisponibilidade a sugerir proteção que não foi comprovada.
- **Mineradores:** CPU alta é indicador fraco; normalizar pelo total e exigir outra família reduz
  falsos positivos contra builds, jogos e indexadores.
- **Registro/inicialização:** toda escrita é reversível, limitada por allowlist e precedida de backup;
  drivers e entradas do sistema exigem confirmação extra.

---

## 6. Testes

### 6.1 Comando

```powershell
python -m unittest discover -s tests -v
```

### 6.2 Resultado da última execução

```text
Ran 145 tests in 11.923s
OK (skipped=3)
```

### 6.3 Distribuição

| Módulo | Testes |
|---|---:|
| `test_cleanup_security.py` | 14 |
| `test_core.py` | 6 |
| `test_miner_detection.py` | 15 |
| `test_network_safety.py` | 9 |
| `test_platform_utils.py` | 10 |
| `test_quarantine_security.py` | 31 |
| `test_stage2.py` | 26 |
| `test_windows_security.py` | 34 |
| **Total** | **145** |

### 6.4 Testes ignorados (3)

| Teste | Motivo |
|---|---|
| `test_cleanup_security.test_file_symlink_is_not_deleted` | Criação de symlink de arquivo exige privilégio no Windows |
| `test_core.test_symlink_refused_and_cleanup_ignores_links` | Teste POSIX-only |
| `test_windows_security.test_symlink_is_detected_when_supported` | Ambiente atual não permite criar symlink |

Os testes de junction rodam quando o ambiente permite; caso contrário, são ignorados com mensagem
explícita.

### 6.5 Cobertura relevante

**Quarentena (`test_quarantine_security.py`)**
- ciphertext autenticado e sem texto puro;
- banco nunca contém chave em texto puro;
- ciphertext adulterado e arquivos trocados entre itens;
- cabeçalho truncado/desconhecido;
- roundtrip em fronteira de chunk;
- nome armazenado não escapa do diretório;
- restauração recusa destino fora das raízes e destino protegido;
- `overwrite` respeitado;
- timestamps e somente-leitura preservados;
- exclusão definitiva exige confirmação e remove a chave;
- diretório, origem ausente e symlink recusados;
- falha ao remover o original faz rollback sem perda;
- recuperação promove cópia `ready` válida e descarta quando o original está intacto;
- migração de item legado XOR;
- falhas de criptografia, verificação e promoção mantêm o original;
- interrupções em restauração e exclusão;
- disco cheio, chave inválida, ACL/fail-closed.

**Windows/falhas (`test_windows_security.py`)**
- ACL privada aplicada, verificada e restaurável;
- atributo somente-leitura aplicado/removido;
- SDDL inválido recusado;
- junction detectada e não seguida;
- DPAPI com AAD e blob corrompido;
- Defender: estado vazio, tempo real desligado, assinaturas antigas, exclusões restritas, falha do
  `MpCmdRun`, atualização não confirmada, validação de varredura;
- Registro fake: falha de backup impede escrita, falha de escrita é reportada, colmeia inválida,
  allowlist;
- inicialização: entrada do Windows exige confirmação extra, Run do usuário reversível, serviço via
  `sc config`, nome inválido recusado, tarefa via ambiente, tarefa da Microsoft protegida, driver
  recusado;
- processos: confirmação obrigatória, autoproteção, `kill_tree` preserva crítico, nome crítico fora do
  `System32` não é tratado como crítico;
- mineradores: normalização por CPUs, limiar com família independente, agregação de GPU por PID,
  falha de GPU desabilita amostragem;
- restauração sobre destino somente-leitura no Windows.

---

## 7. Proposta de arquitetura de assinaturas

**Nada foi baixado, aprovado ou implementado nesta etapa.** A proposta abaixo é de arquitetura; não há
hashes reais nem listas fictícias no repositório.

### 7.1 Objetivo

Permitir que o Sentinel reconheça arquivos já conhecidos **sem** transformar uma lista desatualizada ou
adulterada em veredito automático.

### 7.2 Formato do registro

Cada assinatura deve conter, no mínimo:

```json
{
  "sha256": "<64 hex>",
  "name": "<família/identificador>",
  "severity": "low|medium|high|critical",
  "confidence": "low|medium|high",
  "source": "<origem>",
  "reference": "<link ou identificador interno>",
  "first_seen": "YYYY-MM-DD",
  "added_at": "YYYY-MM-DD",
  "expires_at": "YYYY-MM-DD",
  "tags": ["trojan", "miner"],
  "min_engine": "2.2"
}
```

Regras:
- SHA-256 é o identificador primário; MD5/SHA-1 só como aliases de compatibilidade, nunca como
  identidade principal.
- `source` e `reference` são obrigatórios para auditoria.
- `expires_at` permite desativar listas antigas.
- `min_engine` evita usar regras incompatíveis com a versão instalada.

### 7.3 Empacotamento e versionamento

- Um arquivo `manifest.json` por versão de lista, com:
  - `version`, `generated_at`, `expires_at`;
  - `record_count`;
  - `sha256` do arquivo de dados;
  - assinatura digital do manifesto.
- Dados em formato estável (JSON Lines ou binário compacto) para leitura incremental.
- Versionamento semântico próprio da lista, independente da versão do programa.
- Retenção das duas últimas versões para rollback.

### 7.4 Distribuição e atualização

1. Canal HTTPS com certificate pinning ou verificação de assinatura do manifesto.
2. Download para diretório temporário privado.
3. Verificação de:
   - assinatura digital do manifesto;
   - SHA-256 do arquivo de dados;
   - contagem de registros e schema;
   - data de expiração.
4. Só então promoção atômica para `data/signatures/`.
5. Falha em qualquer etapa mantém a versão anterior e registra a falha; nunca apaga a lista boa.
6. Atualização manual e automática devem ser opt-in, com botão/flag explícito.
7. Sem execução de código baixado: a lista é **dado**, não plugin.

### 7.5 Uso na análise

- Uma correspondência de hash é **evidência forte**, não veredito isolado.
- O resultado deve informar `source`, versão da lista e `confidence`.
- Listas expiradas ou não verificadas não devem gerar classificação automática; no máximo, um aviso.
- Hashes de arquivos legítimos (allowlist) têm precedência sobre listas genéricas, com registro de
  auditoria.
- Nenhuma lista deve ser usada para quarentena automática sem confirmação do usuário nesta fase.

### 7.6 Governança

- Toda amostra/entrada precisa de origem documentada e revisão humana antes de entrar na lista.
- Exclusão/correção de falso positivo deve ser possível por hash e por `source`.
- Logs devem registrar versão da lista usada em cada varredura.
- Não incluir amostras de malware no repositório; apenas metadados.
- Testes futuros devem usar hashes sintéticos gerados em tempo de teste, nunca “hashes de exemplo”
  apresentados como reais.

### 7.7 Fora de escopo nesta etapa

- Download automático de listas.
- Integração com VirusTotal ou qualquer serviço externo.
- Quarentena automática baseada em assinatura.
- Distribuição de amostras.

---

## 8. Riscos e limitações

### 8.1 Riscos residuais

| Risco | Situação |
|---|---|
| ACL/DPAPI variam com política de domínio, perfil e privilégios | Verificação falha fechada, mas a matriz real de ambientes não foi validada |
| Antivírus de terceiros pode assumir a proteção | O Defender reporta o estado que consegue ler, não garante proteção efetiva |
| Processos podem mudar entre análise e encerramento | `create_time` reduz, mas não elimina, a janela de corrida |
| Nome de processo pode ser falsificado | A análise usa também caminho, assinatura e comportamento |
| `psutil.net_connections` pode exigir privilégios | Resultado pode ser incompleto |
| Resolução DNS de pools é *best effort* | Rede offline ou DNS bloqueado reduz a detecção |
| Janela curta de amostragem de CPU/GPU | Picos e cargas intermitentes podem passar |
| Serviços/tarefas/Registro reais não foram alterados nos testes | A integração real ainda depende de validação manual em ambiente descartável |
| Disco cheio e arquivo bloqueado foram simulados | O comportamento real do filesystem pode diferir |
| Caminhos longos, volumes de rede e nuvem | Não validados nesta etapa |
| Symlinks no Windows | Teste ignorado por falta de privilégio no ambiente |
| GUI e executável não existem | O produto atual é núcleo + testes, não aplicação final |

### 8.2 Limitações por analisador

- **Arquivos/PE:** heurísticas geram indícios, não veredito; ausência de assinatura isolada não é
  malware; sem `pefile` a análise é limitada; arquivos em uso podem ser pulados.
- **Processos:** alguns campos exigem administrador; nome pode ser falsificado; CPU/RAM isolados nunca
  são evidência.
- **Rede:** porta incomum é indicador fraco; conexões podem não ser visíveis sem privilégio.
- **Mineradores:** CPU/GPU só contam com outra família; amostragem curta.
- **Inicialização/Registro:** análise somente leitura por padrão; correções limitadas por allowlist e
  podem exigir administrador; ACLs em modo *best effort*.
- **Defender:** depende do PowerShell/Defender; outro antivírus pode estar ativo; consultas podem ser
  restritas.
- **Limpeza:** conservadora por projeto; prefere deixar resíduos a arriscar arquivos do usuário.
- **Assinaturas:** apenas arquitetura proposta; não há lista, download ou verificação implementada.

---

## 9. Classificação das funcionalidades

| Funcionalidade | Classificação | Observação |
|---|---|---|
| Criptografia AES-256-GCM + AAD | **Validada em teste** | Testes de adulteração, troca e truncamento |
| Embrulho de chave com DPAPI | **Validada em teste** | Roundtrip e AAD; depende do usuário Windows |
| Chave mestra com ACL/modo restritivo | **Validada em teste + falha fechada** | Não validada em domínio/GPO |
| Quarentena *write-ahead* | **Validada em teste** | Inclui falhas e recuperação |
| Restauração com verificação e backup | **Validada em teste** | Inclui interrupção e destino somente-leitura |
| Exclusão definitiva | **Validada em teste** | Exige confirmação; recuperação de interrupção |
| Migração de item legado | **Validada em teste** | XOR legado |
| Análise de arquivos/PE | **Parcial** | Heurística; `pefile` opcional; não é veredito |
| Varredura paralela/incremental | **Parcial** | Testada em unidade; volumes grandes não validados |
| Análise de processos | **Parcial** | Testes com fakes; integração real pendente |
| Encerramento de processos | **Parcial** | Confirmação, críticos e `create_time`; janela de corrida residual |
| Análise de rede | **Parcial** | Depende de privilégio e DNS |
| Detecção de mineradores | **Parcial** | Multi-indicador; janela curta |
| Inicialização (Run/Startup/serviços/tarefas) | **Parcial** | Mocks; validação real pendente |
| Registro | **Parcial** | Fake nos testes; escrita real não exercitada |
| Defender | **Parcial** | Somente leitura; validação real pendente |
| Limpeza | **Parcial/conservadora** | Allowlist e idade mínima; não validada em volume real |
| Correlação de achados | **Parcial** | Testada em unidade |
| Interface gráfica | **Não iniciada** | Fora do escopo |
| Executável | **Não iniciado** | Fora do escopo |
| Assinaturas | **Apenas proposta** | Sem download, lista ou hash real |

Legenda:
- **Validada em teste:** comportamento coberto por testes automatizados no ambiente atual.
- **Parcial:** lógica coberta, mas falta validação manual/integração real.
- **Não iniciada / apenas proposta:** não faz parte desta entrega.

---

## 10. Conclusão

A Etapa 2.2 foi concluída no que diz respeito a:

- fechar as falhas P0 de quarentena/criptografia;
- corrigir os problemas encontrados nos analisadores;
- ampliar a suíte para 145 testes, com cobertura Windows e de falhas;
- organizar dependências, `.gitignore` e documentação;
- registrar riscos, limitações e a proposta de assinaturas.

**O projeto é executável como núcleo e a suíte passa, mas não está pronto para uso real.** Antes de
qualquer uso em produção ou de limpezas amplas, são necessários:

1. validação manual em VM Windows 10/11 descartável, com e sem administrador;
2. validação real de Registro, serviços, tarefas e Defender em ambiente controlado;
3. teste com disco cheio real, arquivo bloqueado e symlink com privilégio;
4. revisão de desempenho em volumes grandes e unidades de rede/nuvem;
5. revisão humana dos achados antes de qualquer ação destrutiva.

Nenhum commit foi feito. As alterações estão no working tree para revisão.
