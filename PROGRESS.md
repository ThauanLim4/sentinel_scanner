# PROGRESSO — Sentinel Scanner

Atualizado em: 2026-11-06
Etapa atual: **2.2 — hardening, correções e validação do núcleo**
Interface gráfica: **fora do escopo desta etapa**
Executável: **fora do escopo desta etapa**

## Estado real

- O núcleo é importável e executável no ambiente de desenvolvimento (Python 3.14, Windows).
- A suíte automatizada passa: **145 testes, OK (3 ignorados)** na última execução.
- Nenhum teste usa malware real, limpeza real do sistema, alteração real do Registro, de serviços,
  de tarefas agendadas ou de exclusões do Defender.
- O projeto **não** está pronto para uso real/produção. A validação em cenários reais e em uma
  matriz de Windows 10/11 com e sem administrador ainda é necessária.

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
- [ ] Implementação da GUI (etapa futura).
- [ ] Empacotamento em executável (etapa futura).
- [ ] Mecanismo de atualização de assinaturas (apenas proposto, não implementado).

## Próxima etapa recomendada

1. Validar manualmente o núcleo em VM Windows 10/11 descartável, com e sem administrador.
2. Revisar os tempos de varredura e a amostragem de CPU/GPU em hardware real.
3. Só então iniciar a GUI, consumindo a API do núcleo sem duplicar regras de segurança.
4. Definir e implementar o formato de assinaturas com assinatura digital e atualização segura,
   conforme a proposta do relatório.
