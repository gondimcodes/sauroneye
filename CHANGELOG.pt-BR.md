# Registro de Mudanças (Changelog)

Todas as mudanças notáveis do **SauronEye** serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

---

## [1.0.3] - 2026-08-31

### Adicionado
- **Whitelist Granular de Comandos RCE (`allowed_cmd_patterns`)**: Implementado suporte a padrões e assinaturas personalizadas no `[rce_detector]` para autorizar comandos filhos legítimos (como verificações de saúde do Kong Gateway / OpenResty no ecossistema Supabase), mantendo proteção ativa em tempo real contra webshells e injeções maliciosas.

---

## [1.0.2] - 2026-08-31

### Adicionado
- **Comando de Troca de Senha do Administrador**: Adicionado o comando CLI `sauroneye passwd` permitindo aos operadores atualizar com segurança a senha do admin após validação da senha atual, recalculando novos hashes Argon2id com salt criptográfico de 128 bits.

---

## [1.0.1] - 2026-08-31

### Adicionado
- **Autodefesa e Proteção Nativa**: Monitoramento imutável no código de `/var/lib/sauroneye` e do diretório pai `/var/lib` contra remoção, alteração e movimentação, sem depender de entradas no `config.toml`.
- **Eventos Dedicados de Renomeação (`mv`)**: Criação de `FimEvent::FileRenamed` e `FimEvent::DirectoryRenamed` exibindo claramente os caminhos de origem (`From:`) e destino (`To:`) nos alertas.
- **Relatório PDF em Grade Estruturada (Grid)**: Reformulação da trilha de auditoria no PDF com bordas, divisores verticais de colunas, células delimitadas e repetição automática do cabeçalho em múltiplas páginas.
- **Suporte Completo a IPv6 Multilinha**: Expansão da coluna `ACTOR / IP` para 42mm no PDF com quebra automática em até 2 linhas para acomodar endereços IPv6 completos de 8 hexadecatetos e combinações `usuario [IPv6]`.
- **Deduplicação Global de Alertas**: Mecanismo thread-safe no `AlertDispatcher` para descartar notificações idênticas emitidas simultaneamente dentro de 2,5 segundos.
- **Aprimoramentos no Detector de RCE**:
  - Detecção flexível de processos cruzando o nome do comando (`comm`), caminho do executável (`/proc/PID/exe`) e linha de comando (`cmdline`).
  - Rastreamento e deduplicação de PIDs filhos para evitar repetição de alertas durante comandos de longa duração.

### Modificado
- **Auditoria Zero-Trust**: Remoção de filtros estáticos de editores do código-fonte; todas as exclusões de caminhos passam a ser 100% configuradas pelo operador via `config.toml`.
- **Filtro de Atualizações Legítimas no Relatório**: Respeito estrito à flag `package_manager.notify_legitimate_updates = false` no comando `logs` e na geração do PDF.
- **Limpeza nos Detalhes de Auditoria**: Simplificação dos registros `PURGE_LOGS`, exibindo apenas o total de registros expurgados.

---

## [1.0.0] - 2026-08-30

### Lançamento Inicial
- **FIM em Tempo Real**: Motor de monitoramento com `fanotify` e `inotify` utilizando hashing criptográfico BLAKE3 e XXH3.
- **Sentinela contra RCE e Anomalias de Processos**: Varredura em `/proc` para detecção de shells filhas não autorizadas spawnadas por daemons de rede (`nginx`, `apache2`, `php-fpm`, etc.).
- **Auditoria de Autenticação e Escalação de Privilégios**: Monitoramento PAM capturando logins bem-sucedidos, falhas e uso do `sudo`.
- **Notificador Multicanal**: Alertas instantâneos via Bot do Telegram, API do WhatsApp e Email SMTP com relatórios PDF anexados.
- **Armazenamento Forense em SQLite**: Banco de dados com WAL e autenticação administrativa protegida por argon2id.
- **Relatórios Corporativos em PDF**: Geração automatizada de relatórios periciais de segurança em PDF.
