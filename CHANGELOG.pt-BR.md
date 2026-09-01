# Registro de Mudanças (Changelog)

Todas as mudanças notáveis do **SauronEye** serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

---

## [Em Desenvolvimento] - 1.0.7

### Corrigido
- **Detecção de Gerenciador de Pacotes Reescrita com Advisory Lock `flock()`**: Substituída a abordagem frágil de varredura de nomes de processos em `/proc/*/comm` por um teste de lock exclusivo não-bloqueante via `flock()` nos arquivos de trava canônicos de cada distribuição (`/var/lib/dpkg/lock-frontend`, `/var/lib/rpm/.rpm.lock`, `/var/lib/pacman/db.lck`, `/lib/apk/db/lock`, `/var/lib/zypp/zypp.lock`). Esse é o mecanismo idêntico ao utilizado pelos próprios `apt`, `dpkg`, `dnf`, `pacman` e `apk` para detectar execução concorrente. A abordagem anterior era suscetível a daemons do sistema em execução permanente (ex: `packagekitd`, `apt-cacher-ng`) cujos nomes de processo casavam parcialmente com a lista de detecção, causando supressão silenciosa de todos os alertas FIM. A nova abordagem é totalmente determinística, universal para qualquer gerenciador de pacotes e qualquer distribuição, e imune a colisões de nomes de processo.

---

## [1.0.6] - 2026-08-31

### Adicionado
- **Notificador de Webhook para Microsoft Teams**: Implementada integração nativa de alertas para o Microsoft Teams via Incoming Webhooks (Workflows) com Adaptive Cards v1.4, destaques visuais por severidade, conjuntos estruturados de fatos e Circuit Breaker anti-flood dedicado (limite de 20 alertas/minuto).
- **Notificador de Webhook para Discord**: Implementada integração nativa de alertas para o Discord via Incoming Webhooks com Rich Embeds estilizados (cores por severidade: Crítico vermelho, Atenção laranja, Info azul), suporte a customização de nome/avatar do bot e Circuit Breaker anti-flood dedicado (limite de 30 alertas/minuto).
- **Alerta de Segurança e Auditoria de IP na Limpeza de Logs (`sauroneye logs --purge`)**: Dispara um alerta para todos os canais de notificação configurados e grava o IP de origem do operador sempre que um administrador executa a limpeza/expurgo de registros da trilha de auditoria forense.
- **Rastreabilidade de IP Remoto em Ações Administrativas da CLI**: Todas as ações administrativas (`update`, `passwd`, `logs --purge`) agora capturam e registram a origem remota da sessão SSH ativa (`admin:IP`).
- **Vigilância Nativa e Imutável sobre `/etc/sauroneye`**: Adicionado monitoramento a nível de kernel das configurações do daemon.





---

## [1.0.5] - 2026-08-31


### Adicionado
- **Circuit Breaker Anti-Flood para WhatsApp**: Implementado disjuntor de proteção com janela deslizante de 60 segundos (limite de 10 alertas/minuto), supressão inteligente de rajadas e avisos consolidados de status (`Throttling Ativado` e `Alertas Retomados`), eliminando qualquer risco de banimento de número por spam na Meta.
- **Fila Assíncrona com Rate Limiting para Telegram e WhatsApp**: Implementado sistema de filas MPSC em background com controle de vazão (intervalo de 1,05s para Telegram e 1,2s para WhatsApp) e retry com backoff automático em respostas HTTP 429 (`retry_after`), eliminando erros de limite de requisições durante tempestades de eventos.
- **Supressão de Ruído no PAM**: Filtradas mensagens internas de abertura de sessão do `systemd-user:session`, evitando notificações de login redundantes e ruídos na trilha de auditoria.

---

## [1.0.4] - 2026-08-31


### Adicionado
- **Decodificação Completa de Sockets IPv6 (`/proc/net/tcp6`)**: Implementado algoritmo de decodificação de 128 bits para tabelas de sockets Linux `/proc/net/tcp6` convertendo para `std::net::Ipv6Addr`, garantindo rastreabilidade forense precisa de IPs remotos em conexões SSH e de rede via IPv6.

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
