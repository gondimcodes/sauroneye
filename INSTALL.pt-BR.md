# Guia de Instalação e Implantação — SauronEye 👁️

Este guia detalha o processo de compilação, configuração e implantação do **SauronEye** como um daemon de sistema seguro no Linux.

---

*Leia este guia em outros idiomas: [English](INSTALL.md) | [Português (Brasil)](INSTALL.pt-BR.md)*

---

## Pré-requisitos do Sistema

- **Kernel Linux:** Versão 5.4 ou superior (com suporte a `fanotify`, conectores `/proc` e interfaces Netlink).
- **Toolchain Rust:** Rust 1.75+ (`rustc` e `cargo`).
- **Bibliotecas de Compilação:** `build-essential`, `pkg-config`, `libssl-dev`, `curl` (ou equivalentes da distribuição).

### 1. Instalação das Dependências do Sistema

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y build-essential pkg-config libssl-dev curl

# RHEL / Rocky Linux / AlmaLinux
sudo dnf groupinstall -y "Development Tools" && sudo dnf install -y pkgconfig openssl-devel curl

# Alpine Linux
apk add build-base pkgconfig openssl-dev curl
```

### 2. Instalação do Rust Toolchain (via `rustup`)

Se o Rust ainda não estiver instalado no servidor, instale a toolchain estável oficial:

```bash
# Instalação automatizada do rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Carregar o ambiente do Rust na sessão atual do shell
source "$HOME/.cargo/env"

# Verificar instalação
rustc --version
cargo --version
```

---

## 1. Compilação do Binário Otimizado

Compile o binário estático para release em modo de alta performance:

```bash
cd sauroneye
cargo build --release
```

O binário final compilado estará em `target/release/sauroneye`.

---

## 2. Estrutura de Diretórios e Permissões

Crie os diretórios de execução padrão e instale o binário com permissões restritas:

```bash
# 1. Instalar o executável no path do sistema
sudo install -m 755 target/release/sauroneye /usr/local/bin/sauroneye

# 2. Criar diretórios de configuração e banco com permissões 700 (apenas root)
sudo mkdir -p /etc/sauroneye
sudo mkdir -p /var/lib/sauroneye
sudo chmod 700 /etc/sauroneye /var/lib/sauroneye

# 3. Copiar o template de configuração e restringir leitura (600)
sudo cp config.toml.example /etc/sauroneye/config.toml
sudo chmod 600 /etc/sauroneye/config.toml
```

---

## 3. Configurando o SauronEye

Edite o arquivo `/etc/sauroneye/config.toml` para ajustar os caminhos monitorados, hostname do servidor e credenciais de alerta (Telegram e WhatsApp):

```bash
sudo nano /etc/sauroneye/config.toml
```

---

## 4. Inicialização da Base (One-Time Init)

Execute a rotina inicial de setup para criar o banco de dados SQLite, definir a senha do administrador (com hash Argon2id) e registrar a baseline de integridade inicial:

```bash
sudo sauroneye --config /etc/sauroneye/config.toml init
```

> **Aviso de Segurança:** Após executado com sucesso, o comando `--init` é **bloqueado permanentemente** para prevenir reinicializações maliciosas. Recálculos da baseline após manutenções legítimas exigem o comando `sauroneye update` e a senha do administrador.

---

## 5. Configuração do Serviço no Systemd

Crie o arquivo de serviço em `/etc/systemd/system/sauroneye.service`:

```ini
[Unit]
Description=SauronEye — Sentinela de FIM em Tempo Real e Detecção de Intrusão
After=network.target auditd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sauroneye --config /etc/sauroneye/config.toml run
Restart=always
RestartSec=5s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

# Diretivas de Hardening e Blindagem
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/sauroneye
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Recarregue e inicialize o serviço:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sauroneye
sudo systemctl status sauroneye
```

---

## 6. Verificação de Saúde e Diagnóstico

Confirme que o sentinela está ativo e monitorando o sistema:

```bash
# Checar status da configuração e integridade via CLI
sudo sauroneye --config /etc/sauroneye/config.toml status

# Acompanhar logs em tempo real
sudo journalctl -u sauroneye -f
```
