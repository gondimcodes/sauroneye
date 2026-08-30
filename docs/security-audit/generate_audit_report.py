#!/usr/bin/env python3
"""
Script de Geração do Relatório Executivo de Auditoria de Segurança do SauronEye
Gera documento PDF formatado em pt-BR com gráficos e issues para GitHub prontas.
"""

import os
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.pdfgen import canvas

# Paleta de Cores Estrita
C_CRITICA = colors.HexColor('#B91C1C')
C_ALTA = colors.HexColor('#EA580C')
C_MEDIA = colors.HexColor('#D97706')
C_BAIXA = colors.HexColor('#2563EB')
C_FORTE = colors.HexColor('#059669')
C_DARK = colors.HexColor('#0F172A')
C_BG_HEADER = colors.HexColor('#1E293B')
C_BG_ROW = colors.HexColor('#F8FAFC')
C_BG_CARD = colors.HexColor('#F1F5F9')
C_BORDER = colors.HexColor('#CBD5E1')

def generate_charts(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Gráfico de Rosca por Severidade
    labels_sev = ['Média', 'Baixa', 'Informativa']
    counts_sev = [1, 2, 2] # Total 5 achados
    colors_sev = ['#D97706', '#2563EB', '#64748B']
    
    fig, ax = plt.subplots(figsize=(4.5, 3.5), subplot_kw=dict(aspect="equal"))
    wedges, texts, autotexts = ax.pie(
        counts_sev,
        labels=labels_sev,
        autopct='%1.0f%%',
        pctdistance=0.75,
        colors=colors_sev,
        startangle=140,
        textprops=dict(color="#0F172A", fontsize=9, weight="bold")
    )
    for at in autotexts:
        at.set_color('white')
        at.set_fontsize(10)
    
    # Círculo central para transformar em rosca
    centre_circle = plt.Circle((0, 0), 0.55, fc='white')
    fig.gca().add_artist(centre_circle)
    ax.set_title("Achados por Severidade", fontsize=11, weight='bold', pad=10, color="#0F172A")
    plt.tight_layout()
    donut_path = os.path.join(output_dir, 'chart_donut_severity.png')
    plt.savefig(donut_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    # 2. Gráfico de Barras por Categoria
    categories = [
        '1. Banco/Isolam.',
        '2. Gates/Perm.',
        '3. IDOR',
        '4. Segredos/Hardcode',
        '5. Inputs/Sanitiz.'
    ]
    counts_cat = [0, 1, 0, 2, 2]
    colors_bar = ['#059669', '#2563EB', '#059669', '#D97706', '#2563EB']
    
    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    bars = ax.barh(categories, counts_cat, color=colors_bar, height=0.55)
    ax.set_xlim(0, 3)
    ax.set_xlabel("Número de Achados", fontsize=9, weight='bold', color="#0F172A")
    ax.set_title("Distribuição por Categoria de Auditoria", fontsize=11, weight='bold', pad=10, color="#0F172A")
    ax.grid(axis='x', linestyle='--', alpha=0.5)
    
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.08, bar.get_y() + bar.get_height()/2, f'{int(w)}',
                ha='left', va='center', fontsize=9, weight='bold', color="#0F172A")
        
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    bar_path = os.path.join(output_dir, 'chart_bar_categories.png')
    plt.savefig(bar_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return donut_path, bar_path

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Não desenha header na página 1 (capa)
        if self._pageNumber > 1:
            self.drawString(20 * mm, 287 * mm, "SauronEye — Relatório de Auditoria de Segurança")
            self.drawRightString(190 * mm, 287 * mm, "CONFIDENCIAL — USO INTERNO")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(20 * mm, 284 * mm, 190 * mm, 284 * mm)
            
        # Rodapé em todas as páginas
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(20 * mm, 15 * mm, 190 * mm, 15 * mm)
        self.drawString(20 * mm, 10 * mm, "Gerado automaticamente pelo Motor de Auditoria Antigravity")
        self.drawRightString(190 * mm, 10 * mm, f"Página {self._pageNumber} de {page_count}")
        self.restoreState()

def build_pdf(pdf_path):
    output_dir = os.path.dirname(pdf_path)
    donut_img, bar_img = generate_charts(output_dir)
    
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=20*mm,
        rightMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=C_DARK,
        alignment=0
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#475569")
    )
    
    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=C_DARK,
        spaceBefore=12,
        spaceAfter=6
    )
    
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=C_DARK,
        spaceBefore=8,
        spaceAfter=4
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=C_DARK
    )
    
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    story = []
    
    # ==================== CAPA ====================
    story.append(Spacer(1, 15*mm))
    story.append(Paragraph("Relatório de Auditoria de Segurança", title_style))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("<b>Projeto:</b> SauronEye Sentinel (v1.0.0) — High Performance Real-Time FIM Daemon", subtitle_style))
    story.append(Paragraph("<b>Data da Auditoria:</b> 30 de Agosto de 2026", subtitle_style))
    story.append(Paragraph("<b>Autor:</b> Marcelo Gondim &lt;gondim@ispfocus.net.br&gt;", subtitle_style))
    story.append(Spacer(1, 6*mm))
    
    # Meta Box
    meta_data = [
        [Paragraph("<b>Stack Detectada:</b>", body_style), Paragraph("Rust 1.75+ (Edition 2021), Tokio Async, SQLite3 (rusqlite / WAL), Argon2id, Notify/inotify, printpdf 0.12.5, lettre 0.11", body_style)],
        [Paragraph("<b>Arquitetura:</b>", body_style), Paragraph("Daemon / CLI Standalone de Alta Performance com privilégio de Root. Sem servidor web HTTP embutido e sem frontend SPA/HTML.", body_style)],
        [Paragraph("<b>Escopo Auditado:</b>", body_style), Paragraph("100% dos módulos fonte em <code>src/</code> (analyzer, auth, cli, db, fim, notifier, rce_detect, report, main.rs, config.rs, config.toml.example).", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[35*mm, 135*mm])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_BG_CARD),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 6*mm))
    
    # Nota Metodológica
    story.append(Paragraph("<b>Nota Metodológica e Mapeamento para a Stack Rust/CLI:</b>", h2_style))
    story.append(Paragraph(
        "Como o <b>SauronEye</b> é um daemon/CLI em Rust de segurança para servidores Linux (sem interface web/HTTP), cada uma das cinco categorias foi rigorosamente adaptada para o equivalente nativo da stack:<br/>"
        "<b>1. Banco Sem Tranca (Isolamento):</b> Avaliado o controle de inicialização do SQLite (One-Time Init guard), prevenção de sobrescrita acidental e proteção do esquema local <code>admin_users</code> / <code>audit_logs</code>.<br/>"
        "<b>2. Permissão Definida no Navegador (Gates de CLI/Admin):</b> Mapeado para a verificação de autenticação Argon2id nas operações administrativas de CLI (<code>--init</code>, <code>--update</code>, <code>logs --purge</code>, <code>report</code>) versus chamadas diretas.<br/>"
        "<b>3. IDOR:</b> Mapeado para comandos de CLI e métodos que consultam ou removem registros do banco SQLite (filtros de tempo e integridade das chaves primárias).<br/>"
        "<b>4. Chaves Expostas (Hardcode/Defaults):</b> Mapeado para senhas padrão de inicialização, tokens embutidos de Telegram/WhatsApp/SMTP e tratamento de variáveis de configuração.<br/>"
        "<b>5. Inputs Sem Tratamento (Sanitização/XSS/Injeção):</b> Mapeado para sanitização de strings em relatórios PDF (printpdf), escape de comandos em alertas Telegram/WhatsApp e injeção de caracteres de controle em headers de e-mail SMTP.",
        body_style
    ))
    
    story.append(PageBreak())
    
    # ==================== RESUMO EXECUTIVO ====================
    story.append(Paragraph("1. Resumo Executivo", h1_style))
    story.append(Paragraph(
        "A auditoria de código-fonte identificou que o <b>SauronEye</b> possui uma arquitetura robusta e segura em Rust, "
        "com uso exemplar de <b>Argon2id</b> com salt criptográfico para senhas locais, transações atômicas ACID no SQLite com WAL, "
        "e isolamento estrito contra tampering. Nenhuma vulnerabilidade Crítica ou de Execução Remota de Código foi encontrada. "
        "Foram registrados <b>5 apontamentos</b> (0 Críticos, 0 Altos, 1 Médio, 2 Baixos, 2 Informativos), com foco em hardening de permissões locais e validação de inicialização.",
        body_style
    ))
    story.append(Spacer(1, 4*mm))
    
    # Tabela com Gráficos lado a lado
    chart_table = Table([[
        Image(donut_img, width=70*mm, height=54*mm),
        Image(bar_img, width=85*mm, height=54*mm)
    ]], colWidths=[75*mm, 95*mm])
    chart_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(chart_table)
    story.append(Spacer(1, 4*mm))
    
    # ==================== PONTOS FORTES E FRACOS ====================
    story.append(Paragraph("2. Pontos Fortes e Pontos de Atenção", h1_style))
    
    pf_data = [
        [Paragraph("<b>PONTOS FORTES AUDITADOS (VERIFICADOS)</b>", ParagraphStyle('PFH', parent=body_style, textColor=colors.white, fontName='Helvetica-Bold')),
         Paragraph("<b>PONTOS DE ATENÇÃO / HARDENING</b>", ParagraphStyle('PAH', parent=body_style, textColor=colors.white, fontName='Helvetica-Bold'))],
        [Paragraph(
            "• <b>Autenticação Segura:</b> Hash de senha admin com Argon2id nativo e verificação em tempo constante.<br/>"
            "• <b>One-Time Init Guard:</b> Proteção rigorosa contra reinicialização maliciosa da base (src/main.rs:160).<br/>"
            "• <b>Prevenção de SQL Injection:</b> 100% das queries utilizam parâmetros preparados <code>params![]</code>.<br/>"
            "• <b>Sanitização de PDF:</b> Método <code>sanitize()</code> impede caracteres de controle e corrupção no <code>printpdf</code>.<br/>"
            "• <b>Imunidade a DoS de Memória:</b> Hashing em buffer streaming (64KB) com Blake3 / XxHash64.<br/>"
            "• <b>Tolerância a Falhas:</b> SQLite WAL com cache otimizado e flush em lote sem contenção de I/O.",
            body_style
        ),
         Paragraph(
             "• <b>Permissões de Arquivo SQLite:</b> O arquivo <code>sauron.db</code> herda a umask do processo ao invés de forçar <code>0600</code> estrito.<br/>"
             "• <b>Comandos CLI Informativos sem Auth:</b> <code>sauroneye status</code> exibe caminhos protegidos e configurações sem pedir senha.<br/>"
             "• <b>Exclusão de Feedback Loop:</b> Exclusão de PDFs gerados por nome parcial <code>sauroneye_report</code> no FIM.<br/>"
             "• <b>Validação de Senha em Runtime:</b> Ausência de rejeição em startup caso senha SMTP padrão venha de arquivo copiado sem edição.",
             body_style
         )]
    ]
    t_pf = Table(pf_data, colWidths=[85*mm, 85*mm])
    t_pf.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), C_FORTE),
        ('BACKGROUND', (1,0), (1,0), C_MEDIA),
        ('BACKGROUND', (0,1), (0,1), C_BG_ROW),
        ('BACKGROUND', (1,1), (1,1), C_BG_ROW),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_pf)
    
    story.append(PageBreak())
    
    # ==================== DETALHAMENTO DOS ACHADOS ====================
    story.append(Paragraph("3. Tabela Detalhada de Achados por Categoria", h1_style))
    story.append(Spacer(1, 2*mm))
    
    def badge(sev_text, bg_color):
        return Paragraph(f"<b>{sev_text}</b>", ParagraphStyle('Badge', parent=body_style, textColor=colors.white, alignment=1))

    achados_table_data = [
        [Paragraph("<b>Sev.</b>", ParagraphStyle('TH', parent=body_style, textColor=colors.white, fontName='Helvetica-Bold')),
         Paragraph("<b>Categoria / Arquivo:Linha</b>", ParagraphStyle('TH', parent=body_style, textColor=colors.white, fontName='Helvetica-Bold')),
         Paragraph("<b>Descrição do Achado e Impacto</b>", ParagraphStyle('TH', parent=body_style, textColor=colors.white, fontName='Helvetica-Bold'))]
    ]

    # Achado 1
    achados_table_data.append([
        badge("MÉDIA", C_MEDIA),
        Paragraph("<b>4. Hardcode / Permissões</b><br/><code>src/db/sqlite.rs:26</code>", body_style),
        Paragraph("<b>Criação de banco de dados SQLite sem permissão POSIX 0600 restritiva:</b><br/>O banco <code>sauron.db</code> armazena o hash Argon2id do admin e todo o histórico forense. Se criado com umask padrão de sistema (ex: 022), outros usuários locais sem privilégio de root poderiam ler o banco.", body_style)
    ])
    
    # Achado 2
    achados_table_data.append([
        badge("BAIXA", C_BAIXA),
        Paragraph("<b>2. Gates de Permissão</b><br/><code>src/main.rs:239</code>", body_style),
        Paragraph("<b>Comando <code>sauroneye status</code> expõe paths monitorados sem autenticação:</b><br/>Enquanto <code>update</code>, <code>logs</code> e <code>report</code> exigem senha admin, o comando <code>status</code> lista os diretórios e algoritmo de hash configurados para qualquer usuário que execute o binário.", body_style)
    ])
    
    # Achado 3
    achados_table_data.append([
        badge("BAIXA", C_BAIXA),
        Paragraph("<b>4. Segredos / Validação</b><br/><code>src/config.rs:148</code>", body_style),
        Paragraph("<b>Ausência de validação de startup contra credenciais de exemplo:</b><br/>Se o operador esquecer o valor de exemplo <code>SECRET_PASSWORD</code> no <code>config.toml</code>, o daemon tenta autenticação com credencial inválida sem abortar com erro claro em tempo de boot.", body_style)
    ])
    
    # Achado 4
    achados_table_data.append([
        badge("INFO", colors.HexColor("#64748B")),
        Paragraph("<b>5. Inputs / Sanitização</b><br/><code>src/analyzer/mod.rs:90</code>", body_style),
        Paragraph("<b>Formatação de linha de comando em alertas com quebras de linha cruas:</b><br/>Comandos longos executados por atacantes com caracteres especiais são inseridos diretamente em mensagens de texto. Embora seguro em texto puro, pode alterar visualmente logs no terminal.", body_style)
    ])

    # Achado 5
    achados_table_data.append([
        badge("INFO", colors.HexColor("#64748B")),
        Paragraph("<b>1. Banco / Isolamento</b><br/><code>src/db/schema.rs:18</code>", body_style),
        Paragraph("<b>Monotenant Local com chave fixa 'admin':</b><br/>A tabela <code>admin_users</code> suporta apenas um registro (usuário <code>admin</code>). O isolamento atende ao propósito de daemon de servidor único, mas impede múltiplos operadores com credenciais individuais.", body_style)
    ])

    t_achados = Table(achados_table_data, colWidths=[18*mm, 45*mm, 107*mm])
    t_achados.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_BG_HEADER),
        ('BACKGROUND', (0,1), (0,1), C_MEDIA),
        ('BACKGROUND', (0,2), (0,2), C_BAIXA),
        ('BACKGROUND', (0,3), (0,3), C_BAIXA),
        ('BACKGROUND', (0,4), (0,4), colors.HexColor("#64748B")),
        ('BACKGROUND', (0,5), (0,5), colors.HexColor("#64748B")),
        ('BACKGROUND', (1,1), (-1,1), C_BG_ROW),
        ('BACKGROUND', (1,2), (-1,2), colors.white),
        ('BACKGROUND', (1,3), (-1,3), C_BG_ROW),
        ('BACKGROUND', (1,4), (-1,4), colors.white),
        ('BACKGROUND', (1,5), (-1,5), C_BG_ROW),
        ('BOX', (0,0), (-1,-1), 1, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_achados)
    story.append(Spacer(1, 6*mm))
    
    # ==================== RECOMENDAÇÕES PRIORIZADAS ====================
    story.append(Paragraph("4. Recomendações Priorizadas", h1_style))
    recs = [
        "<b>P1 (Imediata):</b> Adicionar ajuste de permissões <code>std::os::unix::fs::PermissionsExt::set_mode(0o600)</code> no arquivo <code>sauron.db</code> e diretório pai <code>0o700</code> logo após a criação em <code>Database::open</code>.",
        "<b>P2 (Curto Prazo):</b> Implementar autenticação admin ou restrição de exibição para o comando <code>sauroneye status</code>, evitando enumeração local de paths vigiados por usuários não privilegiados.",
        "<b>P3 (Médio Prazo):</b> Adicionar validação em <code>Config::load_from_file</code> para emitir warning ou erro caso segredos contenham valores de placeholder (<code>SECRET_PASSWORD</code>, <code>YOUR_API_KEY_HERE</code>)."
    ]
    for r in recs:
        story.append(Paragraph(f"• {r}", body_style))
        story.append(Spacer(1, 2*mm))

    story.append(PageBreak())
    
    # ==================== ISSUES PARA O GITHUB ====================
    story.append(Paragraph("5. Issues Prontas para o GitHub", h1_style))
    story.append(Paragraph("Abaixo estão os modelos completos em formato Markdown prontos para inclusão no issue tracker do projeto:", body_style))
    story.append(Spacer(1, 4*mm))
    
    issues_text = [
        ("--- ISSUE 1 ---",
         "[Segurança] Forçar permissões POSIX 0600 na criação da base SQLite sauron.db",
         "security, priority/medium, hardening",
         "Ao criar o arquivo de banco de dados SQLite (`sauron.db`) e seu diretório pai `/var/lib/sauroneye`, o sistema utiliza as permissões herdadas da `umask` da sessão do processo atual. Se a umask for permissiva (ex: `0022`), o banco de dados forense contendo o hash Argon2id do admin e os registros de incidentes pode ser lido por usuários locais não-root.",
         "src/db/sqlite.rs:23-26",
         "std::fs::create_dir_all(parent)?;\nlet conn = Connection::open(path_ref)?;",
         "Possível vazamento de logs de auditoria e hashes de credenciais locais para usuários sem privilégio no host.",
         "Utilizar `std::os::unix::fs::PermissionsExt` para aplicar modo `0o700` no diretório e `0o600` no arquivo `sauron.db` imediatamente após sua criação.",
         "- [ ] Diretório pai `/var/lib/sauroneye` criado com permissão 0700.\n- [ ] Arquivo `sauron.db` e seus arquivos WAL/SHM ajustados para 0600.\n- [ ] Teste unitário/integrado verificando permissões no Linux."),

        ("--- ISSUE 2 ---",
         "[Segurança] Exigir autenticação ou restringir saídas no comando CLI 'status'",
         "security, priority/low",
         "O comando `sauroneye status` exibe a lista completa de diretórios monitorados, caminho do banco e algoritmo de hash sem solicitar a senha do administrador, permitindo que usuários locais descubram quais diretórios não estão sob vigilância do FIM.",
         "src/main.rs:239-256",
         "fn handle_status(config: &Config, db: &Database) -> Result<(), ...> {\n    println!(\"Monitored Directories: {:?}\", config.fim.include_paths);",
         "Enumeração de superfície de ataque local (usuário descobre pontos cegos no FIM).",
         "Exigir chamada a `authenticate_admin(db)?` antes de detalhar include_paths no status ou limitar a saída de status básico se não autenticado.",
         "- [ ] `sauroneye status` solicita autenticação antes de expor paths de segurança.\n- [ ] Sem auth, exibe apenas se o daemon está inicializado e versão.")
    ]

    for sep, title, labels, desc, file_line, code, impact, fix, criteria in issues_text:
        issue_box = [
            [Paragraph(f"<b>{sep}</b>", ParagraphStyle('IBH', parent=body_style, textColor=colors.HexColor("#2563EB"), fontName='Helvetica-Bold'))],
            [Paragraph(f"<b>Título:</b> {title}", body_style)],
            [Paragraph(f"<b>Labels:</b> <code>{labels}</code>", body_style)],
            [Paragraph(f"<b>Descrição:</b> {desc}", body_style)],
            [Paragraph(f"<b>Evidência ({file_line}):</b>", body_style)],
            [Paragraph(f"<font face='Courier' size='7'>{code.replace(chr(10), '<br/>')}</font>", code_style)],
            [Paragraph(f"<b>Impacto:</b> {impact}", body_style)],
            [Paragraph(f"<b>Correção Recomendada:</b> {fix}", body_style)],
            [Paragraph(f"<b>Critérios de Aceite:</b><br/>{criteria.replace(chr(10), '<br/>')}", body_style)],
            [Paragraph("<b>--- FIM ISSUE ---</b>", ParagraphStyle('IBF', parent=body_style, textColor=colors.HexColor("#64748B"), fontName='Helvetica-Bold'))]
        ]
        t_issue = Table(issue_box, colWidths=[170*mm])
        t_issue.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_BG_CARD),
            ('BOX', (0,0), (-1,-1), 1, C_BORDER),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_issue)
        story.append(Spacer(1, 4*mm))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Relatório PDF gerado com sucesso em: {pdf_path}")

if __name__ == '__main__':
    target_pdf = sys.argv[1] if len(sys.argv) > 1 else 'docs/security-audit/relatorio-auditoria-seguranca.pdf'
    build_pdf(target_pdf)
