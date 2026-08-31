use chrono::{DateTime, TimeZone, Utc};
use printpdf::*;
use std::error::Error;
use std::path::Path;

use crate::db::AuditLogEntry;

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN: f32 = 15.0;

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii() && !c.is_control() {
                c
            } else {
                ' '
            }
        })
        .collect()
}

struct PdfReportWriter {
    doc: PdfDocument,
    page_index: usize,
    y: f32,
}

impl PdfReportWriter {
    fn new(title: &str) -> Self {
        let mut doc = PdfDocument::new(title);
        doc.pages.push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), vec![]));
        Self {
            doc,
            page_index: 0,
            y: PAGE_H - MARGIN,
        }
    }

    fn new_page(&mut self) {
        self.doc
            .pages
            .push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), vec![]));
        self.page_index = self.doc.pages.len() - 1;
        self.y = PAGE_H - MARGIN;
    }

    fn ensure_space(&mut self, needed_mm: f32) {
        if self.y - needed_mm < (MARGIN + 12.0) {
            self.new_page();
        }
    }

    fn text_at(&mut self, text: &str, size: f32, x: f32, bold: bool) {
        let font = if bold {
            PdfFontHandle::Builtin(BuiltinFont::HelveticaBold)
        } else {
            PdfFontHandle::Builtin(BuiltinFont::Helvetica)
        };
        let page = &mut self.doc.pages[self.page_index];
        page.ops.push(Op::StartTextSection);
        page.ops.push(Op::SetTextCursor {
            pos: Point::new(Mm(x), Mm(self.y)),
        });
        page.ops.push(Op::SetFont {
            font,
            size: Pt(size),
        });
        page.ops.push(Op::ShowText {
            items: vec![TextItem::Text(sanitize(text))],
        });
        page.ops.push(Op::EndTextSection);
    }

    fn hline(&mut self, y: f32, start_x: f32, end_x: f32) {
        let page = &mut self.doc.pages[self.page_index];
        let line = Line {
            points: vec![
                LinePoint {
                    p: Point::new(Mm(start_x), Mm(y)),
                    bezier: false,
                },
                LinePoint {
                    p: Point::new(Mm(end_x), Mm(y)),
                    bezier: false,
                },
            ],
            is_closed: false,
        };
        page.ops.push(Op::DrawLine { line });
    }

    fn vline(&mut self, x: f32, start_y: f32, end_y: f32) {
        let page = &mut self.doc.pages[self.page_index];
        let line = Line {
            points: vec![
                LinePoint {
                    p: Point::new(Mm(x), Mm(start_y)),
                    bezier: false,
                },
                LinePoint {
                    p: Point::new(Mm(x), Mm(end_y)),
                    bezier: false,
                },
            ],
            is_closed: false,
        };
        page.ops.push(Op::DrawLine { line });
    }

    fn draw_row_box(
        &mut self,
        top_y: f32,
        bottom_y: f32,
        x_left: f32,
        x_right: f32,
        col_splits: &[f32],
    ) {
        // Linha superior e inferior
        self.hline(top_y, x_left, x_right);
        self.hline(bottom_y, x_left, x_right);
        // Bordas externas esquerda e direita
        self.vline(x_left, top_y, bottom_y);
        self.vline(x_right, top_y, bottom_y);
        // Divisores verticais de colunas
        for &x in col_splits {
            self.vline(x, top_y, bottom_y);
        }
    }
}

pub fn generate_pdf_report(
    hostname: &str,
    start_ts: i64,
    end_ts: i64,
    logs: &[AuditLogEntry],
    output_path: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut writer = PdfReportWriter::new(&format!("SauronEye Forensic Report — {}", hostname));

    // Header Title
    writer.text_at(
        "SAURONEYE — FORENSIC SECURITY AUDIT REPORT",
        13.0,
        MARGIN,
        true,
    );
    writer.y -= 5.5;

    let start_str = Utc
        .timestamp_opt(start_ts, 0)
        .single()
        .map(|d: DateTime<Utc>| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default();
    let end_str = Utc
        .timestamp_opt(end_ts, 0)
        .single()
        .map(|d: DateTime<Utc>| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default();
    let now_str = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    writer.text_at(
        &format!("Host: {}  |  Generated: {}", hostname, now_str),
        8.5,
        MARGIN,
        false,
    );
    writer.y -= 4.5;
    writer.text_at(
        &format!("Timeframe: From {} To {}", start_str, end_str),
        8.5,
        MARGIN,
        false,
    );
    writer.y -= 5.0;

    writer.hline(writer.y, MARGIN, PAGE_W - MARGIN);
    writer.y -= 7.0;

    // Summary Section
    let total_events = logs.len();
    let tampering_count = logs
        .iter()
        .filter(|l| l.action.contains("TAMPER") || l.action.contains("MODIFIED"))
        .count();
    let auth_count = logs
        .iter()
        .filter(|l| l.action.contains("AUTH") || l.action.contains("LOGIN"))
        .count();
    let rce_count = logs.iter().filter(|l| l.action.contains("RCE")).count();

    writer.text_at("EXECUTIVE AUDIT SUMMARY", 10.0, MARGIN, true);
    writer.y -= 4.5;

    let summary_text = format!(
        "Total Recorded Events: {}  |  Tampering Alerts: {}  |  Auth Events: {}  |  RCE Detections: {}",
        total_events, tampering_count, auth_count, rce_count
    );
    writer.text_at(&summary_text, 8.0, MARGIN, false);
    writer.y -= 7.0;

    // Table Section
    writer.text_at("CHRONOLOGICAL SECURITY AUDIT TRAIL", 10.0, MARGIN, true);
    writer.y -= 4.5;

    // Dimensões da tabela:
    // A4 = 210mm, margens = 15mm cada lado → 180mm de largura total (15mm a 195mm)
    let table_x_start = MARGIN; // 15.0
    let table_x_end = PAGE_W - MARGIN; // 195.0

    // Divisores verticais das colunas:
    // Col 0: 15.0  a 40.0  (25mm - Timestamp: texto ocupa 22mm)
    // Col 1: 40.0  a 71.0  (31mm - Action/Severity: texto ocupa até 28mm)
    // Col 2: 71.0  a 113.0 (42mm - Actor/IP: acomoda IPv6 completo de 8 hexadecatetos ou usuario [IPv6])
    // Col 3: 113.0 a 195.0 (82mm - Details / File Path: acomoda caminhos e hashes)
    let split_1 = MARGIN + 25.0; // 40.0
    let split_2 = MARGIN + 56.0; // 71.0
    let split_3 = MARGIN + 98.0; // 113.0
    let col_splits = [split_1, split_2, split_3];

    // Padding de texto dentro das células
    let pad_x = 1.5;
    let col_ts_text = table_x_start + pad_x;
    let col_action_text = split_1 + pad_x;
    let col_actor_text = split_2 + pad_x;
    let col_details_text = split_3 + pad_x;

    // Cabeçalho da Tabela
    let header_top_y = writer.y;
    let header_bottom_y = header_top_y - 6.0;

    writer.draw_row_box(
        header_top_y,
        header_bottom_y,
        table_x_start,
        table_x_end,
        &col_splits,
    );

    writer.y = header_top_y - 4.2;
    writer.text_at("TIMESTAMP (UTC)", 7.0, col_ts_text, true);
    writer.text_at("ACTION / SEVERITY", 7.0, col_action_text, true);
    writer.text_at("ACTOR / IP", 7.0, col_actor_text, true);
    writer.text_at("DETAILS / FILE PATH", 7.0, col_details_text, true);

    writer.y = header_bottom_y;

    const ACTOR_MAX_CHARS: usize = 28;
    const DETAILS_MAX_CHARS: usize = 58;

    for entry in logs {
        // Normaliza e limpa registros antigos do PURGE_LOGS se contiverem 'between X and Y'
        let mut raw_details = entry.details.replace('\n', " | ");
        if entry.action == "PURGE_LOGS" && raw_details.contains(" between ") {
            if let Some((prefix, _)) = raw_details.split_once(" between ") {
                raw_details = prefix.to_string();
            }
        }

        let details_full = sanitize(&raw_details);
        let d_chars: Vec<char> = details_full.chars().collect();

        let d_line1: String = d_chars.iter().take(DETAILS_MAX_CHARS).collect();
        let d_has_line2 = d_chars.len() > DETAILS_MAX_CHARS;
        let d_line2: String = if d_has_line2 {
            d_chars
                .iter()
                .skip(DETAILS_MAX_CHARS)
                .take(DETAILS_MAX_CHARS)
                .collect()
        } else {
            String::new()
        };

        let actor_clean = sanitize(&entry.actor);
        let actor_formatted = if actor_clean.contains(" [") && actor_clean.ends_with(']') {
            actor_clean
        } else if let Some((user, ip)) = actor_clean.split_once(":::") {
            format!("{} [::{}]", user, ip)
        } else if let Some((user, ip)) = actor_clean.split_once(':') {
            format!("{} [{}]", user, ip)
        } else if actor_clean.contains('.') || actor_clean.contains(':') {
            format!("[{}]", actor_clean)
        } else {
            actor_clean
        };

        let a_chars: Vec<char> = actor_formatted.chars().collect();
        let a_line1: String = a_chars.iter().take(ACTOR_MAX_CHARS).collect();
        let a_has_line2 = a_chars.len() > ACTOR_MAX_CHARS;
        let a_line2: String = if a_has_line2 {
            a_chars
                .iter()
                .skip(ACTOR_MAX_CHARS)
                .take(ACTOR_MAX_CHARS)
                .collect()
        } else {
            String::new()
        };

        let has_multiline = d_has_line2 || a_has_line2;
        let row_height = if has_multiline { 8.5 } else { 5.5 };

        // Garante espaço para a linha da tabela e redesenha o cabeçalho se pular de página
        if writer.y - row_height < (MARGIN + 10.0) {
            writer.new_page();
            writer.y -= 5.0;
            let h_top = writer.y;
            let h_bot = h_top - 6.0;
            writer.draw_row_box(h_top, h_bot, table_x_start, table_x_end, &col_splits);
            writer.y = h_top - 4.2;
            writer.text_at("TIMESTAMP (UTC)", 7.0, col_ts_text, true);
            writer.text_at("ACTION / SEVERITY", 7.0, col_action_text, true);
            writer.text_at("ACTOR / IP", 7.0, col_actor_text, true);
            writer.text_at("DETAILS / FILE PATH", 7.0, col_details_text, true);
            writer.y = h_bot;
        }

        let row_top_y = writer.y;
        let row_bottom_y = row_top_y - row_height;

        writer.draw_row_box(
            row_top_y,
            row_bottom_y,
            table_x_start,
            table_x_end,
            &col_splits,
        );

        let ts_str = Utc
            .timestamp_opt(entry.timestamp, 0)
            .single()
            .map(|d: DateTime<Utc>| d.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let action_clean = sanitize(&entry.action);

        writer.y = row_top_y - 4.0;
        writer.text_at(&ts_str, 6.8, col_ts_text, false);
        writer.text_at(&action_clean, 6.8, col_action_text, false);
        writer.text_at(&a_line1, 6.8, col_actor_text, false);
        writer.text_at(&d_line1, 6.8, col_details_text, false);

        if has_multiline {
            writer.y = row_top_y - 7.5;
            if a_has_line2 {
                writer.text_at(&a_line2, 6.8, col_actor_text, false);
            }
            if d_has_line2 {
                writer.text_at(&d_line2, 6.8, col_details_text, false);
            }
        }

        writer.y = row_bottom_y;
    }

    let mut warnings = Vec::new();
    let bytes = writer.doc.save(&PdfSaveOptions::default(), &mut warnings);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output_path, bytes)?;

    Ok(())
}
