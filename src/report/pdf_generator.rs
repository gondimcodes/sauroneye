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

    // Table Header
    writer.text_at("CHRONOLOGICAL SECURITY AUDIT TRAIL", 10.0, MARGIN, true);
    writer.y -= 5.5;

    // Colunas: A4 = 210mm, margens = 15mm cada lado → 180mm úteis (x vai de 15mm a 195mm)
    // Col 0: Timestamp (UTC)   → x = 15.0  (largura ~26mm)
    // Col 1: Action / Severity → x = 41.0  (largura ~37mm)
    // Col 2: Actor / IP        → x = 78.0  (largura ~45mm para acomodar IPv6 completo)
    // Col 3: Details / Path    → x = 123.0 (largura ~72mm até margem direita de 195mm)
    let col_ts = MARGIN; // 15.0
    let col_action = MARGIN + 26.0; // 41.0
    let col_actor = MARGIN + 63.0; // 78.0
    let col_details = MARGIN + 108.0; // 123.0

    writer.text_at("TIMESTAMP (UTC)", 7.5, col_ts, true);
    writer.text_at("ACTION / SEVERITY", 7.5, col_action, true);
    writer.text_at("ACTOR / IP", 7.5, col_actor, true);
    writer.text_at("DETAILS / FILE PATH", 7.5, col_details, true);
    writer.y -= 4.0;

    // Largura disponível para detalhes em mm (~72mm) a ~1.85 chars/mm em 7pt
    const DETAILS_MAX_CHARS: usize = 48;

    for entry in logs {
        writer.ensure_space(12.0);

        let ts_str = Utc
            .timestamp_opt(entry.timestamp, 0)
            .single()
            .map(|d: DateTime<Utc>| d.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let action_clean = sanitize(&entry.action);
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

        // Junta todas as linhas de detalhes em uma única string para exibição
        let details_full = sanitize(&entry.details.replace('\n', " | "));
        let chars: Vec<char> = details_full.chars().collect();

        let line1: String = chars.iter().take(DETAILS_MAX_CHARS).collect();
        let has_line2 = chars.len() > DETAILS_MAX_CHARS;
        let line2: String = if has_line2 {
            chars
                .iter()
                .skip(DETAILS_MAX_CHARS)
                .take(DETAILS_MAX_CHARS)
                .collect()
        } else {
            String::new()
        };

        writer.text_at(&ts_str, 7.0, col_ts, false);
        writer.text_at(&action_clean, 7.0, col_action, false);
        writer.text_at(&actor_formatted, 7.0, col_actor, false);
        writer.text_at(&line1, 7.0, col_details, false);

        if has_line2 {
            writer.y -= 4.0;
            writer.text_at(&line2, 7.0, col_details, false);
            writer.y -= 4.2;
        } else {
            writer.y -= 4.2;
        }
    }

    let mut warnings = Vec::new();
    let bytes = writer.doc.save(&PdfSaveOptions::default(), &mut warnings);
    std::fs::write(output_path, bytes)?;

    Ok(())
}
