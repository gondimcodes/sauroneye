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

    writer.text_at("TIMESTAMP (UTC)", 7.5, MARGIN, true);
    writer.text_at("ACTION / SEVERITY", 7.5, MARGIN + 38.0, true);
    writer.text_at("ACTOR / IP", 7.5, MARGIN + 85.0, true);
    writer.text_at("DETAILS / FILE PATH", 7.5, MARGIN + 125.0, true);
    writer.y -= 4.0;

    for entry in logs {
        writer.ensure_space(6.0);

        let ts_str = Utc
            .timestamp_opt(entry.timestamp, 0)
            .single()
            .map(|d: DateTime<Utc>| d.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let action_clean = sanitize(&entry.action);
        let actor_clean = sanitize(&entry.actor);

        let details_first_line = entry.details.lines().next().unwrap_or("").trim();
        let details_clean = sanitize(details_first_line);
        let details_short: String = details_clean.chars().take(40).collect();

        writer.text_at(&ts_str, 7.0, MARGIN, false);
        writer.text_at(&action_clean, 7.0, MARGIN + 38.0, false);
        writer.text_at(&actor_clean, 7.0, MARGIN + 85.0, false);
        writer.text_at(&details_short, 7.0, MARGIN + 125.0, false);
        writer.y -= 4.2;
    }

    let mut warnings = Vec::new();
    let bytes = writer.doc.save(&PdfSaveOptions::default(), &mut warnings);
    std::fs::write(output_path, bytes)?;

    Ok(())
}
