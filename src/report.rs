// src/report.rs

use genpdf::{elements, Alignment, Document, Element, SimplePageDecorator};
use std::error::Error;
use std::io::Cursor;
// use genpdf::{elements, fonts, Alignment, Document, Element, SimplePageDecorator};

use crate::dto::AuditReport;

pub fn generate_pdf(dossier: &[AuditReport], output_filename: &str) -> Result<(), Box<dyn Error>> {
    // 1. Embed Fonts directly into the executable memory at compile time
    let font_family = genpdf::fonts::FontFamily {
        regular: genpdf::fonts::FontData::new(
            include_bytes!("../assets/fonts/Roboto-Regular.ttf").to_vec(),
            None,
        )
        .expect("Failed to embed Regular font"),
        bold: genpdf::fonts::FontData::new(
            include_bytes!("../assets/fonts/Roboto-Bold.ttf").to_vec(),
            None,
        )
        .expect("Failed to embed Bold font"),
        italic: genpdf::fonts::FontData::new(
            include_bytes!("../assets/fonts/Roboto-Italic.ttf").to_vec(),
            None,
        )
        .expect("Failed to embed Italic font"),
        bold_italic: genpdf::fonts::FontData::new(
            include_bytes!("../assets/fonts/Roboto-BoldItalic.ttf").to_vec(),
            None,
        )
        .expect("Failed to embed BoldItalic font"),
    };

    let mut doc = Document::new(font_family);
    doc.set_title("Transvina IPv6 Readiness Audit");

    let mut decorator = SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);
    doc.set_paper_size(genpdf::PaperSize::A4);

    // 2. Embed the Logo directly into the executable
    let logo_bytes = include_bytes!("../assets/logo.jpg");

    // Use a Cursor to read the embedded bytes in memory
    match elements::Image::from_reader(Cursor::new(logo_bytes)) {
        Ok(logo) => {
            doc.push(logo.with_alignment(Alignment::Center));
            doc.push(elements::Break::new(1));
        }
        Err(e) => {
            tracing::error!("❌ Embedded PDF Logo failed to load: {}", e);
        }
    }

    // 3. Document Header
    doc.push(
        elements::Paragraph::new("Transvina Edge Shield")
            .aligned(Alignment::Center)
            .styled(genpdf::style::Style::new().bold().with_font_size(24)),
    );

    // ... continue with your existing headers and table layout ...

    doc.push(
        elements::Paragraph::new("Enterprise IPv6 Readiness Audit")
            .aligned(Alignment::Center)
            .styled(genpdf::style::Style::new().italic().with_font_size(14)),
    );
    doc.push(elements::Break::new(2));

    // 4. Adjusted Table Layout Ratios for Portrait mode
    // We give the final diagnosis column more relative width (8) to prevent wrapping
    let mut table = elements::TableLayout::new(vec![4, 2, 2, 2, 8]);
    table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));

    // Render Table Headers
    let headers = vec![
        "Target Domain",
        "Web IPv6",
        "MX IPv6",
        "NS IPv6",
        "Executive Diagnosis",
    ];
    let mut header_row = table.row();
    for head in headers {
        header_row.push_element(
            elements::Paragraph::new(head)
                .styled(genpdf::style::Style::new().bold())
                .padded(2),
        );
    }
    header_row.push().expect("Invalid table header row");

    // Populate Rows from the Dossier
    for record in dossier {
        let mut row = table.row();

        row.push_element(elements::Paragraph::new(&record.domain).padded(2));

        let web_status = if record.web_ipv6_ready && record.web_ipv6_reachable {
            "PASS"
        } else if record.web_ipv6_ready {
            "DNS ONLY"
        } else {
            "FAIL"
        };
        row.push_element(elements::Paragraph::new(web_status).padded(2));

        row.push_element(
            elements::Paragraph::new(if record.mx_ipv6_ready { "PASS" } else { "FAIL" }).padded(2),
        );
        row.push_element(
            elements::Paragraph::new(if record.ns_ipv6_ready { "PASS" } else { "FAIL" }).padded(2),
        );
        row.push_element(elements::Paragraph::new(&record.vulnerability_status).padded(2));

        row.push().expect("Invalid table data row");
    }

    // Now push the fully populated table
    doc.push(table);

    // The correct genpdf Break element
    doc.push(elements::Break::new(2));

    doc.push(
        elements::Paragraph::new(
            "CONFIDENTIAL REPORT - Generated dynamically by the Transvina IPv6-Audit Engine.",
        )
        .aligned(Alignment::Right)
        .styled(genpdf::style::Style::new().italic().with_font_size(9)),
    );

    doc.render_to_file(output_filename)?;

    Ok(())
}

// =====================================================================
// TIER-3 BLACK-BOX INTEGRATION TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_pdf_generation_creates_valid_file() {
        // 1. Arrange dummy data
        let mut dummy = AuditReport::new_failed("test-domain.vn".to_string());
        dummy.synthesize_diagnosis();
        let dossier = vec![dummy];
        let test_file = "test_audit_output.pdf";

        // 2. Execute the Tier-3 edge integration
        let result = generate_pdf(&dossier, test_file);
        assert!(result.is_ok());

        // 3. Verify the file exists and has content (not an empty 0-byte shell)
        let metadata = fs::metadata(test_file).expect("PDF file was not created");
        assert!(metadata.len() > 1000);

        // 4. Cleanup
        fs::remove_file(test_file).unwrap();
    }
}
