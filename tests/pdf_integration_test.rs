// tests/pdf_integration_test.rs

use std::fs;
use tempfile::NamedTempFile;

use ipv6_audit::dto::AuditReport;
use ipv6_audit::report::generate_pdf;

#[test]
fn test_typst_pdf_generation_creates_valid_file() {
    // 1. Arrange dummy data
    let mut dummy = AuditReport::new_failed("test-domain.vn".to_string());
    dummy.synthesize_diagnosis();
    let dossier = vec![dummy];

    // 2. Safely provision an isolated temporary file to prevent cargo test race conditions
    let temp_pdf = NamedTempFile::new().expect("Failed to create temp file");
    let test_file_path = temp_pdf.path().to_str().expect("Invalid temp path");

    // 3. Execute the Tier-3 edge integration (Typst Engine)
    let result = generate_pdf(&dossier, test_file_path);
    assert!(
        result.is_ok(),
        "Typst engine failed to generate PDF: {:?}",
        result.err()
    );

    // 4. Verify the file exists and has content
    // A Typst PDF with baked fonts and charts will be significantly larger than an empty shell.
    let metadata = fs::metadata(test_file_path).expect("PDF file was not created on disk");
    assert!(
        metadata.len() > 1000,
        "Generated Typst PDF is abnormally small ({} bytes). It might be an empty shell!",
        metadata.len()
    );

    // 5. Cleanup is completely automatic!
    // When `temp_pdf` drops out of scope here, the OS automatically deletes the file.
}
