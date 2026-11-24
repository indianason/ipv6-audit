// src/report.rs

use image::{ImageFormat, RgbImage};
use plotters::prelude::*;
use std::error::Error;
use std::fs;
use std::io::Cursor;

use crate::dto::AuditReport;

// Generates a Happy Eyeballs waterfall chart in-memory and returns the PNG bytes.
pub fn generate_waterfall_png(penalty_ms: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let root_width = 800;
    let root_height = 250;
    let mut pixel_buffer = vec![0u8; (root_width * root_height * 3) as usize];

    {
        let root = BitMapBackend::with_buffer(&mut pixel_buffer, (root_width, root_height))
            .into_drawing_area();
        root.fill(&WHITE)?;

        let max_x = (penalty_ms + 150) as f32;

        let mut chart = ChartBuilder::on(&root)
            .margin(20)
            .x_label_area_size(40)
            .y_label_area_size(150)
            .build_cartesian_2d(0f32..max_x, 0..3)?;

        chart
            .configure_mesh()
            .x_desc("Time (milliseconds)")
            .y_labels(2)
            .y_label_formatter(&|y| match y {
                1 => "IPv6 / QUIC Timeout".to_string(),
                2 => "IPv4 Legacy Fallback".to_string(),
                _ => "".to_string(),
            })
            .draw()?;

        // Wasted IPv6 Penalty (Red Bar)
        chart.draw_series(std::iter::once(Rectangle::new(
            [(0.0, 1), (penalty_ms as f32, 2)],
            RED.filled(),
        )))?;

        // Legacy IPv4 Success (Green Bar)
        chart.draw_series(std::iter::once(Rectangle::new(
            [(penalty_ms as f32, 2), ((penalty_ms + 100) as f32, 3)],
            GREEN.filled(),
        )))?;

        root.present()?;
    }

    let img = RgbImage::from_raw(root_width, root_height, pixel_buffer)
        .ok_or("Failed to construct RgbImage from raw pixels")?;

    let mut png_bytes: Vec<u8> = Vec::new();
    let mut cursor = Cursor::new(&mut png_bytes);
    img.write_to(&mut cursor, ImageFormat::Png)?;

    Ok(png_bytes)
}

// The document! macro bakes the template into the binary at compile time!
pub fn generate_pdf(dossier: &[AuditReport], output_filename: &str) -> Result<(), Box<dyn Error>> {
    // 1. We will pass our data as a JSON string to the embedded Typst engine
    let json_data = serde_json::to_string(dossier)?;
    let logo_bytes = include_bytes!("../assets/logo.png");

    // 2. Initialize the Typst engine and chain the initial files
    // The `?` unwraps the Result from the first add_file so the second one can attach to the Document
    let mut builder = typst_bake::document!("audit_template.typ")
        .add_file("dossier.json", json_data.into_bytes())?
        .add_file("logo.png", logo_bytes.to_vec())?;

    // 3. For the waterfall charts, we generate them in memory and inject them too!
    for record in dossier {
        if let Some(penalty) = record.fallback_penalty_ms {
            if penalty > 0 {
                if let Ok(png_bytes) = generate_waterfall_png(penalty) {
                    let image_name = format!("{}_waterfall.png", record.domain.replace(".", "_"));

                    // Re-assign the builder and unwrap the Result with `?`
                    builder = builder.add_file(&image_name, png_bytes)?;
                }
            }
        }
    }

    // 4. Compile the PDF entirely in RAM
    let pdf_bytes = builder.to_pdf()?;

    // 5. Write the final PDF to disk
    fs::write(output_filename, pdf_bytes)?;

    tracing::info!("✅ Executive PDF report saved (Zero external dependencies).");
    Ok(())
}
