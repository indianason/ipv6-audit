// src/main.rs

mod dto;
mod report;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
// use tokio::fs::File;
// use tokio::io::{AsyncBufReadExt, BufReader};
use hickory_resolver::TokioResolver;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use ipv6_audit::engine::scan_endpoint;
// use crate::dto::AuditReport;

/*
// =====================================================================
// MAIN ENGINE EXECUTOR
// =====================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    let raw_domains = vec!["constechvina.vn", "saomocmedia.com", "  BAD INPUT "];

    // UPDATED to use the hickory-resolve v0.26 Builder pattern
    let resolver = TokioResolver::builder_tokio()?.build()?;

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .use_rustls_tls()
        .build()?;

    let mut join_set = JoinSet::new();

    for raw in raw_domains {
        let resolver_clone = resolver.clone();
        let client_clone = client.clone();

        join_set.spawn(async move {
            // Newtype edge validation
            let validated = match ValidatedDomain::try_new(raw) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Skipping invalid domain input: {}", e);
                    return None; // Skip gracefully
                }
            };

            // Typestate Engine Execution
            let target = ReconTarget::new(validated);

            // Compile-time guarantee: You CANNOT call verify_layer7() on a Pending or DnsFailed target.
            let report = match target.resolve_dns(&resolver_clone).await {
                Ok(resolved_target) => resolved_target.verify_layer7(&client_clone).await,
                Err(failed_target) => failed_target.generate_report(),
            };

            Some(report)
        });
    }

    let mut dossier = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(Some(report)) = res {
            dossier.push(report);
        }
    }

    println!("{}", serde_json::to_string_pretty(&dossier)?);
    Ok(())
}
*/

// =====================================================================
// CLI ARGUMENTS
// =====================================================================
/* For production
#[derive(Parser, Debug)]
#[command(author, version, about = "IPv6 Reconnaissance Engine", long_about = None)]
struct Args {
    /// Path to the text file containing domains (one per line)
    #[arg(short, long)]
    input: PathBuf,

    /// Maximum number of concurrent network requests (Mechanical Sympathy bounds)
    #[arg(short, long, default_value_t = 100)]
    concurrency: usize,
}
*/

#[derive(Parser, Debug)]
#[command(author, version, about = "IPv6 Audit Engine", long_about = None)]
#[group(required = true, multiple = false)]
struct InputGroup {
    /// Path to the text file containing domains (one per line)
    #[arg(short, long)]
    pub input: Option<PathBuf>, // Made optional so --self-test can run alone

    /// A single domain to scan directly
    #[arg(short, long)]
    pub domain: Option<String>,

    /// DEV: Fast test to verify this machine has working Layer-7 IPv6 access
    #[arg(long)]
    pub self_test: bool,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "IPv6 Audit Engine")]
struct Args {
    #[command(flatten)]
    inputs: InputGroup,

    /// Maximum number of concurrent network requests
    #[arg(short, long, default_value_t = 100)]
    concurrency: usize,

    /// EXPERT MODE: Perform a recursive root-to-TLD trace to enforce IPv6 Glue Record compliance
    #[arg(long, default_value_t = false)]
    strict_compliance: bool,
}

// =====================================================================
// MAIN ENGINE EXECUTOR
// =====================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    // 1. Parse CLI Arguments
    let args = Args::parse();

    // 2. Initialize Network Clients
    let resolver = TokioResolver::builder_tokio()?.build()?;
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .use_rustls_tls()
        .build()?;

    // 3. Initialize the Bounded Semaphore (The Throttle)
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut join_set = JoinSet::new();

    // 4. Stream the file line-by-line (Zero memory bloat)
    // Ensure input file exists if we are NOT running a self-test
    let mut targets: Vec<String> = Vec::new();

    if let Some(ref domain) = args.inputs.domain {
        info!("Running single-target audit on: {}", domain);
        targets.push(domain.to_string());
    } else if let Some(input_path) = args.inputs.input {
        info!("Opening bulk target file: {:?}", input_path);
        let file = std::fs::File::open(input_path).expect("Failed to open input file");
        let reader = std::io::BufReader::new(file);
        for domain in std::io::BufRead::lines(reader).map_while(Result::ok) {
            if !domain.trim().is_empty() {
                targets.push(domain);
            }
        }
    } else if args.inputs.self_test {
        info!("Executing self-test...");
        // --- THE IPv6 SELF-TEST ---
        if args.inputs.self_test {
            info!("Executing Layer 7 IPv6 Self-Test...");
            // ipv6.google.com has no A (IPv4) record. It only exists on the IPv6 internet.
            match client.get("https://ipv6.google.com").send().await {
                Ok(res) if res.status().is_success() => {
                    info!("✅ SUCCESS: This machine is actively routing traffic on the IPv6 internet.");
                    return Ok(());
                }
                Ok(res) => {
                    error!(
                        "❌ FAILED: Reached the host, but received HTTP status {}",
                        res.status()
                    );
                    return Ok(());
                }
                Err(e) => {
                    error!("❌ FATAL: Cannot reach the IPv6 internet. Check Viettel/VNPT router settings. Error: {}", e);
                    return Ok(());
                }
            }
        }
    }

    /*
    // Determine the output file name dynamically
    let output_filename = if let Some(domain) = &args.inputs.domain {
        format!("{}_recon.csv", domain)
    } else {
        "prospects.csv".to_string()
    };
    */

    // We no longer stream the file asynchronously here, because we already
    // collected all targets into the `targets: Vec<String>` vector above!

    // Iterate over the dynamically populated targets vector
    for raw in targets {
        let resolver_clone = resolver.clone();
        let client_clone = client.clone();

        // Wait for a concurrency ticket BEFORE spawning the task
        let permit = semaphore.clone().acquire_owned().await?;

        join_set.spawn(async move {
            // Drop the permit at the very end of the task so another domain can start
            let _permit = permit;

            // DELEGATE TO THE ENGINE
            match scan_endpoint(&client_clone, &resolver_clone, &raw, args.strict_compliance).await
            {
                Ok(report) => Some(report),
                Err(e) => {
                    warn!("Skipping target '{}': {}", raw, e);
                    None
                }
            }
        });
    }

    // 5. Collect Results
    let mut dossier: Vec<dto::AuditReport> = Vec::new();
    // let mut dossier = [dto::ReconReport];
    while let Some(res) = join_set.join_next().await {
        if let Ok(Some(report)) = res {
            // 1. Map the internal DomainReport to our presentation DTO
            let mut recon_dto = dto::AuditReport {
                domain: report.domain.as_str().to_string(),
                web_ipv6_ready: report.web_ipv6_ready,
                web_ipv6_reachable: report.web_ipv6_reachable,
                mx_ipv6_ready: report.mx_ipv6_ready,
                ns_ipv6_ready: report.ns_ipv6_ready,
                strict_glue_ready: report.strict_glue_ready.expect("REASON"),
                vulnerability_status: String::new(), // We synthesize this next
            };

            // 2. Generate the executive text for the PDF/CSV
            recon_dto.synthesize_diagnosis();

            // 3. Push the correctly typed DTO into the dossier
            dossier.push(recon_dto);
        }
    }

    /*
    // Output JSON strictly to stdout
    println!("{}", serde_json::to_string_pretty(&dossier)?);
    Ok(())
    */

    // 6. Extract the safely sanitized domain from our dossier (or fallback if empty)
    let safe_name = dossier
        .first()
        .map(|r| r.domain.clone())
        .unwrap_or_else(|| "bulk_audit_results".to_string());

    // 7. Generate OS-safe filenames
    let csv_filename = format!("{}_audit.csv", safe_name);
    let pdf_filename = format!("{}_audit.pdf", safe_name);

    info!("Writing final report to: {}", csv_filename);

    // 8. Save the CSV
    let mut wtr = csv::Writer::from_path(&csv_filename).unwrap_or_else(|e| {
        panic!("Failed to create CSV writer: {}", e);
    });

    for record in &dossier {
        wtr.serialize(record).expect("Failed to serialize record");
    }
    wtr.flush().expect("Failed to flush CSV");
    info!("✅ Audit complete. CSV saved.");

    // 9. Generate the Branded PDF
    info!("Compiling executive PDF report to: {}", pdf_filename);
    if let Err(e) = report::generate_pdf(&dossier, &pdf_filename) {
        error!("❌ Failed to generate PDF report: {}", e);
    } else {
        info!("✅ Executive PDF report saved to {}.", pdf_filename);
    }

    /*
    // 6. Output CSV to the physical file
    info!("Writing final report to: {}", output_filename);
    let mut wtr = csv::Writer::from_path(&output_filename).expect("Failed to create CSV writer");

    for record in &dossier {
        wtr.serialize(record)?;
    }
    wtr.flush()?;

    // ... code that saves the CSV ...
    info!("✅ Reconnaissance complete. CSV saved.");

    // 7. Generate the Branded PDF
    let pdf_filename = "prospects_audit_report.pdf";
    info!("Compiling executive PDF report to: {}", pdf_filename);

    if let Err(e) = report::generate_pdf(&dossier, pdf_filename) {
        error!("❌ Failed to generate PDF report: {}", e);
    } else {
        info!("✅ Executive PDF report saved to {}.", pdf_filename);
    }

    // 7. Generate the Branded PDF
    let pdf_filename = output_filename.replace(".csv", ".pdf");
    info!("Compiling executive PDF report to: {}", pdf_filename);

    if let Err(e) = report::generate_pdf(&dossier, &pdf_filename) {
        error!("Failed to generate PDF report: {}", e);
    } else {
        info!("✅ Executive PDF report saved to {}.", pdf_filename);
    }
    */

    Ok(())
}
