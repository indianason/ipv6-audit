// src/main.rs

mod dto;
mod report;

use clap::Parser;
use hickory_resolver::TokioResolver;
use rustls::crypto::ring::default_provider;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{error, info, warn, Level};

use ipv6_audit::engine::scan_endpoint;
use ipv6_audit::quic_audit;

// =====================================================================
// CLI ARGUMENTS
// =====================================================================

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum BrowserProfile {
    /// iOS/macOS Default (250ms head-start for IPv6)
    #[default]
    Safari,
    /// Android/Desktop Chromium (300ms connection timeout for IPv4 fallback)
    Chrome,
}

impl BrowserProfile {
    pub fn fallback_delay(&self) -> Duration {
        match self {
            Self::Safari => Duration::from_millis(250),
            Self::Chrome => Duration::from_millis(300),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "IPv6 Audit Engine", long_about = None)]
#[group(required = true, multiple = false)]
struct InputGroup {
    /// Path to the text file containing domains (one per line)
    #[arg(short, long)]
    pub input: Option<PathBuf>,

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

    /// [E-commerce/Mobile] Execute Happy Eyeballs v3 Protocol Racing
    #[arg(long, default_value_t = false)]
    hev3_audit: bool,

    /// Emulate a specific mobile browser's Happy Eyeballs fallback timer
    #[arg(long, value_enum, default_value_t = BrowserProfile::Safari)]
    pub emulate: BrowserProfile,
}

// =====================================================================
// MAIN ENGINE EXECUTOR
// =====================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0. Install Cryptographic Provider
    let _ = default_provider().install_default();

    // 1. Initialize Structured JSON Telemetry
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_span_list(true)
        .with_current_span(true)
        .init();

    // 2. Parse Arguments & Self-Test Guard
    let args = Args::parse();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .use_rustls_tls()
        .build()?;

    if args.inputs.self_test {
        info!("Executing Layer 7 IPv6 Self-Test...");
        match client.get("https://ipv6.google.com").send().await {
            Ok(res) if res.status().is_success() => {
                info!("✅ SUCCESS: This machine is actively routing traffic on the IPv6 internet.");
            }
            Ok(res) => error!(
                "❌ FAILED: Reached the host, but received HTTP status {}",
                res.status()
            ),
            Err(e) => error!(
                "❌ FATAL: Cannot reach the IPv6 internet. Check router settings. Error: {}",
                e
            ),
        }
        return Ok(());
    }

    let target_display = args.inputs.domain.as_deref().unwrap_or("Bulk Mode");
    info!(
        "Starting IPv6 Audit Engine v0.2.0 for target: {}",
        target_display
    );

    // 3. Initialize Global Clients & QUIC Endpoint
    let resolver = TokioResolver::builder_tokio()?.build()?;
    let quic_endpoint = if args.hev3_audit {
        info!("HEv3 Audit enabled: Initializing shared IPv6 QUIC endpoint...");
        Some(Arc::new(quic_audit::build_shared_ipv6_quic_endpoint()?))
    } else {
        None
    };

    // 4. Collect Targets
    let mut targets: Vec<String> = Vec::new();
    if let Some(domain) = args.inputs.domain {
        targets.push(domain);
    } else if let Some(input_path) = args.inputs.input {
        let file = std::fs::File::open(input_path).expect("Failed to open input file");
        let reader = std::io::BufReader::new(file);
        for domain in std::io::BufRead::lines(reader).map_while(Result::ok) {
            if !domain.trim().is_empty() {
                targets.push(domain);
            }
        }
    }

    // 5. Execute Concurrent Engine Tasks
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut join_set = JoinSet::new();

    for raw in targets {
        let resolver_clone = resolver.clone();
        let client_clone = client.clone();
        let quic_ref = quic_endpoint.clone();
        let permit = semaphore.clone().acquire_owned().await?;
        let fallback_delay = args.emulate.fallback_delay();
        let strict_compliance = args.strict_compliance;

        join_set.spawn(async move {
            let _permit = permit;
            match scan_endpoint(
                &client_clone,
                &resolver_clone,
                &raw,
                strict_compliance,
                quic_ref.as_deref(),
                fallback_delay,
            )
            .await
            {
                Ok(report) => Some(report),
                Err(e) => {
                    warn!("Skipping target '{}': {}", raw, e);
                    None
                }
            }
        });
    }

    // 6. Collect & Synthesize Results
    let mut dossier: Vec<dto::AuditReport> = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(Some(report)) = res {
            let mut recon_dto = dto::AuditReport {
                domain: report.domain.as_str().to_string(),
                web_ipv6_ready: report.web_ipv6_ready,
                web_ipv6_reachable: report.web_ipv6_reachable,
                mx_ipv6_ready: report.mx_ipv6_ready,
                ns_ipv6_ready: report.ns_ipv6_ready,
                strict_glue_ready: report.strict_glue_ready.unwrap_or(false),
                fallback_penalty_ms: report.fallback_penalty_ms,
                vulnerability_status: String::new(),
            };
            recon_dto.synthesize_diagnosis();
            dossier.push(recon_dto);
        }
    }

    if dossier.is_empty() {
        warn!("No valid targets were scanned. Exiting.");
        return Ok(());
    }

    // 7. Output Generation
    let safe_name = dossier.first().map(|r| &r.domain).unwrap();
    let is_bulk = dossier.len() > 1;
    let base_filename = if is_bulk {
        "bulk_audit_results".to_string()
    } else {
        safe_name.clone()
    };

    let csv_filename = format!("{}_audit.csv", base_filename);
    let pdf_filename = format!("{}_audit.pdf", base_filename);

    info!("Writing final report to: {}", csv_filename);
    let mut wtr = csv::Writer::from_path(&csv_filename)?;
    for record in &dossier {
        wtr.serialize(record)?;
    }
    wtr.flush()?;
    info!("✅ Audit complete. CSV saved.");

    info!("Compiling executive PDF report to: {}", pdf_filename);
    if let Err(e) = report::generate_pdf(&dossier, &pdf_filename) {
        error!("❌ Failed to generate PDF report: {}", e);
    } else {
        info!("✅ Executive PDF report saved to {}.", pdf_filename);
    }

    Ok(())
}
