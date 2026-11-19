// src/engine.rs

use crate::domain::errors::AuditError;
use crate::domain::primitives::{AuditTarget, DomainReport, ValidatedDomain};
use hickory_resolver::TokioResolver;
use reqwest::Client;
use tracing::{error, info, instrument, warn};

// use crate::dto::ReconReport;

#[instrument(skip(client, resolver))]
pub async fn scan_endpoint(
    client: &Client,
    resolver: &TokioResolver,
    url: &str,
    strict_mode: bool,
) -> Result<DomainReport, AuditError> {
    // 1. Log the initiation of the engine's workflow
    info!("Initiating engine scan pipeline for target: {}", url);

    let validated = match ValidatedDomain::try_new(url) {
        Ok(v) => {
            info!("Domain validation passed");
            v
        }
        Err(e) => {
            // Log exactly why the domain was rejected before returning the error
            warn!("Engine rejected invalid input '{}': {}", url, e);
            return Err(e);
        }
    };

    let target = AuditTarget::new(validated);

    // 2. Pass the strict mode down to the State Machine
    let report = match target.resolve_dns(resolver, strict_mode).await {
        Ok(resolved_target) => {
            info!("DNS phase successful, progressing to Layer-7 probe");
            resolved_target.verify_layer7(client).await
        }
        Err(failed_target) => {
            // We use error! here because a DNS failure is a critical break in the recon chain
            error!("DNS phase failed. Halting probe and generating fallback report");
            failed_target.generate_report()
        }
    };

    info!("Engine pipeline completed successfully for target");
    Ok(report)
}
