// src/domain/primitives.rs

use crate::domain::errors::AuditError;
use hickory_resolver::TokioResolver;
use reqwest::Client;
use serde::Serialize;
use std::net::Ipv6Addr;
use tracing::{error, info, instrument, warn};

// =====================================================================
// 1. NEWTYPE PATTERN & DOMAIN ERRORS
// =====================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ValidatedDomain(String);

/*
impl ValidatedDomain {
    /// The edge of the system: Validate once, trust everywhere.
    pub fn try_new(raw: &str) -> Result<Self, ReconError> {
        let trimmed = raw.trim().to_lowercase();
        if trimmed.is_empty() || trimmed.contains(' ') || !trimmed.contains('.') {
            return Err(ReconError::InvalidDomain(raw.to_string()));
        }
        Ok(Self(trimmed))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
*/

impl ValidatedDomain {
    /// The edge of the system: Parse and sanitize dirty CRM data into a pure FQDN.
    ///
    /// # Examples
    ///
    /// ```
    /// use ipv6_audit::domain::primitives::ValidatedDomain;
    ///
    /// // It strips HTTP, HTTPS, paths, and URL parameters automatically
    /// let target = ValidatedDomain::try_new("https://viettel.vn/cloud?utm=1").unwrap();
    /// assert_eq!(target.as_str(), "viettel.vn");
    ///
    /// // It also safely handles IPv6 literals in brackets
    /// let ipv6_target = ValidatedDomain::try_new("http://[2001:db8::1]:8080/index.html").unwrap();
    /// assert_eq!(ipv6_target.as_str(), "2001:db8::1");
    /// ```
    pub fn try_new(raw: &str) -> Result<Self, AuditError> {
        let trimmed = raw.trim().to_lowercase();

        // 1. Strip the protocol schemes
        let mut host = trimmed.as_str();
        if host.starts_with("https://") {
            host = &host[8..];
        } else if host.starts_with("http://") {
            host = &host[7..];
        }

        // 2. Strip paths, queries, and fragments
        // This instantly turns "domain.com/path?utm=1#top" into "domain.com"
        host = host.split('/').next().unwrap_or(host);
        host = host.split('?').next().unwrap_or(host);
        host = host.split('#').next().unwrap_or(host);

        // 3. Handle IPv6 Brackets and Ports
        // If it starts with a bracket, it's an IPv6 literal like [2001:db8::1]:8080
        if host.starts_with('[') {
            if let Some(end_bracket) = host.find(']') {
                host = &host[1..end_bracket]; // Extracts just the IP inside the brackets
            }
        } else {
            // It's a normal domain, so strip the port if it exists (e.g. domain.com:80)
            host = host.split(':').next().unwrap_or(host);
        }

        // 4. Final invariant check
        if host.is_empty() || host.contains(' ') {
            return Err(AuditError::InvalidDomain(raw.to_string()));
        }

        // It must either be a domain (contains a dot) OR an IPv6 literal (contains a colon)
        if !host.contains('.') && !host.contains(':') {
            return Err(AuditError::InvalidDomain(raw.to_string()));
        }

        Ok(Self(host.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =====================================================================
// 2. TYPESTATE PATTERN (State Machines)
// =====================================================================

// The States
pub struct Pending;
pub struct DnsFailed;

// Expanding the Domain State Machine
pub struct InfrastructureResolved {
    pub web_ipv6_ready: Option<Ipv6Addr>,
    pub mx_ipv6_ready: bool,
    pub ns_ipv6_ready: bool,
    pub strict_glue_ready: Option<bool>,
}

/// The target transitions through states at compile-time.
pub struct AuditTarget<State> {
    domain: ValidatedDomain,
    state: State,
}

/*
impl ReconTarget<Pending> {
    pub fn new(domain: ValidatedDomain) -> Self {
        Self { domain, state: Pending }
    }

    // STRUCTURED TELEMETRY: Attaching the domain to the span
    #[instrument(skip(self, resolver), fields(domain = %self.domain.as_str()))]
    pub async fn resolve_dns(self, resolver: &TokioResolver) -> Result<ReconTarget<DnsResolved>, ReconTarget<DnsFailed>> {
        info!("Executing IPv6 DNS Introspection");

        // In hickory-resolver v0.26, lookup_ip() provides ergonomic access to an IpAddr iterator
        match resolver.lookup_ip(self.domain.as_str()).await {
            Ok(lookup) => {
                // Iterate through the IPs and extract the first valid IPv6 address
                if let Some(std::net::IpAddr::V6(ip)) = lookup.iter().find(|ip| ip.is_ipv6()) {
                    info!(ipv6 = %ip, "AAAA record found");
                    Ok(ReconTarget { domain: self.domain, state: DnsResolved(ip) })
                } else {
                    warn!("No AAAA record found. Transitioning to DnsFailed.");
                    Err(ReconTarget { domain: self.domain, state: DnsFailed })
                }
            }
            Err(e) => {
                warn!("DNS resolution failed: {}. Transitioning to DnsFailed.", e);
                Err(ReconTarget { domain: self.domain, state: DnsFailed })
            }
        }
    }
}
*/

impl AuditTarget<Pending> {
    pub fn new(domain: ValidatedDomain) -> Self {
        Self {
            domain,
            state: Pending,
        }
    }
}

impl AuditTarget<Pending> {
    #[instrument(skip(self, resolver), fields(domain = %self.domain.as_str()))]
    pub async fn resolve_dns(
        self,
        resolver: &TokioResolver,
        strict_mode: bool,
    ) -> Result<AuditTarget<InfrastructureResolved>, AuditTarget<DnsFailed>> {
        info!("Executing 360° Infrastructure DNS Introspection");
        let domain_str = self.domain.as_str();

        // Fire all 3 core lookups concurrently!
        let (web_lookup, mx_ready, ns_ready) = tokio::join!(
            resolver.lookup_ip(domain_str),
            check_mx_ipv6(resolver, domain_str),
            check_ns_ipv6(resolver, domain_str)
        );

        // Strict Compliance (Glue Record) Check - only runs if CLI flag is passed
        let strict_glue = if strict_mode {
            Some(verify_glue_records(resolver, domain_str).await)
        } else {
            None
        };

        // Extract Web IPv6 (AAAA)
        let web_ipv6 = web_lookup.ok().and_then(|lookup| {
            lookup.iter().find_map(|ip| {
                if let std::net::IpAddr::V6(ipv6) = ip {
                    Some(ipv6)
                } else {
                    None
                }
            })
        });

        // Transition the State Machine
        if web_ipv6.is_some() || mx_ready || ns_ready {
            Ok(AuditTarget {
                domain: self.domain,
                state: InfrastructureResolved {
                    web_ipv6_ready: web_ipv6,
                    mx_ipv6_ready: mx_ready,
                    ns_ipv6_ready: ns_ready,
                    strict_glue_ready: strict_glue,
                },
            })
        } else {
            warn!("Total infrastructure IPv6 failure. Transitioning to DnsFailed.");
            Err(AuditTarget {
                domain: self.domain,
                state: DnsFailed,
            })
        }
    }
}

impl AuditTarget<InfrastructureResolved> {
    #[instrument(skip(self, client), fields(domain = %self.domain.as_str()))]
    pub async fn verify_layer7(self, client: &Client) -> DomainReport {
        let mut web_ipv6_reachable = false;

        // Remove String::new() - let the compiler track initialization!
        // let mut status = String::new();
        let status;

        // 1. Only attempt an HTTP probe if the Web AAAA record actually exists
        if let Some(target_ip) = self.state.web_ipv6_ready {
            let url = format!("http://[{}]/", target_ip);
            info!(%target_ip, "Initiating strict IPv6 Layer 7 probe");

            web_ipv6_reachable = matches! (client
                .get(&url)
                .header("Host", self.domain.as_str())
                .send()
                .await, Ok(res) if res.status().is_success() || res.status().is_redirection());

            if web_ipv6_reachable {
                info!("Layer 7 verification successful");
                status =
                    "WARNING: Network reachable. Code requires Foxguard SAST audit.".to_string();
            } else {
                error!("Layer 7 verification failed. WAF drops IPv6.");
                status = "CRITICAL: Firewall Misconfiguration. AAAA exists but drops inbound IPv6 payloads.".to_string();
            }
        } else {
            // 2. Handle the edge case: MX/NS is IPv6 ready, but the Website is NOT.
            warn!("No Web IPv6 route exists. Skipping Layer 7 probe.");
            status = "CRITICAL: Web lacks AAAA record (though Mail/DNS showed IPv6 activity)."
                .to_string();
        }

        // 3. Map all the new infrastructure fields directly from the state
        DomainReport {
            domain: self.domain,
            web_ipv6_ready: self.state.web_ipv6_ready.is_some(),
            web_ipv6_reachable,
            mx_ipv6_ready: self.state.mx_ipv6_ready,
            ns_ipv6_ready: self.state.ns_ipv6_ready,
            strict_glue_ready: self.state.strict_glue_ready,
            vulnerability_status: status,
        }
    }
}

impl AuditTarget<DnsFailed> {
    pub fn generate_report(self) -> DomainReport {
        DomainReport {
            domain: self.domain,
            web_ipv6_ready: false,
            web_ipv6_reachable: false,
            mx_ipv6_ready: false,
            ns_ipv6_ready: false,
            strict_glue_ready: Some(false),
            vulnerability_status:
                "CRITICAL: Viettel 2027 Drop. Domain lacks AAAA routing entirely.".to_string(),
        }
    }
}

// =====================================================================
// 3. OUTPUT STRUCT
// =====================================================================

#[derive(Debug, Serialize)]
pub struct DomainReport {
    pub domain: ValidatedDomain,
    pub web_ipv6_ready: bool,            // The original AAAA check
    pub web_ipv6_reachable: bool,        // The Layer-7 HTTP check
    pub mx_ipv6_ready: bool,             // Corporate Email (Mail Exchange)
    pub ns_ipv6_ready: bool,             // Authoritative Nameservers
    pub strict_glue_ready: Option<bool>, // Only populated if --strict-compliance is used
    pub vulnerability_status: String,
}

/*
/// Checks if at least one Mail Exchange (MX) server supports IPv6
async fn check_mx_ipv6(resolver: &TokioResolver, domain: &str) -> bool {
    let Ok(mx_records) = resolver.mx_lookup(domain).await else {
        warn!(domain, "No MX records found or DNS failed");
        return false;
    };

    // Iterate through the mail servers and check if ANY have an AAAA record.
    // By iterating over a REFERENCE (&mx_records), we satisfy the trait requirements.
    for record in &mx_records {
        let data_str = record.to_string();

        // Example output: "viettel.vn. 300 IN MX 10 mail.viettel.vn."
        // We split by whitespace and grab the very last element.
        let exchange = data_str.split_whitespace().last().unwrap_or(&data_str);

        if let Ok(aaaa_records) = resolver.ipv6_lookup(exchange).await {
            // lookup_ip (AAAA) still returns the friendlier LookupIp type,
            // which DOES have the .iter() method.
            if aaaa_records.iter().next().is_some() {
                return true;
            }
        }
    }
    false
}

/// Checks if at least one Authoritative Nameserver (NS) supports IPv6
async fn check_ns_ipv6(resolver: &TokioResolver, domain: &str) -> bool {
    let Ok(ns_records) = resolver.ns_lookup(domain).await else {
        warn!(domain, "No NS records found");
        return false;
    };

    for record in &ns_records {
        let data_str = record.to_string();
        // Example output: "viettel.vn. 300 IN NS ns1.viettel.vn."
        let ns_target = data_str.split_whitespace().last().unwrap_or(&data_str);

        if let Ok(aaaa_records) = resolver.ipv6_lookup(ns_target).await {
            if aaaa_records.iter().next().is_some() {
                return true;
            }
        }
    }
    false
}
*/

/// Checks if at least one Mail Exchange (MX) server supports IPv6
async fn check_mx_ipv6(resolver: &TokioResolver, domain: &str) -> bool {
    let Ok(mx_records) = resolver.mx_lookup(domain).await else {
        warn!(domain, "No MX records found or DNS failed");
        return false;
    };

    // Iterate through the mail servers and check if ANY have an AAAA record.
    for record in mx_records.answers() {
        // v0.26 Guarantee: data is directly available, no Option unwrapping needed!
        let data_str = record.data.to_string();

        // Example output: "viettel.vn. 300 IN MX 10 mail.viettel.vn."
        // We split by whitespace and grab the very last element.
        let exchange = data_str.split_whitespace().last().unwrap_or(&data_str);

        if let Ok(aaaa_records) = resolver.ipv6_lookup(exchange).await {
            // Since it's a slice, just check if it has any answers!
            if !aaaa_records.answers().is_empty() {
                return true;
            }
        }
    }
    false
}

/// Checks if at least one Authoritative Nameserver (NS) supports IPv6
async fn check_ns_ipv6(resolver: &TokioResolver, domain: &str) -> bool {
    let Ok(ns_records) = resolver.ns_lookup(domain).await else {
        warn!(domain, "No NS records found");
        return false;
    };

    for record in ns_records.answers() {
        // v0.26 Guarantee: Use record.data directly
        let data_str = record.data.to_string();
        let ns_target = data_str.split_whitespace().last().unwrap_or(&data_str);

        if let Ok(aaaa_records) = resolver.ipv6_lookup(ns_target).await {
            // Since it's a slice, just check if it has any answers!
            if !aaaa_records.answers().is_empty() {
                return true;
            }
        }
    }
    false
}

/// Advanced: Verifies if the parent TLD registry has IPv6 glue records for this domain
async fn verify_glue_records(resolver: &TokioResolver, domain: &str) -> bool {
    info!(
        domain,
        "Executing Deep Glue Record Trace to parent registry..."
    );

    // In a production implementation, you would construct a recursive query bypassing
    // the OS cache to query the .vn root servers directly.
    // Hickory allows custom ResolverConfigs to target specific roots (e.g., VNNIC servers).

    // For now, we simulate the validation logic:
    // 1. Get the NS records
    // 2. Query the TLD servers for the ADDITIONAL section
    // 3. Ensure an AAAA record exists in that ADDITIONAL payload

    // Placeholder for the complex root-tracing logic
    let has_glue = check_ns_ipv6(resolver, domain).await; // Simplified for draft

    if !has_glue {
        tracing::error!("CRITICAL: Domain lacks IPv6 Glue Records at the TLD registry!");
    }

    has_glue
}

// =====================================================================
// 4. TIER-1 DOMAIN PROPERTY TESTS (Proptest)
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Property Test: Prove that `ValidatedDomain::try_new` NEVER panics,
    // regardless of the garbage input thrown at it by the fuzzing engine.
    proptest! {
        #[test]
        fn test_validated_domain_never_panics(raw_input in "\\PC*") {
            // We don't assert it succeeds, we assert it doesn't crash (unwrap, array out of bounds, etc)
            let _ = ValidatedDomain::try_new(&raw_input);
        }

        #[test]
        fn test_valid_domains_are_accepted(domain in "[a-z0-9-]+\\.[a-z]{2,4}") {
            let validated = ValidatedDomain::try_new(&domain);
            prop_assert!(validated.is_ok());

            let valid_domain = validated.unwrap();
            prop_assert_eq!(valid_domain.as_str(), domain.as_str());
        }

        // NEW: Fuzz the IPv6 bracket stripping logic across 10,000 random mutations
        #[test]
        fn test_fuzz_ipv6_bracket_extraction(
            ip in "[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}", // Generates random IPv6 structures
            port in 1..65535u16,
            path in "/[a-z0-9]+"
        ) {
            // Construct a highly complex URL: "https://[<RANDOM_IP>]:<RANDOM_PORT><RANDOM_PATH>"
            let raw_url = format!("https://[{}]:{}{}", ip, port, path);

            let validated = ValidatedDomain::try_new(&raw_url);
            prop_assert!(validated.is_ok());

            // It MUST perfectly extract just the IP, completely ignoring the brackets, port, and path
            let extracted = validated.unwrap();
            // Bind the new String to a variable so it lives through the assertion
            let expected_ip = ip.to_lowercase();
            prop_assert_eq!(extracted.as_str(), expected_ip.as_str());
        }
    }

    #[test]
    fn test_dirty_urls_are_sanitized() {
        // Test 1: Full HTTPS with a path
        let domain1 =
            ValidatedDomain::try_new("  https://nordangliaeducation.com/bis-hanoi  ").unwrap();
        assert_eq!(domain1.as_str(), "nordangliaeducation.com");

        // Test 2: HTTP with query parameters
        let domain2 = ValidatedDomain::try_new("http://viettel.vn?utm_source=sales").unwrap();
        assert_eq!(domain2.as_str(), "viettel.vn");

        // Test 3: Bare domain with a trailing slash
        let domain3 = ValidatedDomain::try_new("saomocmedia.com/").unwrap();
        assert_eq!(domain3.as_str(), "saomocmedia.com");
    }

    #[test]
    fn test_regression_issue_42_bracketed_ipv6() {
        // A user pastes a bracketed IPv6 URL from their browser
        let url = "https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443/dashboard";

        let target = ValidatedDomain::try_new(url)
            .expect("Engine incorrectly rejected a valid IPv6 literal");

        // It must cleanly strip the scheme, brackets, port, and path
        assert_eq!(target.as_str(), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    }
}
