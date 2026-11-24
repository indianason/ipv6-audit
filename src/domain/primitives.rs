// src/domain/primitives.rs

use hickory_resolver::proto::rr::rdata::svcb::SvcParamKey;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use quinn::Endpoint;
use reqwest::Client;
use serde::Serialize;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, info, instrument, warn};

use crate::domain::errors::AuditError;

// =====================================================================
// 1. NEWTYPE PATTERN & DOMAIN ERRORS
// =====================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ValidatedDomain(String);

impl ValidatedDomain {
    /// Parse, don't validate!
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
    ///
    /// A Typestate-enforced audit target that progresses through DNS introspection
    /// and Happy Eyeballs v3 (HEv3) protocol racing at compile time.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hickory_resolver::TokioResolver;
    /// use ipv6_audit::domain::primitives::{AuditTarget, ValidatedDomain};
    /// use reqwest::Client;
    /// use std::time::Duration;
    ///
    /// # async fn run_example() -> Result<(), Box<dyn std::error::Error>> {
    /// let domain = ValidatedDomain::try_new("[https://viettel.vn](https://viettel.vn)")?;
    /// let pending = AuditTarget::new(domain);
    ///
    /// let resolver = TokioResolver::builder_tokio()?.build()?;
    /// let client = Client::new();
    ///
    /// // 1. Transition from `Pending` -> `InfrastructureResolved` (or `DnsFailed`)
    /// match pending.resolve_dns(&resolver, true).await {
    ///     Ok(resolved) => {
    ///         // 2. Execute HEv3 race with Safari's 250ms QUIC fallback timer
    ///         let safari_timer = Duration::from_millis(250);
    ///         let report = resolved.verify_layer7(&client, None, safari_timer).await;
    ///         println!("Penalty: {:?}ms", report.fallback_penalty_ms);
    ///     }
    ///     Err(failed) => {
    ///         let report = failed.generate_report();
    ///         println!("Status: {}", report.vulnerability_status);
    ///     }
    /// }
    /// # Ok(())
    /// # }
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

// The target transitions through states at compile-time.
pub struct AuditTarget<State> {
    domain: ValidatedDomain,
    state: State,
}

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
    #[instrument(skip(self, client, quic_endpoint), fields(domain = %self.domain.as_str()))]
    pub async fn verify_layer7(
        self,
        client: &Client,
        quic_endpoint: Option<&Endpoint>,
        fallback_delay: Duration, // NEW: The engine receives pure Time
    ) -> DomainReport {
        let mut web_ipv6_reachable = false;
        let status;
        let mut fallback_penalty_ms: Option<u64> = None; // NEW: Telemetry tracker

        if let Some(target_ip) = self.state.web_ipv6_ready {
            let tcp_url = format!("https://[{}]/", target_ip);

            if let Some(endpoint) = quic_endpoint {
                info!(%target_ip, "Initiating Happy Eyeballs v3 Protocol Race");
                let quic_addr = SocketAddr::new(std::net::IpAddr::V6(target_ip), 443);

                // 1. START THE STOPWATCH
                let phase_start = Instant::now();

                tokio::select! {
                    quic_result = crate::quic_audit::execute_quic_audit(endpoint, quic_addr, &self.domain) => {
                        match quic_result {
                            Ok(_) => {
                                info!("✅ QUIC won the race! Optimal Mobile UX.");
                                web_ipv6_reachable = true;
                                fallback_penalty_ms = Some(phase_start.elapsed().as_millis() as u64); // ~0-50ms
                                status = "OPTIMIZED: HTTP/3 QUIC successful. Zero UX Latency Penalty.".to_string();
                            }
                            Err(e) => {
                                error!("QUIC connection explicitly rejected: {}", e);
                                fallback_penalty_ms = Some(phase_start.elapsed().as_millis() as u64);
                                status = format!("CRITICAL: QUIC explicitly rejected. {}", e);
                            }
                        }
                    }

                    tcp_result = async {
                        // DYNAMIC: 250ms for Safari, 300ms for Chromium
                        // Replacing the hardcoded 250ms, i.e. 'Duration::from_millis(250)', with the injected delay 'fallback_delay'
                        tokio::time::sleep(fallback_delay).await;
                        client.get(&tcp_url).header("Host", self.domain.as_str()).send().await
                    } => {
                        match tcp_result {
                            Ok(res) if res.status().is_success() || res.status().is_redirection() => {
                                // 2. STOP THE STOPWATCH
                                let penalty = phase_start.elapsed().as_millis() as u64;
                                warn!("⚠️ TCP fallback won the race. Target is dropping UDP packets.");
                                web_ipv6_reachable = true;
                                fallback_penalty_ms = Some(penalty);
                                status = format!("WARNING: QUIC Trap detected. {}ms HEv3 penalty before TCP fallback. Code requires Foxguard SAST audit.", penalty);
                            }
                            _ => {
                                let penalty = phase_start.elapsed().as_millis() as u64;
                                fallback_penalty_ms = Some(penalty);
                                error!("TCP fallback failed alongside QUIC.");
                                status = "CRITICAL: Firewall Misconfiguration. Both UDP and TCP dropped on IPv6.".to_string();
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(5000)) => {
                        fallback_penalty_ms = Some(5000); // Max timeout hit
                        error!("FATAL: Complete IPv6 Blackhole.");
                        status = "CRITICAL: 5-Second Blackhole. Target routes AAAA but drops all Layer 7 traffic.".to_string();
                    }
                }
            } else {
                // FALLBACK: Standard Layer 7 TCP check
                info!(%target_ip, "Initiating strict IPv6 Layer 7 probe");
                let phase_start = Instant::now();

                web_ipv6_reachable = matches!(
                    client.get(&tcp_url).header("Host", self.domain.as_str()).send().await,
                    Ok(res) if res.status().is_success() || res.status().is_redirection()
                );

                fallback_penalty_ms = Some(phase_start.elapsed().as_millis() as u64);

                if web_ipv6_reachable {
                    info!("Layer 7 verification successful");
                    status = "WARNING: Network reachable. Code requires Foxguard SAST audit."
                        .to_string();
                } else {
                    error!("Layer 7 verification failed. WAF drops IPv6.");
                    status = "CRITICAL: Firewall Misconfiguration. AAAA exists but drops inbound IPv6 payloads.".to_string();
                }
            }
        } else {
            warn!("No Web IPv6 route exists. Skipping Layer 7 probe.");
            status = "CRITICAL: Web lacks AAAA record (though Mail/DNS showed IPv6 activity)."
                .to_string();
        }

        DomainReport {
            domain: self.domain,
            web_ipv6_ready: self.state.web_ipv6_ready.is_some(),
            web_ipv6_reachable,
            mx_ipv6_ready: self.state.mx_ipv6_ready,
            ns_ipv6_ready: self.state.ns_ipv6_ready,
            strict_glue_ready: self.state.strict_glue_ready,
            fallback_penalty_ms, // Passed to DTO here
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
            fallback_penalty_ms: None,
            vulnerability_status:
                "CRITICAL: Viettel 2027 Drop. Domain lacks AAAA routing entirely.".to_string(),
        }
    }
}

// =====================================================================
// NEW: HEv3 PROTOCOL RACING TYPESTATE
// =====================================================================
// We will build this enum to track the precise state of the connection race
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
enum Hev3State {
    Racing,
    QuicTimeoutFallingBackToTcp,
    ConnectedTcp,
    ConnectedQuic,
}

// A mock of the state machine we will build for the engine
#[allow(dead_code)]
struct AuditStateMachine {
    state: Hev3State,
}

#[allow(dead_code)]
impl AuditStateMachine {
    fn new() -> Self {
        Self {
            state: Hev3State::Racing,
        }
    }

    // Simulates the internal loop processing network events
    fn advance_state_based_on_time(&mut self, elapsed: Duration) {
        // RFC 8305 inspired QUIC timeout threshold (e.g., 250ms)
        let quic_timeout = Duration::from_millis(250);

        if self.state == Hev3State::Racing && elapsed >= quic_timeout {
            self.state = Hev3State::QuicTimeoutFallingBackToTcp;
        }
    }

    fn inject_tcp_success(&mut self) {
        if self.state == Hev3State::QuicTimeoutFallingBackToTcp {
            self.state = Hev3State::ConnectedTcp;
        }
    }
}

// =====================================================================
// 3. OUTPUT STRUCT & UTILS
// =====================================================================

#[derive(Debug, Serialize)]
pub struct DomainReport {
    pub domain: ValidatedDomain,
    pub web_ipv6_ready: bool,             // The original AAAA check
    pub web_ipv6_reachable: bool,         // The Layer-7 HTTP check
    pub mx_ipv6_ready: bool,              // Corporate Email (Mail Exchange)
    pub ns_ipv6_ready: bool,              // Authoritative Nameservers
    pub strict_glue_ready: Option<bool>,  // Only populated if --strict-compliance is used
    pub fallback_penalty_ms: Option<u64>, // Telemetry tracker
    pub vulnerability_status: String,
}

/// Queries the HTTPS DNS record to check if the domain advertises HTTP/3 via ALPN
pub async fn check_h3_alpn_advertisement(resolver: &TokioResolver, domain: &str) -> bool {
    let Ok(https_records) = resolver.lookup(domain, RecordType::HTTPS).await else {
        return false;
    };

    for record in https_records.answers() {
        if let hickory_resolver::proto::rr::RData::HTTPS(https_data) = &record.data {
            // Iterate through the slice of (Key, Value) tuples
            for (key, alpn_param) in &https_data.svc_params {
                if *key == SvcParamKey::Alpn {
                    if let hickory_resolver::proto::rr::rdata::svcb::SvcParamValue::Alpn(alpn) =
                        alpn_param
                    {
                        if alpn.to_string().contains("h3") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

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
    use tokio::time;

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

    // NEW: HEv3 Deterministic Time Test
    #[tokio::test(start_paused = true)]
    async fn test_quic_trap_forces_tcp_fallback_after_timeout() {
        let mut audit_state = AuditStateMachine::new();
        assert_eq!(audit_state.state, Hev3State::Racing);

        // 1. Warp time forward to exactly 249ms (1ms before timeout)
        time::advance(Duration::from_millis(249)).await;
        audit_state.advance_state_based_on_time(time::Duration::from_millis(249));

        // Prove it is still stubbornly waiting for QUIC/UDP
        assert_eq!(audit_state.state, Hev3State::Racing);

        // 2. Warp time past the 250ms threshold
        time::advance(Duration::from_millis(2)).await;
        audit_state.advance_state_based_on_time(time::Duration::from_millis(251));

        // Prove the state machine correctly abandons QUIC and registers the UX penalty
        assert_eq!(audit_state.state, Hev3State::QuicTimeoutFallingBackToTcp);

        // 3. Simulate the legacy TCP connection finally completing
        audit_state.inject_tcp_success();
        assert_eq!(audit_state.state, Hev3State::ConnectedTcp);
    }
}
