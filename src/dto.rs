// src/dto.rs

use serde::{Deserialize, Serialize};
use std::option::Option;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// The sanitized target domain (e.g., "viettel.vn")
    pub domain: String,

    /// Does the root domain have a valid AAAA routing record?
    pub web_ipv6_ready: bool,

    /// Did the TLS client successfully complete a Layer-7 HTTP probe over IPv6?
    pub web_ipv6_reachable: bool,

    /// Does the corporate Mail Exchange support IPv6 routing?
    pub mx_ipv6_ready: bool,

    /// Do the Authoritative Nameservers support IPv6 routing?
    pub ns_ipv6_ready: bool,

    /// Does the parent TLD registry contain the correct IPv6 delegation?
    pub strict_glue_ready: bool,

    /// The exact millisecond cost of the fallback or timeout
    pub fallback_penalty_ms: Option<u64>,

    /// The final synthesized architectural diagnosis
    pub vulnerability_status: String,
}

impl AuditReport {
    /// Creates a new default report representing a total infrastructure failure
    /// This acts as our baseline before the state machine proves otherwise.
    #[allow(dead_code)]
    pub fn new_failed(domain: String) -> Self {
        Self {
            domain,
            web_ipv6_ready: false,
            web_ipv6_reachable: false,
            mx_ipv6_ready: false,
            ns_ipv6_ready: false,
            strict_glue_ready: false,
            fallback_penalty_ms: Option::None,
            vulnerability_status: "CRITICAL: Total Infrastructure IPv6 Failure".to_string(),
        }
    }

    /// Evaluates the collected booleans to generate the final executive diagnosis
    pub fn synthesize_diagnosis(&mut self) {
        // Hierarchy of failures: The most critical failures are checked first.
        if !self.web_ipv6_ready {
            self.vulnerability_status =
                "CRITICAL: Website drops offline in IPv6-only network".to_string();
        } else if !self.web_ipv6_reachable {
            // FIX: The HEv3 penalty is applied here, ONLY if it has an IP but fails to connect.
            let penalty = self.fallback_penalty_ms.unwrap_or(0);
            self.vulnerability_status = format!(
                "CRITICAL: IPv6 routing blackhole detected. \
                Mobile clients trapped in a {}ms Happy Eyeballs timeout penalty \
                before falling back to IPv4. Immediate conversion rate degradation.",
                penalty
            );
        } else if !self.mx_ipv6_ready {
            self.vulnerability_status =
                "WARN: Web compliant, but Mail Exchange drops IPv6 emails".to_string();
        } else if !self.strict_glue_ready {
            self.vulnerability_status =
                "CRITICAL: TLD Glue missing. Domain invisible to strict resolvers".to_string();
        } else {
            self.vulnerability_status =
                "PASS: Infrastructure is fully 2030 Mandate Compliant".to_string();
        }
    }
}

// =====================================================================
// STANDARD UNIT TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnosis_critical_web_down() {
        let mut report = AuditReport {
            domain: "viettel.vn".to_string(),
            web_ipv6_ready: false, // The trigger
            web_ipv6_reachable: false,
            mx_ipv6_ready: true,
            ns_ipv6_ready: true,
            strict_glue_ready: true,
            fallback_penalty_ms: Option::None,
            vulnerability_status: String::new(),
        };

        report.synthesize_diagnosis();

        assert_eq!(
            report.vulnerability_status,
            "CRITICAL: Website drops offline in IPv6-only network"
        );
    }

    #[test]
    fn test_diagnosis_quic_trap_latency() {
        let mut report = AuditReport {
            domain: "thegioididong.com".to_string(),
            web_ipv6_ready: true,      // It has an IPv6 address...
            web_ipv6_reachable: false, // ...but the firewall drops it
            mx_ipv6_ready: true,
            ns_ipv6_ready: true,
            strict_glue_ready: true,
            fallback_penalty_ms: Some(5000), // Max timeout hit
            vulnerability_status: String::new(),
        };

        report.synthesize_diagnosis();

        assert_eq!(
            report.vulnerability_status,
            "CRITICAL: IPv6 routing blackhole detected. Mobile clients trapped in a 5000ms Happy Eyeballs timeout penalty before falling back to IPv4. Immediate conversion rate degradation."
        );
    }
}
