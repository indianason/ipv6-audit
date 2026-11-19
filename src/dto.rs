// src/dto.rs

use serde::{Deserialize, Serialize};

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
            vulnerability_status: "CRITICAL: Total Infrastructure IPv6 Failure".to_string(),
        }
    }

    /// Evaluates the collected booleans to generate the final executive diagnosis
    pub fn synthesize_diagnosis(&mut self) {
        if !self.web_ipv6_ready {
            self.vulnerability_status =
                "CRITICAL: Website drops offline in IPv6-only network".to_string();
        } else if !self.web_ipv6_reachable {
            self.vulnerability_status =
                "WARN: IPv6 DNS exists, but firewall/server rejected Layer-7 TLS".to_string();
        } else if !self.mx_ipv6_ready {
            self.vulnerability_status =
                "WARN: Web compliant, but Mail Exchange drops IPv6 emails".to_string();
        } else if !self.strict_glue_ready {
            self.vulnerability_status =
                "CRITICAL: TLD Glue missing. Domain invisible to strict resolvers".to_string();
        } else {
            self.vulnerability_status =
                "SECURE: Infrastructure is fully 2030 Mandate Compliant".to_string();
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
            vulnerability_status: String::new(),
        };

        report.synthesize_diagnosis();

        assert_eq!(
            report.vulnerability_status,
            "CRITICAL: Website drops offline in IPv6-only network"
        );
    }
}
