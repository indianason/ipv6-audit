# Transvina IPv6-Audit (`ipv6-audit`)

Enterprise IPv6 infrastructure audit and readiness analyzer engineered for the **2026–2030 Vietnamese IPv6 transition mandate**.

`ipv6-audit` compiles into a zero-dependency, self-contained executable with embedded fonts and branding. It performs end-to-end DNS introspection, parent TLD glue tracing, and strict Layer-7 TLS probing over native IPv6 before generating executive PDF dossiers and machine-readable CSV reports.

---

## Core Capabilities

* **360° DNS Introspection:** Evaluates root `AAAA` routing, Mail Exchange (`MX`) IPv6 readiness, and Authoritative Nameserver (`NS`) dual-stack compliance.
* **Deep TLD Glue Tracing:** Queries parent registries to verify strict IPv6 glue delegation, identifying domains that drop offline in pure IPv6-only networks.
* **Layer-7 WAF & TLS Probing:** Executes live HTTPS handshakes directly against resolved IPv6 addresses to catch silent Web Application Firewall (WAF) drops.
* **Self-Contained Reporting:** Generates executive-ready PDF audit reports and structured CSV exports with zero external file dependencies.

---

## Installation

Download the pre-compiled standalone binary for your platform from the **[Releases](https://github.com/indianason/ipv6-audit/releases)** page:

* **Windows (Client / Executive Audits):** `ipv6-audit-windows-amd64.exe`
* **Linux / Viettel IDC Servers (Static MUSL):** `ipv6-audit-linux-amd64`

On Linux servers, grant execution permissions after downloading:
```bash
chmod +x ipv6-audit-linux-amd64
```

---

## Usage

### Single-Target Audit

Run an audit against a specific domain with strict TLD glue compliance checks:
```bash
./ipv6-audit-linux-amd64 --domain [https://viettel.vn](https://viettel.vn) --strict-compliance
```
(On Windows CMD, replace './ipv6-audit-linux-amd64' with 'ipv6-audit-windows-amd64.exe')

### Batch Infrastructure Audit

Provide a newline-delimited list of domains ('targets.txt') to audit an entire enterprise portfolio:
```bash
./ipv6-audit-linux-amd64 --file targets.txt --strict-compliance
```
(On Windows CMD, replace './ipv6-audit-linux-amd64' with 'ipv6-audit-windows-amd64.exe')

---

## Architecture & Quality Doctrine

Built in Rust following a strict **3-Tier Testing Doctrine**:

* **Tier 1 (Domain Invariants):** Property-based testing ('proptest') validating state machine transitions and diagnosis synthesis.

* **Tier 2 (Unit Verification):** Deterministic validation of DNS primitives, sanitization rules, and DTO mappings.

* **Tier 3 (Black-Box Integration):** Network chaos simulation ('wiremock') and end-to-end PDF/CSV filesystem rendering tests.

---

## License

Licensed under the **Apache License, Version 2.0**. Copyright © 2026 **Transvina**.
