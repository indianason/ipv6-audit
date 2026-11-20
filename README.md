# Transvina IPv6-Audit (`ipv6-audit`)

[![Rust](https://img.shields.io/badge/rust-1.80%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Release](https://github.com/indianason/ipv6-audit/actions/workflows/release.yml/badge.svg)](https://github.com/indianason/ipv6-audit/releases)

Enterprise IPv6 infrastructure audit and readiness analyzer engineered for the **2026–2030 Vietnamese IPv6 transition mandate**.

`ipv6-audit` compiles into a zero-dependency, self-contained executable with embedded fonts and branding. It performs end-to-end DNS introspection, parent TLD glue tracing, and strict Layer-7 TLS probing over native IPv6 before generating executive PDF dossiers and machine-readable CSV reports.

---

## Features

* **Mechanical Sympathy:** Powered by `tokio` asynchronous I/O and zero-allocation string parsing. Scans dozens of domains concurrently using bounded semaphores.
* **Typestate Architecture:** Uses Rust's compiler to mathematically guarantee state transitions (`Pending` -> `InfrastructureResolved`), preventing panics on partial legacy deployments.
* **Smart Edge Sanitization:** Automatically strips dirty CRM data (e.g., `https://`, URL queries, bracketed IPv6 literals, and paths) before execution.
* **Deep TLD Validation:** Identifies catastrophic DNS vulnerabilities, such as missing IPv6 Glue Records at the `.vn` registry level.

---

## Core Capabilities

* **360° DNS Introspection:** Evaluates root `AAAA` routing, Mail Exchange (`MX`) IPv6 readiness, and Authoritative Nameserver (`NS`) dual-stack compliance.
* **Deep TLD Glue Tracing:** Queries parent registries to verify strict IPv6 glue delegation, identifying domains that drop offline in pure IPv6-only networks.
* **Layer-7 WAF & TLS Probing:** Executes live HTTPS handshakes directly against resolved IPv6 addresses to catch silent Web Application Firewall (WAF) drops.
* **Self-Contained Reporting:** Generates executive-ready PDF audit reports and structured CSV exports with zero external file dependencies.

---

## Installation

### Option 1: Pre-compiled Binaries (Recommended)

Download the pre-compiled standalone binary for your platform from the **[Releases](https://github.com/indianason/ipv6-audit/releases)** page:
No installation required—just drop it into your system path.

* **Windows (Client / Executive Audits):** `ipv6-audit-windows-amd64.exe`
* **Linux / Viettel IDC Servers (Static MUSL):** `ipv6-audit-linux-amd64`

On Linux servers, grant execution permissions after downloading:
```bash
chmod +x ipv6-audit-linux-amd64
```

### Option 2: Build from Source
Ensure you have [Rust](https://rustup.rs/) installed, then run:
```bash
git clone [https://github.com/indianason/ipv6-audit.git](https://github.com/indianason/ipv6-audit.git)
cd ipv6-audit
cargo install --path .
```

---

## Usage

### Single-Target Audit

Run an audit against a specific domain with strict TLD glue compliance checks:
```bash
./ipv6-audit-linux-amd64 --domain [https://viettel.vn](https://viettel.vn) --strict-compliance
```
(On Windows CMD, replace './ipv6-audit-linux-amd64' with 'ipv6-audit-windows-amd64.exe')
or
```bash
ipv6-audit -d viettel.vn --strict-compliance
```
Note: The '--strict-compliance' flag forces a recursive root-to-TLD trace to enforce IPv6 Glue Record compliance.

### Batch Infrastructure Audit

Provide a newline-delimited list of domains ('targets.txt') to audit an entire enterprise portfolio:
```bash
./ipv6-audit-linux-amd64 --file targets.txt --strict-compliance
```
(On Windows CMD, replace './ipv6-audit-linux-amd64' with 'ipv6-audit-windows-amd64.exe')
or
```bash
ipv6-audit -i targets.txt --strict-compliance
```
Note: The '--strict-compliance' flag forces a recursive root-to-TLD trace to enforce IPv6 Glue Record compliance.

---

## Architecture & Quality Doctrine

Built in Rust following a strict **3-Tier Testing Doctrine**:

* **Tier 1 (Domain Invariants):** Property-based testing ('proptest') validating state machine transitions and diagnosis synthesis.

* **Tier 2 (Unit Verification):** Deterministic validation of DNS primitives, sanitization rules, and DTO mappings.

* **Tier 3 (Black-Box Integration):** Network chaos simulation ('wiremock') and end-to-end PDF/CSV filesystem rendering tests.

---

## Understanding the Telemetry

The engine outputs a highly structured CSV and an executive-ready PDF mapping the exact architectural state of the target:

Column, Description
'web_ipv6_ready', Does the root domain have a valid AAAA routing record?
'web_ipv6_reachable', Did the TLS client successfully complete a Layer-7 HTTP probe over IPv6?
'mx_ipv6_ready', Does the corporate Mail Exchange support IPv6 routing?
'ns_ipv6_ready], Do the Authoritative Nameservers support IPv6 routing?
'strict_glue_ready', Does the parent TLD registry contain the correct IPv6 delegation?
'vulnerability_status', The final synthesized architectural diagnosis.

---

## License

Licensed under the **Apache License, Version 2.0**. Copyright © 2026 **Transvina**.
