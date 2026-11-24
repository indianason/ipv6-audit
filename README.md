# Transvina IPv6-Audit (`ipv6-audit`)

[![Rust](https://img.shields.io/badge/rust-1.80%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![CI/CD](https://github.com/indianason/ipv6-audit/actions/workflows/release.yml/badge.svg)](https://github.com/indianason/ipv6-audit/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/indianason/ipv6-audit)](https://github.com/indianason/ipv6-audit/releases/latest)

Enterprise IPv6 infrastructure audit and readiness analyzer engineered for the **2026–2030 Vietnamese IPv6 transition mandate**.

`ipv6-audit` compiles into a zero-dependency, single static binary with embedded fonts, templates, and branding. It performs end-to-end DNS introspection, parent TLD glue tracing, Happy Eyeballs v3 (HEv3) QUIC/TCP protocol racing, and strict Layer-7 TLS probing over native IPv6 before compiling executive PDF dossiers and machine-readable CSV reports entirely in RAM.

---

## Features

- **Mechanical Sympathy:** Powered by `tokio` asynchronous I/O, zero-allocation string parsing, and nanosecond-precision `tokio::time::Instant` state machines to strictly enforce protocol racing constraints. Scans dozens of domains concurrently using bounded semaphores.
- **Happy Eyeballs v3 (HEv3) Protocol Racing:** Probes modern HTTP/3 & QUIC (`quinn` + `rustls`) and mechanically simulates Apple Safari (250ms) and Google Chrome (300ms) connection timers, racing IPv6 QUIC/UDP against legacy IPv4 TCP to measure real-world fallback latency penalties.
- **Typestate Architecture:** Uses Rust's compiler to mathematically guarantee state transitions (`Pending` -> `InfrastructureResolved` -> `Hev3State`), preventing panics on partial legacy deployments.
- **Smart Edge Sanitization:** Automatically strips dirty CRM data (e.g., `https://`, URL queries, bracketed IPv6 literals, and paths) before execution.
- **Deep TLD Validation:** Identifies catastrophic DNS vulnerabilities, such as missing IPv6 Glue Records at the `.vn` registry level.
- **Zero-Dependency Typst PDF & Charting:** Embeds the Typst typesetting engine (`typst-bake`), `Roboto` fonts, and pure-Rust `plotters` (`ab_glyph`) waterfall charts directly into the binary — no LaTeX, Chromium, or system `fontconfig` libraries required.

---

## Core Capabilities

- **360° DNS Introspection:** Evaluates root `AAAA` routing, Mail Exchange (`MX`) IPv6 readiness, and Authoritative Nameserver (`NS`) dual-stack compliance.
- **Deep TLD Glue Tracing:** Queries parent registries to verify strict IPv6 glue delegation, identifying domains that drop offline in pure IPv6-only networks.
- **Layer-7 WAF, TLS & QUIC Probing:** Executes live HTTPS and QUIC handshakes directly against resolved IPv6 addresses to catch silent Web Application Firewall (WAF) drops and UDP/443 blackholes.
- **In-Memory Executive Reporting:** Generates visual Happy Eyeballs latency waterfall charts, executive-ready Typst PDF audit dossiers, and structured CSV exports with zero external runtime dependencies.

---

## Installation

### Option 1: Pre-compiled Binaries (Recommended)

Download the pre-compiled standalone binary for your platform from the **[Releases](https://github.com/indianason/ipv6-audit/releases/latest)** page. No installation required — just drop it into your system path.

- **Windows (Client / Executive Audits):** `ipv6-audit-windows-amd64.exe`
- **Linux / Viettel IDC Servers (Static MUSL):** `ipv6-audit-linux-amd64`

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

#### After downloading Pre-compiled Binaries

Run an audit against a specific domain with strict TLD glue compliance checks:
```bash
./ipv6-audit-linux-amd64 --domain [https://viettel.vn](https://viettel.vn) --strict-compliance
```
*(On Windows CMD, replace `./ipv6-audit-linux-amd64` with `ipv6-audit-windows-amd64.exe`)*

#### After building from Source

```bash
ipv6-audit -d viettel.vn --strict-compliance
```
Note: The `--strict-compliance` flag forces a recursive root-to-TLD trace to enforce IPv6 Glue Record compliance.

Run an audit against a specific domain, simulating Google Chrome's 300ms fallback delay timer to measure the QUIC Trap penalty:
```bash
ipv6-audit --domain [https://aws.amazon.com/](https://aws.amazon.com/) --hev3-audit --emulate chrome
```
*Note: The engine will output structured JSON telemetry, generate an `aws.amazon.com_audit.csv`, and compile a heavily stylized `aws.amazon.com_audit.pdf` featuring the HEv3 waterfall chart.*

### Batch Infrastructure Audit

#### After downloading Pre-compiled Binaries

Provide a newline-delimited list of domains (`targets.txt`) to audit an entire enterprise portfolio:
```bash
./ipv6-audit-linux-amd64 --file targets.txt --strict-compliance
```
*(On Windows CMD, replace `./ipv6-audit-linux-amd64` with `ipv6-audit-windows-amd64.exe`)*

For Windows users: Because the executable is completely self-contained, you can run it from any directory (such as your `Downloads` folder) by providing the absolute path to your target list:
```DOS
ipv6-audit-windows-amd64.exe --file C:\Users\Admin\Downloads\targets.txt --strict-compliance
```
```DOS
ipv6-audit-windows-amd64.exe --file C:\Users\Admin\Downloads\targets.txt --hev3-audit --emulate chrome
```

#### After building from Source

```bash
ipv6-audit -i targets.txt --strict-compliance
```
*Note: The `--strict-compliance` flag forces a recursive root-to-TLD trace to enforce IPv6 Glue Record compliance.*

Provide a newline-delimited list of domains (`targets.txt`) to audit an entire enterprise portfolio concurrently:
```bash
ipv6-audit -i targets.txt --hev3-audit --emulate safari
```

---

## Audit Report Metrics

The generated PDF and CSV dossiers include the following telemetry points for each target domain:

| Field Name | Description |
| :--- | :--- |
| `web_ipv6_ready` | Does the root domain have a valid AAAA routing record? |
| `web_ipv6_reachable` | Did the TLS client successfully complete a Layer-7 HTTP probe over IPv6? |
| `mx_ipv6_ready` | Does the corporate Mail Exchange support IPv6 routing? |
| `ns_ipv6_ready` | Do the Authoritative Nameservers support IPv6 routing? |
| `strict_glue_ready` | Does the parent TLD registry contain the correct IPv6 delegation? |
| `fallback_penalty_ms` | Measured latency penalty (ms) - the wasted milliseconds a user waited for IPv6 QUIC before falling back to IPv4 (rendered as a waterfall chart in the PDF dossier). |
| `vulnerability_status` | The final synthesized architectural diagnosis (e.g., Critical Web Down, QUIC Trap Latency). |

---

## Architecture & Quality Doctrine

Built in Rust following a strict **3-Tier Testing Doctrine** and automated DevSecOps CI/CD (`cargo audit --deny warnings`, `cargo fmt -- --check`, `cargo clippy --all-targets -- -D warnings`):

* **Tier 1 (Domain Invariants):** Property-based testing (`proptest`) validating domain sanitization, bracketed IPv6 parsing, HEv3 QUIC fallback state machine transitions, and diagnosis synthesis.

* **Tier 2 (Unit & Doc Verification):** Deterministic validation of DNS primitives, sanitization rules, public API doc-tests, and DTO mappings.

* **Tier 3 (Black-Box Integration):** Network chaos simulation (`wiremock`) and end-to-end embedded Typst PDF/CSV rendering tests.

---

## License

Licensed under the **Apache License, Version 2.0**. Copyright © 2026 **Transvina**.
