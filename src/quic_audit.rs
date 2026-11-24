// src/quic_audit.rs

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::RootCertStore;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, instrument};

use crate::domain::errors::AuditError;
use crate::domain::primitives::ValidatedDomain;

/// [JON]: Built EXACTLY ONCE at application startup and shared across all audits.
/// Prevents UDP socket exhaustion and minimizes OS syscalls.
pub fn build_shared_ipv6_quic_endpoint() -> Result<Endpoint, AuditError> {
    // 1. Strict IPv6 Binding
    let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));

    // Map the IO error strictly to our domain error
    let mut endpoint = Endpoint::client(bind_addr)
        .map_err(|e| AuditError::NetworkConfigurationError(e.to_string()))?;

    // 2. Production TLS Configuration (Luca: No empty root stores!)
    let mut root_store = RootCertStore::empty();
    // Assuming rustls-native-certs is used as per your Cargo.toml
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        root_store.add(cert).unwrap();
    }

    let mut rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Enforce HTTP/3 Protocol Negotiation (ALPN)
    rustls_config.alpn_protocols = vec![b"h3".to_vec()];

    // Wrap the rustls config in the Quinn crypto adapter
    let quic_crypto = QuicClientConfig::try_from(rustls_config)
        .map_err(|e| AuditError::NetworkConfigurationError(e.to_string()))?;

    // 3. Aggressive Timeouts to catch the HEv3 "QUIC Trap"
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_millis(250).try_into().unwrap()));

    // Pass the crypto adapter instead of rustls_config directly
    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// [LUCA]: Strictly requires a `ValidatedDomain` - impossible to pass dirty data.
#[instrument(skip(endpoint), fields(target_ip = %target_addr.ip(), domain = %domain.as_str()))]
pub async fn execute_quic_audit(
    endpoint: &Endpoint,
    target_addr: SocketAddr,
    domain: &ValidatedDomain,
) -> Result<Connection, AuditError> {
    info!("Firing UDP/QUIC HTTP/3 probe...");

    // Initiate the connection. Map Quinn errors to our domain errors.
    let connecting = endpoint
        .connect(target_addr, domain.as_str())
        .map_err(|e| AuditError::QuicConnectionFailed(e.to_string()))?;

    let connection = connecting
        .await
        .map_err(|e| AuditError::QuicConnectionFailed(e.to_string()))?;

    info!("QUIC Handshake successful! UDP Port 443 is routing HTTP/3 correctly.");
    Ok(connection)
}
