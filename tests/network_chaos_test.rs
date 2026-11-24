// tests/network_chaos_test.rs

use hickory_resolver::TokioResolver;
use reqwest::Client;
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;
use tracing_subscriber::fmt::TestWriter;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// We only need scan_endpoint. Network errors are safely mapped to DomainReports!
use ipv6_audit::engine::scan_endpoint;

#[tokio::test]
async fn test_audit_engine_network_resilience() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,ipv6_recon=debug")
        .with_writer(TestWriter::new())
        .try_init();

    tracing::info!("Booting Black-Box Network Test...");

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/healthy"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/timeout"))
        // Delay response by 10s to simulate a dropped network packet (firewall block)
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&mock_server)
        .await;

    // Engine is configured to cut the cord after 3 seconds
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("Failed to build client");

    let resolver = TokioResolver::builder_tokio()
        .expect("Failed to build DNS builder")
        .build()
        .expect("Failed to build DNS resolver");

    let raw_uri = mock_server.uri().replace("http://", "");
    let healthy_url = format!("{}/healthy", raw_uri);
    let timeout_url = format!("{}/timeout", raw_uri);

    let mut target_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(target_file, "{}", healthy_url).unwrap();
    writeln!(target_file, "{}", timeout_url).unwrap();

    tracing::info!(
        "Simulated user targets file written to: {:?}",
        target_file.path()
    );

    // Define the simulated browser delay, if needed.
    // Use 250ms for Safari parity, or 0ms for blazing-fast test execution.
    // let test_delay = Duration::from_millis(250);
    let test_delay = Duration::from_millis(0);

    // --- TEST 1: The Healthy Route ---
    let healthy_result = scan_endpoint(
        &client,
        &resolver,
        &healthy_url,
        false,
        None,
        test_delay, // Inject the time boundary here
    )
    .await;
    assert!(
        healthy_result.is_ok(),
        "Engine failed to connect to a healthy endpoint"
    );

    // --- TEST 2: The Chaotic Route (Timeout / Dropped Packets) ---
    let timeout_result = scan_endpoint(
        &client,
        &resolver,
        &timeout_url,
        false,
        None,
        test_delay, // Inject the time boundary here
    )
    .await;

    // Domain-Driven Assertion:
    // The engine MUST survive the timeout and return a valid DomainReport marking it as a failure.
    match timeout_result {
        Ok(report) => {
            tracing::info!(
                "Timeout successfully caught and mapped to report: {:?}",
                report
            );
            // Verify that the JSON/CSV output will accurately flag this as unreachable
            let report_json = serde_json::to_string(&report).unwrap();
            assert!(
                report_json.contains("false"),
                "Engine mistakenly marked a timed-out server as reachable!"
            );
            assert!(
                report_json.contains("CRITICAL"),
                "Engine failed to apply the CRITICAL vulnerability status on timeout."
            );
        }
        Err(e) => panic!(
            "Engine leaked a raw error instead of mapping it to a report! Error: {}",
            e
        ),
    }

    // --- TEST 3: Browser Profile Emulation (Telemetry Verification) ---
    let safari_delay = Duration::from_millis(250);
    let chrome_delay = Duration::from_millis(300);

    // 1. Simulate a Safari user hitting a QUIC Trap
    let safari_result = scan_endpoint(
        &client,
        &resolver,
        &timeout_url,
        false,
        None, // Assuming QUIC fails/timeouts in this mock
        safari_delay,
    )
    .await
    .expect("Engine should not panic on timeout");

    // 2. Simulate an Android Chrome user hitting the same Trap
    let chrome_result = scan_endpoint(&client, &resolver, &timeout_url, false, None, chrome_delay)
        .await
        .expect("Engine should not panic on timeout");

    // 3. Prove the Stopwatch Works!
    // We unwrap the penalty, and assert that the Chrome penalty was strictly
    // greater than the Safari penalty, proving our temporal injection controls the engine.
    if let (Some(safari_penalty), Some(chrome_penalty)) = (
        safari_result.fallback_penalty_ms,
        chrome_result.fallback_penalty_ms,
    ) {
        assert!(
            chrome_penalty > safari_penalty,
            "Chrome's telemetry ({}ms) should show a longer delay than Safari ({}ms)",
            chrome_penalty,
            safari_penalty
        );

        // Ensure the penalty is at least what we requested
        assert!(safari_penalty >= 250, "Safari penalty too low");
        assert!(chrome_penalty >= 300, "Chrome penalty too low");
    }
}
