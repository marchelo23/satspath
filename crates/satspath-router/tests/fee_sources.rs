use mockito::Server;
use satspath_router::fees::{
    current_time_secs, CachedEstimate, FeeEstimate, FeeEstimatorConfig, FeeSource, FALLBACK_FEES,
};
use satspath_router::fetch_fee_estimate_with_config;
use serde_json::json;
use std::sync::{Arc, RwLock};

#[tokio::test]
async fn test_esplora_mock_fee_estimation() {
    let mut server = Server::new_async().await;
    let url = server.url();

    let esplora_payload = json!({
        "1": 35.5,
        "2": 28.0,
        "3": 22.0,
        "6": 15.0,
        "24": 5.0,
        "144": 2.0,
        "1008": 1.0
    });

    let _m = server
        .mock("GET", "/api/fee-estimates")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(esplora_payload.to_string())
        .create_async()
        .await;

    let config = FeeEstimatorConfig {
        sources: vec![FeeSource::Esplora {
            url: format!("{}/api/fee-estimates", url),
        }],
        min_sources_for_consensus: 1,
        max_staleness_secs: 1800,
        request_timeout_ms: 2000,
        cache: None,
    }
    .with_isolated_cache();

    let report = fetch_fee_estimate_with_config(&config)
        .await
        .expect("report succeeds");

    assert_eq!(report.sources_succeeded, 1);
    assert_eq!(report.estimate.fastest_fee, 36);
    assert_eq!(report.estimate.half_hour_fee, 22);
    assert_eq!(report.estimate.hour_fee, 15);
    assert_eq!(report.estimate.economy_fee, 5);
    assert_eq!(report.estimate.minimum_fee, 1);
    assert!(!report.is_from_cache);
}

#[tokio::test]
async fn test_bitcoin_core_rpc_mock_fee_estimation() {
    let mut server = Server::new_async().await;
    let url = server.url();

    // Mock estimatesmartfee for target 1 (fastest: 0.00030 BTC/kvB = 30 sat/vB)
    let _m1 = server
        .mock("POST", "/")
        .match_body(mockito::Matcher::Regex(r#""params":\s*\[1\]"#.into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "result": { "feerate": 0.00030, "blocks": 1 },
                "error": null,
                "id": "satspath"
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Mock estimatesmartfee for target 3 (half-hour: 0.00020 BTC/kvB = 20 sat/vB)
    let _m3 = server
        .mock("POST", "/")
        .match_body(mockito::Matcher::Regex(r#""params":\s*\[3\]"#.into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "result": { "feerate": 0.00020, "blocks": 3 },
                "error": null,
                "id": "satspath"
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Mock estimatesmartfee for target 6 (hour: 0.00012 BTC/kvB = 12 sat/vB)
    let _m6 = server
        .mock("POST", "/")
        .match_body(mockito::Matcher::Regex(r#""params":\s*\[6\]"#.into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "result": { "feerate": 0.00012, "blocks": 6 },
                "error": null,
                "id": "satspath"
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Mock estimatesmartfee for target 24 (economy: 0.00004 BTC/kvB = 4 sat/vB)
    let _m24 = server
        .mock("POST", "/")
        .match_body(mockito::Matcher::Regex(r#""params":\s*\[24\]"#.into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "result": { "feerate": 0.00004, "blocks": 24 },
                "error": null,
                "id": "satspath"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let config = FeeEstimatorConfig {
        sources: vec![FeeSource::BitcoinCore {
            rpc_url: url,
            rpc_user: Some("testuser".into()),
            rpc_password: Some("testpass".into()),
        }],
        min_sources_for_consensus: 1,
        max_staleness_secs: 1800,
        request_timeout_ms: 2000,
        cache: None,
    }
    .with_isolated_cache();

    let report = fetch_fee_estimate_with_config(&config)
        .await
        .expect("core rpc report succeeds");

    assert_eq!(report.sources_succeeded, 1);
    assert_eq!(report.estimate.fastest_fee, 30);
    assert_eq!(report.estimate.half_hour_fee, 20);
    assert_eq!(report.estimate.hour_fee, 12);
    assert_eq!(report.estimate.economy_fee, 4);
    assert_eq!(report.estimate.minimum_fee, 1);
}

#[tokio::test]
async fn test_multi_source_consensus_neutralizes_malicious_oracle() {
    let mut server = Server::new_async().await;
    let url = server.url();

    // Honest source 1: Mempool.space
    let _m1 = server
        .mock("GET", "/mempool")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "fastestFee": 25,
                "halfHourFee": 18,
                "hourFee": 12,
                "economyFee": 6,
                "minimumFee": 1
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Honest source 2: Esplora
    let _m2 = server
        .mock("GET", "/esplora")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "1": 27.0,
                "3": 19.0,
                "6": 13.0,
                "24": 7.0,
                "1008": 1.0
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Compromised / Malicious source 3: reporting massive fee spike (10,000 sat/vB)
    let _m3 = server
        .mock("GET", "/malicious")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "fastestFee": 10000,
                "halfHourFee": 10000,
                "hourFee": 10000,
                "economyFee": 10000,
                "minimumFee": 10000
            })
            .to_string(),
        )
        .create_async()
        .await;

    let config = FeeEstimatorConfig {
        sources: vec![
            FeeSource::MempoolSpace {
                url: format!("{}/mempool", url),
            },
            FeeSource::Esplora {
                url: format!("{}/esplora", url),
            },
            FeeSource::MempoolSpace {
                url: format!("{}/malicious", url),
            },
        ],
        min_sources_for_consensus: 2,
        max_staleness_secs: 1800,
        request_timeout_ms: 2000,
        cache: None,
    }
    .with_isolated_cache();

    let report = fetch_fee_estimate_with_config(&config)
        .await
        .expect("consensus report succeeds");

    assert_eq!(report.sources_succeeded, 3);
    // Median across [25, 27, 10000] is 27! The 10,000 sat/vB attacker is completely neutralized.
    assert_eq!(report.estimate.fastest_fee, 27);
    // Median across [18, 19, 10000] is 19!
    assert_eq!(report.estimate.half_hour_fee, 19);
    // Median across [12, 13, 10000] is 13!
    assert_eq!(report.estimate.hour_fee, 13);
    // Median across [6, 7, 10000] is 7!
    assert_eq!(report.estimate.economy_fee, 7);
    assert_eq!(report.estimate.minimum_fee, 1);
    assert!(!report.is_from_cache);
}

#[tokio::test]
async fn test_offline_decaying_cache_and_staleness_fallback() {
    let cached_time = current_time_secs();
    let initial_estimate = FeeEstimate {
        fastest_fee: 50,
        half_hour_fee: 40,
        hour_fee: 30,
        economy_fee: 20,
        minimum_fee: 5,
    };

    let isolated_cache = Arc::new(RwLock::new(Some(CachedEstimate {
        estimate: initial_estimate.clone(),
        timestamp_secs: cached_time,
        sources_used: vec!["preloaded_oracle".into()],
    })));

    // Point config to non-existent endpoint to simulate total offline network partition
    let config = FeeEstimatorConfig {
        sources: vec![FeeSource::MempoolSpace {
            url: "http://127.0.0.1:9/unreachable".into(),
        }],
        min_sources_for_consensus: 1,
        max_staleness_secs: 3600,
        request_timeout_ms: 100,
        cache: Some(isolated_cache.clone()),
    };

    let report = fetch_fee_estimate_with_config(&config)
        .await
        .expect("report succeeds via cache");

    assert!(report.is_from_cache);
    // Because elapsed is 0, estimate matches the cached fee exactly
    assert_eq!(report.estimate.hour_fee, 30);
    assert_eq!(report.sources_succeeded, 0);

    // Now test staleness cutoff: simulate an expired cache timestamp older than max_staleness
    let expired_timestamp = cached_time.saturating_sub(7200); // 2 hours ago
    *isolated_cache.write().unwrap() = Some(CachedEstimate {
        estimate: initial_estimate,
        timestamp_secs: expired_timestamp,
        sources_used: vec!["preloaded_oracle".into()],
    });

    let expired_report = fetch_fee_estimate_with_config(&config)
        .await
        .expect("report succeeds via fallback");

    // Stale cache is rejected, falling back to FALLBACK_FEES
    assert_eq!(expired_report.estimate, FALLBACK_FEES);
    assert!(!expired_report.is_from_cache);
}
