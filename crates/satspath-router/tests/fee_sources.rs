use satspath_router::fees::{
    current_time_secs, normalize_esplora_url, CachedEstimate, EsploraFeeEstimate, FeeEstimate,
    FeeEstimatorConfig, FeeSource, FALLBACK_FEES,
};
use satspath_router::fetch_fee_estimate_with_config;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

fn config(sources: Vec<FeeSource>) -> FeeEstimatorConfig {
    FeeEstimatorConfig {
        sources,
        min_sources_for_consensus: 1,
        max_staleness_secs: 1800,
        request_timeout_ms: 100,
        cache: None,
    }
    .with_isolated_cache()
}

#[test]
fn esplora_target_rates_are_parsed_and_sanitized() {
    let estimate = EsploraFeeEstimate(HashMap::from([
        ("1".into(), 35.5),
        ("3".into(), 22.0),
        ("6".into(), 15.0),
        ("24".into(), 5.0),
        ("1008".into(), 1.0),
    ]))
    .to_fee_estimate()
    .unwrap();
    assert_eq!(estimate.fastest_fee, 36);
    assert_eq!(estimate.half_hour_fee, 22);
    assert_eq!(estimate.hour_fee, 15);
    assert_eq!(estimate.economy_fee, 5);
    assert_eq!(estimate.minimum_fee, 1);
    assert_eq!(
        normalize_esplora_url("https://example.com/api"),
        "https://example.com/api/fee-estimates"
    );
}

#[tokio::test]
async fn fee_sources_reject_private_credentials_and_insecure_urls_before_network() {
    for url in [
        "http://127.0.0.1:8332/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://10.0.0.1/",
        "https://169.254.169.254/",
        "https://user:password@example.com/",
        "https://example.com:8332/",
        "https://example.com/#fragment",
        "http://example.com/",
    ] {
        let sources = vec![
            FeeSource::BitcoinCore {
                rpc_url: url.into(),
                rpc_user: Some("secret-user".into()),
                rpc_password: Some("secret-password".into()),
            },
            FeeSource::Esplora { url: url.into() },
            FeeSource::MempoolSpace { url: url.into() },
        ];
        let report = fetch_fee_estimate_with_config(&config(sources))
            .await
            .unwrap();
        assert_eq!(report.sources_succeeded, 0, "{url}");
        assert_eq!(report.estimate, FALLBACK_FEES, "{url}");
    }
}

#[tokio::test]
async fn multi_source_consensus_neutralizes_malicious_oracle() {
    let estimate = |fastest_fee, half_hour_fee, hour_fee, economy_fee| {
        FeeSource::Static(FeeEstimate {
            fastest_fee,
            half_hour_fee,
            hour_fee,
            economy_fee,
            minimum_fee: 1,
        })
    };
    let report = fetch_fee_estimate_with_config(&config(vec![
        estimate(25, 18, 12, 6),
        estimate(27, 19, 13, 7),
        estimate(10_000, 10_000, 10_000, 10_000),
    ]))
    .await
    .unwrap();
    assert_eq!(report.sources_succeeded, 3);
    assert_eq!(report.estimate.fastest_fee, 27);
    assert_eq!(report.estimate.half_hour_fee, 19);
    assert_eq!(report.estimate.hour_fee, 13);
    assert_eq!(report.estimate.economy_fee, 7);
    assert!(!report.is_from_cache);
}

#[tokio::test]
async fn offline_decaying_cache_and_staleness_fallback() {
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

    let config = FeeEstimatorConfig {
        sources: vec![FeeSource::MempoolSpace {
            url: "http://127.0.0.1:9/unreachable".into(),
        }],
        min_sources_for_consensus: 1,
        max_staleness_secs: 3600,
        request_timeout_ms: 100,
        cache: Some(isolated_cache.clone()),
    };
    let report = fetch_fee_estimate_with_config(&config).await.unwrap();
    assert!(report.is_from_cache);
    assert_eq!(report.estimate.hour_fee, 30);
    assert_eq!(report.sources_succeeded, 0);

    *isolated_cache.write().unwrap() = Some(CachedEstimate {
        estimate: initial_estimate,
        timestamp_secs: cached_time.saturating_sub(7200),
        sources_used: vec!["preloaded_oracle".into()],
    });
    let expired = fetch_fee_estimate_with_config(&config).await.unwrap();
    assert_eq!(expired.estimate, FALLBACK_FEES);
    assert!(!expired.is_from_cache);
}
