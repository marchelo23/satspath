//! Multi-source Bitcoin fee estimation engine with median consensus,
//! staleness rejection, and decaying cache fallback.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::RwLock;

use satspath_core::{Result, SatsPathError};

/// Recommended fee rates from mempool.space (camelCase for JSON).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MempoolFeeEstimate {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

/// Raw fee rate estimates from an Esplora-compatible endpoint (/api/fee-estimates).
/// Maps confirmation targets (in blocks as string keys) to sat/vB fee rates (floats).
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct EsploraFeeEstimate(pub HashMap<String, f64>);

impl EsploraFeeEstimate {
    /// Convert Esplora target-based fee estimates into our 5-tier FeeEstimate.
    pub fn to_fee_estimate(&self) -> Option<FeeEstimate> {
        if self.0.is_empty() {
            return None;
        }

        let mut targets: Vec<(u64, f64)> = self
            .0
            .iter()
            .filter_map(|(k, v)| k.parse::<u64>().ok().map(|target| (target, *v)))
            .filter(|(_, rate)| *rate > 0.0 && !rate.is_nan() && !rate.is_infinite())
            .collect();

        if targets.is_empty() {
            return None;
        }

        targets.sort_by_key(|(t, _)| *t);

        let get_rate = |desired: u64| -> u64 {
            if let Some((_, rate)) = targets.iter().find(|(t, _)| *t == desired) {
                return (rate.ceil() as u64).max(1);
            }
            if let Some((_, rate)) = targets.iter().find(|(t, _)| *t >= desired) {
                return (rate.ceil() as u64).max(1);
            }
            if let Some((_, rate)) = targets.last() {
                return (rate.ceil() as u64).max(1);
            }
            1
        };

        let fastest = targets
            .first()
            .map(|(_, r)| (r.ceil() as u64).max(1))
            .unwrap_or(1);
        let half_hour = get_rate(3);
        let hour = get_rate(6);
        let economy = get_rate(24);
        let minimum = targets
            .last()
            .map(|(_, r)| (r.ceil() as u64).max(1))
            .unwrap_or(1);

        let mut est = FeeEstimate {
            fastest_fee: fastest,
            half_hour_fee: half_hour,
            hour_fee: hour,
            economy_fee: economy,
            minimum_fee: minimum,
        };
        est.sanitize();
        Some(est)
    }
}

/// Internal fee estimate type used by the router (sat/vB).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

impl FeeEstimate {
    /// Enforce sanity bounds and non-decreasing ordering:
    /// fastest >= half_hour >= hour >= economy >= minimum >= 1
    pub fn sanitize(&mut self) {
        self.minimum_fee = std::cmp::max(1, self.minimum_fee);
        self.economy_fee = std::cmp::max(self.minimum_fee, self.economy_fee);
        self.hour_fee = std::cmp::max(self.economy_fee, self.hour_fee);
        self.half_hour_fee = std::cmp::max(self.hour_fee, self.half_hour_fee);
        self.fastest_fee = std::cmp::max(self.half_hour_fee, self.fastest_fee);
    }
}

impl From<MempoolFeeEstimate> for FeeEstimate {
    fn from(e: MempoolFeeEstimate) -> Self {
        let mut est = FeeEstimate {
            fastest_fee: e.fastest_fee,
            half_hour_fee: e.half_hour_fee,
            hour_fee: e.hour_fee,
            economy_fee: e.economy_fee,
            minimum_fee: e.minimum_fee,
        };
        est.sanitize();
        est
    }
}

/// Fallback fees when network is unavailable (conservative estimates in sat/vB).
pub const FALLBACK_FEES: FeeEstimate = FeeEstimate {
    fastest_fee: 20,
    half_hour_fee: 15,
    hour_fee: 10,
    economy_fee: 5,
    minimum_fee: 1,
};

/// Configurable fee source descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeSource {
    /// Bitcoin Core JSON-RPC using estimatesmartfee.
    BitcoinCore {
        rpc_url: String,
        rpc_user: Option<String>,
        rpc_password: Option<String>,
    },
    /// Mempool.space recommended fee endpoint (/api/v1/fees/recommended).
    MempoolSpace { url: String },
    /// Esplora fee-estimates endpoint (/api/fee-estimates).
    Esplora { url: String },
    /// Static fee estimate for testing or deterministic environments.
    Static(FeeEstimate),
}

impl FeeSource {
    pub fn name(&self) -> String {
        match self {
            FeeSource::BitcoinCore { rpc_url, .. } => format!("BitcoinCore({})", rpc_url),
            FeeSource::MempoolSpace { url } => format!("MempoolSpace({})", url),
            FeeSource::Esplora { url } => format!("Esplora({})", url),
            FeeSource::Static(_) => "Static".to_string(),
        }
    }
}

/// Configuration for the multi-source fee estimation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimatorConfig {
    /// Prioritized list of fee sources to query.
    pub sources: Vec<FeeSource>,
    /// Minimum number of successful source estimates required for consensus (default: 1).
    pub min_sources_for_consensus: usize,
    /// Maximum age in seconds before a cached estimate is considered stale and rejected (default: 1800, i.e. 30m).
    pub max_staleness_secs: u64,
    /// Request timeout in milliseconds for each oracle call (default: 3000ms).
    pub request_timeout_ms: u64,
}

impl Default for FeeEstimatorConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl FeeEstimatorConfig {
    /// Build configuration from environment variables with sensible defaults.
    pub fn from_env() -> Self {
        let max_staleness_secs = env::var("SATSPATH_FEE_MAX_STALENESS_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1800);

        let request_timeout_ms = env::var("SATSPATH_FEE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000);

        let min_sources_for_consensus = env::var("SATSPATH_FEE_MIN_SOURCES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);

        let mut sources = Vec::new();

        if let Ok(src_str) = env::var("SATSPATH_FEE_SOURCES") {
            for token in src_str.split(',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                match token.to_ascii_lowercase().as_str() {
                    "core" | "bitcoincore" | "rpc" => {
                        let url = env::var("SATSPATH_BITCOIN_RPC_URL")
                            .ok()
                            .or_else(|| env::var("BITCOIN_RPC_URL").ok());
                        let user = env::var("SATSPATH_BITCOIN_RPC_USER")
                            .ok()
                            .or_else(|| env::var("BITCOIN_RPC_USER").ok());
                        let pass = env::var("SATSPATH_BITCOIN_RPC_PASSWORD")
                            .ok()
                            .or_else(|| env::var("BITCOIN_RPC_PASS").ok());
                        if let Some(rpc_url) = url {
                            sources.push(FeeSource::BitcoinCore {
                                rpc_url,
                                rpc_user: user,
                                rpc_password: pass,
                            });
                        }
                    }
                    "mempool" | "mempoolspace" => {
                        let url = env::var("SATSPATH_MEMPOOL_URL").unwrap_or_else(|_| {
                            "https://mempool.space/api/v1/fees/recommended".to_string()
                        });
                        sources.push(FeeSource::MempoolSpace {
                            url: normalize_mempool_url(&url),
                        });
                    }
                    "esplora" => {
                        let url = env::var("SATSPATH_ESPLORA_URL").unwrap_or_else(|_| {
                            "https://blockstream.info/api/fee-estimates".to_string()
                        });
                        sources.push(FeeSource::Esplora {
                            url: normalize_esplora_url(&url),
                        });
                    }
                    other => {
                        if let Some(stripped) = other.strip_prefix("mempool:") {
                            sources.push(FeeSource::MempoolSpace {
                                url: normalize_mempool_url(stripped),
                            });
                        } else if let Some(stripped) = other.strip_prefix("esplora:") {
                            sources.push(FeeSource::Esplora {
                                url: normalize_esplora_url(stripped),
                            });
                        } else if let Some(stripped) = other.strip_prefix("core:") {
                            sources.push(FeeSource::BitcoinCore {
                                rpc_url: stripped.to_string(),
                                rpc_user: None,
                                rpc_password: None,
                            });
                        }
                    }
                }
            }
        }

        // If no explicit sources configured via SATSPATH_FEE_SOURCES, build standard multi-source set:
        if sources.is_empty() {
            let rpc_url = env::var("SATSPATH_BITCOIN_RPC_URL")
                .ok()
                .or_else(|| env::var("BITCOIN_RPC_URL").ok());
            if let Some(url) = rpc_url {
                let user = env::var("SATSPATH_BITCOIN_RPC_USER")
                    .ok()
                    .or_else(|| env::var("BITCOIN_RPC_USER").ok());
                let pass = env::var("SATSPATH_BITCOIN_RPC_PASSWORD")
                    .ok()
                    .or_else(|| env::var("BITCOIN_RPC_PASS").ok());
                sources.push(FeeSource::BitcoinCore {
                    rpc_url: url,
                    rpc_user: user,
                    rpc_password: pass,
                });
            }

            let mempool_url = env::var("SATSPATH_MEMPOOL_URL")
                .unwrap_or_else(|_| "https://mempool.space/api/v1/fees/recommended".to_string());
            sources.push(FeeSource::MempoolSpace {
                url: normalize_mempool_url(&mempool_url),
            });

            let esplora_url = env::var("SATSPATH_ESPLORA_URL")
                .unwrap_or_else(|_| "https://blockstream.info/api/fee-estimates".to_string());
            sources.push(FeeSource::Esplora {
                url: normalize_esplora_url(&esplora_url),
            });

            sources.push(FeeSource::MempoolSpace {
                url: "https://mempool.ninja/api/v1/fees/recommended".to_string(),
            });
        }

        Self {
            sources,
            min_sources_for_consensus,
            max_staleness_secs,
            request_timeout_ms,
        }
    }
}

/// Compute median across multiple fee estimates for each fee tier.
/// Neutralizes malicious or corrupted outliers.
pub fn compute_median_fee(estimates: &[FeeEstimate]) -> Option<FeeEstimate> {
    if estimates.is_empty() {
        return None;
    }
    if estimates.len() == 1 {
        let mut est = estimates[0].clone();
        est.sanitize();
        return Some(est);
    }

    let median_of = |extractor: fn(&FeeEstimate) -> u64| -> u64 {
        let mut vals: Vec<u64> = estimates.iter().map(extractor).collect();
        vals.sort_unstable();
        let len = vals.len();
        if len % 2 == 1 {
            vals[len / 2]
        } else {
            let mid1 = vals[(len / 2) - 1];
            let mid2 = vals[len / 2];
            (mid1 + mid2).div_ceil(2)
        }
    };

    let fastest = median_of(|e| e.fastest_fee);
    let half_hour = median_of(|e| e.half_hour_fee);
    let hour = median_of(|e| e.hour_fee);
    let economy = median_of(|e| e.economy_fee);
    let minimum = median_of(|e| e.minimum_fee);

    let mut est = FeeEstimate {
        fastest_fee: fastest,
        half_hour_fee: half_hour,
        hour_fee: hour,
        economy_fee: economy,
        minimum_fee: minimum,
    };
    est.sanitize();
    Some(est)
}

/// Decay a cached fee estimate towards FALLBACK_FEES over elapsed time.
/// When elapsed >= max_staleness, FALLBACK_FEES is returned.
pub fn decay_estimate(
    cached: &FeeEstimate,
    elapsed_secs: u64,
    max_staleness_secs: u64,
) -> FeeEstimate {
    if max_staleness_secs == 0 || elapsed_secs >= max_staleness_secs {
        return FALLBACK_FEES;
    }
    let factor = (elapsed_secs as f64) / (max_staleness_secs as f64);
    let decay_field = |cached_val: u64, fallback_val: u64| -> u64 {
        let decayed = (cached_val as f64) * (1.0 - factor) + (fallback_val as f64) * factor;
        (decayed.round() as u64).max(1)
    };

    let mut est = FeeEstimate {
        fastest_fee: decay_field(cached.fastest_fee, FALLBACK_FEES.fastest_fee),
        half_hour_fee: decay_field(cached.half_hour_fee, FALLBACK_FEES.half_hour_fee),
        hour_fee: decay_field(cached.hour_fee, FALLBACK_FEES.hour_fee),
        economy_fee: decay_field(cached.economy_fee, FALLBACK_FEES.economy_fee),
        minimum_fee: decay_field(cached.minimum_fee, FALLBACK_FEES.minimum_fee),
    };
    est.sanitize();
    est
}

/// Cached consensus estimate with timestamp and provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEstimate {
    pub estimate: FeeEstimate,
    pub timestamp_secs: u64,
    pub sources_used: Vec<String>,
}

/// Detailed consensus fee estimation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusFeeReport {
    pub estimate: FeeEstimate,
    pub timestamp_secs: u64,
    pub sources_queried: usize,
    pub sources_succeeded: usize,
    pub source_names: Vec<String>,
    pub is_from_cache: bool,
    pub is_decayed: bool,
}

static CACHED_FEE: RwLock<Option<CachedEstimate>> = RwLock::new(None);

pub fn update_cached_fee(estimate: FeeEstimate, sources_used: Vec<String>, timestamp_secs: u64) {
    if let Ok(mut lock) = CACHED_FEE.write() {
        *lock = Some(CachedEstimate {
            estimate,
            timestamp_secs,
            sources_used,
        });
    }
}

pub fn get_cached_fee() -> Option<CachedEstimate> {
    CACHED_FEE.read().ok().and_then(|lock| lock.clone())
}

pub fn clear_cached_fee() {
    if let Ok(mut lock) = CACHED_FEE.write() {
        *lock = None;
    }
}

pub fn current_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn normalize_esplora_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.ends_with("/fee-estimates") {
        trimmed.to_string()
    } else {
        format!("{}/fee-estimates", trimmed)
    }
}

pub fn normalize_mempool_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.ends_with("/api/v1/fees/recommended") {
        trimmed.to_string()
    } else if trimmed.ends_with("/api/v1/fees") {
        format!("{}/recommended", trimmed)
    } else if trimmed.ends_with("/api/v1") {
        format!("{}/fees/recommended", trimmed)
    } else if trimmed.ends_with("/api") {
        format!("{}/v1/fees/recommended", trimmed)
    } else {
        format!("{}/api/v1/fees/recommended", trimmed)
    }
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<SmartFeeResult>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SmartFeeResult {
    feerate: Option<f64>,
    #[allow(dead_code)]
    errors: Option<Vec<String>>,
}

#[cfg(feature = "std")]
pub mod native_fees {
    use super::*;
    use reqwest::Client;

    pub async fn fetch_rpc_target_fee(
        target: u64,
        client: &Client,
        url: &str,
        auth: &Option<(String, Option<String>)>,
    ) -> Option<u64> {
        let req = RpcRequest {
            jsonrpc: "1.0",
            id: "satspath",
            method: "estimatesmartfee",
            params: vec![target],
        };
        let mut builder = client.post(url).json(&req);
        if let Some((user, pass)) = auth {
            builder = builder.basic_auth(user.clone(), pass.as_deref());
        }
        let res = builder
            .send()
            .await
            .ok()?
            .json::<RpcResponse>()
            .await
            .ok()?;
        if res.error.is_some() {
            return None;
        }
        let feerate_btc_kvb = res.result?.feerate?;
        if feerate_btc_kvb <= 0.0 || feerate_btc_kvb.is_nan() {
            return None;
        }
        let sat_vb = (feerate_btc_kvb * 100_000.0).ceil() as u64;
        Some(std::cmp::max(1, sat_vb))
    }

    pub async fn fetch_bitcoin_core_fee(
        url: &str,
        auth: &Option<(String, Option<String>)>,
        client: &Client,
    ) -> Option<FeeEstimate> {
        let (t1, t3, t6, t24) = tokio::join!(
            fetch_rpc_target_fee(1, client, url, auth),
            fetch_rpc_target_fee(3, client, url, auth),
            fetch_rpc_target_fee(6, client, url, auth),
            fetch_rpc_target_fee(24, client, url, auth),
        );

        let fastest = t1.or(t3).or(t6)?;
        let half_hour = t3.or(t6).unwrap_or(fastest);
        let hour = t6.unwrap_or(half_hour);
        let economy = t24.unwrap_or(std::cmp::max(1, hour / 2));
        let minimum = 1;

        let mut est = FeeEstimate {
            fastest_fee: fastest,
            half_hour_fee: half_hour,
            hour_fee: hour,
            economy_fee: economy,
            minimum_fee: minimum,
        };
        est.sanitize();
        Some(est)
    }

    pub async fn fetch_mempool_fee(url: &str, client: &Client) -> Option<FeeEstimate> {
        let resp = client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let est: MempoolFeeEstimate = resp.json().await.ok()?;
        Some(est.into())
    }

    pub async fn fetch_esplora_fee(url: &str, client: &Client) -> Option<FeeEstimate> {
        let resp = client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let map: EsploraFeeEstimate = resp.json().await.ok()?;
        map.to_fee_estimate()
    }

    pub async fn fetch_source_estimate(source: &FeeSource, client: &Client) -> Option<FeeEstimate> {
        match source {
            FeeSource::Static(est) => {
                let mut e = est.clone();
                e.sanitize();
                Some(e)
            }
            FeeSource::BitcoinCore {
                rpc_url,
                rpc_user,
                rpc_password,
            } => {
                let auth = rpc_user.as_ref().map(|u| (u.clone(), rpc_password.clone()));
                fetch_bitcoin_core_fee(rpc_url, &auth, client).await
            }
            FeeSource::MempoolSpace { url } => fetch_mempool_fee(url, client).await,
            FeeSource::Esplora { url } => fetch_esplora_fee(url, client).await,
        }
    }

    pub async fn fetch_consensus_fee(config: &FeeEstimatorConfig) -> Result<ConsensusFeeReport> {
        let now = current_time_secs();
        let client = Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(|e| SatsPathError::NetworkError(e.to_string()))?;

        let mut set = tokio::task::JoinSet::new();
        for source in &config.sources {
            let src = source.clone();
            let cl = client.clone();
            set.spawn(async move {
                let name = src.name();
                let est = fetch_source_estimate(&src, &cl).await;
                (name, est)
            });
        }

        let mut successful_estimates = Vec::new();
        let mut sources_used = Vec::new();

        while let Some(res) = set.join_next().await {
            if let Ok((name, Some(est))) = res {
                sources_used.push(name);
                successful_estimates.push(est);
            }
        }

        if successful_estimates.len() >= config.min_sources_for_consensus {
            if let Some(consensus) = compute_median_fee(&successful_estimates) {
                update_cached_fee(consensus.clone(), sources_used.clone(), now);
                return Ok(ConsensusFeeReport {
                    estimate: consensus,
                    timestamp_secs: now,
                    sources_queried: config.sources.len(),
                    sources_succeeded: successful_estimates.len(),
                    source_names: sources_used,
                    is_from_cache: false,
                    is_decayed: false,
                });
            }
        }

        // Fallback: check cached estimate with decay
        if let Some(cached) = get_cached_fee() {
            let elapsed = now.saturating_sub(cached.timestamp_secs);
            if elapsed < config.max_staleness_secs {
                let decayed = decay_estimate(&cached.estimate, elapsed, config.max_staleness_secs);
                return Ok(ConsensusFeeReport {
                    estimate: decayed,
                    timestamp_secs: cached.timestamp_secs,
                    sources_queried: config.sources.len(),
                    sources_succeeded: successful_estimates.len(),
                    source_names: cached.sources_used,
                    is_from_cache: true,
                    is_decayed: elapsed > 0,
                });
            }
        }

        // Ultimate fallback if no consensus and no valid cache
        Ok(ConsensusFeeReport {
            estimate: FALLBACK_FEES,
            timestamp_secs: now,
            sources_queried: config.sources.len(),
            sources_succeeded: successful_estimates.len(),
            source_names: vec!["FallbackFees".into()],
            is_from_cache: false,
            is_decayed: false,
        })
    }
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm_fees {
    use super::*;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{window, Request, RequestInit, RequestMode, Response};

    pub async fn fetch_fee_estimate() -> Result<FeeEstimate> {
        let window = window().ok_or_else(|| SatsPathError::NetworkError("no window".into()))?;

        let urls = [
            "https://mempool.space/api/v1/fees/recommended",
            "https://mempool.ninja/api/v1/fees/recommended",
        ];

        let mut collected = Vec::new();

        for url in urls {
            let opts = RequestInit::new();
            opts.set_method("GET");
            opts.set_mode(RequestMode::Cors);

            if let Ok(request) = Request::new_with_str_and_init(url, &opts) {
                if let Ok(resp_value) = JsFuture::from(window.fetch_with_request(&request)).await {
                    if let Ok(response) = resp_value.dyn_into::<Response>() {
                        if response.ok() {
                            if let Ok(json) = JsFuture::from(response.json()?).await {
                                if let Ok(estimate) =
                                    serde_wasm_bindgen::from_value::<MempoolFeeEstimate>(json)
                                {
                                    collected.push(estimate.into());
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(median) = compute_median_fee(&collected) {
            Ok(median)
        } else {
            Ok(FALLBACK_FEES)
        }
    }
}

/// Reusable multi-source fee estimator instance.
#[derive(Debug, Clone)]
pub struct MultiSourceFeeEstimator {
    pub config: FeeEstimatorConfig,
}

impl MultiSourceFeeEstimator {
    pub fn new(config: FeeEstimatorConfig) -> Self {
        Self { config }
    }

    pub fn default_from_env() -> Self {
        Self {
            config: FeeEstimatorConfig::default(),
        }
    }

    pub async fn estimate(&self) -> Result<ConsensusFeeReport> {
        fetch_fee_estimate_with_config(&self.config).await
    }
}

/// Fetch current fee estimates with multi-source consensus.
/// Falls back to decaying cache or FALLBACK_FEES on network errors.
pub async fn fetch_fee_estimate() -> Result<FeeEstimate> {
    #[cfg(feature = "std")]
    {
        let config = FeeEstimatorConfig::default();
        match native_fees::fetch_consensus_fee(&config).await {
            Ok(report) => Ok(report.estimate),
            Err(_) => Ok(FALLBACK_FEES),
        }
    }
    #[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "std")))]
    {
        match wasm_fees::fetch_fee_estimate().await {
            Ok(fee) => Ok(fee),
            Err(_) => Ok(FALLBACK_FEES),
        }
    }
    #[cfg(not(any(feature = "std", feature = "wasm")))]
    {
        Ok(FALLBACK_FEES)
    }
}

/// Fetch fee estimate report using explicit configuration.
pub async fn fetch_fee_estimate_with_config(
    config: &FeeEstimatorConfig,
) -> Result<ConsensusFeeReport> {
    #[cfg(feature = "std")]
    {
        native_fees::fetch_consensus_fee(config).await
    }
    #[cfg(not(feature = "std"))]
    {
        Ok(ConsensusFeeReport {
            estimate: FALLBACK_FEES,
            timestamp_secs: 0,
            sources_queried: config.sources.len(),
            sources_succeeded: 0,
            source_names: vec!["FallbackFees".into()],
            is_from_cache: false,
            is_decayed: false,
        })
    }
}

/// Synchronous getter for fallback fees (useful for tests/WASM).
pub fn fallback_fees() -> FeeEstimate {
    FALLBACK_FEES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_estimate_sanitization() {
        let mut est = FeeEstimate {
            fastest_fee: 5,
            half_hour_fee: 10,
            hour_fee: 15,
            economy_fee: 2,
            minimum_fee: 0,
        };
        est.sanitize();
        assert_eq!(est.minimum_fee, 1);
        assert_eq!(est.economy_fee, 2);
        assert_eq!(est.hour_fee, 15);
        assert_eq!(est.half_hour_fee, 15);
        assert_eq!(est.fastest_fee, 15);
    }

    #[test]
    fn test_esplora_parsing_and_mapping() {
        let mut raw = HashMap::new();
        raw.insert("1".to_string(), 25.4);
        raw.insert("2".to_string(), 20.1);
        raw.insert("3".to_string(), 18.0);
        raw.insert("6".to_string(), 12.0);
        raw.insert("24".to_string(), 4.5);
        raw.insert("144".to_string(), 2.0);
        raw.insert("1008".to_string(), 1.0);

        let esplora = EsploraFeeEstimate(raw);
        let est = esplora.to_fee_estimate().expect("should parse");
        assert_eq!(est.fastest_fee, 26);
        assert_eq!(est.half_hour_fee, 18);
        assert_eq!(est.hour_fee, 12);
        assert_eq!(est.economy_fee, 5);
        assert_eq!(est.minimum_fee, 1);
    }

    #[test]
    fn test_esplora_sparse_targets() {
        let mut raw = HashMap::new();
        raw.insert("2".to_string(), 30.0);
        raw.insert("10".to_string(), 15.0);

        let esplora = EsploraFeeEstimate(raw);
        let est = esplora.to_fee_estimate().expect("should parse");
        assert_eq!(est.fastest_fee, 30);
        assert_eq!(est.half_hour_fee, 15);
        assert_eq!(est.hour_fee, 15);
        assert_eq!(est.economy_fee, 15);
        assert_eq!(est.minimum_fee, 15);
    }

    #[test]
    fn test_compute_median_neutralizes_malicious_outlier() {
        let honest_1 = FeeEstimate {
            fastest_fee: 20,
            half_hour_fee: 15,
            hour_fee: 10,
            economy_fee: 5,
            minimum_fee: 1,
        };
        let honest_2 = FeeEstimate {
            fastest_fee: 22,
            half_hour_fee: 16,
            hour_fee: 11,
            economy_fee: 6,
            minimum_fee: 1,
        };
        // Malicious oracle attempts to inflate fee by 500x
        let attacker = FeeEstimate {
            fastest_fee: 10_000,
            half_hour_fee: 10_000,
            hour_fee: 10_000,
            economy_fee: 10_000,
            minimum_fee: 10_000,
        };

        let median = compute_median_fee(&[honest_1, honest_2, attacker]).expect("has median");
        assert_eq!(median.fastest_fee, 22);
        assert_eq!(median.half_hour_fee, 16);
        assert_eq!(median.hour_fee, 11);
        assert_eq!(median.economy_fee, 6);
        assert_eq!(median.minimum_fee, 1);
    }

    #[test]
    fn test_compute_median_even_number_of_sources() {
        let source_a = FeeEstimate {
            fastest_fee: 10,
            half_hour_fee: 8,
            hour_fee: 6,
            economy_fee: 4,
            minimum_fee: 1,
        };
        let source_b = FeeEstimate {
            fastest_fee: 20,
            half_hour_fee: 16,
            hour_fee: 12,
            economy_fee: 8,
            minimum_fee: 2,
        };

        let median = compute_median_fee(&[source_a, source_b]).expect("has median");
        assert_eq!(median.fastest_fee, 15);
        assert_eq!(median.half_hour_fee, 12);
        assert_eq!(median.hour_fee, 9);
        assert_eq!(median.economy_fee, 6);
        assert_eq!(median.minimum_fee, 2);
    }

    #[test]
    fn test_decay_estimate_progression() {
        let cached = FeeEstimate {
            fastest_fee: 100,
            half_hour_fee: 80,
            hour_fee: 60,
            economy_fee: 40,
            minimum_fee: 10,
        };

        let max_staleness = 1000;

        // At 0 seconds elapsed: exact cached estimate
        let d0 = decay_estimate(&cached, 0, max_staleness);
        assert_eq!(d0.hour_fee, 60);

        // At 500 seconds elapsed (50% staleness): halfway between 60 and FALLBACK_FEES.hour_fee (10) = 35
        let d500 = decay_estimate(&cached, 500, max_staleness);
        assert_eq!(d500.hour_fee, 35);

        // At 1000 seconds (100% staleness): falls back to FALLBACK_FEES
        let d1000 = decay_estimate(&cached, 1000, max_staleness);
        assert_eq!(d1000, FALLBACK_FEES);

        // Beyond max staleness: falls back to FALLBACK_FEES
        let d2000 = decay_estimate(&cached, 2000, max_staleness);
        assert_eq!(d2000, FALLBACK_FEES);
    }

    #[test]
    fn test_cache_lifecycle() {
        clear_cached_fee();
        assert!(get_cached_fee().is_none());

        let est = FeeEstimate {
            fastest_fee: 30,
            half_hour_fee: 25,
            hour_fee: 20,
            economy_fee: 10,
            minimum_fee: 2,
        };
        update_cached_fee(est.clone(), vec!["test_oracle".into()], 1234567);

        let cached = get_cached_fee().expect("cached present");
        assert_eq!(cached.estimate, est);
        assert_eq!(cached.timestamp_secs, 1234567);
        assert_eq!(cached.sources_used, vec!["test_oracle"]);

        clear_cached_fee();
        assert!(get_cached_fee().is_none());
    }

    #[test]
    fn test_url_normalization() {
        assert_eq!(
            normalize_esplora_url("https://blockstream.info/api"),
            "https://blockstream.info/api/fee-estimates"
        );
        assert_eq!(
            normalize_esplora_url("https://blockstream.info/api/"),
            "https://blockstream.info/api/fee-estimates"
        );
        assert_eq!(
            normalize_esplora_url("https://blockstream.info/api/fee-estimates"),
            "https://blockstream.info/api/fee-estimates"
        );

        assert_eq!(
            normalize_mempool_url("https://mempool.space"),
            "https://mempool.space/api/v1/fees/recommended"
        );
        assert_eq!(
            normalize_mempool_url("https://mempool.space/"),
            "https://mempool.space/api/v1/fees/recommended"
        );
        assert_eq!(
            normalize_mempool_url("https://mempool.space/api/v1/fees/recommended"),
            "https://mempool.space/api/v1/fees/recommended"
        );
    }
}
