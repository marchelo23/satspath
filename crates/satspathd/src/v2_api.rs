//! V2 API route handlers for the authoritative SatsPath server.
//!
//! These handlers serve proof-carrying resolution envelopes,
//! namespace descriptors, checkpoints, and health status.
//! The server hosts **public identity data only** — no private keys
//! or wallet spending material ever cross this boundary.

use serde::{Deserialize, Serialize};

/// V2 health/readiness response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2HealthResponse {
    pub version: String,
    pub status: String,
    pub checkpoint_age_secs: i64,
    pub witness_quorum_healthy: bool,
    pub replica_count: u32,
}

/// All V2 API route paths.
#[allow(dead_code)]
pub mod routes {
    pub const NAMESPACE: &str = "/v2/namespace";
    pub const RESOLVE: &str = "/v2/resolve";
    pub const CHECKPOINT_LATEST: &str = "/v2/checkpoint/latest";
    pub const HEALTH: &str = "/v2/health";
}

/// Build a health response for the V2 API.
pub fn build_health_response(
    checkpoint_age_secs: i64,
    witness_quorum_healthy: bool,
    replica_count: u32,
) -> V2HealthResponse {
    V2HealthResponse {
        version: "2.0.0".to_string(),
        status: if witness_quorum_healthy
            && replica_count > 0
            && (0..3600).contains(&checkpoint_age_secs)
        {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        checkpoint_age_secs,
        witness_quorum_healthy,
        replica_count,
    }
}
