//! Type definitions for WASM bindings — must match Rust satspath-core exactly

#![allow(
    dead_code,
    clippy::new_without_default,
    clippy::needless_borrow,
    clippy::needless_question_mark
)]
use serde::{Deserialize, Serialize};

/// Bitcoin network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

/// Payment method — tagged union matching Rust `PaymentMethod` enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum PaymentMethod {
    /// On-chain Bitcoin
    Onchain {
        label: String,
        #[serde(default = "default_bitcoin_network")]
        network: BitcoinNetwork,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        silent_payment_pubkey: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pubkey_hint: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        descriptor_hint: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        address_list: Vec<String>,
    },
    /// Lightning Network via LNURL, Lightning Address, or BOLT12
    Lightning {
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lightning_address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lnurl: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bolt12: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receiver_pubkey: Option<String>,
    },
    /// Ark virtual UTXO protocol
    Ark {
        label: String,
        server: String,
        pubkey: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vtxo_pointer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        opaque_uri: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<ArkOwnershipProof>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<i64>,
    },
}

fn default_bitcoin_network() -> BitcoinNetwork {
    BitcoinNetwork::Mainnet
}

/// Ark ownership proof (opaque for now)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArkOwnershipProof {
    pub proof_type: String,
    pub data: serde_json::Value,
}

/// User-owned payment profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProfile {
    /// Human-readable identifier, e.g. "alice@example.com"
    pub alias: String,
    /// Hex-encoded secp256k1 compressed public key
    pub identity_pubkey: String,
    /// Ordered list of payment methods (most preferred first)
    pub methods: Vec<PaymentMethod>,
    /// Unix timestamp of last update
    pub updated_at: i64,
    /// Optional Unix timestamp after which this profile should be considered expired
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Monotonically increasing sequence number for replay protection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// Ordered rail preference list, e.g. ["lightning", "ark", "onchain"]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<String>,
    /// The random nonce for replay protection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Optional key rotation object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<KeyRotation>,
    /// Ownership-proof attestations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub method_verifications: Vec<MethodVerification>,
    /// PQC: Post-quantum hybrid public key bundle (classical + PQC)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid_pubkey: Option<HybridPublicKey>,
    /// PQC: If true, verifiers MUST check the hybrid_signature. If false, it's optional.
    #[serde(default)]
    pub pqc_required: bool,
    #[serde(default)]
    pub revoked: bool,
}

/// A payment profile together with the owner's signature over its contents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPaymentProfile {
    pub profile: PaymentProfile,
    /// Hex-encoded secp256k1 Schnorr signature (64 bytes)
    pub signature: String,
    /// PQC: Hybrid signature (Schnorr + ML-DSA)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid_signature: Option<HybridSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub classical_pubkey: String,
    pub pqc_verification_key: String,
    pub suite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub schnorr_sig: String,
    pub pqc_sig: String,
    pub suite: String,
}

/// Key rotation object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotation {
    pub new_identity_pubkey: String,
    pub rotation_time: i64,
    pub previous_signature: String,
}

/// Method ownership verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodVerification {
    pub method_descriptor: String,
    pub proof_type: String,
    pub proof_data: String,
    pub verified_at: i64,
}

/// Fee estimate from mempool.space
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

/// Live fee rate snapshot used in routing decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRateSnapshot {
    pub fastest_sat_vb: u64,
    pub half_hour_sat_vb: u64,
    pub hour_sat_vb: u64,
}

/// Payment urgency
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentUrgency {
    Low,
    Normal,
    High,
}

/// Routing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRequest {
    pub alias: String,
    pub amount_sats: u64,
    pub signed_profile: SignedPaymentProfile,
    pub urgency: PaymentUrgency,
    pub max_fee_sats: Option<u64>,
    pub max_fee_percent: Option<f64>,
}

/// Execution mode for the selected route
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Preview,
    MainnetPreview,
    TestnetExperimental,
    ManualWallet,
}

/// Swap directive for experimental swap engine
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SwapDirective {
    LightningPayment {
        target_ln_address: Option<String>,
    },
    Bolt12Payment {
        offer: String,
        target_invoice: Option<String>,
        has_blinded_paths: bool,
    },
    SubmarineSwap {
        target_invoice: Option<String>,
    },
    ReverseSwap {
        target_address: Option<String>,
        silent_payment_pubkey: Option<String>,
    },
    ChainSwap {
        target_address: Option<String>,
        silent_payment_pubkey: Option<String>,
    },
    ArkTransfer {
        server: String,
        pubkey: String,
    },
    ArkadeManual,
}

/// Route quote result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteQuote {
    pub selected_method: PaymentMethod,
    pub reason: String,
    pub estimated_fee_sats: u64,
    pub estimated_confirmation: String,
    pub fee_snapshot: Option<FeeEstimate>,
    pub swap_directive: SwapDirective,
    pub execution: ExecutionMode,
    pub wallet_hint: String,
}

/// High-level quote response — matches Rust `QuoteResponse` exactly
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QuoteResponse {
    Ok {
        recipient: QuoteRecipient,
        selected_method: PaymentMethod,
        fee_sats: u64,
        eta: String,
        reason: String,
        qr: String,
        execution: ExecutionMode,
        wallet_hint: String,
    },
    NotRegistered {
        invite: Invite,
    },
    NoRoute {
        reason: String,
    },
    InvalidSignature {
        recipient: QuoteRecipient,
    },
}

/// Recipient info in quote response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRecipient {
    pub alias: String,
    pub verified: bool,
    pub profile_signature_verified: bool,
    pub identifier_verified: bool,
    pub identifier_verification: String,
    pub fingerprint: Option<String>,
}

/// Invite for unregistered users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub alias_hash: String,
    pub amount_sats: u64,
    pub created_at: i64,
    pub expires_at: i64,
    pub claim_url: String,
    pub warning: String,
    pub sender_signature: Option<String>,
    pub sender_pubkey: Option<String>,
}

// ===== Router constants (mirroring Rust satspath-router) =====

/// Fallback fees when network is unavailable (conservative estimates)
pub const FALLBACK_FEES: FeeEstimate = FeeEstimate {
    fastest_fee: 20,
    half_hour_fee: 15,
    hour_fee: 10,
    economy_fee: 5,
    minimum_fee: 1,
};

/// Lightning threshold in satoshis (below this, Lightning is preferred)
pub const LIGHTNING_THRESHOLD_SATS: u64 = 100_000;

/// Maximum acceptable on-chain fee rate in sat/vB
pub const ONCHAIN_FEE_THRESHOLD_SAT_VB: u64 = 10;

/// 10% buffer on fee estimate for safety margin
pub const ONCHAIN_FEE_BUFFER: f64 = 1.10;

impl PaymentUrgency {
    pub fn select_fee_rate(&self, fees: &FeeEstimate) -> u64 {
        match self {
            PaymentUrgency::High => fees.fastest_fee,
            PaymentUrgency::Normal => fees.half_hour_fee,
            PaymentUrgency::Low => fees.hour_fee,
        }
    }

    pub fn expected_confirmation(&self) -> &'static str {
        match self {
            PaymentUrgency::High => "~10 min",
            PaymentUrgency::Normal => "~30 min",
            PaymentUrgency::Low => "~60 min",
        }
    }
}
