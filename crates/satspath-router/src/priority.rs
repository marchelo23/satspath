//! Priority-based rail selection.
//!
//! Unlike [`crate::select_route`] (which prefers Lightning for small amounts),
//! this implements an explicit operator priority:
//!
//! **on-chain → Lightning → Ark**
//!
//! - **On-chain** is the default. It is skipped only when fees are high
//!   (`fastestFee > HIGH_FEE_SAT_VB`) or the payment is very small
//!   (`amount < SMALL_PAYMENT_SATS`, where the miner fee would dominate).
//! - **Lightning** is the next choice, skipped when there is a routing problem
//!   or the payment is very large (`amount > LARGE_PAYMENT_SATS`).
//! - **Ark** is the final fallback.
//!
//! Selection is inert: it picks a rail and explains why. It moves no funds.

use satspath_core::PaymentMethod;

use crate::fees::FeeEstimate;

/// Below this, an on-chain output's miner fee dominates the payment.
pub const SMALL_PAYMENT_SATS: u64 = 1_000;
/// Above this next-block rate, on-chain is considered "expensive".
pub const HIGH_FEE_SAT_VB: u64 = 30;
/// Above this, a payment is large enough that Lightning routing is unreliable.
pub const LARGE_PAYMENT_SATS: u64 = 5_000_000;

/// The chosen rail plus a human-readable reason.
#[derive(Debug, Clone)]
pub struct PriorityDecision {
    pub method: PaymentMethod,
    pub rail: &'static str,
    pub reason: String,
}

fn find(
    methods: &[PaymentMethod],
    pick: impl Fn(&PaymentMethod) -> bool,
) -> Option<&PaymentMethod> {
    methods.iter().find(|m| pick(m))
}

/// Select a rail by the on-chain → Lightning → Ark priority.
///
/// `routing_ok` reflects Lightning routing health (the caller may set it to
/// `false` to model a routing problem). Returns `None` only when the recipient
/// exposes no usable method at all.
pub fn select_priority_route(
    amount_sats: u64,
    fee: &FeeEstimate,
    methods: &[PaymentMethod],
    routing_ok: bool,
) -> Option<PriorityDecision> {
    let onchain = find(methods, |m| matches!(m, PaymentMethod::Onchain { .. }));
    let lightning = find(methods, |m| {
        matches!(
            m,
            PaymentMethod::Lightning { .. } | PaymentMethod::Bolt12(_)
        )
    });
    let ark = find(methods, |m| matches!(m, PaymentMethod::Ark { .. }));

    let small = amount_sats < SMALL_PAYMENT_SATS;
    let high_fee = fee.fastest_fee > HIGH_FEE_SAT_VB;
    let large = amount_sats > LARGE_PAYMENT_SATS;

    // 1. On-chain first — unless high fees or a very small payment.
    if let Some(method) = onchain {
        if !high_fee && !small {
            return Some(PriorityDecision {
                method: method.clone(),
                rail: "onchain",
                reason: format!(
                    "On-chain is the priority rail (fee {} sat/vB ≤ {}, amount ≥ {} sats).",
                    fee.fastest_fee, HIGH_FEE_SAT_VB, SMALL_PAYMENT_SATS
                ),
            });
        }
    }

    // 2. Lightning next — unless a routing problem or a very large payment.
    if let Some(method) = lightning {
        if routing_ok && !large {
            let why = if onchain.is_some() {
                if high_fee {
                    format!(
                        "On-chain skipped (fee {} sat/vB > {}); using Lightning.",
                        fee.fastest_fee, HIGH_FEE_SAT_VB
                    )
                } else {
                    format!(
                        "On-chain skipped (amount < {} sats); using Lightning.",
                        SMALL_PAYMENT_SATS
                    )
                }
            } else {
                "No on-chain method; using Lightning.".to_string()
            };
            return Some(PriorityDecision {
                method: method.clone(),
                rail: "lightning",
                reason: why,
            });
        }
    }

    // 3. Ark fallback.
    if let Some(method) = ark {
        let why = if lightning.is_some() && !routing_ok {
            "Lightning skipped (routing problem); falling back to Ark."
        } else if lightning.is_some() && large {
            "Lightning skipped (payment too large); falling back to Ark."
        } else {
            "Falling back to Ark."
        };
        return Some(PriorityDecision {
            method: method.clone(),
            rail: "ark",
            reason: why.to_string(),
        });
    }

    // 4. Last resort: any remaining method, in priority order.
    let last = onchain.or(lightning).or(ark)?;
    Some(PriorityDecision {
        method: last.clone(),
        rail: last.method_name_static(),
        reason: "Only one rail available; using it despite priority guards.".to_string(),
    })
}

/// Static rail name for the last-resort branch.
trait RailName {
    fn method_name_static(&self) -> &'static str;
}
impl RailName for PaymentMethod {
    fn method_name_static(&self) -> &'static str {
        match self {
            PaymentMethod::Onchain { .. } => "onchain",
            PaymentMethod::Lightning { .. } => "lightning",
            PaymentMethod::Bolt12(_) => "bolt12",
            PaymentMethod::Ark { .. } => "ark",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::BitcoinNetwork;

    fn fee(fastest: u64) -> FeeEstimate {
        FeeEstimate {
            fastest_fee: fastest,
            half_hour_fee: fastest,
            hour_fee: fastest,
            economy_fee: fastest,
            minimum_fee: 1,
        }
    }
    fn onchain() -> PaymentMethod {
        PaymentMethod::Onchain {
            label: "btc".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("bc1qx".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }
    }
    fn lightning() -> PaymentMethod {
        PaymentMethod::Lightning {
            label: "ln".into(),
            lightning_address: Some("a@b.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }
    }
    fn ark() -> PaymentMethod {
        PaymentMethod::Ark {
            label: "ark".into(),
            opaque_uri: None,
            server: "https://ark.x".into(),
            pubkey: "02ab".into(),
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        }
    }

    #[test]
    fn onchain_is_the_default() {
        let m = [onchain(), lightning(), ark()];
        let d = select_priority_route(50_000, &fee(10), &m, true).unwrap();
        assert_eq!(d.rail, "onchain");
    }

    #[test]
    fn high_fees_push_to_lightning() {
        let m = [onchain(), lightning(), ark()];
        let d = select_priority_route(50_000, &fee(40), &m, true).unwrap();
        assert_eq!(d.rail, "lightning");
    }

    #[test]
    fn very_small_payment_pushes_to_lightning() {
        let m = [onchain(), lightning(), ark()];
        let d = select_priority_route(500, &fee(10), &m, true).unwrap();
        assert_eq!(d.rail, "lightning");
    }

    #[test]
    fn routing_problem_falls_back_to_ark() {
        let m = [onchain(), lightning(), ark()];
        // small amount excludes on-chain, routing_ok=false excludes LN → Ark.
        let d = select_priority_route(500, &fee(10), &m, false).unwrap();
        assert_eq!(d.rail, "ark");
    }

    #[test]
    fn very_large_payment_skips_lightning() {
        // High fee excludes on-chain; large amount excludes LN → Ark.
        let m = [onchain(), lightning(), ark()];
        let d = select_priority_route(10_000_000, &fee(40), &m, true).unwrap();
        assert_eq!(d.rail, "ark");
    }

    #[test]
    fn no_methods_returns_none() {
        assert!(select_priority_route(1000, &fee(10), &[], true).is_none());
    }

    #[test]
    fn lightning_only_used_even_if_large() {
        let m = [lightning()];
        let d = select_priority_route(10_000_000, &fee(10), &m, true).unwrap();
        assert_eq!(d.rail, "lightning"); // last-resort: only rail available
    }
}
