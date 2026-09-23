//! Quote and pay handlers.

use satspath_core::{
    privacy::mask_identifier,
    validation::{assert_no_private_material, validate_amount_sats},
};
use satspath_router::QuoteResponse;

use crate::config::AppState;
use crate::handlers::resolve::resolve_profile;
use crate::types::{safety_status, PayRequest, PayResponse, QuoteRequest, WalletHandoff};

pub(crate) async fn quote_response(
    state: &AppState,
    body: QuoteRequest,
) -> satspath_router::QuoteResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return satspath_router::QuoteResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let resolved = match resolve_profile(state, &body.recipient) {
        Ok(resolved) => resolved,
        Err(error) => {
            return satspath_router::QuoteResponse::NoRoute {
                reason: format!("transparency verification failed: {error}"),
            }
        }
    };
    let allowed: Vec<String> = resolved
        .verification
        .payment_method_states
        .iter()
        .filter(|state| state.verified)
        .map(|state| state.descriptor.clone())
        .collect();
    satspath_router::quote_verified_profile(
        resolved.signed_profile,
        &body.recipient,
        body.amount_sats,
        &allowed,
    )
    .await
}

pub(crate) async fn pay_response(state: &AppState, body: PayRequest) -> PayResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        let quote = QuoteResponse::NoRoute {
            reason: e.to_string(),
        };
        return PayResponse::NoRoute {
            decision_protocol: "satspathd.v1",
            reason: e.to_string(),
            quote,
            safety: safety_status(),
        };
    }
    if let Some(memo) = &body.memo {
        if let Err(e) = assert_no_private_material(memo) {
            let quote = QuoteResponse::NoRoute {
                reason: e.to_string(),
            };
            return PayResponse::NoRoute {
                decision_protocol: "satspathd.v1",
                reason: e.to_string(),
                quote,
                safety: safety_status(),
            };
        }
    }

    let quote = quote_response(
        state,
        QuoteRequest {
            recipient: body.recipient.clone(),
            amount_sats: body.amount_sats,
        },
    )
    .await;

    match quote.clone() {
        QuoteResponse::Ok { qr, .. } => match crate::ui::qr_svg(&qr) {
            Ok(qr_svg) => PayResponse::WalletHandoff {
                decision_protocol: "satspathd.v1",
                recipient: body.recipient,
                amount_sats: body.amount_sats,
                quote,
                payment_payload: qr,
                qr_svg,
                handoff: WalletHandoff {
                    mode: "external_wallet",
                    instruction: "Open or scan payment_payload with a wallet you control.",
                    opens_external_wallet: true,
                    daemon_executes_payment: false,
                },
                safety: safety_status(),
            },
            Err(e) => PayResponse::NoRoute {
                decision_protocol: "satspathd.v1",
                reason: e.to_string(),
                quote,
                safety: safety_status(),
            },
        },
        QuoteResponse::NotRegistered { .. } => PayResponse::InviteCreated {
            decision_protocol: "satspathd.v1",
            recipient_hint: mask_identifier(&body.recipient),
            amount_sats: body.amount_sats,
            quote,
            safety: safety_status(),
        },
        QuoteResponse::NoRoute { reason } => PayResponse::NoRoute {
            decision_protocol: "satspathd.v1",
            reason,
            quote,
            safety: safety_status(),
        },
        QuoteResponse::InvalidSignature { .. } => PayResponse::InvalidSignature {
            decision_protocol: "satspathd.v1",
            quote,
            safety: safety_status(),
        },
    }
}
