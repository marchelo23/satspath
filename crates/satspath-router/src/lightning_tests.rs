use crate::lightning::{fetch_invoice_with_options, fetch_lnurl_metadata_with_options};
use crate::{fetch_invoice, LnurlPayMetadata};
use mockito::Server;
use serde_json::json;

/// Deterministic signed fixture, valid from 2023 until 2100 (not endpoint evidence).
pub(crate) fn bound_invoice(
    currency: lightning_invoice::Currency,
    amount: u64,
    expired: bool,
) -> (String, String) {
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{InvoiceBuilder, PaymentSecret};
    use secp256k1::{Secp256k1, SecretKey};
    use std::time::{Duration, UNIX_EPOCH};
    let key = SecretKey::from_slice(&[42; 32]).unwrap();
    let secp = Secp256k1::new();
    let payee = secp256k1::PublicKey::from_secret_key(&secp, &key).to_string();
    let invoice = InvoiceBuilder::new(currency)
        .description("issue 205 deterministic fixture".into())
        .payment_hash(sha256::Hash::from_slice(&[1; 32]).unwrap())
        .payment_secret(PaymentSecret([2; 32]))
        .timestamp(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        .expiry_time(Duration::from_secs(if expired { 1 } else { 2_400_000_000 }))
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(amount * 1000)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
        .unwrap()
        .to_string();
    (invoice, payee)
}

#[tokio::test]
async fn verified_retrieval_binds_payee_amount_currency_and_expiry() {
    use crate::lightning::verified_invoice_from_metadata;
    use lightning_invoice::Currency;
    use satspath_core::PaymentMethod;
    for (currency, network) in [
        (Currency::Bitcoin, "mainnet"),
        (Currency::BitcoinTestnet, "testnet"),
        (Currency::Signet, "signet"),
        (Currency::Regtest, "regtest"),
    ] {
        for case in [
            "valid",
            "payee",
            "amount",
            "network",
            "expired",
            "signature",
        ] {
            let mut server = Server::new_async().await;
            let (mut invoice, mut payee) = bound_invoice(
                currency.clone(),
                if case == "amount" { 2101 } else { 2100 },
                case == "expired",
            );
            if case == "payee" {
                payee = secp256k1::PublicKey::from_secret_key(
                    &secp256k1::Secp256k1::new(),
                    &secp256k1::SecretKey::from_slice(&[43; 32]).unwrap(),
                )
                .to_string();
            }
            if case == "signature" {
                invoice.pop();
                invoice.push('!');
            }
            let metadata = server.mock("GET", "/.well-known/lnurlp/alice")
                .with_body(json!({"callback": format!("{}/callback", server.url()), "minSendable": 1000, "maxSendable": 10000000, "tag": "payRequest"}).to_string())
                .create_async().await;
            let callback = server
                .mock("GET", "/callback?amount=2100000")
                .with_body(json!({"pr": invoice}).to_string())
                .create_async()
                .await;
            let method = PaymentMethod::Lightning {
                label: "fixture".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: Some(payee),
            };
            let configured = if case == "network" {
                if network == "mainnet" {
                    "testnet"
                } else {
                    "mainnet"
                }
            } else {
                network
            };
            let meta = fetch_lnurl_metadata_with_options(
                &format!("alice@{}", server.host_with_port()),
                false,
            )
            .await
            .unwrap();
            let result =
                verified_invoice_from_metadata(&method, &meta, 2100, configured, false).await;
            assert_eq!(
                result.is_ok(),
                case == "valid",
                "{network}/{case}: {result:?}"
            );
            metadata.assert_async().await;
            callback.assert_async().await;
        }
    }
}

#[tokio::test]
async fn verified_retrieval_rejects_unsupported_methods_before_network() {
    use satspath_core::PaymentMethod;
    let method = PaymentMethod::Lightning {
        label: "unbound".into(),
        lightning_address: Some("alice@example.com".into()),
        lnurl: None,
        bolt12: None,
        receiver_pubkey: None,
    };
    assert!(
        crate::lightning::fetch_verified_method_invoice(&method, 2100, "testnet")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn lnurl_transport_rejects_oversized_and_unsuccessful_responses() {
    for (status, body) in [
        (200, "x".repeat(50_001)),
        (302, "{}".into()),
        (503, "{}".into()),
    ] {
        let mut server = Server::new_async().await;
        let request = server
            .mock("GET", "/.well-known/lnurlp/alice")
            .with_status(status)
            .with_body(body)
            .create_async()
            .await;
        let result =
            fetch_lnurl_metadata_with_options(&format!("alice@{}", server.host_with_port()), false)
                .await;
        assert!(result.is_err(), "status {status}");
        request.assert_async().await;
    }
}

#[tokio::test]
async fn lnurl_callback_preserves_query_and_rejects_duplicate_amount() {
    let mut server = Server::new_async().await;
    let (invoice, _) = bound_invoice(lightning_invoice::Currency::Bitcoin, 2100, false);
    let request = server
        .mock(
            "GET",
            "/callback?token=public&amount=2100000&comment=%C3%A9",
        )
        .with_body(json!({"pr": invoice}).to_string())
        .create_async()
        .await;
    let mut meta = LnurlPayMetadata {
        callback: format!("{}/callback?token=public", server.url()),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".into(),
        comment_allowed: 1,
    };
    assert!(
        fetch_invoice_with_options(&meta, 2100, Some("éclair"), false)
            .await
            .is_ok()
    );
    request.assert_async().await;
    meta.callback = format!("{}/callback?amount=1", server.url());
    assert!(fetch_invoice_with_options(&meta, 2100, None, false)
        .await
        .unwrap_err()
        .to_string()
        .contains("ambiguous"));
}

#[tokio::test]
async fn test_full_lnurl_flow_with_mock() {
    let mut server = Server::new_async().await;
    let url = server.url();
    // mockito url is like http://127.0.0.1:12345
    // fetch_lnurl_metadata expects a lightning address like alice@domain
    // and fetches https://domain/.well-known/lnurlp/alice

    // Instead of using fetch_lnurl_metadata directly (which hardcodes https://),
    // let's just mock the LNURL flow since we want to test the full LNURL-pay two-step integration.

    // Mock the LNURL pay metadata response
    let metadata = json!({
        "callback": format!("{}/callback", url),
        "minSendable": 1000,
        "maxSendable": 10000000,
        "tag": "payRequest",
        "commentAllowed": 255
    });

    let _m1 = server
        .mock("GET", "/.well-known/lnurlp/alice")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(metadata.to_string())
        .create_async()
        .await;

    // Mock the callback response
    // Using a valid 2500 sat invoice
    let bolt11 = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzpzz8txr49kpzaem7e4lh5e0cqsjxvnmrgrmrr7x9qktv4u49v8yezahqvqk8c38n6vdxn3xqzwx3qp5v7rqpxdv";
    let callback_resp = json!({
        "pr": bolt11,
        "routes": []
    });

    let _m2 = server
        .mock("GET", "/callback?amount=2500000") // 2500 sats * 1000 msats
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_resp.to_string())
        .create_async()
        .await;

    // Test the client side
    // Since fetch_lnurl_metadata hardcodes `https://`, we'll just construct the metadata manually as if we received it,
    // OR we could change `fetch_lnurl_metadata` to allow testing, but let's test `fetch_invoice` which is the complex part.
    let meta = LnurlPayMetadata {
        callback: format!("{}/callback", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 255,
    };

    let result = fetch_invoice_with_options(&meta, 2500, None, false).await;
    // We expect it to fail validation (either parse error or expired) because we don't have a fresh invoice
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("failed to parse") || err.contains("expired"),
        "Expected validation error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_lnurl_error_flow_with_mock() {
    let mut server = Server::new_async().await;
    let url = server.url();

    let callback_resp = json!({
        "status": "ERROR",
        "reason": "Amount too high"
    });

    let _m2 = server
        .mock("GET", "/callback?amount=5000000")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_resp.to_string())
        .create_async()
        .await;

    let meta = LnurlPayMetadata {
        callback: format!("{}/callback", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    let result = fetch_invoice_with_options(&meta, 5000, None, false).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("LNURL server returned error: Amount too high"),
        "Unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn test_lnurl_amount_out_of_bounds() {
    let meta = LnurlPayMetadata {
        callback: "http://dummy/callback".to_string(),
        min_sendable: 10000,  // 10 sats
        max_sendable: 100000, // 100 sats
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    // Below minimum
    let res_min = fetch_invoice(&meta, 5, None).await;
    assert!(res_min.is_err());
    assert!(res_min.unwrap_err().to_string().contains("below minimum"));

    // Above maximum
    let res_max = fetch_invoice(&meta, 150, None).await;
    assert!(res_max.is_err());
    assert!(res_max.unwrap_err().to_string().contains("exceeds maximum"));
}

#[tokio::test]
async fn test_lnurl_callback_missing_or_empty_pr() {
    let mut server = Server::new_async().await;
    let url = server.url();

    // Mock response with missing `pr`
    let callback_missing_pr = json!({
        "routes": []
    });
    let _m1 = server
        .mock("GET", "/callback-missing?amount=5000000")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_missing_pr.to_string())
        .create_async()
        .await;

    // Mock response with empty `pr`
    let callback_empty_pr = json!({
        "pr": "",
        "routes": []
    });
    let _m2 = server
        .mock("GET", "/callback-empty?amount=5000000")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_empty_pr.to_string())
        .create_async()
        .await;

    let meta_missing = LnurlPayMetadata {
        callback: format!("{}/callback-missing", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    let result_missing = fetch_invoice_with_options(&meta_missing, 5000, None, false).await;
    assert!(result_missing.is_err());
    assert!(result_missing
        .unwrap_err()
        .to_string()
        .contains("missing 'pr'"));

    let meta_empty = LnurlPayMetadata {
        callback: format!("{}/callback-empty", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    let result_empty = fetch_invoice_with_options(&meta_empty, 5000, None, false).await;
    assert!(result_empty.is_err());
    assert!(result_empty
        .unwrap_err()
        .to_string()
        .contains("empty invoice"));
}

#[tokio::test]
async fn test_invalid_lightning_address_format() {
    use crate::fetch_lnurl_metadata;

    // Missing domain
    let res1 = fetch_lnurl_metadata("alice").await;
    assert!(res1.is_err());
    assert!(res1
        .unwrap_err()
        .to_string()
        .contains("invalid Lightning Address"));

    // Multiple @ symbols
    let res2 = fetch_lnurl_metadata("alice@bob@domain.com").await;
    assert!(res2.is_err());
    assert!(res2
        .unwrap_err()
        .to_string()
        .contains("invalid Lightning Address"));
}

#[tokio::test]
async fn test_lnurl_invalid_tag() {
    let mut server = Server::new_async().await;
    let url = server.url();
    let host = url.strip_prefix("http://").unwrap(); // get 127.0.0.1:port

    let metadata_wrong_tag = json!({
        "callback": format!("{}/callback", url),
        "minSendable": 1000,
        "maxSendable": 10000000,
        "tag": "withdrawRequest", // invalid tag
        "commentAllowed": 0
    });

    let _m1 = server
        .mock("GET", "/.well-known/lnurlp/alice")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(metadata_wrong_tag.to_string())
        .create_async()
        .await;

    let addr = format!("alice@{}", host);
    let result = fetch_lnurl_metadata_with_options(&addr, false).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("unexpected LNURL tag"));
}
