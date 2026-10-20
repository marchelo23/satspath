//! HTTP response helpers: JSON, HTML, CORS, and error utilities.

use std::io::Read;

use anyhow::Result;
use serde::Serialize;
use tiny_http::{Header, Request, Response, StatusCode};

use crate::config::AppState;
use crate::types::ErrorResponse;

pub(crate) const MAX_JSON_BODY_BYTES: u64 = 65_536; // 64 KB limit to prevent DoS

#[derive(Debug)]
pub(crate) struct PayloadTooLarge {
    max_bytes: u64,
}

impl std::fmt::Display for PayloadTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "payload too large: maximum allowed request body is {} bytes",
            self.max_bytes
        )
    }
}

impl std::error::Error for PayloadTooLarge {}

pub(crate) fn read_json<T: for<'de> serde::Deserialize<'de>>(
    request: &mut Request,
    state: &AppState,
) -> Result<T> {
    let max_bytes = (state.rate_limiter.max_body_bytes() as u64).min(MAX_JSON_BODY_BYTES);
    let mut body = Vec::new();
    let mut reader = request.as_reader().take(max_bytes + 1);
    reader.read_to_end(&mut body)?;
    if body.len() as u64 > max_bytes {
        state.rate_limiter.record_payload_too_large();
        crate::telemetry::metrics::record_rate_limit_dropped("payload_too_large");
        return Err(PayloadTooLarge { max_bytes }.into());
    }
    if std::str::from_utf8(&body)?.trim().is_empty() {
        anyhow::bail!("request body must be JSON");
    }
    let content_type_ok = request.headers().iter().any(|header| {
        header.field.equiv("Content-Type")
            && header
                .value
                .as_str()
                .split(';')
                .next()
                .is_some_and(|media_type| {
                    media_type.trim().eq_ignore_ascii_case("application/json")
                })
    });
    if !content_type_ok {
        anyhow::bail!("Content-Type must be application/json");
    }
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) fn json_result<T: Serialize>(
    status: StatusCode,
    result: Result<T>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match result {
        Ok(value) => json_response(status, &value),
        Err(e) => json_error(status, e),
    }
}

pub(crate) fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body =
        serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{\"error\":\"json\"}".to_vec());
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

pub(crate) fn empty_response(status: StatusCode) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(Vec::new())
        .with_status_code(status)
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

pub(crate) fn text_response(
    status: StatusCode,
    body: String,
    content_type: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let ct_header = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
        .unwrap_or_else(|_| Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap());
    Response::from_data(body.into_bytes())
        .with_status_code(status)
        .with_header(ct_header)
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

pub(crate) fn request_id_header(request_id: &str) -> Header {
    Header::from_bytes(&b"X-Request-Id"[..], request_id.as_bytes())
        .expect("valid request id header")
}

pub(crate) fn json_error(
    status: StatusCode,
    error: anyhow::Error,
) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        status,
        &ErrorResponse {
            error: error.to_string(),
        },
    )
}

pub(crate) fn handle_read_error(e: anyhow::Error) -> Response<std::io::Cursor<Vec<u8>>> {
    read_error_with_status(StatusCode(400), e)
}

pub(crate) fn read_error_with_status(
    status: StatusCode,
    e: anyhow::Error,
) -> Response<std::io::Cursor<Vec<u8>>> {
    if e.is::<PayloadTooLarge>() {
        json_error(StatusCode(413), e)
    } else {
        json_error(status, e)
    }
}

pub(crate) fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid static header")
}

pub(crate) fn cors_origin_header() -> Header {
    // SEC-CORS: Restrict to local daemon UI and Arkade wallet origins.
    // Override via SATSPATHD_CORS_ORIGIN env var for custom deployments.
    let origin = std::env::var("SATSPATHD_CORS_ORIGIN").unwrap_or_else(|_| {
        "http://localhost:5173, http://localhost:3000, http://127.0.0.1:5173, https://app.arkade.money".to_string()
    });
    // Note: Access-Control-Allow-Origin only supports a single origin value or '*'.
    // For multiple origins, the server should echo back the request Origin if it's
    // in the allowed list. Since tiny_http doesn't give us per-request headers easily,
    // we use the first allowed origin as default. In production, use a reverse proxy
    // (nginx/caddy) for proper multi-origin CORS.
    let first_origin = origin
        .split(',')
        .next()
        .unwrap_or("http://localhost:5173")
        .trim();
    Header::from_bytes(&b"Access-Control-Allow-Origin"[..], first_origin.as_bytes())
        .expect("valid static header")
}

pub(crate) fn cors_methods_header() -> Header {
    Header::from_bytes(
        &b"Access-Control-Allow-Methods"[..],
        &b"GET, POST, OPTIONS"[..],
    )
    .expect("valid static header")
}

pub(crate) fn cors_headers_header() -> Header {
    Header::from_bytes(
        &b"Access-Control-Allow-Headers"[..],
        &b"Content-Type, Authorization, X-Request-Id"[..],
    )
    .expect("valid static header")
}

/// Write a file atomically with owner-only permissions (0600 on Unix).
pub(crate) fn write_owner_only_file(path: &std::path::Path, content: &[u8]) -> anyhow::Result<()> {
    use std::path::Path;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    use secp256k1::rand::RngCore;
    let mut rand_bytes = [0u8; 16];
    secp256k1::rand::thread_rng().fill_bytes(&mut rand_bytes);
    let tmp_path = parent.join(format!(".tmp-{}", hex::encode(rand_bytes)));
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, content)?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}
