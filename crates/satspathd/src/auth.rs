//! Authentication: Bearer token validation.

use tiny_http::Request;

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn check_auth(request: &Request, expected_token: &str) -> anyhow::Result<()> {
    if expected_token.is_empty() {
        anyhow::bail!("Unauthorized: Admin auth token is not configured (fail-closed)");
    }
    for header in request.headers() {
        if header.field.equiv("Authorization") {
            let val = header.value.as_str();
            if let Some(bearer) = val.strip_prefix("Bearer ") {
                if constant_time_eq(bearer.trim().as_bytes(), expected_token.as_bytes()) {
                    return Ok(());
                }
            }
        }
    }
    anyhow::bail!("Unauthorized: Invalid or missing Bearer token");
}
