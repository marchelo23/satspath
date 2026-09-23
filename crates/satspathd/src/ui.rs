//! UI: HTML response, browser opener, QR SVG generator.

use anyhow::Result;
use qrcode::{Color, QrCode};
use tiny_http::{Header, Response, StatusCode};

use crate::http::cors_origin_header;

pub(crate) const INDEX_HTML: &str = include_str!("index.html");

pub(crate) fn html_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let ct = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
        .expect("static header");
    let xcto =
        Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).expect("static header");
    let xfo = Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]).expect("static header");
    let csp = Header::from_bytes(
        &b"Content-Security-Policy"[..],
        &b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"[..],
    )
    .expect("static header");

    Response::from_data(body.as_bytes().to_vec())
        .with_status_code(StatusCode(200))
        .with_header(ct)
        .with_header(xcto)
        .with_header(xfo)
        .with_header(csp)
        .with_header(cors_origin_header())
}

/// Best-effort open of the default browser. Never fails the daemon.
pub(crate) fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let (cmd, args): (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "linux")]
    let (cmd, args): (&str, Vec<&str>) = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let (cmd, args): (&str, Vec<&str>) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let (cmd, args): (&str, Vec<&str>) = ("", vec![]);
    if !cmd.is_empty() {
        let _ = std::process::Command::new(cmd).args(args).spawn();
    }
}

/// Render a payload as a self-contained black-and-white SVG QR.
pub(crate) fn qr_svg(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes()).map_err(|e| anyhow::anyhow!("QR encode: {e}"))?;
    let width = code.width();
    let colors = code.to_colors();
    let quiet = 4usize;
    let size = width + quiet * 2;
    let mut rects = String::new();
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == Color::Dark {
                rects.push_str(&format!(
                    "<rect x='{}' y='{}' width='1' height='1'/>",
                    x + quiet,
                    y + quiet
                ));
            }
        }
    }
    Ok(format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {size} {size}' \
         shape-rendering='crispEdges'><rect width='100%' height='100%' fill='#fff'/>\
         <g fill='#000'>{rects}</g></svg>"
    ))
}
