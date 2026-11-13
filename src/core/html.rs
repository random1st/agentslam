//! Server-rendered pages (sign-in, consent, errors): one calm layout that
//! shares /static/style.css with the rooms app.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// Escape text for HTML element and attribute context.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Content hash of the embedded web assets. Asset URLs carry it (`?v=`), so
/// a CDN in front (Cloudflare caches .css/.js for hours) never serves a
/// stylesheet or script from an older build.
pub static ASSET_VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(include_str!("../../web/style.css"));
    h.update(include_str!("../../web/app.js"));
    h.finalize()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
});

/// Wrap a body fragment (already escaped) in the common page layout.
pub fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>{t} · agentslam</title>\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\">\
         <link rel=\"stylesheet\" href=\"/static/style.css?v={v}\"></head>\
         <body><a class=\"skip\" href=\"#main\">Skip to content</a>\
         <header class=\"topbar\"><a class=\"brand\" href=\"/\">agentslam</a></header>\
         <main id=\"main\" class=\"page narrow\"><h1>{t}</h1>{body}</main></body></html>",
        t = esc(title),
        v = *ASSET_VERSION,
        body = body
    )
}

pub fn html_response(status: StatusCode, title: &str, body: &str) -> Response {
    (status, Html(page(title, body))).into_response()
}

/// Error page: what happened in plain words plus one concrete next step.
pub fn error_page_action(
    status: StatusCode,
    title: &str,
    message: &str,
    action_href: &str,
    action_label: &str,
) -> Response {
    html_response(
        status,
        title,
        &format!(
            "<div class=\"notice error\" role=\"alert\"><p>{}</p></div>\
             <p><a class=\"button primary\" href=\"{}\">{}</a></p>",
            esc(message),
            esc(action_href),
            esc(action_label)
        ),
    )
}

pub fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    error_page_action(status, title, message, "/", "Go to your rooms")
}
