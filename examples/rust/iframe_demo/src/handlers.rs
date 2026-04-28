use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::settings::DemoSettings;
use crate::AppState;

const SESSION_COOKIE: &str = "iframe_demo_sid";

pub fn iframe_origin_for_parent(host_header: Option<&str>, settings: &DemoSettings) -> String {
    let Ok(cfg) = url::Url::parse(&settings.auth_public_origin) else {
        return settings
            .auth_public_origin
            .trim_end_matches('/')
            .to_string();
    };
    let parent_host = host_header
        .and_then(|h| h.split(':').next())
        .unwrap_or("")
        .to_lowercase();
    let cfg_host = cfg.host_str().unwrap_or("").to_lowercase();
    if matches!(cfg_host.as_str(), "localhost" | "127.0.0.1")
        && matches!(parent_host.as_str(), "localhost" | "127.0.0.1")
    {
        let port = cfg
            .port()
            .unwrap_or(if cfg.scheme() == "https" { 443 } else { 80 });
        format!("{}://{}:{}", cfg.scheme(), parent_host, port)
            .trim_end_matches('/')
            .to_string()
    } else {
        settings
            .auth_public_origin
            .trim_end_matches('/')
            .to_string()
    }
}

fn session_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie_hdr = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{SESSION_COOKIE}=");
    for part in cookie_hdr.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(prefix.as_str()) {
            return Some(rest.to_string());
        }
    }
    None
}

fn header_value_set_session(sid: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax"
    ))
    .expect("cookie value")
}

fn header_value_clear_session() -> HeaderValue {
    HeaderValue::from_static("iframe_demo_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn escape_html(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect::<Vec<_>>(),
            '>' => "&gt;".chars().collect::<Vec<_>>(),
            '"' => "&quot;".chars().collect::<Vec<_>>(),
            _ => vec![c],
        })
        .collect()
}

fn subst_template(template: &str, pairs: &[(&str, &str)]) -> String {
    let mut s = template.to_string();
    for (k, v) in pairs {
        s = s.replace(k, v);
    }
    s
}

fn tok_prefix(s: &str) -> String {
    let p: String = s.chars().take(24).collect();
    format!("{p}…")
}

pub async fn index(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Response, axum::http::StatusCode> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let iframe_origin = iframe_origin_for_parent(host.as_deref(), &state.settings);

    let (sid, needs_cookie) = match session_from_headers(&headers) {
        Some(s) => (s, false),
        None => (uuid::Uuid::new_v4().to_string(), true),
    };

    state
        .store
        .ensure_session(&sid, state.settings.client_label)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let confidential_note = if state.settings.is_confidential {
        "(confidential — secret used in <code>/demo/oidc-refresh</code>)"
    } else {
        "(public / PKCE-style client)"
    };

    let html = subst_template(
        include_str!("../templates/index.html"),
        &[
            ("__CLIENT_LABEL__", state.settings.client_label),
            ("__IFRAME_ORIGIN__", &iframe_origin),
            ("__OAUTH_CLIENT_ID__", &state.settings.oauth_client_id),
            ("__CALLBACK_URL__", "/auth/callback"),
            ("__LISTEN_PORT__", &state.settings.listen_port.to_string()),
            ("__CONFIDENTIAL_NOTE__", confidential_note),
        ],
    );

    let mut res = axum::response::Html(html).into_response();
    if needs_cookie {
        res.headers_mut()
            .append(header::SET_COOKIE, header_value_set_session(&sid));
    }
    Ok(res)
}

pub async fn register_page(State(state): State<Arc<AppState>>) -> axum::response::Html<String> {
    let html = subst_template(
        include_str!("../templates/register.html"),
        &[("__CLIENT_LABEL__", state.settings.client_label)],
    );
    axum::response::Html(html)
}

#[derive(Debug, Deserialize)]
pub struct CallbackBody {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

pub async fn auth_callback(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CallbackBody>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    let sid = session_from_headers(&headers).ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": "missing session cookie" })),
    ))?;
    if body.access_token.is_empty() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({ "error": "missing access_token" })),
        ));
    }

    let mut email = None::<String>;
    let mut sub = None::<String>;
    if let Ok(v) = state.oauth.userinfo(&body.access_token).await {
        email = v.get("email").and_then(|x| x.as_str()).map(String::from);
        sub = v.get("sub").and_then(|x| x.as_str()).map(String::from);
    }

    let refresh = body.refresh_token.unwrap_or_default();

    state
        .store
        .save_tokens(
            &sid,
            state.settings.client_label,
            email.as_deref(),
            sub.as_deref(),
            &body.access_token,
            &refresh,
        )
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    Ok(Json(json!({
        "ok": true,
        "redirect": "/profile"
    })))
}

pub async fn profile(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Html<String>, Redirect> {
    let sid = session_from_headers(&headers).ok_or_else(|| Redirect::to("/"))?;
    let rec = match state.store.get_tokens(&sid, state.settings.client_label) {
        Ok(Some(r)) => r,
        _ => return Err(Redirect::to("/")),
    };

    let userinfo = state.oauth.userinfo(&rec.access_token).await.ok();

    let userinfo_json = userinfo
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".to_string()))
        .unwrap_or_else(|| "\"(could not load userinfo)\"".to_string());

    let record_json = serde_json::to_string_pretty(&serde_json::json!({
        "session_id": rec.session_id,
        "email": rec.email,
        "sub": rec.sub,
        "access_token_prefix": tok_prefix(&rec.access_token),
        "refresh_token_prefix": tok_prefix(&rec.refresh_token),
        "updated_at": rec.updated_at,
    }))
    .unwrap_or_else(|_| "{}".to_string());

    let refresh_block = if state.settings.is_confidential
        && state.settings.oauth_client_secret.is_some()
    {
        r##"<h2>Confidential: OIDC refresh</h2>
<p>Calls <code>POST /oauth2/token</code> via <code>authservice-sdk</code> (<code>grant_type=refresh_token</code>).</p>
<button type="button" id="btnRefresh">Refresh tokens</button>
<pre id="refreshOut"></pre>
<script>
document.getElementById("btnRefresh").addEventListener("click", function () {
  fetch("/demo/oidc-refresh", { method: "GET" })
    .then(function (r) { return r.json(); })
    .then(function (j) {
      document.getElementById("refreshOut").textContent = JSON.stringify(j, null, 2);
      if (j.ok) window.location.reload();
    })
    .catch(function (e) { document.getElementById("refreshOut").textContent = String(e); });
});
</script>"##
    } else {
        ""
    };

    let html = subst_template(
        include_str!("../templates/profile.html"),
        &[
            ("__CLIENT_LABEL__", state.settings.client_label),
            ("__OAUTH_CLIENT_ID__", &state.settings.oauth_client_id),
            ("__USERINFO_JSON__", &escape_html(&userinfo_json)),
            ("__RECORD_JSON__", &escape_html(&record_json)),
            ("__REFRESH_BLOCK__", refresh_block),
        ],
    );

    Ok(axum::response::Html(html))
}

/// Confidential-only: refresh via `authservice-sdk` (`grant_type=refresh_token` on `/oauth2/token`).
pub async fn oidc_refresh(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    fn json_resp(status: axum::http::StatusCode, msg: impl Into<String>) -> Response {
        (status, Json(json!({ "error": msg.into() }))).into_response()
    }

    if !state.settings.is_confidential || state.settings.oauth_client_secret.is_none() {
        return json_resp(
            axum::http::StatusCode::BAD_REQUEST,
            "only for confidential client with secret",
        );
    }

    let Some(sid) = session_from_headers(&headers) else {
        return json_resp(axum::http::StatusCode::BAD_REQUEST, "no session");
    };

    let rec = match state.store.get_tokens(&sid, state.settings.client_label) {
        Ok(Some(r)) => r,
        Ok(None) => return json_resp(axum::http::StatusCode::BAD_REQUEST, "no session"),
        Err(e) => return json_resp(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let refreshed = match state
        .oauth
        .refresh(
            &state.client_config,
            &rec.refresh_token,
            Some(state.settings.jwt_audience.as_str()),
        )
        .await
    {
        Ok(x) => x,
        Err(e) => return json_resp(axum::http::StatusCode::BAD_REQUEST, e.to_string()),
    };

    let access = refreshed.access_token.clone();
    let refresh = refreshed
        .refresh_token
        .unwrap_or_else(|| rec.refresh_token.clone());

    let mut email = rec.email.clone();
    let mut sub = rec.sub.clone();
    if let Ok(v) = state.oauth.userinfo(&access).await {
        email = v.get("email").and_then(|x| x.as_str()).map(String::from);
        sub = v.get("sub").and_then(|x| x.as_str()).map(String::from);
    }

    if let Err(e) = state.store.save_tokens(
        &sid,
        state.settings.client_label,
        email.as_deref(),
        sub.as_deref(),
        &access,
        &refresh,
    ) {
        return json_resp(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    let info = state.oauth.userinfo(&access).await.ok();

    Json(json!({
        "ok": true,
        "userinfo": info,
    }))
    .into_response()
}

pub async fn logout(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    if let Some(sid) = session_from_headers(&headers) {
        if let Ok(Some(rec)) = state.store.get_tokens(&sid, state.settings.client_label) {
            if !rec.refresh_token.is_empty() {
                let url = format!(
                    "{}/auth/logout",
                    state.settings.auth_api_base.trim_end_matches('/')
                );
                let _ = state
                    .http
                    .post(url)
                    .json(&json!({ "refresh_token": rec.refresh_token }))
                    .send()
                    .await;
            }
            let _ = state.store.clear_tokens(&sid, state.settings.client_label);
        }
    }

    let mut res = Redirect::to("/").into_response();
    res.headers_mut()
        .append(header::SET_COOKIE, header_value_clear_session());
    res
}

pub async fn admin_tokens(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let rows = state
        .store
        .list_for_client(state.settings.client_label, 50)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({
        "client": state.settings.client_label,
        "rows": rows,
    })))
}
