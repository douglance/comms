//! Cloudflare host for the shared Incurs command catalog.
#[cfg(target_arch = "wasm32")]
mod auth;
#[cfg(target_arch = "wasm32")]
mod codemode;
#[cfg(target_arch = "wasm32")]
mod data;
#[cfg(target_arch = "wasm32")]
mod enrollment;
#[cfg(target_arch = "wasm32")]
mod linear;
#[cfg(target_arch = "wasm32")]
mod media;
#[cfg(target_arch = "wasm32")]
mod questions;
#[cfg(target_arch = "wasm32")]
mod slack;
#[cfg(target_arch = "wasm32")]
mod slack_oauth;

#[cfg(target_arch = "wasm32")]
mod host {
    use axum::http::StatusCode;
    use axum::{Json, Router, response::IntoResponse};
    use comms_core::Backend;
    use incurs::http::{RouterOptions, build_cli_router_with};
    use serde_json::json;
    use std::sync::Arc;
    use tower_service::Service;
    use worker::{Context, Env, HttpRequest, event};

    #[event(fetch)]
    async fn fetch(
        request: HttpRequest,
        env: Env,
        ctx: Context,
    ) -> worker::Result<axum::response::Response> {
        let mut response = match dispatch(request, env, ctx).await {
            Ok(response) => response,
            Err(error) => {
                let code = error.to_string();
                let (status, public_code) = match code.as_str() {
                    "ACCESS_TOKEN_REQUIRED"
                    | "UNAUTHORIZED"
                    | "AGENT_REVOKED"
                    | "AGENT_EXPIRED" => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
                    "LINEAR_STATE_INVALID"
                    | "LINEAR_IDENTITY_MISMATCH"
                    | "LINEAR_SIGNATURE_INVALID"
                    | "LINEAR_EVENT_INVALID"
                    | "QUESTION_FORBIDDEN"
                    | "SLACK_OAUTH_STATE_INVALID"
                    | "SLACK_OAUTH_INSTALLATION_MISMATCH" => (StatusCode::FORBIDDEN, "FORBIDDEN"),
                    "LINEAR_APP_NOT_INSTALLED"
                    | "LINEAR_AGENT_NOT_FOUND"
                    | "QUESTION_NOT_FOUND" => (StatusCode::NOT_FOUND, "NOT_FOUND"),
                    "LINEAR_REQUEST_INVALID"
                    | "LINEAR_REQUEST_TOO_LARGE"
                    | "MISSING_ID"
                    | "SLACK_OAUTH_STATE_REQUIRED"
                    | "SLACK_OAUTH_CODE_REQUIRED" => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
                    _ if code.contains("signature") || code.contains("Signature") => {
                        (StatusCode::FORBIDDEN, "INVALID_SIGNATURE")
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
                };
                (
                    status,
                    Json(json!({"ok":false,"error":{"code":public_code}})),
                )
                    .into_response()
            }
        };
        for (name, value) in [
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
        ] {
            response.headers_mut().insert(name, value.parse().unwrap());
        }
        Ok(response)
    }

    async fn dispatch(
        request: HttpRequest,
        env: Env,
        ctx: Context,
    ) -> worker::Result<axum::response::Response> {
        let path = request.uri().path().to_owned();
        let base = format!(
            "{}://{}",
            request.uri().scheme_str().unwrap_or("https"),
            request.uri().authority().map(|a| a.as_str()).unwrap_or("")
        );
        if path == "/health" {
            return Ok(
                Json(json!({"service":"comms","version":env!("CARGO_PKG_VERSION")}))
                    .into_response(),
            );
        }
        if let Some(origin) = request.headers().get("origin")
            && origin.to_str().ok() != Some(base.as_str())
        {
            return Ok((StatusCode::FORBIDDEN, Json(json!({"ok":false,"error":{"code":"ORIGIN_REJECTED","message":"Origin is not allowed"}}))).into_response());
        }
        if path.starts_with("/owner/linear/") {
            return crate::linear::owner(request, env, base)
                .await
                .map(|response| response.map(axum::body::Body::new));
        }
        if path == "/linear/oauth/callback" {
            return crate::linear::callback(request, env)
                .await
                .map(|response| response.map(axum::body::Body::new));
        }
        if path == "/linear/events" {
            return crate::linear::events(request, env)
                .await
                .map(|response| response.map(axum::body::Body::new));
        }
        if path.starts_with("/owner/slack/") {
            return crate::slack_oauth::handle(request, env, base)
                .await
                .map(|response| response.map(axum::body::Body::new));
        }
        if path == "/slack/interactions" || path == "/slack/events" {
            let config = crate::questions::SlackQuestionConfig::from_env(&env).await?;
            let response =
                crate::questions::handle_slack_question_callback(request, env.clone(), config)
                    .await?;
            let (parts, body) = response.into_parts();
            let bytes = http_body_util::BodyExt::collect(body)
                .await
                .map_err(|_| worker::Error::RustError("CALLBACK_RESPONSE_FAILED".into()))?
                .to_bytes();
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && let Some(signal) = value.pointer("/data/resume").filter(|v| !v.is_null())
                && let Ok(signal) =
                    serde_json::from_value::<comms_interactions::ResumeSignal>(signal.clone())
            {
                ctx.wait_until(async move {
                    let _ = crate::codemode::resume_from_slack(&env, &signal).await;
                });
            }
            return Ok(axum::response::Response::from_parts(
                parts,
                axum::body::Body::from(bytes),
            ));
        }
        if crate::auth::is_auth_route(&path) {
            return crate::auth::handle(request, env, base)
                .await
                .map(|response| response.map(axum::body::Body::new));
        }
        let agent = if request.method() == axum::http::Method::GET
            && path.starts_with("/media/")
            && request
                .uri()
                .query()
                .is_some_and(|query| query.split('&').any(|pair| pair.starts_with("ticket=")))
        {
            crate::auth::authenticate_download_request(&env, &request).await
        } else {
            crate::auth::authenticate_agent(&env, &request).await
        };
        let agent = match agent {
            Ok(agent) => agent,
            Err(_) => return Ok((StatusCode::UNAUTHORIZED, Json(json!({"ok":false,"error":{"code":"UNAUTHORIZED","message":"An active agent credential is required"}}))).into_response()),
        };
        if path == "/questions"
            || path.starts_with("/questions/")
            || path.starts_with("/api/question/")
        {
            let config = crate::questions::SlackQuestionConfig::from_env(&env).await?;
            return crate::questions::handle_agent_question(request, env, agent, config).await;
        }
        if path == "/agent/me" {
            return Ok(Json(json!({"ok":true,"data":{"agent_id":agent.id,"label":agent.label,"expires_at":agent.expires_at}})).into_response());
        }
        if path == "/media" || path.starts_with("/media/") || path.starts_with("/uploads") {
            return crate::media::handle(request, env, agent, base)
                .await
                .map(|response| response.map(axum::body::Body::new));
        }
        if path == "/api/slack/invoke" || path == "/api/slack/api" {
            let bytes = http_body_util::BodyExt::collect(request.into_body())
                .await
                .map_err(|_| worker::Error::RustError("REQUEST_BODY_FAILED".into()))?
                .to_bytes();
            let input: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| worker::Error::RustError("malformed JSON body".into()))?;
            let backend = crate::data::DataBackend::new(env, agent, base);
            return match backend.call("slack_call", input).await {
                Ok(value) => Ok(Json(json!({"ok":true,"data":value})).into_response()),
                Err(message) => Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok":false,"error":{"code":"SLACK_ERROR","message":message}})),
                )
                    .into_response()),
            };
        }
        if crate::codemode::is_route(&path) {
            return crate::codemode::handle(request, env, agent, base)
                .await
                .map(|response| response.map(axum::body::Body::new));
        }
        let id = agent.id.clone();
        let cli = comms_core::cli(Arc::new(crate::data::DataBackend::new(env, agent, base)));
        let api = build_cli_router_with(&cli, RouterOptions::default())
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        let mut routes = Router::new().nest("/api", api);
        let mut response = routes.call(request).await?;
        response.headers_mut().insert(
            "x-comms-agent",
            id.parse()
                .map_err(|e| worker::Error::RustError(format!("{e}")))?,
        );
        response
            .headers_mut()
            .insert("cache-control", "no-store".parse().unwrap());
        response
            .headers_mut()
            .insert("x-content-type-options", "nosniff".parse().unwrap());
        Ok(response)
    }
}
