// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0
use super::{test_app, STATUS};
use drawbridge_auth::{providers::github, providers::ProviderType, session::Session, COOKIE_NAME};

use std::{env, str};

use http::{Request, StatusCode};
use hyper::Body;
use oauth2::AccessToken;
use regex::Regex;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use tower::util::ServiceExt;

/// Check if a user is authenticated.
pub async fn status(session: Option<Session>) -> (StatusCode, String) {
    match session {
        None => (StatusCode::FORBIDDEN, "Not logged in.".to_owned()),
        Some(session) => match session.provider_type {
            ProviderType::GitHub => match github::PROVIDER.validate(&session).await {
                Err(e) => (StatusCode::FORBIDDEN, format!("Invalid session: {}", e)),
                Ok(username) => (
                    StatusCode::OK,
                    format!("Logged in as {} via {}.", username, session),
                ),
            },
        },
    }
}

#[tokio::test]
async fn status_authenticated() {
    let key = RsaPrivateKey::from_pkcs8_der(include_bytes!("../../rsa2048-priv.der")).unwrap();
    let session = Session::new(
        ProviderType::GitHub,
        AccessToken::new(env::var("GH_DRAWBRIDGE_TOKEN").expect("GH_DRAWBRIDGE_TOKEN env var")),
    );
    let app = test_app("localhost");
    let response = app
        .oneshot(
            Request::builder()
                .uri(STATUS)
                .header(
                    "Cookie",
                    format!("{}={}", COOKIE_NAME, session.encrypt(&key).unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    let message = Regex::new(r#"Logged in as .+ via GitHub.com."#).unwrap();
    assert!(message.is_match(body));
}

#[tokio::test]
async fn status_bad_token() {
    let key = RsaPrivateKey::from_pkcs8_der(include_bytes!("../../rsa2048-priv.der")).unwrap();
    let session = Session::new(
        ProviderType::GitHub,
        AccessToken::new("BAD TOKEN".to_owned()),
    );
    let app = test_app("localhost");
    let response = app
        .oneshot(
            Request::builder()
                .uri(STATUS)
                .header(
                    "Cookie",
                    format!("{}={}", COOKIE_NAME, session.encrypt(&key).unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body = str::from_utf8(&body).unwrap();
    assert_eq!(body, "Invalid session: OAuth error: Bad credentials");
}

#[tokio::test]
async fn status_unauthenticated() {
    let app = test_app("localhost");
    let response = app
        .oneshot(Request::builder().uri(STATUS).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body = str::from_utf8(&body).unwrap();
    assert_eq!(body, "Not logged in.");
}
