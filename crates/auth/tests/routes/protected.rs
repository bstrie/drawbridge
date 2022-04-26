// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0
use super::{test_app, PROTECTED};
use drawbridge_auth::{providers::ProviderType, session::Session, COOKIE_NAME};

use std::str;

use axum::response::IntoResponse;
use http::{Request, StatusCode};
use hyper::Body;
use oauth2::AccessToken;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use tower::util::ServiceExt;

/// This is just an example of how to implement endpoints behind OAuth.
pub async fn protected(session: Session) -> impl IntoResponse {
    format!(
        "Welcome to the protected area\nHere's your info:\n{:?}",
        session
    )
}

#[tokio::test]
async fn protected_authenticated() {
    let key = RsaPrivateKey::from_pkcs8_der(include_bytes!("../../rsa2048-priv.der")).unwrap();
    let session = Session::new(
        ProviderType::GitHub,
        AccessToken::new("BAD TOKEN".to_owned()),
    );
    let app = test_app("localhost");
    let response = app
        .oneshot(
            Request::builder()
                .uri(PROTECTED)
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
    let body = str::from_utf8(&body).unwrap();
    assert_eq!(
        body,
        r#"Welcome to the protected area
Here's your info:
Session { provider_type: GitHub, token: AccessToken([redacted]) }"#
    );
}

#[tokio::test]
async fn protected_redirect() {
    let app = test_app("localhost");
    let response = app
        .oneshot(
            Request::builder()
                .uri(PROTECTED)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap(),
        "/auth/github"
    );
}
