// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0
use super::test_app;
use drawbridge_auth::{GITHUB, GITHUB_AUTHORIZED};

use std::str;

use http::{Request, StatusCode};
use hyper::Body;
use regex::Regex;
use tower::ServiceExt;

#[tokio::test]
async fn github_login() {
    let app = test_app("localhost");
    let response = app
        .oneshot(Request::builder().uri(GITHUB).body(Body::empty()).unwrap())
        .await
        .unwrap();

    let url = Regex::new(
        r#"https://github.com/login/oauth/authorize\?response_type=code&response_type=code&client_id=(.+)&state=(.+)&redirect_uri=http%3A%2F%2Flocalhost%2Fgithub%2Fauthorized&scope=identify"#
    ).unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(url.is_match(
        response
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap()
    ));
}

#[tokio::test]
async fn github_login_authorized() {
    // TODO: write a successful test for this endpoint
    let app = test_app("localhost");
    let response = app
        .oneshot(
            Request::builder()
                .uri(GITHUB_AUTHORIZED)
                .header("Cookie", format!("SESSION={}", "bad_session"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body = str::from_utf8(&body).unwrap();
    assert_eq!(
        body,
        "Failed to deserialize query string. Expected something of type `drawbridge_auth::providers::github::AuthRequest`. Error: missing field `code`"
    );
}
