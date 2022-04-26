// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0
mod protected;
mod route;
mod status;

use drawbridge_auth::app;

use std::env;

use axum::{extract::Extension, routing::get, Router};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};

pub const STATUS: &str = "/status";
pub const PROTECTED: &str = "/protected";

pub fn test_app(host: &str) -> Router {
    // TODO: generate this key at runtime or pull the path from the command line args: https://github.com/profianinc/drawbridge/issues/18
    let key = RsaPrivateKey::from_pkcs8_der(include_bytes!("../../rsa2048-priv.der")).unwrap();

    Router::new()
        .merge(app(
            host,
            env::var("GH_OAUTH_CLIENT_ID").expect("GH_OAUTH_CLIENT_ID env var"),
            env::var("GH_OAUTH_SECRET").expect("GH_OAUTH_SECRET env var"),
        ))
        .route(STATUS, get(status::status))
        .route(PROTECTED, get(protected::protected))
        .layer(Extension(key))
}
