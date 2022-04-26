// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0
pub mod error;
pub mod providers;
pub mod redirect;
pub mod routes;
pub mod session;

use axum::{extract::Extension, routing::get, Router};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use routes::{github_login, github_login_authorized, AUTH_URL, TOKEN_URL};

pub const COOKIE_NAME: &str = "SESSION";
pub const GITHUB: &str = "/auth/github";
pub const GITHUB_AUTHORIZED: &str = "/github/authorized";

pub fn app(host: &str, client_id: String, client_secret: String) -> Router {
    let oauth_client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(AUTH_URL.to_string()).unwrap(),
        Some(TokenUrl::new(TOKEN_URL.to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(format!("http://{}{}", host, GITHUB_AUTHORIZED)).unwrap());

    Router::new()
        .route(GITHUB_AUTHORIZED, get(github_login_authorized))
        .route(GITHUB, get(github_login))
        .layer(Extension(oauth_client))
}
