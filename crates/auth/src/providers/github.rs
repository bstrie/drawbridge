// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0
use crate::{error::Error, session::Session};

use http::header::USER_AGENT;
use serde::Deserialize;

// TODO: move any remaining github specific functionality here
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
    pub state: String,
}

#[derive(Copy, Clone)]
pub struct GitHub;

pub const PROVIDER: GitHub = GitHub;

impl GitHub {
    /// Validate if a session should be considered active.
    pub async fn validate(&self, session: &Session) -> Result<String, Error> {
        #[derive(Deserialize)]
        struct GitHubUser {
            login: String,
        }

        #[derive(Deserialize)]
        struct GitHubError {
            message: String,
        }

        let client = reqwest::Client::new();

        let body: String = client
            .get("https://api.github.com/user")
            .header(USER_AGENT, "drawbridge")
            .bearer_auth(session.token.secret())
            .send()
            .await
            .map_err(Error::Request)?
            .text()
            .await
            .map_err(Error::Request)?;

        let user =
            serde_json::from_str::<GitHubUser>(&body).map_err(|_| {
                match serde_json::from_str::<GitHubError>(&body) {
                    Err(e) => Error::Serde(e.to_string()),
                    Ok(error) => Error::OAuth(error.message),
                }
            })?;

        Ok(user.login)
    }
}
