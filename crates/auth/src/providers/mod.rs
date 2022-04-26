// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0
pub mod github;

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ProviderType {
    GitHub,
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ProviderType::GitHub => "GitHub.com",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderType;

    #[test]
    fn auth_type_display() {
        assert_eq!(format!("{}", ProviderType::GitHub), "GitHub.com");
    }
}
