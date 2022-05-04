// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

use super::{Node, Repository, Result};

use drawbridge_jose::jws::Jws;
use drawbridge_jose::MediaTyped;
use drawbridge_type::{TagEntry, TagName, TreeEntry, TreePath};

use anyhow::bail;
use http::header::CONTENT_TYPE;
use http::StatusCode;

pub struct Tag<'a> {
    pub(crate) repo: &'a Repository<'a>,
    pub(crate) name: &'a TagName,
}

impl Tag<'_> {
    pub fn path<'a>(&'a self, path: &'a TreePath) -> Node<'_> {
        Node { tag: self, path }
    }

    pub fn create(&self, entry: &TagEntry) -> Result<bool> {
        let res = self
            .repo
            .client
            .inner
            .put(
                self.repo
                    .client
                    .url
                    .join(&format!("{}/_tag/{}", self.repo.name, self.name))?
                    .as_str(),
            )
            // TODO: Calculate and set Content-Digest
            // https://github.com/profianinc/drawbridge/issues/102
            .set(
                CONTENT_TYPE.as_str(),
                match entry {
                    TagEntry::Unsigned(..) => TreeEntry::TYPE,
                    TagEntry::Signed(..) => Jws::TYPE,
                },
            )
            .send_json(entry)?;
        match StatusCode::from_u16(res.status()) {
            Ok(StatusCode::CREATED) => Ok(true),
            Ok(StatusCode::OK) => Ok(false),
            _ => bail!("unexpected status code: {}", res.status()),
        }
    }

    pub fn get(&self) -> Result<TagEntry> {
        let res = self
            .repo
            .client
            .inner
            .get(
                self.repo
                    .client
                    .url
                    .join(&format!("{}/_tag/{}", self.repo.name, self.name))?
                    .as_str(),
            )
            .call()?;
        // TODO: Verify Content-Digest
        // TODO: Verify Content-Length
        // https://github.com/profianinc/drawbridge/issues/103
        match StatusCode::from_u16(res.status()) {
            Ok(StatusCode::OK) => res.into_json().map_err(Into::into),
            _ => bail!("unexpected status code: {}", res.status()),
        }
    }
}