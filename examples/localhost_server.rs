// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use drawbridge_app::Builder;
use hyper::Server;

#[tokio::main]
async fn main() {
    let socket = (Ipv4Addr::LOCALHOST, 12345).into();

    let service = Builder::new().build();

    let server = Server::bind(&socket).serve(service);

    println!("Listening on {socket}...");

    server.await.unwrap();
}
