//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
fn main() {
    let protos = ["src/proto/svr3.proto", "src/proto/svr4.proto"];
    prost_build::compile_protos(&protos, &["src"]).expect("Protobufs in src are valid");
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto);
    }
}
