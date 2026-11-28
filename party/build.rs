const SERDE: &str =
    r#"#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]"#;
/// The message format, from `proto/party.proto`.
const WIRE: [&str; 2] = [".party.v1.EncryptedMessage", ".party.v1.Header"];
/// The party's secret-holding state messages, from `proto/party_state.proto`, with `prost`.
const STATE: [&str; 3] = [
    ".party.v1.Party",
    ".party.v1.SkippedChain",
    ".party.v1.MessageKey",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(has_pq)");
    if cfg!(any(feature = "ml-kem-1024", feature = "ml-kem-768")) {
        println!("cargo:rustc-cfg=has_pq");
    }
    let mut protos = vec!["proto/party.proto"];
    let mut includes = vec!["proto"];
    let mut config = prost_build::Config::new();
    config.bytes(WIRE);
    // The party's state has its own serde impl, on `Party`.
    for message in WIRE {
        config.type_attribute(message, SERDE);
    }
    if cfg!(feature = "prost") {
        protos.push("proto/party_state.proto");
        includes.push("../ratchetx2/proto");
        // It holds keys: zeroized on drop, so it has no `Bytes`, which cannot be, and its
        // `Debug` is written by hand, without them.
        config
            .extern_path(".ratchetx2.v1", "::ratchetx2::proto")
            .skip_debug(STATE);
        for message in STATE {
            config.type_attribute(
                message,
                "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
            );
        }
        // `EvictedRange` holds only public u64 counters (and prost derives `Copy` for it),
        // so derive `Zeroize` without `ZeroizeOnDrop`.
        config.type_attribute(".party.v1.EvictedRange", "#[derive(::zeroize::Zeroize)]");
        println!("cargo:rerun-if-changed=../ratchetx2/proto");
    }
    #[cfg(feature = "protox")]
    config.compile_fds(protox::compile(&protos, &includes)?)?;
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&protos, &includes)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
