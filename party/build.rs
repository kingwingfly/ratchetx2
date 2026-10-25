const SERDE: &str =
    r#"#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]"#;
const RKYV: &str =
    r#"#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]"#;
/// The message format, from `proto/party.proto`.
const WIRE: [&str; 2] = [".party.v1.EncryptedMessage", ".party.v1.Header"];
/// The party's state, from `proto/party_state.proto`, with the `prost` feature.
const STATE: [&str; 3] = [
    ".party.v1.Party",
    ".party.v1.SkippedChain",
    ".party.v1.MessageKey",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut protos = vec!["proto/party.proto"];
    let mut includes = vec!["proto"];
    let mut config = prost_build::Config::new();
    config.bytes(WIRE);
    // The party's state has its own serde and rkyv impls, on `Party`.
    for message in WIRE {
        config
            .type_attribute(message, SERDE)
            .type_attribute(message, RKYV);
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
        println!("cargo:rerun-if-changed=../ratchetx2/proto");
    }
    #[cfg(feature = "protox")]
    config.compile_fds(protox::compile(&protos, &includes)?)?;
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&protos, &includes)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
