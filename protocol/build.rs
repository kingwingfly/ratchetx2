const PROTOS: [&str; 4] = [
    "proto/attachment.proto",
    "proto/handshake.proto",
    "proto/mailbox.proto",
    "proto/notify.proto",
];
const INCLUDES: [&str; 2] = ["proto", "../party/proto"];
const SERDE: &str =
    r#"#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]"#;
const RKYV: &str =
    r#"#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=../party/proto");

    let mut config = prost_build::Config::new();
    config
        .bytes(["."])
        .extern_path(".party.v1", "::party::proto")
        .type_attribute(".", SERDE)
        .type_attribute(".", RKYV);
    #[cfg(feature = "protox")]
    config.compile_fds(protox::compile(PROTOS, INCLUDES)?)?;
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&PROTOS, &INCLUDES)?;
    Ok(())
}
