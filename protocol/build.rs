const PROTOS: [&str; 5] = [
    "proto/attachment.proto",
    "proto/content.proto",
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
        // A message's content stays in `Vec`s, as its clients take its files.
        .bytes([".attachment", ".handshake", ".mailbox", ".notify"])
        .extern_path(".party.v1", "::party::proto")
        // It holds a key: its `Debug` is written by hand, without it.
        .skip_debug([".content.v1.AttachmentPointer"])
        .type_attribute(".", SERDE)
        .type_attribute(".", RKYV);
    #[cfg(feature = "protox")]
    config.compile_fds(protox::compile(PROTOS, INCLUDES)?)?;
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&PROTOS, &INCLUDES)?;
    Ok(())
}
