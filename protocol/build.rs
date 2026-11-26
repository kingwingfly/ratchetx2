const PROTOS: [&str; 5] = [
    "proto/attachment.proto",
    "proto/content.proto",
    "proto/handshake_v2.proto",
    "proto/mailbox_v2.proto",
    "proto/notify.proto",
];
const INCLUDES: [&str; 2] = ["proto", "../party/proto"];
const SERDE: &str =
    r#"#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=../party/proto");

    let mut config = prost_build::Config::new();
    config
        // A message's content stays in `Vec`s, as its clients take its files.
        .bytes([".attachment", ".handshake", ".mailbox", ".notify"])
        .extern_path(".party.v1", "::party::proto")
        // Messages holding secret keys or tokens redact them in hand-written `Debug` impls.
        .skip_debug([
            ".content.v1.AttachmentPointer",
            ".attachment.v1.StartUploadResponse",
            ".attachment.v1.PutChunkRequest",
            ".attachment.v1.DeleteAttachmentRequest",
            ".mailbox.v2.PushV2Request",
        ])
        .message_attribute(
            ".content.v1.AttachmentPointer",
            "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
        )
        .type_attribute(".", SERDE);
    #[cfg(feature = "protox")]
    config.compile_fds(protox::compile(PROTOS, INCLUDES)?)?;
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&PROTOS, &INCLUDES)?;
    Ok(())
}
