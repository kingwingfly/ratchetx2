const BASE_PROTOS: [&str; 5] = [
    "proto/attachment.proto",
    "proto/content.proto",
    "proto/handshake.proto",
    "proto/mailbox.proto",
    "proto/notify.proto",
];
#[cfg(feature = "pq")]
const PQ_PROTOS: [&str; 2] = ["proto/handshake_v2.proto", "proto/mailbox_v2.proto"];
const INCLUDES: [&str; 2] = ["proto", "../party/proto"];
const SERDE: &str =
    r#"#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]"#;
const RKYV: &str =
    r#"#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=../party/proto");

    #[allow(unused_mut)]
    let mut protos: Vec<&str> = BASE_PROTOS.to_vec();
    #[cfg(feature = "pq")]
    protos.extend_from_slice(&PQ_PROTOS);

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
        ])
        .message_attribute(
            ".content.v1.AttachmentPointer",
            "#[derive(::zeroize::Zeroize)]",
        )
        .field_attribute(
            ".notify.v1.SubscribeRequest.audience",
            r#"#[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "String::is_empty"))]"#,
        )
        .type_attribute(".", SERDE)
        .type_attribute(".", RKYV);
    #[cfg(feature = "protox")]
    config.compile_fds(protox::compile(&protos, INCLUDES)?)?;
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&protos, &INCLUDES)?;
    Ok(())
}
