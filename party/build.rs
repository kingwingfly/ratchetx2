fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = ["proto/party.proto"];
    let mut config = prost_build::Config::new();
    config
        .bytes(["."])
        .type_attribute(
            ".",
            r#"#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]"#,
        )
        .type_attribute(
            ".",
            r#"#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]"#,
        );
    #[cfg(feature = "protox")]
    config.compile_fds(protox::compile(protos, ["proto"])?)?;
    #[cfg(not(feature = "protox"))]
    config.compile_protos(&protos, &["proto"])?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
