fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile_protos(&["proto/message.proto", "proto/x3dh.proto"], &["proto"])?;
    Ok(())
}
