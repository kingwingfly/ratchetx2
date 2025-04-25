fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .emit_rerun_if_changed(true)
        .compile_protos(&["proto/message.proto", "proto/x3dh.proto"], &["proto"])?;
    Ok(())
}
