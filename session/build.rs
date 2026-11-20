fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    // With `prost`, generate the states' messages.
    #[cfg(feature = "prost")]
    {
        let protos = ["proto/session.proto"];
        let includes = [
            "proto",
            "../party/proto",
            "../ratchetx2/proto",
            "../x3dh/proto",
        ];
        for include in includes {
            println!("cargo:rerun-if-changed={include}");
        }
        let mut config = prost_build::Config::new();
        config
            .extern_path(".party.v1", "::party::proto")
            .extern_path(".ratchetx2.v1", "::ratchetx2::proto")
            .extern_path(".x3dh.v1", "::x3dh::proto")
            // Messages holding key material are zeroized on drop, have no `Bytes` (which cannot
            // be zeroized), and have hand-written `Debug` without keys. All-primitive metadata
            // messages (`PeerPqState`, `SessionSecurity`) derive `Copy` from prost, so they
            // derive `Zeroize` (without `ZeroizeOnDrop`) and are zeroized by `SessionState`'s
            // drop.
            .message_attribute(
                ".session.v1.ClientState",
                "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
            )
            .message_attribute(
                ".session.v1.SessionState",
                "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
            )
            .message_attribute(
                ".session.v1.EarlierSession",
                "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
            )
            .message_attribute(".session.v1.PeerPqState", "#[derive(::zeroize::Zeroize)]")
            .message_attribute(
                ".session.v1.SessionSecurity",
                "#[derive(::zeroize::Zeroize)]",
            )
            .skip_debug(["."]);
        #[cfg(feature = "protox")]
        config.compile_fds(protox::compile(protos, includes)?)?;
        #[cfg(not(feature = "protox"))]
        config.compile_protos(&protos, &includes)?;
    }
    Ok(())
}
