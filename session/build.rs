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
            // They hold keys: zeroized on drop, so they have no `Bytes`, which cannot be, and
            // their `Debug` is written by hand, without them.
            .type_attribute(
                ".",
                "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
            )
            .skip_debug(["."]);
        #[cfg(feature = "protox")]
        config.compile_fds(protox::compile(protos, includes)?)?;
        #[cfg(not(feature = "protox"))]
        config.compile_protos(&protos, &includes)?;
    }
    Ok(())
}
