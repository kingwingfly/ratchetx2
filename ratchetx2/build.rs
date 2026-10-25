fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    // With `prost`, generate the state messages; protox compiles them, so protoc is not needed.
    #[cfg(feature = "prost")]
    {
        println!("cargo:rerun-if-changed=proto");
        prost_build::Config::new()
            // They hold keys: zeroized on drop, and their `Debug` is written by hand, without
            // them.
            .type_attribute(
                ".",
                "#[derive(::zeroize::Zeroize, ::zeroize::ZeroizeOnDrop)]",
            )
            .skip_debug(["."])
            .compile_fds(protox::compile(["proto/ratchetx2.proto"], ["proto"])?)?;
    }
    Ok(())
}
