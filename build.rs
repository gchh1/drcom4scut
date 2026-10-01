fn main() {
    println!("cargo:rerun-if-env-changed=NPCAP_SDK_DIR");
    println!("cargo:rerun-if-changed=Packet.lib");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let directory = if let Some(sdk) = std::env::var_os("NPCAP_SDK_DIR") {
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        match arch.as_str() {
            "x86_64" => std::path::PathBuf::from(sdk).join("Lib/x64"),
            "x86" => std::path::PathBuf::from(sdk).join("Lib"),
            _ => panic!("This Windows build supports x86/x86_64 only"),
        }
    } else {
        std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
    };
    println!("cargo:rustc-link-search=native={}", directory.display());
}
