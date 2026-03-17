fn main() {
    // Use local spandsp build with V.34 support (LGPL — shared library).
    // Built from v90modem/spandsp-master/ with --enable-v34.
    let home = std::env::var("HOME").unwrap();
    let prefix = format!("{home}/.local");
    println!("cargo:rustc-link-search={prefix}/lib");
    println!("cargo:rustc-link-lib=dylib=spandsp");
    // Set rpath so all binaries in the workspace find libspandsp.so at
    // runtime without needing LD_LIBRARY_PATH.  DEP_SPANDSP_LINK_ARG
    // doesn't propagate to downstream bins, so we write .cargo/config.toml.
    let config_dir = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent().unwrap().parent().unwrap().join(".cargo");
    let config_path = config_dir.join("config.toml");
    let rpath_line = format!(
        "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"link-arg=-Wl,-rpath,{prefix}/lib\"]\n"
    );
    // Only write if the content would change (avoid retriggering builds).
    let current = std::fs::read_to_string(&config_path).unwrap_or_default();
    if current != rpath_line {
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(&config_path, &rpath_line).unwrap();
    }
    println!("cargo:include={prefix}/include");
    // Real V.34 symbols are in libspandsp.so — no stubs needed.
}
