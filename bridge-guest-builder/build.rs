use sp1_helper::build_program;

fn main() {
    // Tell Cargo to rerun this build script if SKIP_GUEST_BUILD changes.
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");

    // Register our custom cfg flag so that Cargo (and Clippy) know it's valid.
    println!("cargo:rustc-check-cfg=cfg(skip_guest_build)");

    // Check the environment variable and set the custom cfg flag if needed.
    if std::env::var("SKIP_GUEST_BUILD").unwrap_or_default() == "1" {
        println!("cargo:rustc-cfg=skip_guest_build");
    }

    build_program("bridge-guest");
}
