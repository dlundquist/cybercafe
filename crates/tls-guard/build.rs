fn main() {
    println!("cargo:rustc-link-lib=netfilter_queue");
    println!("cargo:rustc-link-lib=nfnetlink");
}
