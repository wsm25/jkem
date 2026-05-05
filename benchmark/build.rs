fn main() {
    println!("cargo:rerun-if-changed=mlkem-native/mlkem/mlkem_native.c");
    println!("cargo:rerun-if-changed=mlkem-native/mlkem/mlkem_native.h");
    println!("cargo:rerun-if-changed=mlkem-native/mlkem/mlkem_native_config.h");
    println!("cargo:rerun-if-changed=src/bench_mlkem_native_config.h");
    println!("cargo:rerun-if-changed=src/mlkem_native_wrapper.c");

    cc::Build::new()
        .file("src/mlkem_native_wrapper.c")
        .include("mlkem-native")
        .include("mlkem-native/mlkem")
        .include("src")
        .define("MLK_CONFIG_FILE", "\"bench_mlkem_native_config.h\"")
        .compile("mlkem_native512");
}
