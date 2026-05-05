fn main() {
    println!("cargo:rerun-if-changed=mlkem-native/mlkem/mlkem_native.c");
    println!("cargo:rerun-if-changed=mlkem-native/mlkem/mlkem_native.h");
    println!("cargo:rerun-if-changed=mlkem-native/mlkem/mlkem_native_config.h");
    println!("cargo:rerun-if-changed=src/mlkem_native_wrapper.c");

    cc::Build::new()
        .file("mlkem-native/mlkem/mlkem_native.c")
        .file("src/mlkem_native_wrapper.c")
        .include("mlkem-native")
        .include("mlkem-native/mlkem")
        .define("MLK_CONFIG_PARAMETER_SET", "512")
        .define("MLK_CONFIG_NO_RANDOMIZED_API", None)
        .compile("mlkem_native512");
}
