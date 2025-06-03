// build.rs
extern crate prost_build;

fn main() {
    // Компиляция protobuf
    prost_build::compile_protos(
        &["src/proto/checkin.proto", "src/proto/mcs.proto"],
        &["src/proto"],
    )
    .unwrap();

    // Генерация заголовков только при feature ffi
    #[cfg(feature = "ffi")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let config = cbindgen::Config::from_file("cbindgen.toml")
            .unwrap_or_default();

        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(config)
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file("include/fcm_push_listener.h");
    }
}