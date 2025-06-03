use std::env;
use std::path::PathBuf;

fn main() {
    // Компиляция protobuf файлов - это обязательно!
    prost_build::compile_protos(
        &["src/proto/checkin.proto", "src/proto/mcs.proto"],
        &["src/proto"],
    )
    .unwrap();

    // Генерация C/C++ заголовочного файла только если включена feature ffi
    if env::var("CARGO_FEATURE_FFI").is_ok() {
        let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let output_dir = PathBuf::from(&crate_dir).join("include");
        
        // Создаем директорию если её нет
        std::fs::create_dir_all(&output_dir).unwrap();

        // Настройка cbindgen
        let config = cbindgen::Config::from_file("cbindgen.toml")
            .unwrap_or_default();

        // Генерируем заголовочный файл
        cbindgen::Builder::new()
            .with_crate(crate_dir)
            .with_config(config)
            .with_language(cbindgen::Language::Cxx)
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(output_dir.join("fcm_push_listener.h"));

        println!("cargo:rerun-if-changed=src/ffi.rs");
        println!("cargo:rerun-if-changed=cbindgen.toml");
    }
}