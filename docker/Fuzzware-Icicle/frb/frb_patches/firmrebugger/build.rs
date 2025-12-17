fn main() {
    compile_tinycc();

    cc::Build::new().include("tinycc").files(["firmrebugger.c"]).compile("firmrebugger");
    println!("cargo:rustc-link-lib=firmrebugger");

    println!("cargo:rerun-if-changed=./firmrebugger.h");
    println!("cargo:rerun-if-changed=./firmrebugger.c");

    let bindings = bindgen::builder()
        .header("firmrebugger.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .size_t_is_usize(true)
        .layout_tests(false)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .translate_enum_integer_types(true)
        .generate()
        .expect("failed to generated bindings");

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("firmrebugger.rs")).expect("failed to write bindings");
}

fn compile_tinycc() {
    let tinycc_path = std::path::Path::new("/home/user/fuzzware-icicle/tinycc/");
    // let configure_path = tinycc_path.join("./configure").canonicalize().unwrap();
    // println!("cargo:rerun-if-changed={}", configure_path.display());

    // if !std::path::Path::new("./tinycc/config.h").exists() {
    //     let status = std::process::Command::new(&configure_path)
    //         .current_dir(&tinycc_path)
    //         .arg("--enable-static")
    //         .status()
    //         .expect("failed to configure tinycc");
    //     assert!(status.success());
    // }

    // println!(
    //     "cargo:rerun-if-changed={}",
    //     tinycc_path.join("Makefile").canonicalize().unwrap().display()
    // );

    // let status = std::process::Command::new("make")
    //     .current_dir(tinycc_path)
    //     .status()
    //     .expect("failed to make tinycc");
    // assert!(status.success());

    println!("cargo:rustc-link-search=native={}", tinycc_path.canonicalize().unwrap().display());
    println!("cargo:rustc-link-lib=static=tcc");
}
