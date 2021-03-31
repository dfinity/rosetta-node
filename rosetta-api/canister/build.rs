use prost_build::Config;
use std::env;

fn main() {
    let proto_file = "proto/types.proto";
    println!("cargo:rerun-if-changed={}", proto_file);

    let base_types_proto_dir = match env::var("IC_BASE_TYPES_PROTO_INCLUDES") {
        Ok(dir) => dir,
        Err(_) => "../../types/base_types/proto".into(),
    };

    let mut config = Config::new();
    config.extern_path(".ic_base_types.pb.v1", "::ic-base-types");
    config.out_dir("gen");

    config
        .compile_protos(&[proto_file], &["proto/", &base_types_proto_dir])
        .unwrap();
}
