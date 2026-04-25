fn main() {
    let proto_path = std::path::PathBuf::from("../../proto/rl_protocol.proto");
    prost_build::Config::new()
        .compile_protos(&[proto_path], &["../../proto/"])
        .expect("Failed to compile protobuf");
}
