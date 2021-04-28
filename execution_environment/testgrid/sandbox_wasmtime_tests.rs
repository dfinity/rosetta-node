mod common;
use ic_config::{embedders::EmbedderType, execution_environment::Config};
use ic_utils::ic_features::*;

pub fn config() -> Config {
    cow_state_feature::enable(cow_state_feature::cow_state);
    sandboxed_execution_feature::enable(sandboxed_execution_feature::sandboxed_execution);

    Config {
        embedder_type: EmbedderType::Wasmtime,
        ..Config::default()
    }
}
