use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ic_embedders::{Embedder, LucetEmbedder, PersistenceType, WasmtimeEmbedder};
use ic_replicated_state::{BinaryEncodedWasm, NumWasmPages};
use ic_test_utilities::with_test_replica_logger;

fn wat2wasm(wat: &str) -> Result<BinaryEncodedWasm, wabt::Error> {
    wabt::wat2wasm(wat).map(BinaryEncodedWasm::new)
}

fn criterion_benchmark(c: &mut Criterion) {
    with_test_replica_logger(|log| {
        let mut group = c.benchmark_group("instantiate");

        let read_wasm = || {
            use std::io::Read;
            let mut file = std::fs::File::open("benches/bigmap_index_instrumented.wasm").unwrap();
            let mut wasm = Vec::new();
            file.read_to_end(&mut wasm).unwrap();
            BinaryEncodedWasm::new(wasm)
        };

        group.bench_function("wasmtime", |b| {
            let embedder = WasmtimeEmbedder::new(PersistenceType::Sigsegv, log.clone());
            let wasm = read_wasm();
            let compiled = embedder.compile(&wasm).unwrap();
            b.iter(|| {
                black_box(embedder.new_instance(&compiled, &[], NumWasmPages::from(0), None, None))
            })
        });

        group.bench_function("lucet", |b| {
            let embedder = LucetEmbedder::new(PersistenceType::Sigsegv, log.clone());
            let wasm = read_wasm();
            let compiled = embedder.compile(&wasm).unwrap();
            b.iter(|| {
                black_box(embedder.new_instance(&compiled, &[], NumWasmPages::from(0), None, None))
            })
        });

        group.finish();
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
