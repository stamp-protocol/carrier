use ahash::RandomState;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use stamp_core::{
    crypto::base::{
        rng::{self, RngCore},
        Hash,
    },
    dag::TransactionID,
};
use std::collections::HashMap;

fn benchmarks(c: &mut Criterion) {
    let mut rng = rng::chacha8_seeded(
        Hash::new_blake3(b"what are YOU doing here?")
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap(),
    );
    let ids = (0..100000)
        .map(|i| TransactionID::from(Hash::new_blake3(format!("{}", i).as_bytes()).unwrap()))
        .collect::<Vec<_>>();
    let mut group = c.benchmark_group("hash::fill");
    for hash_size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("HashMap", hash_size), hash_size, |b, &size| {
            b.iter(|| {
                let mut map = HashMap::new();
                for i in 0..size {
                    map.insert(&ids[i], i);
                }
            });
        });
        group.bench_with_input(BenchmarkId::new("AHash", hash_size), hash_size, |b, &size| {
            b.iter(|| {
                let mut map: HashMap<&TransactionID, usize, RandomState> = HashMap::default();
                for i in 0..size {
                    map.insert(&ids[i], i);
                }
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("hash::get_seq");
    for hash_size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("HashMap", hash_size), hash_size, |b, &size| {
            let mut map = HashMap::new();
            for i in 0..size {
                map.insert(&ids[i], i);
            }
            b.iter_batched(
                || map.clone(),
                |map| {
                    for i in 0..size {
                        let _ = map.get(&ids[i]).unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_with_input(BenchmarkId::new("AHash", hash_size), hash_size, |b, &size| {
            let mut map: HashMap<&TransactionID, usize, RandomState> = HashMap::default();
            for i in 0..size {
                map.insert(&ids[i], i);
            }
            b.iter_batched(
                || map.clone(),
                |map| {
                    for i in 0..size {
                        let _ = map.get(&ids[i]).unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("hash::get_rng");
    for hash_size in [10, 100, 1000, 10000].iter() {
        let indexes = (0..*hash_size).map(|_| rng.next_u64() as usize % hash_size).collect::<Vec<_>>();
        group.bench_with_input(BenchmarkId::new("HashMap", hash_size), hash_size, |b, &size| {
            let mut map = HashMap::new();
            for i in 0..size {
                map.insert(&ids[i], i);
            }
            b.iter_batched(
                || map.clone(),
                |map| {
                    for i in &indexes {
                        let _ = map.get(&ids[*i]).unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_with_input(BenchmarkId::new("AHash", hash_size), hash_size, |b, &size| {
            let mut map: HashMap<&TransactionID, usize, RandomState> = HashMap::default();
            for i in 0..size {
                map.insert(&ids[i], i);
            }
            b.iter_batched(
                || map.clone(),
                |map| {
                    for i in &indexes {
                        let _ = map.get(&ids[*i]).unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
