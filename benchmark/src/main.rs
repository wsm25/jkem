use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput};
use jkem::{
    MlKem512,
    params::{MlKem512 as MlKem512Params, MlKemParams, SharedSecret},
};
use mlkem_bench::{bytes32, bytes64, mlkem_native};
use std::hint::black_box;

fn main() {
    let mut criterion = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3))
        .configure_from_args();

    kem(&mut criterion);
    criterion.final_summary();
}

fn kem(c: &mut Criterion) {
    let native_keypair_coins = bytes64(3, 4);
    let native_encaps_coins = bytes32(5);

    let (jkem_ek, jkem_dk) = MlKem512::keygen().unwrap();
    let (jkem_ct, jkem_ss) = MlKem512::encaps(&jkem_ek).unwrap();
    assert_eq!(jkem_ss, MlKem512::decaps(&jkem_dk, &jkem_ct).unwrap());

    let (native_ek, native_dk) = mlkem_native::keypair_derand(&native_keypair_coins);
    let (native_ct, native_ss) = mlkem_native::enc_derand(&native_ek, &native_encaps_coins);
    assert_eq!(native_ss, mlkem_native::dec(&native_ct, &native_dk));

    let keygen_bytes = (MlKem512Params::encapsulation_key_bytes()
        + MlKem512Params::decapsulation_key_bytes()) as u64;
    let encaps_bytes = (MlKem512Params::encapsulation_key_bytes()
        + MlKem512Params::ciphertext_bytes()
        + size_of::<SharedSecret>()) as u64;
    let decaps_bytes = (MlKem512Params::decapsulation_key_bytes()
        + MlKem512Params::ciphertext_bytes()
        + size_of::<SharedSecret>()) as u64;

    let mut group = c.benchmark_group("keygen");
    group.throughput(Throughput::BytesDecimal(keygen_bytes));
    group.bench_function("mlkem-native", |b| {
        b.iter(|| mlkem_native::keypair_derand(black_box(&native_keypair_coins)))
    });
    group.bench_function("jkem", |b| b.iter(|| MlKem512::keygen().unwrap()));
    group.finish();

    let mut group = c.benchmark_group("encaps");
    group.throughput(Throughput::BytesDecimal(encaps_bytes));
    group.bench_function("mlkem-native", |b| {
        b.iter(|| mlkem_native::enc_derand(black_box(&native_ek), black_box(&native_encaps_coins)))
    });
    group.bench_function("jkem", |b| {
        b.iter(|| MlKem512::encaps(black_box(&jkem_ek)).unwrap())
    });
    group.finish();

    let mut group = c.benchmark_group("decaps");
    group.throughput(Throughput::BytesDecimal(decaps_bytes));
    group.bench_function("mlkem-native", |b| {
        b.iter_batched(
            || (native_dk, native_ct),
            |(dk, ct)| mlkem_native::dec(black_box(&ct), black_box(&dk)),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("jkem", |b| {
        b.iter_batched(
            || (jkem_dk, jkem_ct),
            |(dk, ct)| MlKem512::decaps(black_box(&dk), black_box(&ct)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}
