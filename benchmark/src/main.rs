use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
use hybrid_array::{
    sizes::{U1920, U1952, U3936},
    typenum::{U2, U5, U11},
};
use jkem::{
    MlKem,
    params::{MlKem512, MlKem768, MlKem1024, MlKemParams, N},
};
use mlkem_bench::{
    bytes32, bytes64,
    mlkem_native::{self, NativeKemParams},
};
use std::hint::black_box;

struct MlKem1280;
impl MlKemParams for MlKem1280 {
    type K = U5;
    type Eta1 = U2;
    type Eta2 = U2;
    type Du = U11;
    type Dv = U5;
    type PolyVectorBytes = U1920;
    type EncapsulationKeyBytes = U1952;
    type DecapsulationKeyBytes = U3936;
    type CiphertextBytes = U1920;
}

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
    bench_native::<MlKem512>(c, "mlkem-512");
    bench_jkem::<MlKem512>(c, "mlkem-512");
    bench_native::<MlKem768>(c, "mlkem-768");
    bench_jkem::<MlKem768>(c, "mlkem-768");
    bench_native::<MlKem1024>(c, "mlkem-1024");
    bench_jkem::<MlKem1024>(c, "mlkem-1024");
    bench_jkem::<MlKem1280>(c, "mlkem-1280-exp");
}

fn bench_jkem<P>(c: &mut Criterion, label: &'static str)
where
    P: MlKemParams,
{
    let (ek, dk) = MlKem::<P>::keygen().unwrap();
    let (ct, ss) = MlKem::<P>::encaps(&ek).unwrap();
    assert_eq!(ss, MlKem::<P>::decaps(&dk, &ct).unwrap());

    let mut group = c.benchmark_group("keygen");
    group.throughput(Throughput::BytesDecimal(keygen_bytes::<P>()));
    group.bench_function(BenchmarkId::new("jkem", label), |b| {
        b.iter(|| MlKem::<P>::keygen().unwrap())
    });
    group.finish();

    let mut group = c.benchmark_group("encaps");
    group.throughput(Throughput::BytesDecimal(encaps_bytes::<P>()));
    group.bench_function(BenchmarkId::new("jkem", label), |b| {
        b.iter(|| MlKem::<P>::encaps(black_box(&ek)).unwrap())
    });
    group.finish();

    let mut group = c.benchmark_group("decaps");
    group.throughput(Throughput::BytesDecimal(decaps_bytes::<P>()));
    group.bench_function(BenchmarkId::new("jkem", label), |b| {
        b.iter_batched(
            || (dk.clone(), ct.clone()),
            |(dk, ct)| MlKem::<P>::decaps(black_box(&dk), black_box(&ct)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_native<P>(c: &mut Criterion, label: &'static str)
where
    P: NativeKemParams,
{
    let keypair_coins = bytes64(3, 4);
    let encaps_coins = bytes32(5);
    let (ek, dk) = mlkem_native::keypair_derand::<P>(&keypair_coins);
    let (ct, ss) = mlkem_native::enc_derand::<P>(&ek, &encaps_coins);
    assert_eq!(ss, mlkem_native::dec::<P>(&ct, &dk));

    let mut group = c.benchmark_group("keygen");
    group.throughput(Throughput::BytesDecimal(keygen_bytes::<P>()));
    group.bench_function(BenchmarkId::new("mlkem-native", label), |b| {
        b.iter(|| mlkem_native::keypair_derand::<P>(black_box(&keypair_coins)))
    });
    group.finish();

    let mut group = c.benchmark_group("encaps");
    group.throughput(Throughput::BytesDecimal(encaps_bytes::<P>()));
    group.bench_function(BenchmarkId::new("mlkem-native", label), |b| {
        b.iter(|| mlkem_native::enc_derand::<P>(black_box(&ek), black_box(&encaps_coins)))
    });
    group.finish();

    let mut group = c.benchmark_group("decaps");
    group.throughput(Throughput::BytesDecimal(decaps_bytes::<P>()));
    group.bench_function(BenchmarkId::new("mlkem-native", label), |b| {
        b.iter_batched(
            || (dk.clone(), ct.clone()),
            |(dk, ct)| mlkem_native::dec::<P>(black_box(&ct), black_box(&dk)),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn keygen_bytes<P>() -> u64
where
    P: MlKemParams,
{
    real_throughput_bytes::<P>(4, 0)
}

fn encaps_bytes<P>() -> u64
where
    P: MlKemParams,
{
    real_throughput_bytes::<P>(5, 1)
}

fn decaps_bytes<P>() -> u64
where
    P: MlKemParams,
{
    real_throughput_bytes::<P>(6, 1)
}

fn real_throughput_bytes<P>(linear_terms: usize, constant_terms: usize) -> u64
where
    P: MlKemParams,
{
    const COEFFICIENT_BYTES: usize = size_of::<i16>();
    let k = P::k();
    let poly_bytes = N * COEFFICIENT_BYTES;
    (poly_bytes * (k * k + linear_terms * k + constant_terms)) as u64
}
