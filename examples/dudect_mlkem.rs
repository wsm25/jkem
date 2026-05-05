use dudect_bencher::rand::{Rng, RngCore, SeedableRng};
use dudect_bencher::{
    BenchRng, Class, CtRunner,
    ctbench::{BenchMetadata, BenchName, BenchOpts, run_benches_console},
};
use jkem::params::{
    CIPHERTEXT_BYTES, DECAPSULATION_KEY_BYTES, ENCAPSULATION_KEY_BYTES, SHARED_SECRET_BYTES,
};
use jkem::{Fo, MlKem512};
use std::{hint::black_box, path::PathBuf, time::Instant};

const SAMPLES: usize = 100_000;
const KEYGEN_Z_CASES: usize = 1_024;
const KEYGEN_Z_SAMPLES_PER_CASE: usize = 128;

type Ek = [u8; ENCAPSULATION_KEY_BYTES];
type Dk = [u8; DECAPSULATION_KEY_BYTES];
type Ct = [u8; CIPHERTEXT_BYTES];
type Ss = [u8; SHARED_SECRET_BYTES];

fn random_array<const N: usize>(rng: &mut BenchRng) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

fn deterministic_z(case: usize) -> [u8; 32] {
    let mut z = [0u8; 32];
    let mut state = (case as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);

    for chunk in z.chunks_exact_mut(8) {
        state ^= state >> 30;
        state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        state ^= state >> 27;
        state = state.wrapping_mul(0x94d0_49bb_1331_11eb);
        state ^= state >> 31;
        chunk.copy_from_slice(&state.to_le_bytes());
    }

    z
}

fn fixed_keys() -> (Ek, Dk) {
    let seed = [0x42u8; 32];
    let z = [0xa5u8; 32];
    unsafe { MlKem512::keygen_with_seed(&seed, &z) }.expect("fixed keygen must succeed")
}

fn fixed_encapsulation(ek: &Ek) -> (Ct, Ss) {
    let message = [0x7bu8; 32];
    unsafe { MlKem512::encaps_with_message(ek, &message) }
        .expect("fixed encapsulation must succeed")
}

// Current public API cannot vary the secret noise seed while holding `rho`
// fixed, because both are derived from the same 32-byte seed. This scan keeps
// that seed fixed and checks each deterministic `z` case separately against
// random `z`, then reports the worst absolute Welch t-statistic.
fn run_keygen_z_scan() {
    let mut rng = BenchRng::from_entropy();
    let fixed_seed = [0x42u8; 32];
    let mut worst = KeygenZResult::default();

    for case in 0..KEYGEN_Z_CASES {
        let result = keygen_z_case_t(case, fixed_seed, deterministic_z(case), &mut rng);
        if result.t.abs() > worst.t.abs() {
            worst = result;
        }
    }

    println!(
        "keygen_z_scan: cases = {}, samples/case = {}, worst case = {}, max t = {:+0.5}, fixed-z mean ns = {:+0.2}, random-z mean ns = {:+0.2}",
        KEYGEN_Z_CASES,
        KEYGEN_Z_SAMPLES_PER_CASE,
        worst.case,
        worst.t,
        worst.fixed_z.mean,
        worst.random_z.mean,
    );
}

#[derive(Clone, Copy, Default)]
struct KeygenZResult {
    case: usize,
    t: f64,
    fixed_z: RunningStats,
    random_z: RunningStats,
}

#[derive(Clone, Copy, Default)]
struct RunningStats {
    count: usize,
    mean: f64,
    sq_diffs: f64,
}

impl RunningStats {
    fn push(&mut self, value: f64) {
        self.count += 1;
        let diff = value - self.mean;
        self.mean += diff / self.count as f64;
        self.sq_diffs += diff * (value - self.mean);
    }

    fn variance(self) -> f64 {
        self.sq_diffs / (self.count as f64 - 1.0)
    }
}

fn keygen_z_case_t(
    case: usize,
    fixed_seed: [u8; 32],
    fixed_z: [u8; 32],
    rng: &mut BenchRng,
) -> KeygenZResult {
    let mut fixed_z_stats = RunningStats::default();
    let mut random_z_stats = RunningStats::default();

    for _ in 0..KEYGEN_Z_SAMPLES_PER_CASE {
        fixed_z_stats.push(time_keygen(fixed_seed, fixed_z) as f64);
        random_z_stats.push(time_keygen(fixed_seed, random_array::<32>(rng)) as f64);
    }

    KeygenZResult {
        case,
        t: welch_t(fixed_z_stats, random_z_stats),
        fixed_z: fixed_z_stats,
        random_z: random_z_stats,
    }
}

fn time_keygen(seed: [u8; 32], z: [u8; 32]) -> u64 {
    let start = Instant::now();
    let (ek, dk) = unsafe { MlKem512::keygen_with_seed(&seed, &z) }.expect("keygen must succeed");
    black_box((ek[0], dk[0]));
    let elapsed = start.elapsed();
    elapsed.as_secs() * 1_000_000_000 + u64::from(elapsed.subsec_nanos())
}

fn welch_t(lhs: RunningStats, rhs: RunningStats) -> f64 {
    let numerator = lhs.mean - rhs.mean;
    let denominator =
        (lhs.variance() / lhs.count as f64 + rhs.variance() / rhs.count as f64).sqrt();
    numerator / denominator
}

// Encapsulation is tested through the deterministic hook so the message can be
// classified as fixed versus random without measuring OS RNG behavior.
fn dudect_encaps(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (ek, _) = fixed_keys();
    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);
    let fixed_message = [0x7bu8; 32];

    for _ in 0..SAMPLES {
        if rng.r#gen::<bool>() {
            inputs.push(fixed_message);
            classes.push(Class::Left);
        } else {
            inputs.push(random_array::<32>(rng));
            classes.push(Class::Right);
        }
    }

    for (class, message) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let (ct, ss) = unsafe { MlKem512::encaps_with_message(&ek, &message) }
                .expect("encapsulation must succeed");
            (ct[0], ss[0])
        });
    }
}

// Decapsulation compares valid ciphertexts against one-bit-modified invalid
// ciphertexts. The expected behavioral difference is success versus fallback
// shared secret; the FO transform should select between them without branching
// on the validity bit.
fn dudect_decaps(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (ek, dk) = fixed_keys();
    let (valid_ct, _) = fixed_encapsulation(&ek);
    let mut inputs = Vec::with_capacity(SAMPLES);
    let mut classes = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        if rng.r#gen::<bool>() {
            inputs.push(valid_ct);
            classes.push(Class::Left);
        } else {
            let mut modified = valid_ct;
            modified[i % CIPHERTEXT_BYTES] ^= 1;
            inputs.push(modified);
            classes.push(Class::Right);
        }
    }

    for (class, ct) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let ss = MlKem512::decaps(&dk, &ct).expect("decapsulation must succeed");
            ss[0]
        });
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut filter = None;
    let mut continuous = false;
    let mut out = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--filter" => filter = args.next(),
            "--continuous" => {
                continuous = true;
                filter = args.next();
            }
            "--out" => out = args.next().map(PathBuf::from),
            "--help" | "-h" => {
                println!(
                    "Usage: dudect_mlkem [--filter BENCH] [--continuous BENCH] [--out FILE]\n\nBENCH values include keygen_z_scan, encaps, decaps"
                );
                return;
            }
            other => panic!("unknown argument: {other}"),
        }
    }

    let run_keygen_scan = filter
        .as_deref()
        .map_or(true, |value| "keygen_z_scan".contains(value));
    if run_keygen_scan && !continuous {
        run_keygen_z_scan();
    }

    let benches = vec![
        BenchMetadata {
            name: BenchName("dudect_encaps"),
            seed: None,
            benchfn: dudect_encaps,
        },
        BenchMetadata {
            name: BenchName("dudect_decaps"),
            seed: None,
            benchfn: dudect_decaps,
        },
    ];

    let bench_filter = match filter {
        Some(value) if "keygen_z_scan".contains(&value) => Some("__skip_dudect__".to_string()),
        other => other,
    };

    run_benches_console(
        BenchOpts {
            continuous,
            filter: bench_filter,
            file_out: out,
        },
        benches,
    )
    .unwrap();
}
