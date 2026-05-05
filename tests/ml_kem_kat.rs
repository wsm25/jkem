use hybrid_array::{Array, ArraySize, typenum::Unsigned};
use jkem::{
    JkemError, MlKem,
    params::{
        Ciphertext, DecapsulationKey, EncapsulationKey, MlKem512, MlKem768, MlKem1024, MlKemParams,
        SharedSecret,
    },
};
use sha3::{
    digest::{Digest, ExtendableOutput, Update, XofReader},
    {Sha3_256, Shake256},
};
use std::sync::OnceLock;

const KAT_CASES: usize = 100;

macro_rules! ml_kem_kat_tests {
    (
        $params:ty,
        $module:ident,
        $file_test:ident,
        $pk_test:ident,
        $sk_test:ident,
        $ct_test:ident,
        $encaps_ss_test:ident,
        $decaps_ss_test:ident,
        $malformed_test:ident,
        $path:literal,
        $digest:literal
    ) => {
        mod $module {
            use super::*;

            const KAT: &str = include_str!($path);
            const KAT_SHA256: &str = $digest;
            static KAT_CASES: OnceLock<Vec<KatCase<$params>>> = OnceLock::new();

            fn kat_cases() -> &'static [KatCase<$params>] {
                KAT_CASES
                    .get_or_init(|| parse_kat_cases::<$params>(KAT))
                    .as_slice()
            }

            #[test]
            fn $file_test() {
                assert_kat_file(KAT, KAT_SHA256, kat_cases());
            }

            #[test]
            fn $pk_test() {
                assert_public_keys::<$params>(kat_cases());
            }

            #[test]
            fn $sk_test() {
                assert_secret_keys::<$params>(kat_cases());
            }

            #[test]
            fn $ct_test() {
                assert_ciphertexts::<$params>(kat_cases());
            }

            #[test]
            fn $encaps_ss_test() {
                assert_encapsulated_shared_secrets::<$params>(kat_cases());
            }

            #[test]
            fn $decaps_ss_test() {
                assert_decapsulated_shared_secrets::<$params>(kat_cases());
            }

            #[test]
            fn $malformed_test() {
                run_malformed_input_checks(kat_cases());
            }
        }
    };
}

ml_kem_kat_tests!(
    MlKem512,
    ml_kem_512,
    ml_kem_512_kat_file_is_present_and_unchanged,
    ml_kem_512_public_keys_match_kat,
    ml_kem_512_secret_keys_match_kat,
    ml_kem_512_ciphertexts_match_kat,
    ml_kem_512_encapsulated_shared_secrets_match_kat,
    ml_kem_512_decapsulated_shared_secrets_match_kat,
    ml_kem_512_rejects_malformed_inputs,
    "data/ml_kem_512.kat",
    "a3fb26d2a4d555f190889f4f50d894fd5feb66276eb14786684f160f1e901fb1"
);

ml_kem_kat_tests!(
    MlKem768,
    ml_kem_768,
    ml_kem_768_kat_file_is_present_and_unchanged,
    ml_kem_768_public_keys_match_kat,
    ml_kem_768_secret_keys_match_kat,
    ml_kem_768_ciphertexts_match_kat,
    ml_kem_768_encapsulated_shared_secrets_match_kat,
    ml_kem_768_decapsulated_shared_secrets_match_kat,
    ml_kem_768_rejects_malformed_inputs,
    "data/ml_kem_768.kat",
    "91a4a2547b595d481fbca645b567391f3fcacfdf3f99670f1dfdd0340bc6dc86"
);

ml_kem_kat_tests!(
    MlKem1024,
    ml_kem_1024,
    ml_kem_1024_kat_file_is_present_and_unchanged,
    ml_kem_1024_public_keys_match_kat,
    ml_kem_1024_secret_keys_match_kat,
    ml_kem_1024_ciphertexts_match_kat,
    ml_kem_1024_encapsulated_shared_secrets_match_kat,
    ml_kem_1024_decapsulated_shared_secrets_match_kat,
    ml_kem_1024_rejects_malformed_inputs,
    "data/ml_kem_1024.kat",
    "9497435b73a0f2d854434ca595297f68a7c474ae9fb79bb5f2a49a9bd1c4f905"
);

struct KatCase<P>
where
    P: MlKemParams,
{
    d: [u8; 32],
    z: [u8; 32],
    pk: EncapsulationKey<P>,
    sk: DecapsulationKey<P>,
    m: [u8; 32],
    ct: Ciphertext<P>,
    ss: SharedSecret,
}

fn assert_kat_file<P>(input: &str, expected_digest: &str, cases: &[KatCase<P>])
where
    P: MlKemParams,
{
    let digest = Sha3_256::digest(input.as_bytes());
    assert_eq!(hex::encode(digest), expected_digest);
    assert_eq!(cases.len(), KAT_CASES);
}

fn assert_public_keys<P>(cases: &[KatCase<P>])
where
    P: MlKemParams,
{
    for (idx, case) in cases.iter().enumerate() {
        let (ek, _) = unsafe { MlKem::<P>::keygen_internal(&case.d, &case.z) }
            .unwrap_or_else(|err| panic!("case {idx}: keygen failed: {err}"));
        assert_eq!(ek, case.pk, "case {idx}: pk mismatch");
    }
}

fn assert_secret_keys<P>(cases: &[KatCase<P>])
where
    P: MlKemParams,
{
    for (idx, case) in cases.iter().enumerate() {
        let (_, dk) = unsafe { MlKem::<P>::keygen_internal(&case.d, &case.z) }
            .unwrap_or_else(|err| panic!("case {idx}: keygen failed: {err}"));
        assert_eq!(dk, case.sk, "case {idx}: sk mismatch");
    }
}

fn assert_ciphertexts<P>(cases: &[KatCase<P>])
where
    P: MlKemParams,
{
    for (idx, case) in cases.iter().enumerate() {
        let (ct, _) = unsafe { MlKem::<P>::encaps_internal(&case.pk, &case.m) }
            .unwrap_or_else(|err| panic!("case {idx}: encaps failed: {err}"));
        assert_eq!(ct, case.ct, "case {idx}: ct mismatch");
    }
}

fn assert_encapsulated_shared_secrets<P>(cases: &[KatCase<P>])
where
    P: MlKemParams,
{
    for (idx, case) in cases.iter().enumerate() {
        let (_, ss) = unsafe { MlKem::<P>::encaps_internal(&case.pk, &case.m) }
            .unwrap_or_else(|err| panic!("case {idx}: encaps failed: {err}"));
        assert_eq!(ss, case.ss, "case {idx}: ss mismatch");
    }
}

fn assert_decapsulated_shared_secrets<P>(cases: &[KatCase<P>])
where
    P: MlKemParams,
{
    for (idx, case) in cases.iter().enumerate() {
        let ss = MlKem::<P>::decaps(&case.sk, &case.ct)
            .unwrap_or_else(|err| panic!("case {idx}: decaps failed: {err}"));
        assert_eq!(ss, case.ss, "case {idx}: ss mismatch");
    }
}

fn run_malformed_input_checks<P>(cases: &[KatCase<P>])
where
    P: MlKemParams,
{
    let case = &cases[0];
    for index in [
        0,
        P::CiphertextBytes::USIZE / 2,
        P::CiphertextBytes::USIZE - 1,
    ] {
        let mut modified = case.ct.clone();
        modified[index] ^= 1;

        let ss = MlKem::<P>::decaps(&case.sk, &modified).unwrap();

        assert_eq!(
            ss,
            shake256([&case.z[..], &modified[..]]),
            "modified byte {index}"
        );
    }

    let mut ek = case.pk.clone();
    ek[0] = 0x01;
    ek[1] = 0x0d;
    let err = unsafe { MlKem::<P>::encaps_internal(&ek, &case.m) }.unwrap_err();
    assert_eq!(
        err,
        JkemError::InvalidParameter {
            name: "encapsulation key",
            message: "encoded coefficient is not in [0, q)",
        }
    );

    let mut dk = case.sk.clone();
    dk[P::PolyVectorBytes::USIZE + P::EncapsulationKeyBytes::USIZE] ^= 1;
    let err = MlKem::<P>::decaps(&dk, &case.ct).unwrap_err();
    assert_eq!(
        err,
        JkemError::InvalidParameter {
            name: "decapsulation key",
            message: "stored H(ek) does not match ek",
        }
    );
}

fn shake256<'a, const N: usize>(input: impl IntoIterator<Item = &'a [u8]>) -> [u8; N] {
    let mut output = [0u8; N];
    let mut hasher = Shake256::default();
    for chunk in input {
        hasher.update(chunk);
    }
    hasher.finalize_xof().read(&mut output);
    output
}

fn kat_chunks(input: &str) -> impl Iterator<Item = &str> {
    input.split("\n\n").filter(|chunk| !chunk.trim().is_empty())
}

fn parse_kat_cases<P>(input: &str) -> Vec<KatCase<P>>
where
    P: MlKemParams,
{
    let cases = kat_chunks(input)
        .enumerate()
        .map(|(idx, chunk)| parse_kat_case::<P>(chunk, idx))
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), KAT_CASES);
    cases
}

fn parse_kat_case<P>(input: &str, idx: usize) -> KatCase<P>
where
    P: MlKemParams,
{
    let mut current = RawKatCase::<P>::default();

    for (line_no, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let (key, value) = line
            .split_once(" = ")
            .unwrap_or_else(|| panic!("case {idx}, line {}: invalid KAT line", line_no + 1));
        current.set(key, value, idx, line_no + 1);
    }

    current.finish(idx)
}

struct RawKatCase<P>
where
    P: MlKemParams,
{
    d: Option<[u8; 32]>,
    z: Option<[u8; 32]>,
    pk: Option<EncapsulationKey<P>>,
    sk: Option<DecapsulationKey<P>>,
    m: Option<[u8; 32]>,
    ct: Option<Ciphertext<P>>,
    ss: Option<SharedSecret>,
}

impl<P> Default for RawKatCase<P>
where
    P: MlKemParams,
{
    fn default() -> Self {
        Self {
            d: None,
            z: None,
            pk: None,
            sk: None,
            m: None,
            ct: None,
            ss: None,
        }
    }
}

impl<P> RawKatCase<P>
where
    P: MlKemParams,
{
    fn set(&mut self, key: &str, value: &str, idx: usize, line_no: usize) {
        match key {
            "d" => set_slot(
                &mut self.d,
                decode_hex(value, "d", idx, line_no),
                key,
                idx,
                line_no,
            ),
            "z" => set_slot(
                &mut self.z,
                decode_hex(value, "z", idx, line_no),
                key,
                idx,
                line_no,
            ),
            "pk" => set_slot(
                &mut self.pk,
                decode_hex_array(value, "pk", idx, line_no),
                key,
                idx,
                line_no,
            ),
            "sk" => set_slot(
                &mut self.sk,
                decode_hex_array(value, "sk", idx, line_no),
                key,
                idx,
                line_no,
            ),
            "m" => set_slot(
                &mut self.m,
                decode_hex(value, "m", idx, line_no),
                key,
                idx,
                line_no,
            ),
            "ct" => set_slot(
                &mut self.ct,
                decode_hex_array(value, "ct", idx, line_no),
                key,
                idx,
                line_no,
            ),
            "ss" => set_slot(
                &mut self.ss,
                decode_hex(value, "ss", idx, line_no),
                key,
                idx,
                line_no,
            ),
            _ => panic!("case {idx}, line {line_no}: unknown KAT key {key:?}"),
        }
    }

    fn finish(self, idx: usize) -> KatCase<P> {
        KatCase {
            d: required(self.d, "d", idx),
            z: required(self.z, "z", idx),
            pk: required(self.pk, "pk", idx),
            sk: required(self.sk, "sk", idx),
            m: required(self.m, "m", idx),
            ct: required(self.ct, "ct", idx),
            ss: required(self.ss, "ss", idx),
        }
    }
}

fn set_slot<T>(slot: &mut Option<T>, value: T, key: &str, idx: usize, line_no: usize) {
    assert!(
        slot.is_none(),
        "case {idx}, line {line_no}: duplicate KAT key {key}"
    );
    *slot = Some(value);
}

fn required<T>(value: Option<T>, name: &str, idx: usize) -> T {
    value.unwrap_or_else(|| panic!("case {idx}: missing KAT key {name}"))
}

fn decode_hex_array<N>(value: &str, name: &str, idx: usize, line_no: usize) -> Array<u8, N>
where
    N: ArraySize,
{
    assert_eq!(
        value.len(),
        N::USIZE * 2,
        "case {idx}, line {line_no}: {name} has {} hex chars",
        value.len()
    );

    let mut out = Array::<u8, N>::default();
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(value.as_bytes()[2 * i], name, idx, line_no);
        let lo = hex_nibble(value.as_bytes()[2 * i + 1], name, idx, line_no);
        *byte = (hi << 4) | lo;
    }
    out
}

fn decode_hex<const N: usize>(value: &str, name: &str, idx: usize, line_no: usize) -> [u8; N] {
    assert_eq!(
        value.len(),
        N * 2,
        "case {idx}, line {line_no}: {name} has {} hex chars",
        value.len()
    );

    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(value.as_bytes()[2 * i], name, idx, line_no);
        let lo = hex_nibble(value.as_bytes()[2 * i + 1], name, idx, line_no);
        *byte = (hi << 4) | lo;
    }
    out
}

fn hex_nibble(value: u8, name: &str, idx: usize, line_no: usize) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("case {idx}, line {line_no}: {name} contains non-hex byte"),
    }
}
