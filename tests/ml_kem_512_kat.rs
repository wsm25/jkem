use jkem::{
    Fo, JkemError, MlKem512,
    params::{
        CIPHERTEXT_BYTES, DECAPSULATION_KEY_BYTES, ENCAPSULATION_KEY_BYTES, SHARED_SECRET_BYTES,
    },
};
use sha2::{Digest, Sha256};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const KAT: &str = include_str!("data/ml_kem_512.kat");
const KAT_SHA256: &str = "ff4efa2b73bafc459d6fb0557d90b05c4bc50cf5d02e30b383edf2e88fa969d8";
const KAT_CASES: usize = 100;

struct KatCase {
    d: [u8; 32],
    z: [u8; 32],
    pk: [u8; ENCAPSULATION_KEY_BYTES],
    sk: [u8; DECAPSULATION_KEY_BYTES],
    m: [u8; 32],
    ct: [u8; CIPHERTEXT_BYTES],
    ss: [u8; SHARED_SECRET_BYTES],
}

#[test]
fn ml_kem_512_kat_file_is_present_and_unchanged() {
    let digest = Sha256::digest(KAT.as_bytes());
    assert_eq!(hex::encode(digest), KAT_SHA256);

    let cases = parse_kat(KAT);
    assert_eq!(cases.len(), KAT_CASES);
}

#[test]
fn ml_kem_512_fo_round_trips_with_fixed_inputs() {
    let case = parse_kat(KAT).remove(0);
    let (ek, dk) = unsafe { MlKem512::keygen_with_seed(&case.d, &case.z) }.unwrap();
    let (ct, ss) = unsafe { MlKem512::encaps_with_message(&ek, &case.m) }.unwrap();
    let decapsulated = MlKem512::decaps(&dk, &ct).unwrap();

    assert_eq!(decapsulated, ss);
}

#[test]
fn ml_kem_512_keygen_matches_kat() {
    for (idx, case) in parse_kat(KAT).iter().enumerate() {
        let (ek, dk) = unsafe { MlKem512::keygen_with_seed(&case.d, &case.z) }
            .unwrap_or_else(|err| panic!("case {idx}: keygen failed: {err}"));

        assert_eq!(ek, case.pk, "case {idx}: pk mismatch");
        assert_eq!(dk, case.sk, "case {idx}: sk mismatch");
    }
}

#[test]
fn ml_kem_512_encaps_matches_kat() {
    for (idx, case) in parse_kat(KAT).iter().enumerate() {
        let ek = case.pk;
        let (ct, ss) = unsafe { MlKem512::encaps_with_message(&ek, &case.m) }
            .unwrap_or_else(|err| panic!("case {idx}: encaps failed: {err}"));

        assert_eq!(ct, case.ct, "case {idx}: ct mismatch");
        assert_eq!(ss, case.ss, "case {idx}: ss mismatch");
    }
}

#[test]
fn ml_kem_512_decaps_matches_kat() {
    for (idx, case) in parse_kat(KAT).iter().enumerate() {
        let dk = case.sk;
        let ct = case.ct;
        let ss = MlKem512::decaps(&dk, &ct)
            .unwrap_or_else(|err| panic!("case {idx}: decaps failed: {err}"));

        assert_eq!(ss, case.ss, "case {idx}: ss mismatch");
    }
}

#[test]
fn ml_kem_512_decaps_uses_fallback_for_modified_ciphertexts() {
    let case = parse_kat(KAT).remove(0);
    for index in [0, CIPHERTEXT_BYTES / 2, CIPHERTEXT_BYTES - 1] {
        let mut modified = case.ct;
        modified[index] ^= 1;

        let ss = MlKem512::decaps(&case.sk, &modified).unwrap();

        let mut fallback_input = [0u8; 32 + CIPHERTEXT_BYTES];
        fallback_input[..32].copy_from_slice(&case.z);
        fallback_input[32..].copy_from_slice(&modified);
        assert_eq!(ss, shake256(&fallback_input), "modified byte {index}");
    }
}

#[test]
fn ml_kem_512_encaps_rejects_non_canonical_public_key_coefficients() {
    let case = parse_kat(KAT).remove(0);
    let mut ek = case.pk;
    ek[0] = 0x01;
    ek[1] = 0x0d;

    let err = match unsafe { MlKem512::encaps_with_message(&ek, &case.m) } {
        Ok(_) => panic!("encapsulation accepted non-canonical public key"),
        Err(err) => err,
    };

    assert_eq!(
        err,
        JkemError::InvalidParameter {
            name: "encapsulation key",
            message: "encoded coefficient is not in [0, q)",
        }
    );
}

#[test]
fn ml_kem_512_decaps_rejects_decapsulation_key_with_wrong_public_key_hash() {
    let case = parse_kat(KAT).remove(0);
    let mut dk = case.sk;
    dk[1568] ^= 1;

    let err = MlKem512::decaps(&dk, &case.ct).unwrap_err();

    assert_eq!(
        err,
        JkemError::InvalidParameter {
            name: "decapsulation key",
            message: "stored H(ek) does not match ek",
        }
    );
}

fn shake256<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    let mut hasher = Shake256::default();
    hasher.update(input);
    hasher.finalize_xof().read(&mut output);
    output
}

fn parse_kat(input: &str) -> Vec<KatCase> {
    let mut cases = Vec::new();
    let mut current = RawKatCase::default();

    for (line_no, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            if !current.is_empty() {
                cases.push(current.finish(line_no));
                current = RawKatCase::default();
            }
            continue;
        }

        let (key, value) = line
            .split_once(" = ")
            .unwrap_or_else(|| panic!("line {}: invalid KAT line", line_no + 1));
        current.set(key, value, line_no + 1);
    }

    if !current.is_empty() {
        cases.push(current.finish(input.lines().count()));
    }

    cases
}

#[derive(Default)]
struct RawKatCase {
    d: Option<Vec<u8>>,
    z: Option<Vec<u8>>,
    pk: Option<Vec<u8>>,
    sk: Option<Vec<u8>>,
    m: Option<Vec<u8>>,
    ct: Option<Vec<u8>>,
    ss: Option<Vec<u8>>,
}

impl RawKatCase {
    fn is_empty(&self) -> bool {
        self.d.is_none()
            && self.z.is_none()
            && self.pk.is_none()
            && self.sk.is_none()
            && self.m.is_none()
            && self.ct.is_none()
            && self.ss.is_none()
    }

    fn set(&mut self, key: &str, value: &str, line_no: usize) {
        let bytes = hex::decode(value).unwrap_or_else(|err| panic!("line {line_no}: {err}"));
        let slot = match key {
            "d" => &mut self.d,
            "z" => &mut self.z,
            "pk" => &mut self.pk,
            "sk" => &mut self.sk,
            "m" => &mut self.m,
            "ct" => &mut self.ct,
            "ss" => &mut self.ss,
            _ => panic!("line {line_no}: unknown KAT key {key:?}"),
        };

        assert!(slot.is_none(), "line {line_no}: duplicate KAT key {key}");
        *slot = Some(bytes);
    }

    fn finish(self, line_no: usize) -> KatCase {
        KatCase {
            d: fixed(self.d, "d", line_no),
            z: fixed(self.z, "z", line_no),
            pk: fixed(self.pk, "pk", line_no),
            sk: fixed(self.sk, "sk", line_no),
            m: fixed(self.m, "m", line_no),
            ct: fixed(self.ct, "ct", line_no),
            ss: fixed(self.ss, "ss", line_no),
        }
    }
}

fn fixed<const N: usize>(value: Option<Vec<u8>>, name: &str, line_no: usize) -> [u8; N] {
    let value = value.unwrap_or_else(|| panic!("line {line_no}: missing KAT key {name}"));
    value
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| panic!("line {line_no}: {name} has {} bytes", value.len()))
}
