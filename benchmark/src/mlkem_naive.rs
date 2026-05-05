use jkem::params::{
    CIPHERTEXT_BYTES, DECAPSULATION_KEY_BYTES, ENCAPSULATION_KEY_BYTES, SHARED_SECRET_BYTES,
};

const KEYPAIR_COIN_BYTES: usize = 64;
const ENCAPS_COIN_BYTES: usize = 32;

unsafe extern "C" {
    fn bench_mlkem_native_keypair_derand(
        pk: *mut u8,
        sk: *mut u8,
        coins: *const u8,
    ) -> i32;
    fn bench_mlkem_native_enc_derand(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
    ) -> i32;
    fn bench_mlkem_native_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

pub fn keypair_derand(
    coins: &[u8; KEYPAIR_COIN_BYTES],
) -> ([u8; ENCAPSULATION_KEY_BYTES], [u8; DECAPSULATION_KEY_BYTES]) {
    let mut pk = [0u8; ENCAPSULATION_KEY_BYTES];
    let mut sk = [0u8; DECAPSULATION_KEY_BYTES];
    let rc = unsafe {
        bench_mlkem_native_keypair_derand(pk.as_mut_ptr(), sk.as_mut_ptr(), coins.as_ptr())
    };
    assert_eq!(rc, 0, "mlkem-native keypair_derand failed");
    (pk, sk)
}

pub fn enc_derand(
    pk: &[u8; ENCAPSULATION_KEY_BYTES],
    coins: &[u8; ENCAPS_COIN_BYTES],
) -> ([u8; CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES]) {
    let mut ct = [0u8; CIPHERTEXT_BYTES];
    let mut ss = [0u8; SHARED_SECRET_BYTES];
    let rc = unsafe {
        bench_mlkem_native_enc_derand(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr(), coins.as_ptr())
    };
    assert_eq!(rc, 0, "mlkem-native enc_derand failed");
    (ct, ss)
}

pub fn dec(
    ct: &[u8; CIPHERTEXT_BYTES],
    sk: &[u8; DECAPSULATION_KEY_BYTES],
) -> [u8; SHARED_SECRET_BYTES] {
    let mut ss = [0u8; SHARED_SECRET_BYTES];
    let rc = unsafe { bench_mlkem_native_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    assert_eq!(rc, 0, "mlkem-native dec failed");
    ss
}
