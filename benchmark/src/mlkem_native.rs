use jkem::{
    params::{Ciphertext, DecapsulationKey, EncapsulationKey, MlKem512, SharedSecret},
};

const KEYPAIR_COIN_BYTES: usize = 64;
const ENCAPS_COIN_BYTES: usize = 32;

unsafe extern "C" {
    fn bench_mlkem_native_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
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
) -> (EncapsulationKey<MlKem512>, DecapsulationKey<MlKem512>) {
    let mut pk = EncapsulationKey::<MlKem512>::default();
    let mut sk = DecapsulationKey::<MlKem512>::default();
    let rc = unsafe {
        bench_mlkem_native_keypair_derand(pk.as_mut_ptr(), sk.as_mut_ptr(), coins.as_ptr())
    };
    assert_eq!(rc, 0, "mlkem-native keypair_derand failed");
    (pk, sk)
}

pub fn enc_derand(
    pk: &EncapsulationKey<MlKem512>,
    coins: &[u8; ENCAPS_COIN_BYTES],
) -> (Ciphertext<MlKem512>, SharedSecret) {
    let mut ct = Ciphertext::<MlKem512>::default();
    let mut ss = [0u8; 32];
    let rc = unsafe {
        bench_mlkem_native_enc_derand(
            ct.as_mut_ptr(),
            ss.as_mut_ptr(),
            pk.as_ptr(),
            coins.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "mlkem-native enc_derand failed");
    (ct, ss)
}

pub fn dec(ct: &Ciphertext<MlKem512>, sk: &DecapsulationKey<MlKem512>) -> SharedSecret {
    let mut ss = [0u8; 32];
    let rc = unsafe { bench_mlkem_native_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    assert_eq!(rc, 0, "mlkem-native dec failed");
    ss
}
