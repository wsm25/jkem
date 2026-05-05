use jkem::params::{
    Ciphertext, DecapsulationKey, EncapsulationKey, MlKem512, MlKem768, MlKem1024, SharedSecret,
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
    fn bench_mlkem_native768_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn bench_mlkem_native768_enc_derand(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
    ) -> i32;
    fn bench_mlkem_native768_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
    fn bench_mlkem_native1024_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    fn bench_mlkem_native1024_enc_derand(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
        coins: *const u8,
    ) -> i32;
    fn bench_mlkem_native1024_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

pub trait NativeKemParams: jkem::params::MlKemParams {
    unsafe fn keypair_derand_raw(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32;
    unsafe fn enc_derand_raw(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32;
    unsafe fn dec_raw(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

impl NativeKemParams for MlKem512 {
    unsafe fn keypair_derand_raw(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32 {
        unsafe { bench_mlkem_native_keypair_derand(pk, sk, coins) }
    }

    unsafe fn enc_derand_raw(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32 {
        unsafe { bench_mlkem_native_enc_derand(ct, ss, pk, coins) }
    }

    unsafe fn dec_raw(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32 {
        unsafe { bench_mlkem_native_dec(ss, ct, sk) }
    }
}

impl NativeKemParams for MlKem768 {
    unsafe fn keypair_derand_raw(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32 {
        unsafe { bench_mlkem_native768_keypair_derand(pk, sk, coins) }
    }

    unsafe fn enc_derand_raw(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32 {
        unsafe { bench_mlkem_native768_enc_derand(ct, ss, pk, coins) }
    }

    unsafe fn dec_raw(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32 {
        unsafe { bench_mlkem_native768_dec(ss, ct, sk) }
    }
}

impl NativeKemParams for MlKem1024 {
    unsafe fn keypair_derand_raw(pk: *mut u8, sk: *mut u8, coins: *const u8) -> i32 {
        unsafe { bench_mlkem_native1024_keypair_derand(pk, sk, coins) }
    }

    unsafe fn enc_derand_raw(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> i32 {
        unsafe { bench_mlkem_native1024_enc_derand(ct, ss, pk, coins) }
    }

    unsafe fn dec_raw(ss: *mut u8, ct: *const u8, sk: *const u8) -> i32 {
        unsafe { bench_mlkem_native1024_dec(ss, ct, sk) }
    }
}

pub fn keypair_derand<P>(
    coins: &[u8; KEYPAIR_COIN_BYTES],
) -> (EncapsulationKey<P>, DecapsulationKey<P>)
where
    P: NativeKemParams,
{
    let mut pk = EncapsulationKey::<P>::default();
    let mut sk = DecapsulationKey::<P>::default();
    let rc = unsafe { P::keypair_derand_raw(pk.as_mut_ptr(), sk.as_mut_ptr(), coins.as_ptr()) };
    assert_eq!(rc, 0, "mlkem-native keypair_derand failed");
    (pk, sk)
}

pub fn enc_derand<P>(
    pk: &EncapsulationKey<P>,
    coins: &[u8; ENCAPS_COIN_BYTES],
) -> (Ciphertext<P>, SharedSecret)
where
    P: NativeKemParams,
{
    let mut ct = Ciphertext::<P>::default();
    let mut ss = [0u8; 32];
    let rc = unsafe {
        P::enc_derand_raw(
            ct.as_mut_ptr(),
            ss.as_mut_ptr(),
            pk.as_ptr(),
            coins.as_ptr(),
        )
    };
    assert_eq!(rc, 0, "mlkem-native enc_derand failed");
    (ct, ss)
}

pub fn dec<P>(ct: &Ciphertext<P>, sk: &DecapsulationKey<P>) -> SharedSecret
where
    P: NativeKemParams,
{
    let mut ss = [0u8; 32];
    let rc = unsafe { P::dec_raw(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
    assert_eq!(rc, 0, "mlkem-native dec failed");
    ss
}
