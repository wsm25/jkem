//! Parameter sets and shared ML-KEM constants.
//!
//! - **ML-KEM-512**: K = 2, ETA_1 = 3, ETA_2 = 2, D_U = 10, D_V = 4
//! - **ML-KEM-768**: K = 3, ETA_1 = 2, ETA_2 = 2, D_U = 10, D_V = 4
//! - **ML-KEM-1024**: K = 4, ETA_1 = 2, ETA_2 = 2, D_U = 11, D_V = 5
//!
use hybrid_array::{
    Array, ArraySize,
    sizes::{U768, U800, U1088, U1152, U1184, U1536, U1568, U1632, U2400, U3168},
    typenum::{U2, U3, U4, U5, U10, U11, Unsigned},
};

pub const N: usize = 256;
pub const Q: u16 = 3329;
pub const ZETA: u16 = 17;

pub type Bytes<N> = Array<u8, N>;
pub type EncapsulationKey<P> = Bytes<<P as MlKemParams>::EncapsulationKeyBytes>;
pub type DecapsulationKey<P> = Bytes<<P as MlKemParams>::DecapsulationKeyBytes>;
pub type Ciphertext<P> = Bytes<<P as MlKemParams>::CiphertextBytes>;
pub type PolyVectorBytes<P> = Bytes<<P as MlKemParams>::PolyVectorBytes>;
pub type SharedSecret = [u8; 32];

/// Parameter values and dependent byte lengths for an ML-KEM parameter set.
pub trait MlKemParams {
    type K: ArraySize;
    type Eta1: Unsigned;
    type Eta2: Unsigned;
    type Du: Unsigned;
    type Dv: Unsigned;
    type PolyVectorBytes: ArraySize;
    type EncapsulationKeyBytes: ArraySize;
    type DecapsulationKeyBytes: ArraySize;
    type CiphertextBytes: ArraySize;

    #[inline]
    fn k() -> usize {
        Self::K::USIZE
    }

    #[inline]
    fn eta1() -> usize {
        Self::Eta1::USIZE
    }

    #[inline]
    fn eta2() -> usize {
        Self::Eta2::USIZE
    }

    #[inline]
    fn du() -> usize {
        Self::Du::USIZE
    }

    #[inline]
    fn dv() -> usize {
        Self::Dv::USIZE
    }

    #[inline]
    fn poly_vector_bytes() -> usize {
        Self::PolyVectorBytes::USIZE
    }

    #[inline]
    fn encapsulation_key_bytes() -> usize {
        Self::EncapsulationKeyBytes::USIZE
    }

    #[inline]
    fn decapsulation_key_bytes() -> usize {
        Self::DecapsulationKeyBytes::USIZE
    }

    #[inline]
    fn ciphertext_bytes() -> usize {
        Self::CiphertextBytes::USIZE
    }
}

pub struct MlKem512;
impl MlKemParams for MlKem512 {
    type K = U2;
    type Eta1 = U3;
    type Eta2 = U2;
    type Du = U10;
    type Dv = U4;
    type PolyVectorBytes = U768;
    type EncapsulationKeyBytes = U800;
    type DecapsulationKeyBytes = U1632;
    type CiphertextBytes = U768;
}

pub struct MlKem768;
impl MlKemParams for MlKem768 {
    type K = U3;
    type Eta1 = U2;
    type Eta2 = U2;
    type Du = U10;
    type Dv = U4;
    type PolyVectorBytes = U1152;
    type EncapsulationKeyBytes = U1184;
    type DecapsulationKeyBytes = U2400;
    type CiphertextBytes = U1088;
}

pub struct MlKem1024;
impl MlKemParams for MlKem1024 {
    type K = U4;
    type Eta1 = U2;
    type Eta2 = U2;
    type Du = U11;
    type Dv = U5;
    type PolyVectorBytes = U1536;
    type EncapsulationKeyBytes = U1568;
    type DecapsulationKeyBytes = U3168;
    type CiphertextBytes = U1568;
}
