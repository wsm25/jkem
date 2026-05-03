//! Fujisaki-Okamoto style KEM wrapper over a compatible PKE.
//!
//! `Fo<P>` keeps the wrapper generic while `MlKem512` aliases the concrete
//! ML-KEM-512 instantiation.
//!
//! ```
//! use jkem::fo::MlKem512;
//!
//! let (ek, dk) = MlKem512::keygen()?;
//! let (ct, ss) = MlKem512::encaps(&ek)?;
//! assert_eq!(MlKem512::decaps(&dk, &ct)?, ss);
//!
//! # Ok::<(), jkem::JkemError>(())
//! ```

use core::marker::PhantomData;

use crate::{
    error::Result,
    pke::{FoPke, MlKem512Pke, Pke},
};

pub type MlKem512 = Fo<MlKem512Pke>;

pub struct Fo<P> {
    _pke: PhantomData<P>,
}

impl<P: FoPke> Fo<P> {
    pub fn keygen() -> Result<(
        <P as FoPke>::EncapsulationKey,
        <P as FoPke>::DecapsulationKey,
    )> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        getrandom::fill(&mut d)?;
        getrandom::fill(&mut z)?;
        P::pke_keygen_from_dz(&d, &z)
    }

    #[doc(hidden)]
    pub fn keygen_with_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(
        <P as FoPke>::EncapsulationKey,
        <P as FoPke>::DecapsulationKey,
    )> {
        P::pke_keygen_from_dz(d, z)
    }

    pub fn encaps(
        ek: &<P as FoPke>::EncapsulationKey,
    ) -> Result<(<P as Pke>::Ciphertext, <P as FoPke>::SharedSecret)> {
        let mut message = [0u8; 32];
        getrandom::fill(&mut message)?;
        P::encaps_with_message_fo(ek, &message)
    }

    #[doc(hidden)]
    pub fn encaps_with_message(
        ek: &<P as FoPke>::EncapsulationKey,
        message: &[u8; 32],
    ) -> Result<(<P as Pke>::Ciphertext, <P as FoPke>::SharedSecret)> {
        P::encaps_with_message_fo(ek, message)
    }

    pub fn decaps(
        dk: &<P as FoPke>::DecapsulationKey,
        ct: &<P as Pke>::Ciphertext,
    ) -> Result<<P as FoPke>::SharedSecret> {
        P::decaps_fo(dk, ct)
    }
}

impl Fo<MlKem512Pke> {}
