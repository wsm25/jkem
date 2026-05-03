use core::ops::{Deref, DerefMut};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct WipeBytes<const N: usize>([u8; N]);

impl<const N: usize> WipeBytes<N> {
    pub(crate) fn zeroed() -> Self {
        Self([0u8; N])
    }

    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> Deref for WipeBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for WipeBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
