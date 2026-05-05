pub mod mlkem_naive;

pub fn bytes32(seed: u8) -> [u8; 32] {
    core::array::from_fn(|i| seed.wrapping_add((i as u8).wrapping_mul(17)))
}

pub fn bytes64(first_seed: u8, second_seed: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&bytes32(first_seed));
    out[32..].copy_from_slice(&bytes32(second_seed));
    out
}
