use super::SharingMode;
use rand::TryCryptoRng;

pub struct Arithmetic;

impl SharingMode for Arithmetic {
    type Share = u64;

    fn zero() -> u64 { 0 }
    fn random<T: TryCryptoRng>(rng: &mut T) -> Result<u64, T::Error> {
        rng.try_next_u64()
    }
    fn add(a: Self::Share, b: Self::Share) -> u64 {
        a.wrapping_add(b)
    }
    fn sub(sum: Self::Share, a: Self::Share) -> u64 {
        sum.wrapping_sub(a)
    }
}