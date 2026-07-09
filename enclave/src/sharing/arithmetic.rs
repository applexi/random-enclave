use super::SharingMode;
use rand::TryCryptoRng;

pub struct Arithmetic;

impl SharingMode for Arithmetic {
    type Share = u64;

    fn zero() -> Self::Share { 0 }
    fn random<T: TryCryptoRng>(rng: &mut T) -> Result<Self::Share, T::Error> {
        rng.try_next_u64()
    }
    fn add(a: Self::Share, b: Self::Share) -> Self::Share {
        a.wrapping_add(b)
    }
    fn sub(a: Self::Share, b: Self::Share) -> Self::Share {
        a.wrapping_sub(b)
    }
}