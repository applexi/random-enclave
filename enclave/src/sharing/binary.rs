use super::SharingMode;
use rand::TryCryptoRng;

pub struct Binary;

impl SharingMode for Binary {
    type Share = bool;

    fn zero() -> Self::Share { false }
    fn random<T: TryCryptoRng>(rng: &mut T) -> Result<Self::Share, T::Error> {
        Ok(rng.try_next_u32()? & 1 == 1)
    }
    fn add(a: Self::Share, b: Self::Share) -> Self::Share {
        a ^ b
    }
    fn sub(a: Self::Share, b: Self::Share) -> Self::Share {
        a ^ b
    }
}