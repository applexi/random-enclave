use super::SharingMode;
use rand::TryCryptoRng;

pub struct Binary;

impl SharingMode for Binary {
    type Share = bool;

    fn zero() -> bool { false }
    fn random<T: TryCryptoRng>(rng: &mut T) -> Result<bool, T::Error> {
        Ok(rng.try_next_u32()? & 1 == 1)
    }
    fn add(a: Self::Share, b: Self::Share) -> bool {
        a ^ b
    }
    fn sub(sum: Self::Share, a: Self::Share) -> bool {
        a ^ sum
    }
}