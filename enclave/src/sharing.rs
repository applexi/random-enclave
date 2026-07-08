use std::marker::PhantomData;
use rand::TryCryptoRng;

mod arithmetic;
mod binary;

pub type ArithmeticSharing = AdditiveSharing<arithmetic::Arithmetic>;
pub type BinarySharing = AdditiveSharing<binary::Binary>;

const DEFAULT_N : usize = 5;

pub struct AdditiveSharing<T: SharingMode> {
    n: usize,
    _sharing: PhantomData<T>,
}

pub trait SharingMode {
    type Share: Copy;

    fn zero() -> Self::Share;
    fn random<T: TryCryptoRng>(rng: &mut T) -> Result<Self::Share, T::Error>;
    fn add(a: Self::Share, b: Self::Share) -> Self::Share;
    fn sub(sum: Self::Share, a: Self::Share) -> Self::Share;

    fn sum<I: IntoIterator<Item = Self::Share>>(iter: I) -> Self::Share {
        iter.into_iter().fold(Self::zero(), Self::add)
    }
}

impl<T: SharingMode> AdditiveSharing<T> {
    pub fn new() -> Self {
        AdditiveSharing{ n: DEFAULT_N, _sharing: PhantomData }
    }
    pub fn share<R: TryCryptoRng>(&self, rng: &mut R, secret: T::Share) -> Result<Vec<T::Share>, R::Error> {
        let mut a: Vec<T::Share> = (0..self.n - 1)
            .map(|_| T::random(rng))
            .collect::<Result<Vec<T::Share>, R::Error>>()?;
        let sum = T::sum(a.iter().copied());
        let a_n = T::sub(secret, sum);
        a.push(a_n);
        Ok(a)
    }
    pub fn reconstruct(&self, shares: &[T::Share]) -> T::Share {
        assert!(shares.len() == self.n);
        T::sum(shares.iter().copied())
    }
}