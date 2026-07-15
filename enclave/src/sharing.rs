use std::marker::PhantomData;
use rand::TryCryptoRng;

mod arithmetic;
mod binary;

/// An additive sharing scheme for [`ArithShare`]
pub type ArithmeticSharing = AdditiveSharing<arithmetic::Arithmetic>;
/// An additive sharing scheme for [`BitShare`]
pub type BinarySharing = AdditiveSharing<binary::Binary>;

/// A type `u64` share
pub type ArithShare = <arithmetic::Arithmetic as SharingMode>::Share;
/// A type `bool` share
pub type BitShare = <binary::Binary as SharingMode>::Share;

/// Generates a random [`ArithShare`]
pub fn random_arith<R: TryCryptoRng>(rng: &mut R) -> Result<ArithShare, R::Error> {
    arithmetic::Arithmetic::random(rng)
}

/// Interface for a type `share`, algebraic operations on shares, and generating a random share
pub trait SharingMode {
    type Share: Copy;

    fn zero() -> Self::Share;
    fn random<T: TryCryptoRng>(rng: &mut T) -> Result<Self::Share, T::Error>;
    fn add(a: Self::Share, b: Self::Share) -> Self::Share;
    fn sub(a: Self::Share, b: Self::Share) -> Self::Share;

    fn sum(shares: &[Self::Share]) -> Self::Share {
        shares.iter().fold(Self::zero(), |acc, share| Self::add(acc, *share))
    }
}

/// With a valid [`SharingMode`], defines a valid additive secret sharing scheme
pub struct AdditiveSharing<T: SharingMode> {
    n: usize,
    _sharing: PhantomData<T>,
}

impl<T: SharingMode> AdditiveSharing<T> {
    pub fn new() -> Self {
        AdditiveSharing{ n: common::DEFAULT_N, _sharing: PhantomData }
    }
    /// Returns [`DEFAULT_N`] shares from a given secret
    pub fn share<R: TryCryptoRng>(&self, rng: &mut R, secret: T::Share) -> Result<Vec<T::Share>, R::Error> {
        let mut a: Vec<T::Share> = (0..self.n - 1)
            .map(|_| T::random(rng))
            .collect::<Result<Vec<T::Share>, R::Error>>()?;
        let sum = T::sum(&a);
        let a_n = T::sub(secret, sum);
        a.push(a_n);
        Ok(a)
    }
    /// Given [`DEFAULT_N`] shares, returns their sum
    pub fn reconstruct(&self, shares: &[T::Share]) -> T::Share {
        assert!(shares.len() == self.n);
        T::sum(shares)
    }
}