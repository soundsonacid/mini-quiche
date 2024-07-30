use std::{
    fmt::{Debug, Display},
    ops::{BitAnd, BitOrAssign, Shl, Shr},
};

pub trait BitsExt {
    fn new(bits: u8) -> Self;
    fn from_num(bits: u8) -> Self;
    fn to_inner(&self) -> u8;
    fn zero() -> Self;
    fn one() -> Self;
    fn bits(&self) -> &[bool];
}

#[derive(PartialEq, Debug)]
pub struct Bits<const N: usize, T> {
    pub bits: [bool; N],
    _phantom: std::marker::PhantomData<T>,
}

impl<const N: usize, T> Bits<N, T>
where
    T: Copy + Clone + Debug + Display, // For format
    T: Shr<usize, Output = T>,         // For >> operator
    T: Shl<usize, Output = T>,         // For << operator
    T: BitAnd<Output = T>,             // For & operator
    T: BitOrAssign,                    // For |= operator
    T: PartialEq + From<u8>,           // For comparison
{
    // size checking enforced at compile-time by T
    pub fn from(bytes: T) -> Self {
        let mut bits: Vec<bool> = Vec::with_capacity(N);
        for i in 0..N {
            let bit = (bytes >> i) & T::from(1) == T::from(1);
            bits.push(bit);
        }
        Self {
            bits: bits
                .try_into()
                .expect(&format!("bytes {} fits into Bits of len {}", bytes, N)),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn to_inner(&self) -> T {
        let mut inner: T = T::from(0);
        for i in 0..N {
            if self.bits[i] {
                inner |= T::from(1) << i;
            }
        }
        inner
    }

    pub fn bits(&self) -> &[bool] {
        &self.bits
    }
}

#[cfg(test)]
mod test_bits {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn rand(modulus: u128) -> u8 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % modulus) as u8
    }

    fn generate_random_u8() -> u8 {
        rand(256)
    }

    fn generate_random_u16() -> u16 {
        rand(65536).into()
    }

    fn generate_random_u32() -> u32 {
        rand(4294967296).into()
    }

    #[test]
    fn test_u8() {
        let invariant = 0b1010_1010;
        let bits = Bits::<8, u8>::from(invariant);
        assert_eq!(
            bits.bits,
            [false, true, false, true, false, true, false, true]
        );
        let inner = bits.to_inner();
        assert_eq!(inner, invariant);

        for _ in 0..100 {
            let random = generate_random_u8();
            let bits = Bits::<8, u8>::from(random);
            let inner = bits.to_inner();
            assert_eq!(inner, random);
        }
    }

    #[test]
    fn test_u16() {
        let invariant = 0b1010_1010_1010_1010;
        let bits = Bits::<16, u16>::from(invariant);
        assert_eq!(
            bits.bits,
            [
                false, true, false, true, false, true, false, true, false, true, false, true,
                false, true, false, true
            ]
        );
        let inner = bits.to_inner();
        assert_eq!(inner, invariant);

        for _ in 0..100 {
            let random = generate_random_u16();
            let bits = Bits::<16, u16>::from(random);
            let inner = bits.to_inner();
            assert_eq!(inner, random);
        }
    }

    #[test]
    fn test_u32() {
        let invariant = 0b1010_1010_1010_1010_1010_1010_1010_1010;
        let bits = Bits::<32, u32>::from(invariant);
        assert_eq!(
            bits.bits,
            [
                false, true, false, true, false, true, false, true, false, true, false, true,
                false, true, false, true, false, true, false, true, false, true, false, true,
                false, true, false, true, false, true, false, true
            ]
        );
        let inner = bits.to_inner();
        assert_eq!(inner, invariant);

        for _ in 0..100 {
            let random = generate_random_u32();
            let bits = Bits::<32, u32>::from(random);
            let inner = bits.to_inner();
            assert_eq!(inner, random);
        }
    }
}
