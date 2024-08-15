use crate::result::{QuicheError, QuicheResult};

// heavily inspired by quinn
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct VarInt(pub(crate) u64);

impl VarInt {
    pub const MAX: Self = Self((1 << 62) - 1);

    #[inline(always)]
    pub const fn new_u32(value: u32) -> Self {
        Self(value as u64)
    }

    #[inline(always)]
    pub const fn zero() -> Self {
        Self(0)
    }

    pub fn new_u64(value: u64) -> QuicheResult<Self> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(QuicheError("VarInt value exceeds maximum".to_string()))
        }
    }

    pub unsafe fn new_unchecked(value: u64) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub const fn to_inner(self) -> u64 {
        self.0
    }

    // this is horrible and i know it is, but it seems to be fine
    #[inline(always)]
    pub fn usize(self) -> usize {
        let value = self.to_inner();
        if value > usize::MAX as u64 {
            panic!("Value {} is too large to fit into a usize", value);
        }
        value as usize
    }

    pub fn size(self) -> usize {
        if self.0 < (2u64.pow(6)) {
            1 // byte
        } else if self.0 < (2u64.pow(14)) {
            2 // bytes
        } else if self.0 < (2u64.pow(30)) {
            4 // bytes
        } else {
            8 // bytes
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        let value = self.0;
        let size = self.size();

        let prefix = match size {
            1 => 0b00,
            2 => 0b01,
            4 => 0b10,
            8 => 0b11,
            _ => unreachable!(),
        };
        buf.push((prefix << 6 | (value >> (8 * (size - 1)) & 0x3F)) as u8);

        for i in (0..size - 1).rev() {
            buf.push(((value >> (8 * i)) & 0xFF) as u8);
        }

        buf
    }

    pub fn decode(bytes: &mut Vec<u8>) -> QuicheResult<Self> {
        if bytes.is_empty() {
            return Ok(Self::new_u32(0))
        }
        let first_byte = bytes.remove(0);
        let disc = (first_byte & 0b11_000000) >> 6;
        let mut val = (first_byte & 0b00_111111) as u64;

        for _ in 0..2u64.pow(disc as u32) - 1 {
            val <<= 8;
            val |= bytes.remove(0) as u64;
        }

        Self::new_u64(val)
    }
}

impl Default for VarInt {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn rand_u64(modulus: u128) -> u64 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % modulus) as u64
    }

    #[test]
    fn test_varint() {
        assert_eq!((2 << 5) - 1, 63);
        let varint_xsmall = VarInt::new_u32(63);
        let xsmall_encoded = varint_xsmall.encode();
        assert_eq!(xsmall_encoded, vec![0b00_111111]);
        let xsmall_decoded = VarInt::decode(&mut xsmall_encoded.clone()).unwrap();
        assert_eq!(varint_xsmall, xsmall_decoded);

        let varint_small = VarInt::new_u32(16_383);
        let small_encoded = varint_small.encode();
        assert_eq!(small_encoded, vec![0b01_111111, 0b11_111111]);
        let small_decoded = VarInt::decode(&mut small_encoded.clone()).unwrap();
        assert_eq!(varint_small, small_decoded);

        let varint_medium = VarInt::new_u64(357_913_941).unwrap();
        let medium_encoded = varint_medium.encode();
        assert_eq!(
            medium_encoded,
            vec![0b10_010101, 0b01_010101, 0b01_010101, 0b01_010101]
        );
        let medium_decoded = VarInt::decode(&mut medium_encoded.clone()).unwrap();
        assert_eq!(varint_medium, medium_decoded);

        let varint_large = VarInt::new_u64(1_537_228_672_809_129_301).unwrap();
        let large_encoded = varint_large.encode();
        assert_eq!(
            large_encoded,
            vec![
                0b11_010101,
                0b01_010101,
                0b01_010101,
                0b01_010101,
                0b01_010101,
                0b01_010101,
                0b01_010101,
                0b01_010101
            ]
        );
        let large_decoded = VarInt::decode(&mut large_encoded.clone()).unwrap();
        assert_eq!(varint_large, large_decoded);
    }

    #[test]
    fn test_cast() {
        let num_casts = 1_000_000;
        for _ in 0..num_casts {
            let varint = VarInt::new_u64(rand_u64(u64::MAX as u128 + 1)).unwrap();
            let casted: usize = varint.usize();
            assert_eq!(varint.to_inner(), casted as u64);
        }
    }
}
