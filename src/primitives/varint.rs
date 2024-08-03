use crate::result::{QuicheError, QuicheResult};

// heavily inspired by quinn
#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct VarInt(pub(crate) u64);

impl VarInt {
    pub const MAX: Self = Self((1 << 62) - 1);

    pub const fn new_u32(value: u32) -> Self {
        Self(value as u64)
    }

    pub fn new_u64(value: u64) -> QuicheResult<Self> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(QuicheError("VarInt value exceeds maximum".to_string()))
        }
    }

    pub const fn into_inner(self) -> u64 {
        self.0
    }

    pub fn size(self) -> usize {
        if self.0 < (2 << 6) {
            1
        } else if self.0 < (2 << 14) {
            2
        } else if self.0 < (2 << 30) {
            4
        } else {
            8
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut target = 0;
        unimplemented!()
    }

    pub fn decode(bytes: &mut Vec<u8>) -> Self {
        unimplemented!()
    }
}
