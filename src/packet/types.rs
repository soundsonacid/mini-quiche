use crate::bits::{Bits, BitsExt};
use crate::{bits_ext, rand, VarInt};

// unfortunately it's really annoying to implement a 160 bit integer
#[derive(PartialEq, Debug, Clone)]
pub struct ConnectionId {
    // this MUST NOT exceed 20 bytes
    // endpoints which receive a version 1 long header with a cid_len > 20 must drop the packet
    // to faciliate version negotiation packets, servers should be equipped to handle a cid_len > 20
    pub cid_len: u8,
    pub cid: Vec<u8>,
}

impl ConnectionId {
    pub fn new(cid_len: u8, cid: Vec<u8>) -> Self {
        Self { cid_len, cid }
    }

    pub fn arbitrary() -> Self {
        let cid_len = rand(20) + 1;
        let cid = (0..cid_len).map(|_| rand(255)).collect();
        Self { cid_len, cid }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct PacketNumber(pub VarInt);

impl PacketNumber {
    pub fn size(&self) -> usize {
        self.0.size()
    }
}

bits_ext!(SingleBit, crate::bits::BitsExt<u8>, 1, u8);
bits_ext!(TwoBits, crate::bits::BitsExt<u8>, 2, u8);
bits_ext!(FourBits, crate::bits::BitsExt<u8>, 4, u8);
bits_ext!(SevenBits, crate::bits::BitsExt<u8>, 7, u8);
bits_ext!(LongPacketType, crate::bits::BitsExt<u8>, 2, u8);
bits_ext!(HeaderForm, crate::bits::BitsExt<u8>, 1, u8);

impl Default for SingleBit {
    fn default() -> Self {
        Self::zero()
    }
}

impl LongPacketType {
    #[inline(always)]
    pub fn initial() -> Self {
        Self::zero()
    }

    #[inline(always)]
    pub fn zero_rtt() -> Self {
        Self::one()
    }

    #[inline(always)]
    pub fn handshake() -> Self {
        Self(Bits::from(0b10))
    }

    #[inline(always)]
    pub fn retry() -> Self {
        Self(Bits::from(0b11))
    }
}

impl HeaderForm {
    #[inline(always)]
    pub fn short() -> Self {
        Self::zero()
    }

    #[inline(always)]
    pub fn long() -> Self {
        Self::one()
    }
}
