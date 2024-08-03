use crate::bits::{Bits, BitsExt};
use crate::bits_ext;

// unfortunately it's really annoying to implement a 160 bit integer
#[derive(PartialEq, Debug)]
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
}

#[derive(PartialEq, Debug)]
pub struct PacketNumber {
    pub num: u32,
}

impl PacketNumber {
    pub fn new(num: u32) -> Self {
        Self { num }
    }
}

bits_ext!(SingleBit, crate::bits::BitsExt<u8>, 1, u8);
bits_ext!(TwoBits, crate::bits::BitsExt<u8>, 2, u8);
bits_ext!(FourBits, crate::bits::BitsExt<u8>, 4, u8);
bits_ext!(SevenBits, crate::bits::BitsExt<u8>, 7, u8);
bits_ext!(LongPacketType, crate::bits::BitsExt<u8>, 2, u8);
bits_ext!(HeaderForm, crate::bits::BitsExt<u8>, 1, u8);

impl LongPacketType {
    pub fn initial() -> Self {
        Self::zero()
    }

    pub fn zero_rtt() -> Self {
        Self::one()
    }

    pub fn handshake() -> Self {
        Self(Bits::from(0b10))
    }

    pub fn retry() -> Self {
        Self(Bits::from(0b11))
    }
}

impl HeaderForm {
    pub fn short() -> Self {
        Self::zero()
    }

    pub fn long() -> Self {
        Self::one()
    }
}
