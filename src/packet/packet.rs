use crate::{bits::BitsExt, result::QuicheResult, VarInt};

use super::{
    header::{Header, LongHeader, LongHeaderExtension, ShortHeader},
    ConnectionId, FourBits, HeaderForm, LongPacketType, PacketNumber, SingleBit, TwoBits,
};

#[derive(PartialEq, Debug, Clone)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>, // TODO: change to Vec<Frame>
}

impl Packet {
    pub fn contains_frames(&self) -> bool {
        // retry and version negotiation packets do not contain frames
        !matches!(self.header, Header::Retry(_) | Header::VersionNegotiate(_))
    }

    pub fn initial(
        version_id: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        type_specific_bits: FourBits,
        token_length: VarInt,
        token: Vec<u8>,
        length: VarInt,
        packet_number: PacketNumber,
        payload: Vec<u8>,
    ) -> Self {
        let header = Header::Initial(LongHeader::initial(
            version_id,
            dst_cid,
            src_cid,
            type_specific_bits,
            token_length,
            token,
            length,
            packet_number,
        ));
        Self { header, payload }
    }

    pub fn long_header(
        long_packet_type: LongPacketType,
        type_specific_bits: FourBits,
        version_id: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        extension: LongHeaderExtension,
        payload: Vec<u8>,
    ) -> Self {
        let header = Header::Long(LongHeader::new(
            long_packet_type,
            type_specific_bits,
            version_id,
            dst_cid,
            src_cid,
            extension,
        ));
        Self { header, payload }
    }

    pub fn short_header(
        spin_bit: SingleBit,
        reserved_bits: TwoBits,
        key_phase: SingleBit,
        number_len: TwoBits,
        dst_cid: ConnectionId,
        number: Vec<u8>,
        payload: Vec<u8>,
    ) -> Self {
        let header = Header::Short(ShortHeader::new(
            spin_bit,
            reserved_bits,
            key_phase,
            number_len,
            dst_cid,
            number,
        ));
        Self { header, payload }
    }

    pub fn encode(&self) -> QuicheResult<Vec<u8>> {
        let mut encoded = self.header.encode()?;
        encoded.extend(self.payload.iter());
        Ok(encoded)
    }

    pub fn decode(bytes: &mut Vec<u8>) -> QuicheResult<Self> {
        match bytes[0] & 0b10_000000 == HeaderForm::short().to_inner() {
            true => return Packet::decode_short_header(bytes),
            false => return Packet::decode_long_header(bytes),
        }
    }

    fn decode_long_header(bytes: &mut Vec<u8>) -> QuicheResult<Self> {
        let dst_cid_len = bytes[5] as usize;
        let src_cid_len = bytes[5 + dst_cid_len + 1] as usize;

        let header_len = 1 + 4 + 1 + dst_cid_len + 1 + src_cid_len;
        let header_ext_len = LongHeader::extension_length(&mut bytes.clone());

        let mut header_bytes = bytes.drain(..header_len + header_ext_len).collect();

        // drains everything except payload
        let decoded_header = LongHeader::decode(&mut header_bytes)?;

        Ok(Self {
            header: decoded_header,
            payload: bytes.clone(),
        })
    }

    fn decode_short_header(bytes: &mut Vec<u8>) -> QuicheResult<Self> {
        let number_len = TwoBits::from_num(bytes[0] & 0b00_000011);
        let dst_cid_len = bytes[1] as usize;

        let header_len = 1 + 1 + dst_cid_len + number_len.invert().to_inner() as usize + 1;

        let mut header_bytes = bytes.drain(..header_len).collect();

        // drains everything except payload
        let decoded_header = ShortHeader::decode(&mut header_bytes)?;

        Ok(Self {
            header: decoded_header,
            payload: bytes.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use super::*;
    // this might be bad practice, but who cares, it's for tests
    use crate::packet::header::test_header::{
        generate_random_long_header, generate_random_short_header, rand,
    };

    fn generate_random_payload() -> Vec<u8> {
        let len = rand(19);
        (0..len).map(|_| rand(255)).collect()
    }

    #[test]
    fn test_long_packet() {
        let original_initial_packet = Packet::initial(
            1,
            ConnectionId::new(8, vec![0; 8]),
            ConnectionId::new(8, vec![0; 8]),
            FourBits::from_num(3),
            VarInt::new_u32(8),
            vec![1, 0, 1, 0, 1, 0, 1, 0],
            VarInt::new_u32(12),
            PacketNumber(VarInt::new_u32(8)),
            vec![0, 1, 0, 1, 0, 1, 0, 1],
        );

        let mut initial_packet_bytes = original_initial_packet.encode().unwrap();

        let reconstructed_initial_packet = Packet::decode(&mut initial_packet_bytes).unwrap();

        assert_eq!(original_initial_packet, reconstructed_initial_packet);

        let num_packets = 100;
        for i in 0..num_packets {
            println!("Testing random long packet {}", i);
            let header = generate_random_long_header();
            let packet = Packet {
                header,
                payload: generate_random_payload(),
            };
            let mut packet_bytes = packet.encode().unwrap();
            let reconstructed_packet = Packet::decode(&mut packet_bytes).unwrap();
            assert_eq!(packet, reconstructed_packet);
        }
    }

    #[test]
    fn test_short_packet() {
        let original_short_packet = Packet::short_header(
            SingleBit::zero(),
            TwoBits::zero(),
            SingleBit::one(),
            TwoBits::from_num(3),
            ConnectionId::new(8, vec![0; 8]),
            vec![0, 1, 0, 1],
            vec![0; 8],
        );

        let mut short_packet_bytes = original_short_packet.encode().unwrap();

        let reconstructed_short_packet = Packet::decode(&mut short_packet_bytes).unwrap();

        assert_eq!(original_short_packet, reconstructed_short_packet);

        let num_packets = 100;
        for i in 0..num_packets {
            println!("Testing random short packet {}", i);
            let header = generate_random_short_header();
            let packet = Packet {
                header,
                payload: generate_random_payload(),
            };
            let mut packet_bytes = packet.encode().unwrap();
            let reconstructed_packet = Packet::decode(&mut packet_bytes).unwrap();
            assert_eq!(packet, reconstructed_packet);
        }
    }
}
