use crate::{
    bits::{decompose_bits, BitsExt},
    result::QuicheResult,
};

use super::{
    header::{Header, LongHeader, ShortHeader},
    ConnectionId, FourBits, HeaderForm, LongPacketType, SingleBit, TwoBits,
};

#[derive(PartialEq, Debug)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
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
        payload: Vec<u8>,
    ) -> Self {
        let header = Header::Initial(LongHeader::initial(
            version_id,
            dst_cid,
            src_cid,
            type_specific_bits,
        ));
        Self { header, payload }
    }

    pub fn long_header(
        long_packet_type: LongPacketType,
        type_specific_bits: FourBits,
        version_id: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        payload: Vec<u8>,
    ) -> Self {
        let header = Header::Long(LongHeader::new(
            long_packet_type,
            type_specific_bits,
            version_id,
            dst_cid,
            src_cid,
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
        match bytes[0] & 1 == HeaderForm::short().to_inner() {
            true => return Packet::decode_short_header(bytes),
            false => return Packet::decode_long_header(bytes),
        }
    }

    fn decode_long_header(bytes: &mut Vec<u8>) -> QuicheResult<Self> {
        let dst_cid_len = bytes
            .get(5)
            .expect("No destination connection ID length found");
        let src_cid_len = bytes
            .get(5 + *dst_cid_len as usize + 1)
            .expect("No source connection ID length found");
        let end_of_header = 1 + 4 + 1 + dst_cid_len + 1 + src_cid_len;
        let mut header_bytes = bytes
            .drain(0..(end_of_header as usize))
            .collect::<Vec<u8>>();
        let decoded_header = LongHeader::decode(&mut header_bytes)?;
        // at this point the only remaining bytes should be the payload
        let payload = bytes.clone();
        Ok(Self {
            header: decoded_header,
            payload,
        })
    }

    fn decode_short_header(bytes: &mut Vec<u8>) -> QuicheResult<Self> {
        let first_byte = bytes.get(0).expect("first byte").clone();
        let bits = decompose_bits(first_byte, &[6, 2]);
        let number_len = TwoBits::from_bits(bits.get(1).unwrap().clone()).to_inner() + 1; // one less than size of number in bytes
        let dst_cid_len = bytes
            .get(1)
            .expect("No destination connection ID length found");
        let end_of_header = 1 + 1 + dst_cid_len + number_len;
        let mut header_bytes = bytes
            .drain(0..(end_of_header as usize))
            .collect::<Vec<u8>>();
        let decoded_header = ShortHeader::decode(&mut header_bytes)?;
        // at this point the only remaining bytes should be the payload
        let payload = bytes.clone();
        Ok(Self {
            header: decoded_header,
            payload,
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
            vec![0; 8],
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
