use crate::{bits::BitsExt, result::QuicheResult, VarInt};

use super::{
    frame::Frame, header::{Header, LongHeader, LongHeaderExtension, ShortHeader}, ConnectionId, FourBits, HeaderForm, LongPacketType, PacketNumber, SingleBit, TwoBits
};

#[derive(PartialEq, Debug, Clone)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<Frame>, 
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
        payload: Vec<Frame>,
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
        payload: Vec<Frame>,
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
        payload: Vec<Frame>,
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
        encoded.extend(self.payload.iter().map(|frame| frame.encode()).flatten());
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

        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let frame = Frame::decode(bytes)?;
            frames.push(frame);
        }
        Ok(Self {
            header: decoded_header,
            payload: frames,
        })
    }

    fn decode_short_header(bytes: &mut Vec<u8>) -> QuicheResult<Self> {
        let number_len = TwoBits::from_num(bytes[0] & 0b00_000011);
        let dst_cid_len = bytes[1] as usize;

        let header_len = 1 + 1 + dst_cid_len + number_len.invert().to_inner() as usize + 1;

        let mut header_bytes = bytes.drain(..header_len).collect();

        // drains everything except payload
        let decoded_header = ShortHeader::decode(&mut header_bytes)?;

        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let frame = Frame::decode(bytes)?;
            frames.push(frame);
        }
        Ok(Self {
            header: decoded_header,
            payload: frames,
        })
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use super::*;
    use crate::frame_size;
    use crate::macros::FrameType;
    use crate::packet::frame::STREAM_RANGE;
    // this might be bad practice, but who cares, it's for tests
    use crate::packet::header::test_header::{
        generate_random_long_header, generate_random_short_header,
    };
    use crate::rand::rand;
    use crate::packet::frame::test_frame::generate_random_frame;

    // testing only. this is definitely bad practice.
    impl Header {
        pub(crate) fn ty(&self) -> u8 {
            match self {
                Header::Initial(header) 
                | Header::Retry(header)
                | Header::VersionNegotiate(header)
                | Header::Long(header) => {
                    header.ty()
                },
                _ => unreachable!(),
            }
        }

        pub(crate) fn rem_len(&self) -> usize {
            match self {
                Header::Initial(header) 
                | Header::Retry(header)
                | Header::VersionNegotiate(header)
                | Header::Long(header) => {
                    header.rem_len()
                },
                _ => unreachable!(),
            }
        }
    }
    
    // testing only. this is definitely bad practice.
    impl Frame {
        pub(crate) fn must_be_last(&self) -> bool {
            match self {
                Frame::Stream { length, .. } => length.to_inner() == 0,
                _ => false,
            }
        }
    }

    // long header packets CANNOT contain:
    // 1. STREAM
    // 2. MAX_DATA
    // 3. MAX_STREAM_DATA
    // 4. MAX_STREAMS
    // 5. DATA_BLOCKED
    // 6. STREAM_DATA_BLOCKED
    // 7. STREAMS_BLOCKED
    // 8. NEW_CONNECTION_ID
    // 9. RETIRE_CONNECTION_ID
    // 10. PATH_CHALLENGE
    // 11. PATH_RESPONSE
    // 12. HANDSHAKE_DONE   
    const PROHIBITED_LONG_HEADER_FRAMES: [FrameType; 14] = [
        FrameType::STREAM,
        FrameType::MAX_DATA,
        FrameType::MAX_STREAM_DATA,
        FrameType::MAX_STREAMS_BIDI,
        FrameType::MAX_STREAMS_UNI,
        FrameType::DATA_BLOCKED,
        FrameType::STREAM_DATA_BLOCKED,
        FrameType::STREAMS_BLOCKED_BIDI,
        FrameType::STREAMS_BLOCKED_UNI,
        FrameType::NEW_CONNECTION_ID,
        FrameType::RETIRE_CONNECTION_ID,
        FrameType::PATH_CHALLENGE,
        FrameType::PATH_RESPONSE,
        FrameType::HANDSHAKE_DONE,
    ];
    // initial packets can ONLY contain:
    // 1. CRYPTO
    // 2. PADDING
    // 3. CONNECTION_CLOSE_APPLICATION
    // 4. ACK
    // 5. ACK_ECN
    const ALLOWED_INITIAL_FRAMES: [FrameType; 5] = [
        FrameType::CRYPTO,
        FrameType::PADDING,
        FrameType::CONNECTION_CLOSE_APPLICATION,
        FrameType::ACK,
        FrameType::ACK_ECN
    ];
    fn generate_random_long_header_payload(len: usize, header: Header) -> Vec<Frame> {
        let ty = header.ty();
        println!("rem_len: {}", len);
        println!("ty: {}", ty);
        let mut curr_size: usize = 0;
        let mut frames = Vec::new();
        while curr_size < len {
            let frame = generate_random_frame();
            if PROHIBITED_LONG_HEADER_FRAMES.contains(&frame.ty()) {
                continue;
            }
            if ty == LongPacketType::initial().to_inner() && !ALLOWED_INITIAL_FRAMES.contains(&frame.ty()) {
                continue;
            }
            let frame_size = frame_size!(frame.clone());
            if curr_size + frame_size > len {
                continue;
            }
            frames.push(frame);
            curr_size += frame_size;
        }
        if curr_size < len {
            while curr_size < len {
                frames.push(Frame::Padding);
                curr_size += 1;
            }
        }
        frames
    }

    // short header packets CANNOT contain:
    // 1. CRYPTO
    // 2. NEW_TOKEN
    const PROHIBITED_SHORT_HEADER_FRAMES: [FrameType; 2] = [FrameType::CRYPTO, FrameType::NEW_TOKEN];
    fn generate_random_short_header_payload(num_packets: u8) -> Vec<Frame> {
        let mut frames = Vec::new();
        for _ in 0..num_packets {
            let frame = generate_random_frame();
            if PROHIBITED_SHORT_HEADER_FRAMES.contains(&frame.ty()) {
                continue;
            }
            if frame.must_be_last() {
                break;
            }
            frames.push(frame);
        }
        frames
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
            vec![Frame::Crypto {
                offset: VarInt::new_u32(2),
                crypto_length: VarInt::new_u32(10),
                crypto_data: vec![1, 0, 1, 0, 1, 0, 1, 0, 1, 0]
            }],
        );

        let mut initial_packet_bytes = original_initial_packet.encode().unwrap();

        let reconstructed_initial_packet = Packet::decode(&mut initial_packet_bytes).unwrap();

        assert_eq!(original_initial_packet, reconstructed_initial_packet);

        let num_packets = 10;
        for i in 0..num_packets {
            println!("Testing random long packet {}", i);
            let header = generate_random_long_header();
            let packet = Packet {
                header: header.clone(),
                payload: generate_random_long_header_payload(header.rem_len(), header),
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
            vec![Frame::Ping, Frame::Padding, Frame::Padding, Frame::Padding],
        );

        let mut short_packet_bytes = original_short_packet.encode().unwrap();

        let reconstructed_short_packet = Packet::decode(&mut short_packet_bytes).unwrap();

        assert_eq!(original_short_packet, reconstructed_short_packet);

        let num_packets = 10_000;
        for i in 0..num_packets {
            println!("Testing random short packet {}", i);
            let header = generate_random_short_header();
            let packet = Packet {
                header,
                payload: generate_random_short_header_payload(rand(14) + 1),
            };
            let mut packet_bytes = packet.encode().unwrap();
            let reconstructed_packet = Packet::decode(&mut packet_bytes).unwrap();
            assert_eq!(packet, reconstructed_packet);
        }
    }
}
