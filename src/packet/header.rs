use crate::{
    bits::{compose_bits, decompose_bits, BitsExt},
    result::{require, QuicheResult},
    VarInt,
};

use super::types::*;

// From QUIC spec
// Upon first receiving an Initial or Retry packet from the server, the client uses the Source Connection ID supplied by the server as the Destination Connection ID for subsequent packets, including any 0-RTT packets.
// This means that a client might have to change the connection ID it sets in the Destination Connection ID field twice during connection establishment:
// once in response to a Retry packet and once in response to an Initial packet from the server.
// Once a client has received a valid Initial packet from the server, it MUST discard any subsequent packet it receives on that connection with a different Source Connection ID.

// A client MUST change the Destination Connection ID it uses for sending packets in response to only the first received Initial or Retry packet.
// A server MUST set the Destination Connection ID it uses for sending packets based on the first received Initial packet.
// Any further changes to the Destination Connection ID are only permitted if the values are taken from NEW_CONNECTION_ID frames;
// if subsequent Initial packets include a different Source Connection ID, they MUST be discarded.
// This avoids unpredictable outcomes that might otherwise result from stateless processing of multiple Initial packets with different Source Connection IDs.

// i would like to avoid dynamic dispatch
// that is why this is an enum and `Header` is not a trait implemented for `LongHeader` and `ShortHeader` with `encode` and `decode` methods
// i also think the distinction between initial, retry, and long headers is important, and that wouldn't be as obvious with a trait
#[derive(PartialEq, Debug, Clone)]
pub enum Header {
    Initial(LongHeader),
    Retry(LongHeader),
    VersionNegotiate(LongHeader),
    Long(LongHeader),
    Short(ShortHeader),
}

impl Header {
    pub fn decode(bytes: &mut Vec<u8>) -> Header {
        match bytes[0] & 0b10_000000 == HeaderForm::short().to_inner() {
            true => ShortHeader::decode(bytes).unwrap(),
            false => LongHeader::decode(bytes).unwrap(),
        }
    }

    pub fn encode(&self) -> QuicheResult<Vec<u8>> {
        match self {
            Header::Initial(header)
            | Header::Retry(header)
            | Header::VersionNegotiate(header)
            | Header::Long(header) => header.encode(),
            Header::Short(header) => header.encode(),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum LongHeaderExtension {
    Initial {
        token_length: VarInt,
        token: Vec<u8>,
        length: VarInt,
        packet_number: PacketNumber,
    },
    ZeroRTT {
        length: VarInt,
        packet_number: PacketNumber,
    },
    Handshake {
        length: VarInt,
        packet_number: PacketNumber,
    },
    Retry {
        retry_token: Vec<u8>,
        retry_integrity_tag: [u8; 16],
    },
    VersionNegotiation {
        supported_versions: Vec<u32>,
    },
}

impl LongHeaderExtension {
    pub fn decode(bytes: &mut Vec<u8>, ty: u8) -> QuicheResult<Self> {
        // really cheap hacky way of identifying what type of LongHeaderExtension this is...
        match ty {
            0 => {
                let token_length = VarInt::decode(bytes)?;
                let token = bytes
                    .drain(..token_length.to_inner() as usize)
                    .collect::<Vec<u8>>();
                let length = VarInt::decode(bytes)?;
                let packet_number = PacketNumber(VarInt::decode(bytes)?);
                Ok(LongHeaderExtension::Initial {
                    token_length,
                    token,
                    length,
                    packet_number,
                })
            }
            1 => {
                let length = VarInt::decode(bytes)?;
                let packet_number = PacketNumber(VarInt::decode(bytes)?);
                Ok(LongHeaderExtension::ZeroRTT {
                    length,
                    packet_number,
                })
            }
            2 => {
                let length = VarInt::decode(bytes)?;
                let packet_number = PacketNumber(VarInt::decode(bytes)?);
                Ok(LongHeaderExtension::Handshake {
                    length,
                    packet_number,
                })
            }
            3 => {
                let retry_token = bytes.drain(..bytes.len() - 16).collect::<Vec<u8>>();
                let retry_integrity_tag = bytes
                    .drain(..)
                    .collect::<Vec<u8>>()
                    .try_into()
                    .expect("retry integrity tag bytes");
                Ok(LongHeaderExtension::Retry {
                    retry_token,
                    retry_integrity_tag,
                })
            }
            4 => {
                let supported_versions: Vec<u32> = bytes
                    .chunks(4)
                    .map(|v| u32::from_le_bytes(v.try_into().expect("version bytes")))
                    .collect();
                bytes.drain(0..supported_versions.len() * 4);
                Ok(LongHeaderExtension::VersionNegotiation { supported_versions })
            }
            _ => unreachable!(),
        }
    }

    pub fn encode(&self) -> QuicheResult<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            LongHeaderExtension::Initial {
                token_length,
                token,
                length,
                packet_number,
            } => {
                bytes.extend(token_length.encode());
                bytes.extend(token.iter());
                bytes.extend(length.encode());
                bytes.extend(packet_number.0.encode());
            }
            LongHeaderExtension::ZeroRTT {
                length,
                packet_number,
            }
            | LongHeaderExtension::Handshake {
                length,
                packet_number,
            } => {
                bytes.extend(length.encode());
                bytes.extend(packet_number.0.encode())
            }
            LongHeaderExtension::Retry {
                retry_token,
                retry_integrity_tag,
            } => {
                bytes.extend(retry_token.iter());
                bytes.extend(retry_integrity_tag.iter())
            }
            LongHeaderExtension::VersionNegotiation { supported_versions } => {
                bytes.extend(supported_versions.iter().flat_map(|v| v.to_le_bytes()));
            }
        }

        Ok(bytes)
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct LongHeader {
    header_form: HeaderForm,
    // always set to 1 unless the packet is a version negotation packet
    // packets containing a zero value for this bit are NOT valid in quic version 1
    fixed_bit: SingleBit,
    long_packet_type: LongPacketType,
    // semantics of these bits are determined by the long_packet_type
    type_specific_bits: FourBits,
    // indicates what version of quic is being used & determines how the rest of the packet is parsed
    version_id: u32,
    // during the handshake, long header packets are used to establish connection IDs for both client & server
    // each endpoint uses the src_cid to specify the dst_cid of packets being sent to them
    // after processing the Initial packet, each endpoint sets the dst_cid in subsequent packets to the src_cid it's received
    // the dst_cid in the Initial packet from a client that hasn't yet received an Initial or Retry packet is set to an unpredictable value
    // this dst_cid must be at least 8 bytes in length
    // the dst_cid from the Initial packet is used to determine packet protection keys for Initial packets - these change after receiving a Retry packet
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    extension: LongHeaderExtension,
}

impl LongHeader {
    pub fn len(&self) -> QuicheResult<usize> {
        let len = 1 + 4 + 1 + self.dst_cid.cid_len + 1 + self.src_cid.cid_len;
        // TODO: this is horrible why is this check here
        require(len <= 47, "LongHeader length must not exceed 47 bytes")?;
        Ok(len.into())
    }

    pub fn new(
        long_packet_type: LongPacketType,
        type_specific_bits: FourBits,
        version_id: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        extension: LongHeaderExtension,
    ) -> Self {
        Self {
            header_form: HeaderForm::long(),
            fixed_bit: SingleBit::one(),
            long_packet_type,
            type_specific_bits,
            version_id,
            dst_cid,
            src_cid,
            extension,
        }
    }

    // least significant 2 bits - reserved bits
    // most significant 2 bits - packet number length
    pub fn initial(
        version_id: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        type_specific_bits: FourBits,
        token_length: VarInt,
        token: Vec<u8>,
        length: VarInt,
        packet_number: PacketNumber,
    ) -> Self {
        Self {
            header_form: HeaderForm::long(),
            fixed_bit: SingleBit::one(),
            long_packet_type: LongPacketType::initial(),
            type_specific_bits,
            version_id,
            dst_cid,
            src_cid,
            extension: LongHeaderExtension::Initial {
                token_length,
                token,
                length,
                packet_number,
            },
        }
    }

    pub fn version_negotiate(
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        supported_versions: Vec<u32>,
    ) -> Self {
        Self {
            header_form: HeaderForm::long(),
            // fixed_bit through type_specific_bits are unused for version_negotiation packets
            fixed_bit: SingleBit::zero(),
            long_packet_type: LongPacketType::zero(),
            type_specific_bits: FourBits::zero(),
            version_id: 0,
            dst_cid,
            src_cid,
            extension: LongHeaderExtension::VersionNegotiation { supported_versions },
        }
    }

    pub fn decode(bytes: &mut Vec<u8>) -> QuicheResult<Header> {
        let first_byte = bytes.remove(0);
        let bitvec = decompose_bits(first_byte, &[4, 2, 1, 1]);

        let header_form_bits = bitvec[3].clone();
        let header_form = HeaderForm::from_bits(header_form_bits);

        let fixed_bit_bits = bitvec[2].clone();
        let fixed_bit = SingleBit::from_bits(fixed_bit_bits);

        let mut long_packet_bits = bitvec[1].clone();
        // TODO: this feels horrible and wrong
        long_packet_bits.reverse();
        let long_packet_type = LongPacketType::from_bits(long_packet_bits);

        let mut type_specific_four_bits = bitvec[0].clone();
        // TODO: this feels horrible and wrong
        type_specific_four_bits.reverse();
        let type_specific_bits = FourBits::from_bits(type_specific_four_bits);

        let version_id_bytes = bytes.drain(..4).collect::<Vec<u8>>();
        let version_id = u32::from_le_bytes(version_id_bytes.try_into().expect("version_id bytes"));

        let dst_cid_len = bytes.remove(0);

        let dst_cid_data = bytes.drain(..dst_cid_len as usize).collect::<Vec<u8>>();

        let dst_cid = ConnectionId::new(dst_cid_len, dst_cid_data);

        let src_cid_len = bytes.remove(0);

        let src_cid_data = bytes.drain(..src_cid_len as usize).collect::<Vec<u8>>();

        let src_cid = ConnectionId::new(src_cid_len, src_cid_data);

        let extension_ty = match long_packet_type.to_inner() {
            0 => match fixed_bit.to_inner() {
                0 => 4,
                1 => 0,
                _ => unreachable!(),
            },
            1 => 1,
            2 => 2,
            3 => 3,
            _ => unreachable!(),
        };

        let extension = LongHeaderExtension::decode(bytes, extension_ty)?;

        // TODO: this feels hacky and wrong
        let header_enum = match long_packet_type.to_inner() {
            0 => match fixed_bit.to_inner() {
                0 => Header::VersionNegotiate,
                1 => Header::Initial,
                _ => unreachable!(),
            },
            3 => Header::Retry,
            _ => Header::Long,
        };

        require(
            bytes.is_empty(),
            "LongHeader::decode: Failed to read all bytes",
        )?;

        Ok(header_enum(Self {
            header_form,
            fixed_bit,
            long_packet_type,
            type_specific_bits,
            version_id,
            dst_cid,
            src_cid,
            extension,
        }))
    }

    // returns a Vec<u8> which MUST NOT exceed 47 bytes
    pub fn encode(&self) -> QuicheResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.len()?);

        let bitvec = [
            self.header_form.bits(),        // 1
            self.fixed_bit.bits(),          // 1
            self.long_packet_type.bits(),   // 2
            self.type_specific_bits.bits(), // 4
        ]
        .concat();

        let first_byte = compose_bits(&bitvec);
        bytes.push(first_byte);

        bytes.extend(self.version_id.to_le_bytes());

        bytes.push(self.dst_cid.cid_len);
        bytes.extend(self.dst_cid.cid.iter());

        bytes.push(self.src_cid.cid_len);
        bytes.extend(self.src_cid.cid.iter());

        bytes.extend(self.extension.encode()?);

        Ok(bytes)
    }

    pub fn extension_length(bytes: &mut Vec<u8>) -> usize {
        let packet_type = (bytes[0] & 0b00_110000) >> 4;
        let fixed_bit = (bytes[0] & 0b01_000000) >> 6;
        let dst_cid_len = bytes[5] as usize;
        let src_cid_len = bytes[5 + dst_cid_len + 1] as usize;
        let base_header_len = 7 + dst_cid_len + src_cid_len;

        let mut ext_bytes = bytes[base_header_len..].to_vec();
        match packet_type {
            0x00 => {
                match fixed_bit {
                    // version negotiation
                    0 => {
                        // don't contain frames, the rest of the packet is the header extension
                        bytes.len() - base_header_len
                    }
                    // initial
                    1 => {
                        let token_length = VarInt::decode(&mut ext_bytes).unwrap();
                        ext_bytes.drain(..token_length.to_inner() as usize);
                        let length = VarInt::decode(&mut ext_bytes).unwrap();
                        let packet_number = VarInt::decode(&mut ext_bytes).unwrap();
                        return token_length.size()
                            + length.size()
                            + packet_number.size()
                            + token_length.to_inner() as usize;
                    }
                    _ => unreachable!(),
                }
            }
            // zero rtt / handshake
            0x01 | 0x02 => {
                // invariant here is that packet_number.size() + (bytes.len() - base_header_len + length.size() + packet_number.size()) == length
                let length = VarInt::decode(&mut ext_bytes).unwrap();
                let packet_number = VarInt::decode(&mut ext_bytes).unwrap();
                return length.size() + packet_number.size();
            }
            // retry
            0x03 => {
                // don't contain frames, the rest of the packet is the header extension
                bytes.len() - base_header_len
            }
            _ => unreachable!(),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct ShortHeader {
    header_form: HeaderForm,
    // packets containing a zero value for this bit are NOT valid in quic version 1
    fixed_bit: SingleBit,
    // this bit enables passive latency monitoring throughout the duration of a connection
    // the server stores the value received, while the client "spins" it after one RTT.
    // observers can measure the time between two spin bit flips to determine the RTT of the connection
    // this bit is only present in 1-RTT packets.  in other packets it will be a randomly generated value.
    spin_bit: SingleBit,
    // protected using header protection
    reserved_bits: TwoBits,
    // this allows the recipient of a packet to identify the packet protection keys
    // which are used to protect the packet
    // this bit is protected using header protection
    key_phase: SingleBit,
    // length of the packet number field, one less than the length of the packet number field in bytes
    // protected using header protection
    number_len: TwoBits,
    // a connection id that is chosen by the intended recipient of the packet.
    dst_cid: ConnectionId,
    // 1-4 bytes long.
    // protected using header protection
    number: Vec<u8>,
}

impl ShortHeader {
    pub fn len(&self) -> QuicheResult<usize> {
        let len = 1 + 1 + 1 + 2 + 1 + 2 + 1 + self.dst_cid.cid_len + 4;
        require(len <= 33, "ShortHeader length must not exceed 33 bytes")?;
        Ok(len.into())
    }

    pub fn new(
        spin_bit: SingleBit,
        reserved_bits: TwoBits,
        key_phase: SingleBit,
        number_len: TwoBits,
        dst_cid: ConnectionId,
        number: Vec<u8>,
    ) -> Self {
        Self {
            header_form: HeaderForm::short(),
            fixed_bit: SingleBit::one(),
            spin_bit,
            reserved_bits,
            key_phase,
            number_len,
            dst_cid,
            number,
        }
    }

    pub fn one_rtt(
        spin_bit: SingleBit,
        reserved_bits: TwoBits,
        key_phase: SingleBit,
        number_len: TwoBits,
        dst_cid: ConnectionId,
        number: Vec<u8>,
    ) -> Self {
        Self {
            header_form: HeaderForm::short(),
            fixed_bit: SingleBit::one(),
            spin_bit,
            reserved_bits,
            key_phase,
            number_len,
            dst_cid,
            number,
        }
    }

    pub fn decode(bytes: &mut Vec<u8>) -> QuicheResult<Header> {
        // the first byte of the short header is the header form + fixed bit + spin bit + reserved bits + key phase + number length
        let first_byte = bytes.remove(0);
        let bitvec = decompose_bits(first_byte, &[2, 1, 2, 1, 1, 1]);
        let header_form_bits = bitvec[5].clone();
        let header_form = HeaderForm::from_bits(header_form_bits);

        let fixed_bit_bits = bitvec[4].clone();
        let fixed_bit = SingleBit::from_bits(fixed_bit_bits);

        let spin_bit_bits = bitvec[3].clone();
        let spin_bit = SingleBit::from_bits(spin_bit_bits);

        let mut reserved_bits_bits = bitvec[2].clone();
        // TODO: this feels horrible and wrong
        reserved_bits_bits.reverse();
        let reserved_bits = TwoBits::from_bits(reserved_bits_bits);

        let key_phase_bits = bitvec[1].clone();
        let key_phase = SingleBit::from_bits(key_phase_bits);

        let number_len_bits = bitvec[0].clone();
        let number_len = TwoBits::from_bits(number_len_bits.clone());

        let dst_cid_len = bytes.remove(0);

        let dst_cid_data = bytes.drain(..dst_cid_len as usize).collect::<Vec<u8>>();

        // +1 because number len is one less than size of number in bytes
        let number = bytes
            .drain(..(number_len.invert().to_inner() as usize + 1))
            .collect::<Vec<u8>>();

        require(
            bytes.is_empty(),
            "ShortHeader::decode: Failed to read all bytes",
        )?;

        number_len.invert();
        Ok(Header::Short(Self {
            header_form,
            fixed_bit,
            spin_bit,
            reserved_bits,
            key_phase,
            number_len: number_len.invert(),
            dst_cid: ConnectionId::new(dst_cid_len, dst_cid_data),
            number,
        }))
    }

    // returns a Vec<u8> which MUST NOT exceed 33 bytes
    pub fn encode(&self) -> QuicheResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.len()?);

        let bitvec = [
            self.header_form.bits(),   // 1
            self.fixed_bit.bits(),     // 1
            self.spin_bit.bits(),      // 1
            self.reserved_bits.bits(), // 2
            self.key_phase.bits(),     // 1
            self.number_len.bits(),    // 2
        ]
        .concat();

        let first_byte = compose_bits(&bitvec);
        bytes.push(first_byte);

        bytes.push(self.dst_cid.cid_len);
        bytes.extend(self.dst_cid.cid.iter());

        bytes.extend(self.number.iter());

        Ok(bytes)
    }
}

#[cfg(test)]
pub mod test_header {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn rand(modulus: u128) -> u8 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % modulus) as u8
    }

    pub fn generate_random_long_header() -> Header {
        let header_type = rand(4);
        let header_enum_gen = vec![
            Header::Initial,
            Header::Retry,
            Header::VersionNegotiate,
            Header::Long,
        ];
        let header_enum = header_enum_gen[header_type as usize];

        let header_form = HeaderForm::long();
        let long_packet_type = match header_type {
            0 => LongPacketType::initial(),
            1 => LongPacketType::retry(),
            2 => {
                if rand(2) == 0 {
                    LongPacketType::zero_rtt()
                } else {
                    LongPacketType::handshake()
                }
            }
            4 => LongPacketType::zero(), // version negotiate
            _ => unreachable!("header_type should be 0, 1, 2, 3"),
        };

        let fixed_bit = match header_type {
            4 => SingleBit::zero(),
            _ => SingleBit::one(),
        };

        let extension = match long_packet_type.to_inner() {
            0 => match fixed_bit.to_inner() {
                0 => LongHeaderExtension::VersionNegotiation {
                    supported_versions: vec![
                        rand(32).into(),
                        rand(32).into(),
                        rand(32).into(),
                        rand(32).into(),
                    ],
                },
                1 => LongHeaderExtension::Initial {
                    token_length: VarInt::new_u32(rand(2).into()),
                    token: vec![rand(256); rand(20) as usize],
                    length: VarInt::new_u32(rand(2).into()),
                    packet_number: PacketNumber(VarInt::new_u32(rand(32) as u32)),
                },
                _ => unreachable!("fixed_bit should be 0 or 1"),
            },
            1 => LongHeaderExtension::ZeroRTT {
                length: VarInt::new_u32(rand(2).into()),
                packet_number: PacketNumber(VarInt::new_u32(rand(32) as u32)),
            },
            2 => LongHeaderExtension::Handshake {
                length: VarInt::new_u32(rand(2).into()),
                packet_number: PacketNumber(VarInt::new_u32(rand(32) as u32)),
            },
            3 => LongHeaderExtension::Retry {
                retry_token: vec![rand(256); rand(20) as usize],
                retry_integrity_tag: vec![rand(256); 16].try_into().unwrap(),
            },
            _ => unreachable!("long_packet_type should be 0, 1, 2, or 3"),
        };

        let type_specific_bits = FourBits::from_num(rand(16));
        let version_id = rand(32);
        let dst_cid_len = rand(20);
        let src_cid_len = rand(20);
        let mut dst_cid_data = Vec::with_capacity(dst_cid_len as usize);
        let mut src_cid_data = Vec::with_capacity(src_cid_len as usize);
        for _ in 0..dst_cid_len {
            dst_cid_data.push(rand(256));
        }
        for _ in 0..src_cid_len {
            src_cid_data.push(rand(256));
        }
        let dst_cid = ConnectionId::new(dst_cid_len, dst_cid_data);
        let src_cid = ConnectionId::new(src_cid_len, src_cid_data);

        header_enum(LongHeader {
            header_form,
            fixed_bit,
            long_packet_type,
            type_specific_bits,
            version_id: version_id as u32,
            dst_cid,
            src_cid,
            extension,
        })
    }

    pub fn generate_random_short_header() -> Header {
        let header_form = HeaderForm::short();
        let fixed_bit = SingleBit::from_num(rand(2));
        let spin_bit = SingleBit::from_num(rand(2));
        let reserved_bits = TwoBits::from_num(rand(4));
        let key_phase = SingleBit::from_num(rand(2));
        let number_len = TwoBits::from_num(rand(3));
        let dst_cid_len = rand(19);
        let mut dst_cid_data = Vec::with_capacity(dst_cid_len as usize);
        for _ in 0..dst_cid_len {
            dst_cid_data.push(rand(256));
        }
        let mut number = Vec::with_capacity(number_len.to_inner() as usize);
        for _ in 0..number_len.to_inner() + 1 {
            number.push(rand(256));
        }

        Header::Short(ShortHeader {
            header_form,
            fixed_bit,
            spin_bit,
            reserved_bits,
            key_phase,
            number_len,
            dst_cid: ConnectionId::new(dst_cid_len, dst_cid_data),
            number,
        })
    }

    #[test]
    fn test_long_encode_decode() {
        let original_initial_header = Header::Initial(LongHeader::initial(
            1,
            ConnectionId::new(8, vec![0; 8]),
            ConnectionId::new(8, vec![0; 8]),
            FourBits::from_num(0),
            VarInt::new_u32(8),
            vec![0, 1, 0, 1, 0, 1, 0, 1],
            VarInt::new_u32(4),
            PacketNumber(VarInt::new_u32(8)),
        ));

        let mut initial_header_bytes = original_initial_header.encode().unwrap();

        dbg!(initial_header_bytes.clone());

        let reconstructed_initial_header = Header::decode(&mut initial_header_bytes);

        assert_eq!(original_initial_header, reconstructed_initial_header);

        let num_headers = 100;
        for i in 0..num_headers {
            println!("Testing random long header {}", i);
            let original_header = generate_random_long_header();
            let mut header_bytes = original_header.encode().unwrap();
            let reconstructed_header = Header::decode(&mut header_bytes);
            assert_eq!(original_header, reconstructed_header);
        }
    }

    #[test]
    fn test_short_encode_decode() {
        let original_one_rtt_header = Header::Short(ShortHeader::one_rtt(
            SingleBit::zero(),
            TwoBits::zero(),
            SingleBit::one(),
            TwoBits::from_num(3),
            ConnectionId::new(8, vec![0; 8]),
            vec![0, 1, 0, 1],
        ));

        let mut one_rtt_header_bytes = original_one_rtt_header.encode().unwrap();

        dbg!(one_rtt_header_bytes.clone());

        let reconstructed_one_rtt_header = Header::decode(&mut one_rtt_header_bytes);

        assert_eq!(original_one_rtt_header, reconstructed_one_rtt_header);

        let num_headers = 100;
        for i in 0..num_headers {
            println!("Testing random short header {}", i);
            let original_header = generate_random_short_header();
            let mut header_bytes = original_header.encode().unwrap();
            let reconstructed_header = Header::decode(&mut header_bytes);
            assert_eq!(original_header, reconstructed_header);
        }
    }
}
