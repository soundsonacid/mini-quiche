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
#[derive(PartialEq, Debug)]
pub enum Header {
    Initial(LongHeader),
    Retry(LongHeader),
    VersionNegotiate(LongHeader),
    Long(LongHeader),
    Short(ShortHeader),
}

impl Header {
    pub fn decode(bytes: &mut Vec<u8>) -> Header {
        match bytes[0] & 1 == HeaderForm::short().to_inner() {
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

#[derive(PartialEq, Debug)]
pub enum LongHeaderExtensions {
    Initial {
        token_length: VarInt,
        token: Vec<u8>,
        length: VarInt,
        packet_number: u32,
    },
    ZeroRTT {
        length: VarInt,
        packet_number: u32,
    },
    Handshake {
        length: VarInt,
        packet_number: u32,
    },
    Retry {
        retry_token: Vec<u8>,
    },
    VersionNegotiation {
        supported_versions: Vec<u32>,
    },
}

impl LongHeaderExtensions {
    pub fn decode(bytes: &mut Vec<u8>, ty: u8) -> QuicheResult<Self> {
        // really cheap hacky way of identifying what type of LongHeaderExtension this is...
        match ty {
            0 => {
                unimplemented!()
            }
            1 => {
                unimplemented!()
            }
            2 => {
                unimplemented!()
            }
            3 => {
                unimplemented!()
            }
            4 => {
                unimplemented!()
            }
            _ => unreachable!(),
        }
    }

    pub fn encode(&self) -> QuicheResult<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            LongHeaderExtensions::Initial {
                token_length,
                token,
                length,
                packet_number,
            } => {
                bytes.extend(token_length.encode());
                bytes.extend(token.iter());
                bytes.extend(length.encode());
                bytes.extend(packet_number.to_le_bytes());
            }
            LongHeaderExtensions::ZeroRTT {
                length,
                packet_number,
            }
            | LongHeaderExtensions::Handshake {
                length,
                packet_number,
            } => {
                bytes.extend(length.encode());
                bytes.extend(packet_number.to_le_bytes())
            }
            LongHeaderExtensions::Retry { retry_token } => {
                bytes.extend(retry_token.iter());
            }
            LongHeaderExtensions::VersionNegotiation { supported_versions } => {
                bytes.extend(supported_versions.iter().flat_map(|v| v.to_le_bytes()));
            }
        }

        Ok(bytes)
    }
}

#[derive(PartialEq, Debug)]
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
    ) -> Self {
        Self {
            header_form: HeaderForm::long(),
            fixed_bit: SingleBit::one(),
            long_packet_type,
            type_specific_bits,
            version_id,
            dst_cid,
            src_cid,
        }
    }

    // least significant 2 bits - reserved bits
    // most significant 2 bits - packet number length
    pub fn initial(
        version_id: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        type_specific_bits: FourBits,
    ) -> Self {
        Self {
            header_form: HeaderForm::long(),
            fixed_bit: SingleBit::one(),
            long_packet_type: LongPacketType::initial(),
            type_specific_bits,
            version_id,
            dst_cid,
            src_cid,
        }
    }

    pub fn version_negotiate(dst_cid: ConnectionId, src_cid: ConnectionId) -> Self {
        Self {
            header_form: HeaderForm::long(),
            // fixed_bit through type_specific_bits are unused for version_negotiation packets
            fixed_bit: SingleBit::zero(),
            long_packet_type: LongPacketType::zero(),
            type_specific_bits: FourBits::zero(),
            version_id: 0,
            dst_cid,
            src_cid,
        }
    }

    pub fn decode(bytes: &mut Vec<u8>) -> QuicheResult<Header> {
        // the first byte of the long header is the header form + fixed bit + long packet type + type specific bits
        let first_byte = bytes.remove(0);

        let bitvec = decompose_bits(first_byte, &[1, 1, 2, 4]);

        let header_form_bits = bitvec.get(0).expect("header form bits");
        let header_form = HeaderForm::from_bits(header_form_bits.clone());

        let fixed_bit_bits = bitvec.get(1).expect("fixed bit bits");
        let fixed_bit = SingleBit::from_bits(fixed_bit_bits.clone());

        let long_packet_bits = bitvec.get(2).expect("long packet bits");
        let long_packet_type = LongPacketType::from_bits(long_packet_bits.clone());

        // TODO: this feels hacky and wrong
        let header_enum = match long_packet_type.to_inner() {
            0 => Header::Initial,
            3 => Header::Retry,
            _ => Header::Long,
        };

        let type_specific_four_bits = bitvec.get(3).expect("type specific bits");

        let type_specific_bits = FourBits::from_bits(type_specific_four_bits.clone());

        let version_id_bytes = bytes.drain(0..4).collect::<Vec<u8>>();
        let version_id = u32::from_le_bytes(version_id_bytes.try_into().expect("version_id bytes"));

        let dst_cid_len = bytes.remove(0);
        let dst_cid_data = bytes.drain(0..dst_cid_len as usize).collect::<Vec<u8>>();

        let dst_cid = ConnectionId::new(dst_cid_len, dst_cid_data);

        let src_cid_len = bytes.remove(0);
        let src_cid_data = bytes.drain(0..src_cid_len as usize).collect::<Vec<u8>>();

        let src_cid = ConnectionId::new(src_cid_len, src_cid_data);

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

        Ok(bytes)
    }
}

// packet protection

#[derive(PartialEq, Debug)]
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

        let bitvec = decompose_bits(first_byte, &[1, 1, 1, 2, 1, 2]);

        let header_form_bits = bitvec.get(0).expect("header form bits");
        let header_form = HeaderForm::from_bits(header_form_bits.clone());

        let fixed_bit_bits = bitvec.get(1).expect("fixed bit bits");
        let fixed_bit = SingleBit::from_bits(fixed_bit_bits.clone());

        let spin_bit_bits = bitvec.get(2).expect("spin bit bits");
        let spin_bit = SingleBit::from_bits(spin_bit_bits.clone());

        let reserved_bits_bits = bitvec.get(3).expect("reserved bits bits");
        let reserved_bits = TwoBits::from_bits(reserved_bits_bits.clone());

        let key_phase_bits = bitvec.get(4).expect("key phase bits");
        let key_phase = SingleBit::from_bits(key_phase_bits.clone());

        let number_len_bits = bitvec.get(5).expect("number length bits");
        let number_len = TwoBits::from_bits(number_len_bits.clone());

        let dst_cid_len = bytes.remove(0);
        let dst_cid_data = bytes.drain(0..dst_cid_len as usize).collect::<Vec<u8>>();

        // +1 because number len is one less than size of number in bytes
        let number = bytes
            .drain(0..(number_len.to_inner() as usize + 1))
            .collect::<Vec<u8>>();

        require(
            bytes.is_empty(),
            "LongHeader::decode: Failed to read all bytes",
        )?;

        Ok(Header::Short(Self {
            header_form,
            fixed_bit,
            spin_bit,
            reserved_bits,
            key_phase,
            number_len,
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
        let header_type = rand(3);
        let header_enum_gen = vec![Header::Initial, Header::Retry, Header::Long];
        let header_enum = header_enum_gen[header_type as usize];

        let header_form = HeaderForm::long();
        let fixed_bit = SingleBit::from_num(rand(2));
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
            _ => unreachable!("header_type should be 0, 1, or 2"),
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
        })
    }

    pub fn generate_random_short_header() -> Header {
        let header_form = HeaderForm::short();
        let fixed_bit = SingleBit::from_num(rand(2));
        let spin_bit = SingleBit::from_num(rand(2));
        let reserved_bits = TwoBits::from_num(rand(4));
        let key_phase = SingleBit::from_num(rand(2));
        let number_len = TwoBits::from_num(rand(4));
        let dst_cid_len = rand(20);
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
            FourBits::from_num(3),
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
