use crate::{
    bits::BitsExt,
    result::{require, QuicheResult},
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

#[derive(PartialEq, Debug)]
pub enum Header {
    Initial(LongHeader),
    Retry(LongHeader),
    Long(LongHeader),
    Short(ShortHeader),
}

impl Header {
    pub fn decode(bytes: &mut Vec<u8>) -> Header {
        match bytes[0] & 1 == HeaderForm::long().to_inner() {
            true => LongHeader::decode(bytes).unwrap(),
            false => {
                unimplemented!()
            }
        }
    }

    pub fn encode(&self) -> QuicheResult<Vec<u8>> {
        match self {
            Header::Initial(header) | Header::Retry(header) | Header::Long(header) => {
                header.encode()
            }
            Header::Short(_header) => {
                unimplemented!()
            }
        }
    }
}

// First byte:
// 0 bit offset - long header
// 1 bit offset - fixed bit
// 2-3 bit offset - long packet type
// 4-7 bit offset - type specific bits
// 0-3 bit offset - version id
// 4 bit offset - dst cid len
// 4 bi
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
        // TODO: this is horrible why is this here
        require(len <= 47, "LongHeader length must not exceed 47 bytes")?;
        // 1 byte for header_form (1 bit) + fixed_bit (1 bit) + long_packet_type (2 bits) + type_specific_bits (4 bits)
        // 4 bytes for version_id (u32 = 32 bits)
        // 1 byte for dst_cid.cid_len (u8 = 8 bits)
        // dst_cid.cid_len bytes for dst_cid.cid
        // 1 byte for src_cid.cid_len (u8 = 8 bits)
        // src_cid.cid_len bytes for src_cid.cid
        Ok(len.into())
    }

    // type_specific_bits for Initial headers:
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
        let mut first_byte = bytes.remove(0);

        let header_form_bit = first_byte & 1;
        let header_form = HeaderForm::from_num(header_form_bit);
        first_byte = first_byte >> 1;

        let fixed_bit_bit = first_byte & 1;
        let fixed_bit = SingleBit::from_num(fixed_bit_bit);
        first_byte = first_byte >> 1;

        let mut long_packet_two_bits = 0;

        let long_packet_type_low_bit = first_byte & 1;
        first_byte = first_byte >> 1;

        let long_packet_type_high_bit = first_byte & 1;
        first_byte = first_byte >> 1;

        long_packet_two_bits |= long_packet_type_high_bit;
        long_packet_two_bits = long_packet_two_bits << 1;
        long_packet_two_bits |= long_packet_type_low_bit;

        let long_packet_type = LongPacketType::from_num(long_packet_two_bits);

        // TODO: this feels hacky and wrong
        let header_enum = match long_packet_type.to_inner() {
            0 => Header::Initial,
            3 => Header::Retry,
            _ => Header::Long,
        };

        let mut type_specific_four_bits = 0;

        let type_specific_bits_bit_one = first_byte & 1;
        first_byte = first_byte >> 1;

        let type_specific_bits_bit_two = first_byte & 1;
        first_byte = first_byte >> 1;

        let type_specific_bits_bit_three = first_byte & 1;
        first_byte = first_byte >> 1;

        let type_specific_bits_bit_four = first_byte & 1;

        type_specific_four_bits |= type_specific_bits_bit_four;
        type_specific_four_bits = type_specific_four_bits << 1;
        type_specific_four_bits |= type_specific_bits_bit_three;
        type_specific_four_bits = type_specific_four_bits << 1;
        type_specific_four_bits |= type_specific_bits_bit_two;
        type_specific_four_bits = type_specific_four_bits << 1;
        type_specific_four_bits |= type_specific_bits_bit_one;

        let type_specific_bits = FourBits::from_num(type_specific_four_bits);

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
        let mut first_byte = 0;

        first_byte |= self.header_form.bits()[0] as u8;

        first_byte = first_byte << 1;
        first_byte |= self.fixed_bit.bits()[0] as u8;

        first_byte = first_byte << 1;
        first_byte |= self.long_packet_type.bits()[0] as u8;

        first_byte = first_byte << 1;
        first_byte |= self.long_packet_type.bits()[1] as u8;

        first_byte = first_byte << 1;
        first_byte |= self.type_specific_bits.bits()[0] as u8;

        first_byte = first_byte << 1;
        first_byte |= self.type_specific_bits.bits()[1] as u8;

        first_byte = first_byte << 1;
        first_byte |= self.type_specific_bits.bits()[2] as u8;

        first_byte = first_byte << 1;
        first_byte |= self.type_specific_bits.bits()[3] as u8;

        first_byte = u8::reverse_bits(first_byte);
        bytes.push(first_byte);

        bytes.extend(self.version_id.to_le_bytes());

        bytes.push(self.dst_cid.cid_len);
        bytes.extend(self.dst_cid.cid.iter());

        bytes.push(self.src_cid.cid_len);
        bytes.extend(self.src_cid.cid.iter());

        Ok(bytes)
    }
}

#[derive(PartialEq, Debug)]
pub struct ShortHeader {}

#[cfg(test)]
mod test_header {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn rand(modulus: u128) -> u8 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % modulus) as u8
    }

    fn generate_random_long_header() -> Header {
        let header_type = rand(3);
        let header_enum_gen = vec![Header::Initial, Header::Retry, Header::Long];
        let header_enum = header_enum_gen[header_type as usize];

        let header_form = HeaderForm::from_num(rand(4));
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

    #[test]
    fn test_long_encode_decode() {
        let original_initial_header = Header::Initial(LongHeader::initial(
            1,
            ConnectionId::new(8, vec![0; 8]),
            ConnectionId::new(8, vec![0; 8]),
            FourBits::zero(),
        ));

        let mut initial_header_bytes = original_initial_header.encode().unwrap();

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

    fn _test_short_encode_decode() {
        unimplemented!()
    }
}
