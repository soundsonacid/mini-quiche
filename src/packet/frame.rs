use std::ops::RangeInclusive;

use crate::{frame, packet::error::ProtocolError, result::QuicheResult, BitsExt, VarInt};

use super::{ConnectionId, SingleBit};

const STREAM_FIN: u8 = 0x01;
const STREAM_LEN: u8 = 0x02;
const STREAM_OFF: u8 = 0x04;
pub const STREAM_RANGE: RangeInclusive<FrameType> = FrameType(0x08)..=FrameType(0x0f);

// frame architecture is inspired by quinn

frame! {
    // padding frames have no semantic value, they can be used to increase the size of a packet
    // i.e. increase an initial packet to the minimum required size or provide protection against traffic analysis
    // padding frames contain no content
    PADDING = 0x00,
    // ping frames contain no content
    // a ping frame should elicit an ack or ack ecn frame from the receiver
    PING = 0x01,
    // ack frames contain one or more "ack ranges", which identify acknowledged packets
    // version negotiation & retry packets CANNOT be acknowledged because they do not contain a packet number
    // rather than relying on an ack frame, they are implicitly acknowledged by the next initial packet sent by the client
    // all ack frames (ack and ack_ecn) contain the following fields:
    // 1. largest acknowledged: a variable-length int representing the largest packet number the peer is acknowledging
    // this is usually the largest packet number the peer has received prior to generating the ack frame.  the packet number here is NOT truncated.
    //
    // 2. ack delay: a variable-length int representing the ack delay in microsec.
    // decoded by multiplying ack_delay * (2 ^ ack delay exponent sent by sender of ack frame)
    //
    // 3. ack range count: a variable-length int specifying the number of ack ranges in the frame
    //
    // 4. first ack range: a variable-length int indicating the number of packets between the largest acknowledged & the smallest packet in the range
    // or, the smallest packet ack'd in the range is largest ack - first ack range
    //
    // 5. ack ranges: contains additional ranges of packets that are alternately not ack'd and ack'd
    //
    // ack ranges contain the following fields:
    // 1. gap: a variable-length int indicating the number of unack'd packets between the packet num one lower than the smallest in the prior range
    // or, the largest packet in the next range = previous smallest packet - gap - 2
    //
    // 2. ack range length: a variable-length int indicating the number of ack'd packets before the largest, determined by the gap
    //
    // the largest packet num for any given ack range is determined by cumulatively subtracting the size of all preceding ack range lengths and gaps
    // each gap indicates a range of unack'd packets. the number of packets in the gap is gap + 1.
    //
    // if any computed packet number is negative, a connection error of type FRAME_ENCODING_ERROR MUST be generated.
    ACK = 0x02,
    // ack ecn frames also contain the cumulative count of quic packets with associated ecn marks received on the connection
    // the information in here should be used to manage congestion state
    // three ecn counts are included in the ack ecn frame:
    // 1. etc0 count: a variable-length int representing the total num packets received with the ECT(0) codepoint in the num space of the frame
    //
    // 2. etc1 count: a variable-length int representing the total num packets received with the ECT(1) codepoint in the num space of the frame
    //
    // 3. ecn-ce count: a variable-length int representing the total num packets received with the ECN-CE codepoint in the num space of the frame
    //
    // ecn counts are maintained separately for each packet number space
    ACK_ECN = 0x03,
    // a reset stream frame is used to abruptly terminate the sending part of a stream
    // a receiver of reset stream can discard any data it's already received
    // an endpoint that receives a reset stream frame for a send only stream MUST terminate the connection with STREAM_STATE_ERROR
    // reset stream frames contain the following fields:
    // 1. stream id: a variable-length int encoding of the stream id being terminated
    //
    // 2. application protocol error code: a variable-length int containing the application protocol error code
    //
    // 3. final size: a variable-length int indicating the final size of the stream by the reset stream sender, in units of bytes
    // the final size is the amount of "flow control credit" that was consumed by a stream.
    // assuming that every contiguous byte on the stream was sent once, the final size is the number of bytes sent.
    // this is one higher than the offset of the byte with the largest offset sent on the stream, or zero if nothing was sent.
    // a sender always communicates the final size of a stream reliability, regardless of how the stream is terminated.
    // an endpoint MUST NOT send data on a stream at or beyond the final size.
    RESET_STREAM = 0x04,
    // a stop sending frame is used to communicate that incoming data is being discarded on receipt per application request.
    // or, requesting that a peer cease transmission of data on a stream.
    // stop sending streams contain the following fields:
    // 1. stream id: a variable-length int encoding of the stream id being ignored
    //
    // 2. application protocol error code: a variable-length int containing the application protocol error code
    STOP_SENDING = 0x05,
    // a crypto frame is used to communicate cryptographic handshake messages
    // it can be sent in all packet types EXCEPT 0-RTT packets
    // crypto frames contain the following fields
    // 1. offset: a variable-length int specifying the byte offset in the stream for the crypto data in this frame
    //
    // 2. length: a variable-length int specifying the length of the crypto data in this frame
    //
    // 3. crypto data: the cryptographic message data
    // the largest offset delivered on a stream (offset + data len) cannot exceed 2^62 - 1. FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.
    // the crypto frame stream does not have an explicit end, so they do not contain a "FIN" bit.
    CRYPTO = 0x06,
    // a new token frame is used to provide a client with a token to send in their Initial header of a future connection
    // new token frames contain the following fields:
    // 1. token length: a variable-length int specifying the length of the token in bytes
    //
    // 2. token: an "opaque blob" the client can use with a future Initial packet.  the token MUST NOT be empty.  empty = FRAME_ENCODING_ERROR
    // a client may receive the same token value if packets containing this frame are incorrectly determined to be lost.
    // clients are responsible for discarding duplicates.
    // clients MUST NOT send these frames. PROTOCOL_VIOLATION
    NEW_TOKEN = 0x07,
    STREAM = 0x08,
    // STREAM
    // a max data frame is used in flow control to inform the peer of the maximum amount of total data that can be sent on the connection
    // max data frames contain the following fields:
    // 1. maximum data: a variable-length int indicating teh maximum amount of data that can be sent on the entire connection
    // all data sent in streams counts towards this limit.  the sum of the final sizes on ALL streams MUST NOT exceed the value advertised by a receiver.
    // an endpoint MUST terminate with FLOW_CONTROL_ERROR if it receives more data than the maximum data value it has sent.
    MAX_DATA = 0x10,
    // a max stream data frame is used in flow control to inform a peer of the maximum amount of data that can be sent on a stream
    // receiving a max stream data frame for a locally initiated stream that has not yet been created MUST throw STREAM_STATE_ERROR
    // an endpoint that receives a max stream data frame for a recv-only stream MUST terminate the connection with STREAM_STATE_ERROR
    // max stream data frames contain the following fields:
    // 1. stream id: a variable-length int encoding of the stream id
    //
    // 2. maximum stream data: a variable-length int indicating the maximum amount of data that can be sent on the stream in bytes
    // an endpoint should account for the largest received offset of data that is sent or recv on the stream.
    // loss or reordering can mean that the largest recv offset can be gt the total size of data recv on that stream
    // receiving stream frames might not increase the largest recv offset
    // an endpoint MUST terminate with FLOW_CONTROL_ERROR if it receives more data on a stream than the maximum data value it has sent.
    MAX_STREAM_DATA = 0x11,
    // max streams frames inform peers of the cumulative number of streams of a given type it is permitted to open
    // max stream frames contain the following fields:
    // 1. maximum streams: a count of the cumulative number of streams of the corresponding type that can be opened over the lifetime of the connection.
    // receipt of a frame that permits opening of a stream gt this limit MUST FRAME_ENCODING_ERROR
    MAX_STREAMS_BIDI = 0x12,
    MAX_STREAMS_UNI = 0x13,
    // a sender SHOULD send a data blocked frame when it wishes to send data but is unable to do so due to connection-level flow control
    // these frames can be used as input to tuning of flow control algorithms
    // data blocked frames contain the following fields:
    // 1. maximum data: a variable-length int indicating the connection-level limit at which blocking occured.
    DATA_BLOCKED = 0x14,
    // a sender SHOULD send a stream data blocked frame when it wishes to send data but is unable to do so due to stream-level flow control
    // analogous to data blocked
    // an endpoint that receives a stream data blocked frame for a send only stream MUST terminate the connection with STREAM_STATE_ERROR
    // stream data blocked frames contain the following fields:
    // 1. stream id - a variable-length int encoding of the stream that is blocked
    //
    // 2. maximum stream data - a variable-length int indicating the offset of the stream at which blocking occured
    STREAM_DATA_BLOCKED = 0x15,
    // a sender SHOULD send a streams blocked frame when it wishes to open a stream but is unable to do so due to the maximum stream limit set by its peer (see: max streams frames)
    // a streams blocked frame does not open the stream, but informs the peer that a new stream was needed and that it was unable to be opened
    // streams blocked frames contain the following fields:
    // 1. maximum streams: a variable-length int indicating the number of streams of the corresponding type allowed at the time the frame was sent.
    STREAMS_BLOCKED_BIDI = 0x16,
    STREAMS_BLOCKED_UNI = 0x17,
    // a new connection id frame is sent to inform the peer of alternative connection ids that can be used to break linkability when migrating connections
    // new connection id frames contain the following fields:
    // 1. sequence number: a variable-length int indicating the sequence number for this connection id, assigned by the sender
    //
    // 2. retire prior to: a variable-length int indicating which connection ids should be retired
    //
    // 3. length: a u8 containing the length of the connection ID.  values < 1 or > 20 are invalid, MUST FRAME_ENCODING_ERROR
    //
    // 4. connection id: the new connection id of the specified length
    //
    // 5. stateless reset token: a 128 bit value that will be used for a stateless reset when the associated connection id is used.
    //
    // an endpoint MUST NOT send this frame if it currently requires its peer to send packets with a zero-len dst_cid
    // changing the length of a cid t/f - makes it difficult to identify when the cid changed, receipt of this in that scenario MUST PROTOCOL_VIOLATION
    // endpoints MAY treat receipt of a new cid w/ different reset token or a diff sequence number as PROTOCOL_VIOLATION
    // retire prior to applies to cids established during setup & the preferred address transport parameter. receiving a value here gt sequence num MUST FRAME_ENCODING_ERROR
    // an endpoint which receives a sequence number < the rpt field of a previously received new cid frame MUST send a corresponding retire cid frame unless it has already done so for that seq num
    NEW_CONNECTION_ID = 0x18,
    // retire connection id frames are sent to indicate that an endpoint will no longer use a cid issued by its peer
    // this includes the cid provided during the handshake.
    // sending this also serves as a request to the peer to send additional cid's for future use, using the new connection id frame
    // retire connection id frames contain the following fields:
    // 1. sequence number: a variable-length int indicating the sequence number of the connection id being retired
    // receipt of a retire connection id frame containing a seq num > any previously sent to the peer MUST PROTOCOL_VIOLATION
    // the sequence number specified in a retire connection id frame MUST NOT refer to the dst_cid of the packet in while the frame is contained.  peer MAY PROTOCOL_VIOLATION
    // an endpoin that provides a zero-length cid MUST treat receipt of this frame as PROTOCOL_VIOLATION
    RETIRE_CONNECTION_ID = 0x19,
    // a path challenge frame is used to check reachability to the peer and for path validation during connection migration
    // path challenge frames contain the following fields:
    // 1. data: an 8 byte field of arbitrary data, chosen by the sender.
    // the receipient of this frame MUST generate a path response frame, containing the same data value.
    PATH_CHALLENGE = 0x1a,
    // a path response frame is sent in response to a path challenge frame
    // a path response frame contains the following fields:
    // 1. data: an 8 byte value that was sent in the corresponding path challenge frame
    // if the data field does not match a previously sent path challenge frame, the endpoint MAY PROTOCOL_VIOLATION
    PATH_RESPONSE = 0x1b,
    // an endpoint sends a connection close frame to inform its peer that the connection is being closed
    // if there are open streams that have not been closed, they are implicitly closed when the conn is closed
    // connection close frames contain the following fields:
    // 1. error code: a variable length int that indicates the reason for closing. values are defined in the transport error codes section for 0x1c, 0x1d uses codes defined by app protocol
    //
    // 2. frame type: a variable-length int encoding the type of frame that triggered the error. 0 == unknown. 0x1d does not include this field.
    //
    // 3. reason phrase length: a variable-length int indicating the length of the reason phrase
    //
    // 4. reason phrase: additional diagnostic information of the closure, this can be 0 length and SHOULD be be utf-8 encoded string
    CONNECTION_CLOSE_TRANSPORT = 0x1c,
    // this type of connection close frame can only be sent using 0-RTT or 1-RTT packets.
    // if an application wishes to abandon a connection during the handshake, an endpoint can send a 0x1c frame with an error code of APPLICATION_ERROR in an initial or handshake packet
    CONNECTION_CLOSE_APPLICATION = 0x1d,
    // the server sends a handshake done frame to signal completion of the handshake to the client
    // these frames have no content
    // a handshake done frame can only be sent by the server.  servers MUST NOT send a handshake done frame before completing the handshake
    // a server MUST treat receipt of this frame as PROTOCOL_VIOLATION
    HANDSHAKE_DONE = 0x1e,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    // 0x00
    Padding,
    // 0x01
    Ping,
    // 0x02
    Ack {
        largest_acknowledged: VarInt,
        ack_delay: VarInt,
        ack_range_count: VarInt,
        first_ack_range: VarInt,
        ack_ranges: Vec<(VarInt, VarInt)>,
    },
    // 0x03
    AckEcn {
        largest_acknowledged: VarInt,
        ack_delay: VarInt,
        ack_range_count: VarInt,
        first_ack_range: VarInt,
        ack_ranges: Vec<(VarInt, VarInt)>,
        ect0_count: VarInt,
        ect1_count: VarInt,
        ecn_ce_count: VarInt,
    },
    // 0x04
    ResetStream {
        stream_id: VarInt,
        application_protocol_error_code: VarInt,
        final_size: VarInt,
    },
    // 0x05
    StopSending {
        stream_id: VarInt,
        application_protocol_error_code: VarInt,
    },
    // 0x06
    Crypto {
        offset: VarInt,
        crypto_length: VarInt,
        crypto_data: Vec<u8>,
    },
    // 0x07
    NewToken {
        token_length: VarInt,
        token: Vec<u8>,
    },
    // 0x08 - 0x0f
    Stream {
        stream_id: VarInt,
        offset: VarInt,
        length: VarInt,
        fin: SingleBit,
        // if length is not present this extends to the end of the packet
        stream_data: Vec<u8>,
    },
    // 0x10
    MaxData(VarInt),
    // 0x11
    MaxStreamData {
        stream_id: VarInt,
        max_stream_data: VarInt,
    },
    // 0x12 (bidi), 0x13 (uni)
    MaxStreams {
        stream_type: StreamType,
        max_streams: VarInt,
    },
    // 0x14
    DataBlocked(VarInt),
    // 0x15
    StreamDataBlocked {
        stream_id: VarInt,
        stream_data_limit: VarInt,
    },
    // 0x16 (bidi), 0x17 (uni)
    StreamsBlocked {
        stream_type: StreamType,
        max_streams: VarInt,
    },
    // 0x18
    NewConnectionId {
        sequence_number: VarInt,
        retire_prior_to: VarInt,
        connection_id: ConnectionId,
        stateless_reset_token: [u8; 16],
    },
    // 0x19
    RetireConnectionId(VarInt),
    // 0x1a
    PathChallenge([u8; 8]),
    // 0x1b
    PathResponse([u8; 8]),
    // 0x1c (protocol), 0x1d (application)
    ConnectionClose {
        error_code: VarInt,
        frame_type: Option<u8>,
        reason_phrase_length: VarInt,
        reason_phrase: String,
    },
    // 0x1e
    HandshakeDone,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

impl Frame {
    pub(crate) fn ty(&self) -> FrameType {
        use self::Frame::*;
        match *self {
            Padding => FrameType::PADDING,
            Ping => FrameType::PING,
            Ack { .. } => FrameType::ACK,
            AckEcn { .. } => FrameType::ACK_ECN,
            ResetStream { .. } => FrameType::RESET_STREAM,
            StopSending { .. } => FrameType::STOP_SENDING,
            Crypto { .. } => FrameType::CRYPTO,
            NewToken { .. } => FrameType::NEW_TOKEN,
            Stream {
                ref offset,
                ref length,
                ref fin,
                ..
            } => {
                let mut ty = FrameType::STREAM.0;
                if fin.to_inner() == 1 {
                    ty |= 0x01;
                }
                if length.to_inner() > 0 {
                    ty |= 0x02;
                }
                if offset.to_inner() == 1 {
                    ty |= 0x04;
                }
                FrameType(ty)
            }
            MaxData(_) => FrameType::MAX_DATA,
            MaxStreamData { .. } => FrameType::MAX_STREAM_DATA,
            MaxStreams { stream_type, .. } => match stream_type {
                StreamType::Bidirectional => FrameType::MAX_STREAMS_BIDI,
                StreamType::Unidirectional => FrameType::MAX_STREAMS_UNI,
            },
            DataBlocked(_) => FrameType::DATA_BLOCKED,
            StreamDataBlocked { .. } => FrameType::STREAM_DATA_BLOCKED,
            StreamsBlocked { stream_type, .. } => match stream_type {
                StreamType::Bidirectional => FrameType::STREAMS_BLOCKED_BIDI,
                StreamType::Unidirectional => FrameType::STREAMS_BLOCKED_UNI,
            },
            NewConnectionId { .. } => FrameType::NEW_CONNECTION_ID,
            RetireConnectionId(_) => FrameType::RETIRE_CONNECTION_ID,
            PathChallenge(_) => FrameType::PATH_CHALLENGE,
            PathResponse(_) => FrameType::PATH_RESPONSE,
            ConnectionClose { error_code, .. } => {
                if ProtocolError::is_protocol_error(error_code.to_inner()) {
                    FrameType::CONNECTION_CLOSE_TRANSPORT
                } else {
                    FrameType::CONNECTION_CLOSE_APPLICATION
                }
            }
            HandshakeDone => FrameType::HANDSHAKE_DONE,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        use self::Frame::*;
        let mut buf = Vec::new();
        buf.push(self.ty().to_inner());
        match *self {
            Padding | Ping | HandshakeDone => {}
            Ack {
                largest_acknowledged,
                ack_delay,
                ack_range_count,
                first_ack_range,
                ref ack_ranges,
            } => {
                buf.extend(largest_acknowledged.encode());
                buf.extend(ack_delay.encode());
                buf.extend(ack_range_count.encode());
                buf.extend(first_ack_range.encode());
                for (gap, len) in ack_ranges {
                    buf.extend(gap.encode());
                    buf.extend(len.encode());
                }
            }
            AckEcn {
                largest_acknowledged,
                ack_delay,
                ack_range_count,
                first_ack_range,
                ref ack_ranges,
                ect0_count,
                ect1_count,
                ecn_ce_count,
            } => {
                buf.extend(largest_acknowledged.encode());
                buf.extend(ack_delay.encode());
                buf.extend(ack_range_count.encode());
                buf.extend(first_ack_range.encode());
                for (gap, len) in ack_ranges {
                    buf.extend(gap.encode());
                    buf.extend(len.encode());
                }
                buf.extend(ect0_count.encode());
                buf.extend(ect1_count.encode());
                buf.extend(ecn_ce_count.encode());
            }
            ResetStream {
                stream_id,
                application_protocol_error_code,
                final_size,
            } => {
                buf.extend(stream_id.encode());
                buf.extend(application_protocol_error_code.encode());
                buf.extend(final_size.encode());
            }
            StopSending {
                stream_id,
                application_protocol_error_code,
            } => {
                buf.extend(stream_id.encode());
                buf.extend(application_protocol_error_code.encode());
            }
            Crypto {
                offset,
                crypto_length,
                ref crypto_data,
            } => {
                buf.extend(offset.encode());
                buf.extend(crypto_length.encode());
                buf.extend(crypto_data);
            }
            NewToken {
                token_length,
                ref token,
            } => {
                buf.extend(token_length.encode());
                buf.extend(token);
            }
            Stream {
                stream_id,
                offset,
                length,
                ref fin,
                ref stream_data,
            } => {
                let mut ty = 0;
                if fin.to_inner() == 1 {
                    ty |= 0x01;
                }
                if length.to_inner() > 0 {
                    ty |= 0x02;
                }
                if offset.to_inner() > 0 {
                    ty |= 0x04;
                }
                buf.push(ty);
                buf.extend(stream_id.encode());
                if offset.to_inner() > 0 {
                    buf.extend(offset.encode());
                }
                if length.to_inner() > 0 {
                    buf.extend(length.encode());
                }
                buf.extend(stream_data);
            }
            MaxData(maximum_data) => {
                buf.extend(maximum_data.encode());
            }
            MaxStreamData {
                stream_id,
                max_stream_data,
            } => {
                buf.extend(stream_id.encode());
                buf.extend(max_stream_data.encode());
            }
            MaxStreams { max_streams, .. } => {
                buf.extend(max_streams.encode());
            }
            DataBlocked(maximum_data) => {
                buf.extend(maximum_data.encode());
            }
            StreamDataBlocked {
                stream_id,
                stream_data_limit,
            } => {
                buf.extend(stream_id.encode());
                buf.extend(stream_data_limit.encode());
            }
            StreamsBlocked { max_streams, .. } => {
                buf.extend(max_streams.encode());
            }
            NewConnectionId {
                sequence_number,
                retire_prior_to,
                ref connection_id,
                stateless_reset_token,
            } => {
                buf.extend(sequence_number.encode());
                buf.extend(retire_prior_to.encode());
                buf.push(connection_id.cid_len);
                buf.extend(&connection_id.cid);
                buf.extend(&stateless_reset_token);
            }
            RetireConnectionId(sequence_number) => {
                buf.extend(sequence_number.encode());
            }
            PathChallenge(ref data) => {
                buf.extend(data);
            }
            PathResponse(ref data) => {
                buf.extend(data);
            }
            ConnectionClose {
                error_code,
                frame_type,
                reason_phrase_length,
                ref reason_phrase,
            } => {
                buf.extend(error_code.encode());
                if let Some(frame_type) = frame_type {
                    buf.push(frame_type);
                }
                buf.extend(reason_phrase_length.encode());
                buf.extend(reason_phrase.as_bytes());
            }
        }

        buf
    }

    pub fn decode(bytes: &mut Vec<u8>) -> QuicheResult<Frame> {
        let ty = FrameType(bytes.remove(0));
        match ty {
            FrameType::PADDING => Ok(Frame::Padding {}),
            FrameType::PING => Ok(Frame::Ping {}),
            FrameType::HANDSHAKE_DONE => Ok(Frame::HandshakeDone {}),
            FrameType::ACK => {
                let largest_acknowledged = VarInt::decode(bytes)?;
                let ack_delay = VarInt::decode(bytes)?;
                let ack_range_count = VarInt::decode(bytes)?;
                let first_ack_range = VarInt::decode(bytes)?;
                let mut ack_ranges: Vec<(VarInt, VarInt)> =
                    Vec::with_capacity(ack_range_count.usize());
                let mut next_smallest = largest_acknowledged.sub(&first_ack_range)?;

                for _ in 0..ack_range_count.to_inner() {
                    let gap = VarInt::decode(bytes)?;
                    let ack_range_length = VarInt::decode(bytes)?;

                    if gap.addn(2)?.gt(&next_smallest) {
                        return Err(ProtocolError::FrameEncodingError.into());
                    }

                    next_smallest = next_smallest.sub(&gap.addn(2)?)?;

                    if ack_range_length.gt(&next_smallest) {
                        return Err(ProtocolError::FrameEncodingError.into());
                    }

                    ack_ranges.push((gap, ack_range_length));
                }
                Ok(Frame::Ack {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                    ack_ranges,
                })
            }
            FrameType::ACK_ECN => {
                let largest_acknowledged = VarInt::decode(bytes)?;
                let ack_delay = VarInt::decode(bytes)?;
                let ack_range_count = VarInt::decode(bytes)?;
                let first_ack_range = VarInt::decode(bytes)?;
                let mut ack_ranges: Vec<(VarInt, VarInt)> =
                    Vec::with_capacity(ack_range_count.usize());
                let mut next_smallest = largest_acknowledged.sub(&first_ack_range)?;

                for _ in 0..ack_range_count.to_inner() {
                    let gap = VarInt::decode(bytes)?;
                    let ack_range_length = VarInt::decode(bytes)?;

                    if gap.addn(2)?.gt(&next_smallest) {
                        return Err(ProtocolError::FrameEncodingError.into());
                    }

                    next_smallest = next_smallest.sub(&gap.addn(2)?)?;

                    if ack_range_length.gt(&next_smallest) {
                        return Err(ProtocolError::FrameEncodingError.into());
                    }

                    ack_ranges.push((gap, ack_range_length));
                }
                let ect0_count = VarInt::decode(bytes)?;
                let ect1_count = VarInt::decode(bytes)?;
                let ecn_ce_count = VarInt::decode(bytes)?;
                Ok(Frame::AckEcn {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                    ack_ranges,
                    ect0_count,
                    ect1_count,
                    ecn_ce_count,
                })
            }
            FrameType::RESET_STREAM => {
                let stream_id = VarInt::decode(bytes)?;
                let application_protocol_error_code = VarInt::decode(bytes)?;
                let final_size = VarInt::decode(bytes)?;
                Ok(Frame::ResetStream {
                    stream_id,
                    application_protocol_error_code,
                    final_size,
                })
            }
            FrameType::STOP_SENDING => {
                let stream_id = VarInt::decode(bytes)?;
                let application_protocol_error_code = VarInt::decode(bytes)?;
                Ok(Frame::StopSending {
                    stream_id,
                    application_protocol_error_code,
                })
            }
            FrameType::CRYPTO => {
                let offset = VarInt::decode(bytes)?;
                let crypto_length = VarInt::decode(bytes)?;
                let crypto_data = bytes.drain(..crypto_length.usize()).collect();

                if offset.add(&crypto_length)?.gtn(2 << 62 - 1) {
                    return Err(ProtocolError::CryptoBufferExceeded.into());
                }

                Ok(Frame::Crypto {
                    offset,
                    crypto_length,
                    crypto_data,
                })
            }
            FrameType::NEW_TOKEN => {
                let token_length = VarInt::decode(bytes)?;
                let token = bytes.drain(..token_length.usize()).collect();
                Ok(Frame::NewToken {
                    token_length,
                    token,
                })
            }
            ty if STREAM_RANGE.contains(&ty) => {
                let stream_ty = bytes.remove(0);
                let stream_id = VarInt::decode(bytes)?;

                let mut offset: Option<VarInt> = None;
                let mut length: Option<VarInt> = None;
                let mut fin = SingleBit::zero();

                if (stream_ty & STREAM_FIN) != 0 {
                    fin = SingleBit::one();
                }

                if (stream_ty & STREAM_OFF) != 0 {
                    offset = Some(VarInt::decode(bytes)?);
                }

                if (stream_ty & STREAM_LEN) != 0 {
                    length = Some(VarInt::decode(bytes)?);
                }

                let stream_data = if let Some(len) = length {
                    bytes.drain(..len.usize()).collect()
                } else {
                    bytes.drain(..).collect()
                };

                Ok(Frame::Stream {
                    stream_id,
                    offset: offset.unwrap_or_default(),
                    length: length.unwrap_or_default(),
                    fin,
                    stream_data,
                })
            }
            FrameType::MAX_DATA => {
                let maximum_data = VarInt::decode(bytes)?;
                Ok(Frame::MaxData(maximum_data))
            }
            FrameType::MAX_STREAM_DATA => {
                let stream_id = VarInt::decode(bytes)?;
                let max_stream_data = VarInt::decode(bytes)?;
                Ok(Frame::MaxStreamData {
                    stream_id,
                    max_stream_data,
                })
            }
            FrameType::MAX_STREAMS_BIDI => {
                let max_streams = VarInt::decode(bytes)?;
                Ok(Frame::MaxStreams {
                    stream_type: StreamType::Bidirectional,
                    max_streams,
                })
            }
            FrameType::MAX_STREAMS_UNI => {
                let max_streams = VarInt::decode(bytes)?;
                Ok(Frame::MaxStreams {
                    stream_type: StreamType::Unidirectional,
                    max_streams,
                })
            }
            FrameType::DATA_BLOCKED => {
                let maximum_data = VarInt::decode(bytes)?;
                Ok(Frame::DataBlocked(maximum_data))
            }
            FrameType::STREAM_DATA_BLOCKED => {
                let stream_id = VarInt::decode(bytes)?;
                let stream_data_limit = VarInt::decode(bytes)?;
                Ok(Frame::StreamDataBlocked {
                    stream_id,
                    stream_data_limit,
                })
            }
            FrameType::STREAMS_BLOCKED_BIDI => {
                let max_streams = VarInt::decode(bytes)?;
                Ok(Frame::StreamsBlocked {
                    stream_type: StreamType::Bidirectional,
                    max_streams,
                })
            }
            FrameType::STREAMS_BLOCKED_UNI => {
                let max_streams = VarInt::decode(bytes)?;
                Ok(Frame::StreamsBlocked {
                    stream_type: StreamType::Unidirectional,
                    max_streams,
                })
            }
            FrameType::NEW_CONNECTION_ID => {
                let sequence_number = VarInt::decode(bytes)?;
                let retire_prior_to = VarInt::decode(bytes)?;
                let cid_len = bytes.remove(0);

                if cid_len.lt(&1) || cid_len.gt(&20) {
                    return Err(ProtocolError::FrameEncodingError.into());
                }

                if retire_prior_to.gt(&sequence_number) {
                    return Err(ProtocolError::FrameEncodingError.into());
                }

                let cid = bytes.drain(..cid_len as usize).collect();
                let stateless_reset_token = bytes.drain(..16).collect::<Vec<u8>>();
                Ok(Frame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id: ConnectionId { cid_len, cid },
                    stateless_reset_token: stateless_reset_token.try_into().unwrap(),
                })
            }
            FrameType::RETIRE_CONNECTION_ID => {
                let sequence_number = VarInt::decode(bytes)?;
                Ok(Frame::RetireConnectionId(sequence_number))
            }
            FrameType::PATH_CHALLENGE => {
                let challenge = bytes.drain(..8).collect::<Vec<u8>>();
                Ok(Frame::PathChallenge(challenge.try_into().unwrap()))
            }
            FrameType::PATH_RESPONSE => {
                let response = bytes.drain(..8).collect::<Vec<u8>>();
                Ok(Frame::PathResponse(response.try_into().unwrap()))
            }
            FrameType::CONNECTION_CLOSE_TRANSPORT => {
                let error_code = VarInt::decode(bytes)?;
                let frame_type = bytes.remove(0);
                let reason_phrase_length = VarInt::decode(bytes)?;
                let reason_phrase_bytes = bytes.drain(..reason_phrase_length.usize()).collect();
                let reason_phrase = String::from_utf8(reason_phrase_bytes).unwrap();
                Ok(Frame::ConnectionClose {
                    error_code,
                    frame_type: Some(frame_type),
                    reason_phrase_length,
                    reason_phrase,
                })
            }
            FrameType::CONNECTION_CLOSE_APPLICATION => {
                let error_code = VarInt::decode(bytes)?;
                let reason_phrase_length = VarInt::decode(bytes)?;
                let reason_phrase_bytes = bytes.drain(..reason_phrase_length.usize()).collect();
                let reason_phrase = String::from_utf8(reason_phrase_bytes).unwrap();
                Ok(Frame::ConnectionClose {
                    error_code,
                    frame_type: None,
                    reason_phrase_length,
                    reason_phrase,
                })
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_frame {
    use super::*;
    use crate::rand::rand;

    pub fn generate_random_frame() -> Frame {
        let ty = rand(31);
        match ty {
            0x00 => Frame::Padding,
            0x01 => Frame::Ping,
            0x02 => {
                let largest_acknowledged = VarInt::new_u32(rand(1000) as u32);
                let ack_delay = VarInt::new_u32(7);
                let ack_range_count = VarInt::new_u32(4);
                let first_ack_range =
                    VarInt::new_u32(rand((largest_acknowledged.to_inner() + 1) as u128) as u32);

                let mut remaining = largest_acknowledged.sub(&first_ack_range).unwrap();
                if remaining.lt(&VarInt::new_u32(8)) {
                    return Frame::Ack {
                        largest_acknowledged,
                        ack_delay,
                        ack_range_count: VarInt::new_u32(0),
                        first_ack_range,
                        ack_ranges: vec![],
                    };
                }

                let ack_ranges: Vec<(VarInt, VarInt)> = (0..ack_range_count.to_inner())
                    .map(|_| {
                        let gap = if remaining.to_inner() > 2 {
                            let max_gap = remaining.to_inner() - 2;
                            VarInt::new_u32(rand((max_gap + 1) as u128) as u32)
                        } else {
                            VarInt::zero()
                        };

                        remaining = if gap.to_inner() + 2 < remaining.to_inner() {
                            remaining.sub(&gap.addn(2).unwrap()).unwrap()
                        } else {
                            VarInt::zero()
                        };

                        let ack_range_length = if remaining.to_inner() > 0 {
                            VarInt::new_u32(rand((remaining.to_inner() + 1) as u128) as u32)
                        } else {
                            VarInt::zero()
                        };

                        remaining = if ack_range_length.to_inner() < remaining.to_inner() {
                            remaining.sub(&ack_range_length).unwrap()
                        } else {
                            VarInt::zero()
                        };

                        (gap, ack_range_length)
                    })
                    .take_while(|(gap, ack_range_length)| {
                        gap.to_inner() > 0 || ack_range_length.to_inner() > 0
                    })
                    .collect();

                let actual_ack_range_count = VarInt::new_u32(ack_ranges.len() as u32);

                Frame::Ack {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count: actual_ack_range_count,
                    first_ack_range,
                    ack_ranges,
                }
            }
            0x03 => {
                let largest_acknowledged = VarInt::new_u32(rand(1000) as u32);
                let ack_delay = VarInt::new_u32(7);
                let first_ack_range =
                    VarInt::new_u32(rand((largest_acknowledged.to_inner() + 1) as u128) as u32);
                let ect0_count = VarInt::new_u32(7);
                let ect1_count = VarInt::new_u32(7);
                let ecn_ce_count = VarInt::new_u32(7);

                if largest_acknowledged
                    .sub(&first_ack_range)
                    .unwrap()
                    .lt(&VarInt::new_u32(8))
                {
                    return Frame::AckEcn {
                        largest_acknowledged,
                        ack_delay,
                        ack_range_count: VarInt::new_u32(0),
                        first_ack_range,
                        ack_ranges: vec![],
                        ect0_count,
                        ect1_count,
                        ecn_ce_count,
                    };
                }

                let mut remaining = largest_acknowledged.sub(&first_ack_range).unwrap();
                let mut ack_ranges = Vec::new();

                while remaining.to_inner() > 0 {
                    if ack_ranges.len() >= 4 {
                        // Limit to 4 ack ranges for this example
                        break;
                    }

                    let max_gap = if remaining.to_inner() > 2 {
                        remaining.to_inner() - 2
                    } else {
                        0
                    };
                    let gap = VarInt::new_u32(rand((max_gap + 1) as u128) as u32);

                    if gap.to_inner() + 2 >= remaining.to_inner() {
                        // If gap would make next_smallest zero or negative, break the loop
                        break;
                    }

                    remaining = remaining.sub(&gap.addn(2).unwrap()).unwrap();

                    let max_ack_range_length = remaining.to_inner();
                    let ack_range_length =
                        VarInt::new_u32(rand((max_ack_range_length + 1) as u128) as u32);

                    remaining = if ack_range_length.to_inner() < remaining.to_inner() {
                        remaining.sub(&ack_range_length).unwrap()
                    } else {
                        VarInt::zero()
                    };

                    ack_ranges.push((gap, ack_range_length));
                }

                Frame::AckEcn {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count: VarInt::new_u32(ack_ranges.len() as u32),
                    first_ack_range,
                    ack_ranges,
                    ect0_count,
                    ect1_count,
                    ecn_ce_count,
                }
            }
            0x04 => {
                let stream_id = VarInt::new_u32(rand(255) as u32);
                let application_protocol_error_code = VarInt::new_u32(rand(255) as u32);
                let final_size = VarInt::new_u32(rand(255) as u32);
                Frame::ResetStream {
                    stream_id,
                    application_protocol_error_code,
                    final_size,
                }
            }
            0x05 => {
                let stream_id = VarInt::new_u32(rand(255) as u32);
                let application_protocol_error_code = VarInt::new_u32(rand(255) as u32);
                Frame::StopSending {
                    stream_id,
                    application_protocol_error_code,
                }
            }
            0x06 => {
                let offset = VarInt::new_u32(rand(255) as u32);
                let crypto_length = VarInt::new_u32(65);
                let mut crypto_data = Vec::with_capacity(crypto_length.usize());
                for _ in 0..crypto_length.to_inner() {
                    crypto_data.push(rand(255) as u8);
                }
                Frame::Crypto {
                    offset,
                    crypto_length,
                    crypto_data,
                }
            }
            0x07 => {
                let token_length = VarInt::new_u32(65);
                let mut token = Vec::with_capacity(token_length.usize());
                for _ in 0..token_length.to_inner() {
                    token.push(rand(255) as u8);
                }
                Frame::NewToken {
                    token_length,
                    token,
                }
            }
            stream_ty @ 0x08
            | stream_ty @ 0x09
            | stream_ty @ 0x0a
            | stream_ty @ 0x0b
            | stream_ty @ 0x0c
            | stream_ty @ 0x0d
            | stream_ty @ 0x0e
            | stream_ty @ 0x0f => {
                let stream_id = VarInt::new_u32(rand(1_000_000) as u32); // Random stream_id
                let offset = if (stream_ty & 0x04) != 0 {
                    VarInt::new_u32(rand(1_000) as u32)
                } else {
                    VarInt::default()
                };

                let length = if (stream_ty & 0x02) != 0 {
                    VarInt::new_u32(rand(1024) as u32)
                } else {
                    VarInt::default()
                };

                let fin = if (stream_ty & 0x01) != 0 {
                    SingleBit::one()
                } else {
                    SingleBit::zero()
                };

                let stream_data = if length.0 > 0 {
                    (0..length.0).map(|_| rand(256) as u8).collect()
                } else {
                    vec![rand(256) as u8; 64]
                };

                Frame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    stream_data,
                }
            }
            0x10 => {
                let maximum_data = VarInt::new_u32(rand(255) as u32);
                Frame::MaxData(maximum_data)
            }
            0x11 => {
                let stream_id = VarInt::new_u32(rand(255) as u32);
                let max_stream_data = VarInt::new_u32(rand(255) as u32);
                Frame::MaxStreamData {
                    stream_id,
                    max_stream_data,
                }
            }
            0x12 => {
                let stream_type = StreamType::Bidirectional;
                let max_streams = VarInt::new_u32(rand(255) as u32);
                Frame::MaxStreams {
                    stream_type,
                    max_streams,
                }
            }
            0x13 => {
                let stream_type = StreamType::Unidirectional;
                let max_streams = VarInt::new_u32(rand(255) as u32);
                Frame::MaxStreams {
                    stream_type,
                    max_streams,
                }
            }
            0x14 => {
                let maximum_data = VarInt::new_u32(rand(255) as u32);
                Frame::DataBlocked(maximum_data)
            }
            0x15 => {
                let stream_id = VarInt::new_u32(rand(255) as u32);
                let stream_data_limit = VarInt::new_u32(rand(255) as u32);
                Frame::StreamDataBlocked {
                    stream_id,
                    stream_data_limit,
                }
            }
            0x16 => {
                let stream_type = StreamType::Bidirectional;
                let max_streams = VarInt::new_u32(rand(255) as u32);
                Frame::StreamsBlocked {
                    stream_type,
                    max_streams,
                }
            }
            0x17 => {
                let stream_type = StreamType::Unidirectional;
                let max_streams = VarInt::new_u32(rand(255) as u32);
                Frame::StreamsBlocked {
                    stream_type,
                    max_streams,
                }
            }
            0x18 => {
                let sequence_number = VarInt::new_u32(rand(255) as u32);
                let retire_prior_to =
                    VarInt::new_u32(rand(sequence_number.to_inner() as u128) as u32);
                let cid_len = rand(20) as u8 + 1;
                let mut cid = Vec::with_capacity(cid_len as usize);
                for _ in 0..cid_len {
                    cid.push(rand(255) as u8);
                }
                let mut stateless_reset_token = [0; 16];
                for i in 0..16 {
                    stateless_reset_token[i] = rand(255) as u8;
                }
                Frame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id: ConnectionId { cid_len, cid },
                    stateless_reset_token,
                }
            }
            0x19 => {
                let sequence_number = VarInt::new_u32(rand(255) as u32);
                Frame::RetireConnectionId(sequence_number)
            }
            0x1a => {
                let mut challenge = [0; 8];
                for i in 0..8 {
                    challenge[i] = rand(255) as u8;
                }
                Frame::PathChallenge(challenge)
            }
            0x1b => {
                let mut response = [0; 8];
                for i in 0..8 {
                    response[i] = rand(255) as u8;
                }
                Frame::PathResponse(response)
            }
            0x1c => {
                let error_code: u16 = match rand(2) {
                    0 => rand(0x11) as u16,
                    1 => 0x0100 + rand(0x0100) as u16,
                    _ => unreachable!(),
                };
                let frame_type = rand(31);
                let reason_phrase_length = VarInt::new_u32(rand(1948) as u32);
                let mut reason_phrase = Vec::with_capacity(reason_phrase_length.usize());
                for _ in 0..reason_phrase_length.to_inner() {
                    let valid_char = rand(95) as u8 + 32;
                    reason_phrase.push(valid_char);
                }
                Frame::ConnectionClose {
                    error_code: VarInt::new_u64(error_code as u64).unwrap(),
                    frame_type: Some(frame_type),
                    reason_phrase_length,
                    reason_phrase: String::from_utf8(reason_phrase).unwrap(),
                }
            }
            0x1d => {
                let error_code = match rand(2) {
                    0 => {
                        let temp = rand(0x00EF) as u16;
                        if temp >= 0xEF {
                            temp + 0x0110
                        } else {
                            temp + 0x11
                        }
                    }
                    1 => 0x0200 + rand((u64::MAX - 0x0200).into()) as u16,
                    _ => unreachable!(),
                };
                let reason_phrase_length = VarInt::new_u32(rand(1948) as u32);
                let mut reason_phrase = Vec::with_capacity(reason_phrase_length.usize());
                for _ in 0..reason_phrase_length.to_inner() {
                    let valid_char = rand(95) as u8 + 32;
                    reason_phrase.push(valid_char);
                }
                Frame::ConnectionClose {
                    error_code: VarInt::new_u64(error_code as u64).unwrap(),
                    frame_type: None,
                    reason_phrase_length,
                    reason_phrase: String::from_utf8(reason_phrase).unwrap(),
                }
            }
            0x1e => Frame::HandshakeDone,
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_frame() {
        let num_frames = 1_000_000;
        for i in 0..num_frames {
            println!("frame test: {}", i);
            let frame = generate_random_frame();
            let encoded = frame.encode();
            let decoded = Frame::decode(&mut encoded.clone()).unwrap();
            assert_eq!(frame, decoded, "frame ty: {}", frame.ty().to_inner());
        }
    }
}
