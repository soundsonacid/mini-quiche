use crate::frame;

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
    // an endpoin that receives a reset stream frame for a send only stream MUST terminate the connection with STREAM_STATE_ERROR
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

pub struct Frame {
    pub frame_type: FrameType,
    pub frame_data: Vec<u8>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_frames() {}
}
