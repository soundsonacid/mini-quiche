#[macro_export]
macro_rules! bits_ext {
    ($structname:ident, $trait:path, $len:literal, $t:ty) => {
        #[repr(transparent)]
        #[derive(PartialEq, Debug, Clone)]
        pub struct $structname(Bits<$len, $t>);

        impl $trait for $structname {
            fn from_num(bits: $t) -> Self {
                Self(Bits::from(bits))
            }

            fn from_bits(bits: Vec<bool>) -> Self {
                Self(Bits::from_bits(bits))
            }

            fn to_inner(&self) -> $t {
                self.0.to_inner()
            }

            fn zero() -> Self {
                Self(Bits::from(0))
            }

            fn one() -> Self {
                Self(Bits::from(1))
            }

            fn bits(&self) -> &[bool] {
                self.0.bits()
            }

            fn invert(&self) -> Self {
                Self(self.0.invert())
            }
        }
    };
}

#[derive(PartialEq, Eq, PartialOrd)]
pub struct FrameType(pub(crate) u8);

#[macro_export]
macro_rules! frame {
    {$($frame:ident = $encoding:expr,)*} => {
        use crate::macros::FrameType;

        impl FrameType {
            $(pub const $frame: FrameType = FrameType($encoding);)*

            pub fn to_inner(&self) -> u8 {
                self.0
            }
        }
    }
}

#[macro_export]
macro_rules! frame_size {
    ($frame:expr) => {{
        let size = match $frame {
            Frame::Padding => 1,
            Frame::Ping => 1,
            Frame::Ack { largest_acknowledged, ack_delay, ack_range_count, first_ack_range, ref ack_ranges } => {
                1 + largest_acknowledged.size() + ack_delay.size() + ack_range_count.size() + first_ack_range.size() +
                ack_ranges.iter().map(|(gap, len)| gap.size() + len.size()).sum::<usize>()
            },
            Frame::AckEcn { largest_acknowledged, ack_delay, ack_range_count, first_ack_range, ref ack_ranges, ect0_count, ect1_count, ecn_ce_count } => {
                1 + largest_acknowledged.size() + ack_delay.size() + ack_range_count.size() + first_ack_range.size() +
                ack_ranges.iter().map(|(gap, len)| gap.size() + len.size()).sum::<usize>() +
                ect0_count.size() + ect1_count.size() + ecn_ce_count.size()
            },
            Frame::ResetStream { stream_id, application_protocol_error_code, final_size } => {
                1 + stream_id.size() + application_protocol_error_code.size() + final_size.size()
            },
            Frame::StopSending { stream_id, application_protocol_error_code } => {
                1 + stream_id.size() + application_protocol_error_code.size()
            },
            Frame::Crypto { offset, crypto_length, ref crypto_data } => {
                1 + offset.size() + crypto_length.size() + crypto_data.len()
            },
            Frame::NewToken { token_length, token } => {
                1 + token_length.size() + token.len()
            },
            Frame::Stream { stream_id, offset, length, fin: _, stream_data } => {
                1 + stream_id.size() + offset.size() + length.size() + 1 + stream_data.len()
            },
            Frame::MaxData(max_data) => 1 + max_data.size(),
            Frame::MaxStreamData { stream_id, max_stream_data } => {
                1 + stream_id.size() + max_stream_data.size()
            },
            Frame::MaxStreams { max_streams, .. } => 1 + 1 + max_streams.size(),
            Frame::DataBlocked(max_data) => 1 + max_data.size(),
            Frame::StreamDataBlocked { stream_id, stream_data_limit } => {
                1 + stream_id.size() + stream_data_limit.size()
            },
            Frame::StreamsBlocked { max_streams, .. } => 1 + 1 + max_streams.size(),
            Frame::NewConnectionId { sequence_number, retire_prior_to, connection_id, stateless_reset_token: _} => {
                1 + sequence_number.size() + retire_prior_to.size() + 1 + connection_id.cid.len() + 16
            },
            Frame::RetireConnectionId(sequence_number) => 1 + sequence_number.size(),
            Frame::PathChallenge(_) => 1 + 8,
            Frame::PathResponse(_) => 1 + 8,
            Frame::ConnectionClose { error_code, frame_type, reason_phrase_length, reason_phrase } => {
                1 + error_code.size() + frame_type.map_or(1, |_| 2) + reason_phrase_length.size() + reason_phrase.len()
            },
            Frame::HandshakeDone => 1,
        };
        size
    }};
}