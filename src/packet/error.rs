use crate::result::QuicheError;

#[repr(u64)]
#[derive(Debug)]
pub enum ProtocolError {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    CryptoError(u64),
}

impl ProtocolError {
    pub fn new_u16(value: u64) -> Self {
        match value {
            0x00 => ProtocolError::NoError,
            0x01 => ProtocolError::InternalError,
            0x02 => ProtocolError::ConnectionRefused,
            0x03 => ProtocolError::FlowControlError,
            0x04 => ProtocolError::StreamLimitError,
            0x05 => ProtocolError::StreamStateError,
            0x06 => ProtocolError::FinalSizeError,
            0x07 => ProtocolError::FrameEncodingError,
            0x08 => ProtocolError::TransportParameterError,
            0x09 => ProtocolError::ConnectionIdLimitError,
            0x0a => ProtocolError::ProtocolViolation,
            0x0b => ProtocolError::InvalidToken,
            0x0c => ProtocolError::ApplicationError,
            0x0d => ProtocolError::CryptoBufferExceeded,
            0x0e => ProtocolError::KeyUpdateError,
            0x0f => ProtocolError::AeadLimitReached,
            0x10 => ProtocolError::NoViablePath,
            0x0100..=0x01ff => ProtocolError::CryptoError(value),
            _ => unreachable!(),
        }
    }

    pub fn is_protocol_error(code: u64) -> bool {
        matches!(code, 0x00..=0x10) || matches!(code, 0x0100..=0x01ff)
    }
}

impl Into<QuicheError> for ProtocolError {
    fn into(self) -> QuicheError {
        QuicheError(format!("Transport error: {:?}", self))
    }
}
