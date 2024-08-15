#[derive(PartialEq)]
pub(crate) enum ConnectionState {
    Handshake,
    Connected,
    Closing,
    Closed,
}
