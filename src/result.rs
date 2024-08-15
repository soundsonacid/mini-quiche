use std::{error::Error, fmt};

pub type QuicheResult<T> = Result<T, QuicheError>;

#[derive(Debug)]
pub struct QuicheError(pub(crate) String);

impl Error for QuicheError {}

impl fmt::Display for QuicheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuicheError: {}", self.0)
    }
}

impl From<std::io::Error> for QuicheError {
    fn from(err: std::io::Error) -> Self {
        QuicheError(err.to_string())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for QuicheError {
    fn from(err: tokio::sync::mpsc::error::SendError<T>) -> Self {
        QuicheError(err.to_string())
    }
}

pub fn require(cond: bool, msg: &str) -> QuicheResult<()> {
    if !cond {
        return Err(QuicheError(msg.to_string()));
    }
    Ok(())
}
