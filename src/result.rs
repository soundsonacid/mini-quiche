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

pub fn require(cond: bool, msg: &str) -> QuicheResult<()> {
    if !cond {
        return Err(QuicheError(msg.to_string()));
    }
    Ok(())
}
