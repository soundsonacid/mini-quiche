pub trait Coder {
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &mut Vec<u8>) -> Self;
}
