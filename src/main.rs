pub mod primitives;
pub use primitives::*;

pub mod connection;
pub mod macros;
pub mod packet;
pub mod result;

pub const MINI_QUICHE_VERSION: u32 = 0b0000_0010;

fn main() {
    println!("Hello, world!");
}
