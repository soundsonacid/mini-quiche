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
