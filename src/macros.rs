#[macro_export]
macro_rules! bits_ext {
    ($structname:ident, $trait:path, $len:literal, $t:ty) => {
        #[repr(transparent)]
        #[derive(PartialEq, Debug)]
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
        }
    };
}

#[macro_export]
macro_rules! frame {
    {$($typename:ident = $encoding:expr,)*} => {
        #[allow(non_camel_case_types)]
        #[derive(Debug, PartialEq)]
        pub enum FrameType {
            $($typename),*
        }

        impl FrameType {
            $(pub const $typename: u64 = $encoding;)*
        }
    }
}
