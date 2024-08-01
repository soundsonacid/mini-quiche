#[macro_export]
macro_rules! bits_ext {
    ($structname:ident, $trait:path, $len:literal, $t:ty) => {
        #[repr(transparent)]
        #[derive(PartialEq, Debug)]
        pub struct $structname(Bits<$len, $t>);

        impl $trait for $structname {
            fn from_num(bits: u8) -> Self {
                Self(Bits::from(bits))
            }

            fn from_bits(bits: Vec<bool>) -> Self {
                Self(Bits::from_bits(bits))
            }

            fn to_inner(&self) -> u8 {
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
