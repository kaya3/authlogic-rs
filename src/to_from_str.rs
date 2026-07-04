/// Trait for conversion of IDs to and from strings. This is used to encode and
/// decode session IDs in cookies, and challenge IDs in URLs.
/// 
/// Implementations are required to preserve round trips, and not 
pub trait ToFromStr: Sized {
    /// A printable ASCII character which cannot appear in the string
    /// representation of an ID.
    const EXCLUDED: char;
    
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
    
    fn try_parse(str: &str) -> Option<Self>;
}

/// Wrapper for using a generic ID type in a `format!(...)` string.
pub(crate) struct DisplayWrapper<T: ToFromStr>(pub(crate) T);

impl <T: ToFromStr> std::fmt::Display for DisplayWrapper<T> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ToFromStr::fmt(&self.0, fmt)
    }
}

macro_rules! impl_for_numbers {
    ($($ty: ident),+) => {
        $(
            impl ToFromStr for $ty {
                const EXCLUDED: char = '.';
                
                #[inline(always)]
                fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    std::fmt::LowerHex::fmt(self, fmt)
                }
                
                #[inline(always)]
                fn try_parse(hex_str: &str) -> Option<Self> {
                    $ty::from_str_radix(hex_str, 16).ok()
                }
            }
        )+
    };
}

impl_for_numbers!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);

#[cfg(test)]
mod test {
    use super::*;
    
    fn dump<T: ToFromStr>(x: T) -> String {
        format!("{}", DisplayWrapper(x))
    }
    
    #[test]
    fn number_to_hex() {
        assert_eq!("1", dump(1u8));
        assert_eq!("1", dump(1u16));
        assert_eq!("1", dump(1u32));
        assert_eq!("1", dump(1u64));
        assert_eq!("1", dump(1u128));
        assert_eq!("1", dump(1usize));
        
        assert_eq!("1", dump(1i8));
        assert_eq!("1", dump(1i16));
        assert_eq!("1", dump(1i32));
        assert_eq!("1", dump(1i64));
        assert_eq!("1", dump(1i128));
        assert_eq!("1", dump(1isize));
        
        assert_eq!("12", dump(0x12u8));
        assert_eq!("1234", dump(0x1234u16));
        assert_eq!("12345678", dump(0x12345678u32));
        assert_eq!("123456789abcdef0", dump(0x123456789ABCDEF0u64));
        assert_eq!("123456789abcdef0123456789abcdef0", dump(0x123456789ABCDEF0123456789ABCDEF0u128));
        
        assert_eq!("12", dump(0x12i8));
        assert_eq!("1234", dump(0x1234i16));
        assert_eq!("12345678", dump(0x12345678i32));
        assert_eq!("123456789abcdef0", dump(0x123456789ABCDEF0i64));
        assert_eq!("123456789abcdef0123456789abcdef0", dump(0x123456789ABCDEF0123456789ABCDEF0i128));
    }
    
    #[test]
    fn number_from_hex() {
        assert_eq!(Some(1u8), u8::try_parse("1"));
        assert_eq!(Some(1u16), u16::try_parse("1"));
        assert_eq!(Some(1u32), u32::try_parse("1"));
        assert_eq!(Some(1u64), u64::try_parse("1"));
        assert_eq!(Some(1u128), u128::try_parse("1"));
        assert_eq!(Some(1usize), usize::try_parse("1"));
        
        assert_eq!(Some(1i8), i8::try_parse("1"));
        assert_eq!(Some(1i16), i16::try_parse("1"));
        assert_eq!(Some(1i32), i32::try_parse("1"));
        assert_eq!(Some(1i64), i64::try_parse("1"));
        assert_eq!(Some(1i128), i128::try_parse("1"));
        assert_eq!(Some(1isize), isize::try_parse("1"));
        
        assert_eq!(Some(0x12u8), u8::try_parse("12"));
        assert_eq!(Some(0x1234u16), u16::try_parse("1234"));
        assert_eq!(Some(0x12345678u32), u32::try_parse("12345678"));
        assert_eq!(Some(0x123456789ABCDEF0u64), u64::try_parse("123456789abcdef0"));
        assert_eq!(Some(0x123456789ABCDEF0123456789ABCDEF0u128), u128::try_parse("123456789abcdef0123456789abcdef0"));
        
        assert_eq!(Some(0x12i8), i8::try_parse("12"));
        assert_eq!(Some(0x1234i16), i16::try_parse("1234"));
        assert_eq!(Some(0x12345678i32), i32::try_parse("12345678"));
        assert_eq!(Some(0x123456789ABCDEF0i64), i64::try_parse("123456789abcdef0"));
        assert_eq!(Some(0x123456789ABCDEF0123456789ABCDEF0i128), i128::try_parse("123456789abcdef0123456789abcdef0"));
    }
}
