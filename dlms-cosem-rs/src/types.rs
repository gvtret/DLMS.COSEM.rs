extern crate alloc;
use alloc::vec::Vec;
use heapless::String;

const MAX_STRING_SIZE: usize = 256;
const MAX_VEC_SIZE: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Data {
    NullData,
    Array(Vec<Data>),
    Structure(Vec<Data>),
    Boolean(bool),
    BitString(heapless::Vec<u8, MAX_VEC_SIZE>),
    DoubleLong(i32),
    DoubleLongUnsigned(u32),
    OctetString(heapless::Vec<u8, MAX_VEC_SIZE>),
    VisibleString(String<MAX_STRING_SIZE>),
    Utf8String(String<MAX_STRING_SIZE>),
    Bcd(i8),
    Integer(i8),
    Long(i16),
    Unsigned(u8),
    LongUnsigned(u16),
    Long64(i64),
    Long64Unsigned(u64),
    Enum(u8),
    Float32(f32),
    Float64(f64),
    DateTime(heapless::Vec<u8, 12>),
    Date(heapless::Vec<u8, 5>),
    Time(heapless::Vec<u8, 4>),
    DontCare,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_data_enum() {
        let data = Data::Array(Vec::new());
        let cloned_data = data.clone();
        assert_eq!(data, cloned_data);
    }
}
