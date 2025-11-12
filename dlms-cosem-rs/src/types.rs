use std::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
pub enum CosemData {
    NullData,
    Array(Vec<CosemData>),
    Structure(Vec<CosemData>),
    Boolean(bool),
    BitString(Vec<u8>),
    DoubleLong(i32),
    DoubleLongUnsigned(u32),
    OctetString(Vec<u8>),
    VisibleString(String),
    Utf8String(String),
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
    DateTime(Vec<u8>),
    Date(Vec<u8>),
    Time(Vec<u8>),
    DontCare,
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_data_enum() {
        let data = CosemData::Array(Vec::new());
        let cloned_data = data.clone();
        assert_eq!(data, cloned_data);
    }
}
