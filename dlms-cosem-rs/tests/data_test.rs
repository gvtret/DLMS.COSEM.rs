use dlms_cosem::cosem_object::CosemObject;
use dlms_cosem::data::Data;
use dlms_cosem::types::CosemData;

#[test]
fn test_data_new() {
    let data = Data::new(CosemData::Unsigned(10));
    assert_eq!(data.class_id(), 1);
    assert_eq!(data.get_attribute(2), Some(CosemData::Unsigned(10)));
}

#[test]
fn test_data_set_get() {
    let mut data = Data::new(CosemData::NullData);
    data.set_attribute(2, CosemData::Unsigned(20)).unwrap();
    assert_eq!(data.get_attribute(2), Some(CosemData::Unsigned(20)));
}
