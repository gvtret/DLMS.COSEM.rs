use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::CosemData;
use std::vec::Vec;

#[derive(Debug)]
pub struct SapAssignment {
    pub logical_device_name_list: Vec<u8>,
}

impl CosemObject for SapAssignment {
    fn class_id(&self) -> u16 {
        21
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(CosemData::OctetString(self.logical_device_name_list.clone())),
            _ => None,
        }
    }

    fn set_attribute(
        &mut self,
        _attribute_id: CosemObjectAttributeId,
        _data: CosemData,
    ) -> Option<()> {
        None
    }

    fn invoke_method(
        &mut self,
        _method_id: CosemObjectMethodId,
        _data: CosemData,
    ) -> Option<CosemData> {
        None
    }
}
