use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;
use heapless::Vec;

#[derive(Debug)]
pub struct SapAssignment {
    pub logical_device_name_list: Vec<u8, 2048>,
}

impl CosemObject for SapAssignment {
    fn class_id(&self) -> u16 {
        21
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => {
                let mut vec = heapless::Vec::new();
                vec.extend_from_slice(&self.logical_device_name_list)
                    .unwrap();
                Some(CosemData::OctetString(vec))
            }
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
