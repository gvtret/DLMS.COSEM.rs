use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;

#[derive(Debug)]
pub struct AssociationLN {
    // simplified for now
}

impl CosemObject for AssociationLN {
    fn class_id() -> u16 {
        15
    }

    fn get_attribute(&self, _attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        None
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
