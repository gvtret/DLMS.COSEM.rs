use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;

#[derive(Debug)]
pub struct Register {
    value: CosemData,
    scaler_unit: CosemData,
}

impl CosemObject for Register {
    fn class_id() -> u16 {
        3
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.value.clone()),
            3 => Some(self.scaler_unit.clone()),
            _ => None,
        }
    }

    fn set_attribute(
        &mut self,
        attribute_id: CosemObjectAttributeId,
        data: CosemData,
    ) -> Option<()> {
        match attribute_id {
            2 => {
                self.value = data;
                Some(())
            }
            _ => None,
        }
    }

    fn invoke_method(
        &mut self,
        _method_id: CosemObjectMethodId,
        _data: CosemData,
    ) -> Option<CosemData> {
        None
    }
}
