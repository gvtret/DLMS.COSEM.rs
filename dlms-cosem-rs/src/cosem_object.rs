use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;

pub trait CosemObject: Send {
    fn class_id(&self) -> u16;
    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData>;
    fn set_attribute(
        &mut self,
        attribute_id: CosemObjectAttributeId,
        data: CosemData,
    ) -> Option<()>;
    fn invoke_method(
        &mut self,
        method_id: CosemObjectMethodId,
        data: CosemData,
    ) -> Option<CosemData>;
}
