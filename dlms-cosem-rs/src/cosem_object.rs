use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data;

pub trait CosemObject {
    fn class_id() -> u16;
    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<Data>;
    fn set_attribute(&mut self, attribute_id: CosemObjectAttributeId, data: Data) -> Option<()>;
    fn invoke_method(&mut self, method_id: CosemObjectMethodId, data: Data) -> Option<Data>;
}
