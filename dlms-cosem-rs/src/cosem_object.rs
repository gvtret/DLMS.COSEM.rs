use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::CosemData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeAccessMode {
    NoAccess = 0,
    Read = 1,
    Write = 2,
    ReadWrite = 3,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttributeAccessDescriptor {
    pub attribute_id: CosemObjectAttributeId,
    pub access_mode: AttributeAccessMode,
    pub selective_access_descriptor: Option<CosemData>,
}

impl AttributeAccessDescriptor {
    pub fn new(attribute_id: CosemObjectAttributeId, access_mode: AttributeAccessMode) -> Self {
        Self {
            attribute_id,
            access_mode,
            selective_access_descriptor: None,
        }
    }

    pub fn with_selective_access(
        attribute_id: CosemObjectAttributeId,
        access_mode: AttributeAccessMode,
        selective_access_descriptor: Option<CosemData>,
    ) -> Self {
        Self {
            attribute_id,
            access_mode,
            selective_access_descriptor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodAccessMode {
    NoAccess = 0,
    Access = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodAccessDescriptor {
    pub method_id: CosemObjectMethodId,
    pub access_mode: MethodAccessMode,
}

impl MethodAccessDescriptor {
    pub fn new(method_id: CosemObjectMethodId, access_mode: MethodAccessMode) -> Self {
        Self {
            method_id,
            access_mode,
        }
    }
}

pub trait CosemObject: Send {
    fn class_id(&self) -> u16;
    fn version(&self) -> u8 {
        0
    }
    fn attribute_access_rights(&self) -> Vec<AttributeAccessDescriptor> {
        Vec::new()
    }
    fn method_access_rights(&self) -> Vec<MethodAccessDescriptor> {
        Vec::new()
    }
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
