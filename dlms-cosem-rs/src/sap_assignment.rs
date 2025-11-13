use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::cosem_object::{CosemObject, CosemObjectCallbackHandlers};
use crate::types::CosemData;
use std::sync::Arc;
use std::vec::Vec;

#[derive(Debug)]
pub struct SapAssignment {
    pub logical_device_name_list: Vec<u8>,
    callbacks: Arc<CosemObjectCallbackHandlers>,
}

impl SapAssignment {
    pub fn new() -> Self {
        Self {
            logical_device_name_list: Vec::new(),
            callbacks: Arc::new(CosemObjectCallbackHandlers::new()),
        }
    }

    pub fn with_logical_device_names(names: Vec<u8>) -> Self {
        Self {
            logical_device_name_list: names,
            callbacks: Arc::new(CosemObjectCallbackHandlers::new()),
        }
    }

    pub fn callback_handlers(&self) -> Arc<CosemObjectCallbackHandlers> {
        Arc::clone(&self.callbacks)
    }
}

impl Default for SapAssignment {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for SapAssignment {
    fn class_id(&self) -> u16 {
        21
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(CosemData::OctetString(
                self.logical_device_name_list.clone(),
            )),
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

    fn callbacks(&self) -> Option<Arc<CosemObjectCallbackHandlers>> {
        Some(Arc::clone(&self.callbacks))
    }
}
