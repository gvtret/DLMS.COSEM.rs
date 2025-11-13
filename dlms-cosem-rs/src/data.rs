use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::cosem_object::{CosemObject, CosemObjectCallbackHandlers};
use crate::types::CosemData;
use std::sync::Arc;

#[derive(Debug)]
pub struct Data {
    value: CosemData,
    callbacks: Arc<CosemObjectCallbackHandlers>,
}

impl Data {
    pub fn new(value: CosemData) -> Self {
        Self {
            value,
            callbacks: Arc::new(CosemObjectCallbackHandlers::new()),
        }
    }

    pub fn callback_handlers(&self) -> Arc<CosemObjectCallbackHandlers> {
        Arc::clone(&self.callbacks)
    }
}

impl CosemObject for Data {
    fn class_id(&self) -> u16 {
        1
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.value.clone()),
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

    fn callbacks(&self) -> Option<Arc<CosemObjectCallbackHandlers>> {
        Some(Arc::clone(&self.callbacks))
    }
}
