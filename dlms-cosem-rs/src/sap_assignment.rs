#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::cosem_object::CosemObject;
use crate::types::Data as CosemData;

#[derive(Debug)]
pub struct SapAssignment {
    pub logical_device_name_list: CosemData,
}

impl SapAssignment {
    pub fn new() -> Self {
        Self {
            logical_device_name_list: CosemData::Array(Vec::new()),
        }
    }
}

impl Default for SapAssignment {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for SapAssignment {
    fn class_id() -> u16 {
        21
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.logical_device_name_list.clone()),
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
                self.logical_device_name_list = data;
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
