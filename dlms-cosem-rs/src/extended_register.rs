use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::cosem_object::{
    AttributeAccessDescriptor, AttributeAccessMode, CosemObject, CosemObjectCallbackHandlers,
    MethodAccessDescriptor, MethodAccessMode,
};
use crate::types::CosemData;
use std::sync::Arc;

#[derive(Debug)]
pub struct ExtendedRegister {
    value: CosemData,
    scaler_unit: CosemData,
    status: CosemData,
    capture_time: CosemData,
    callbacks: Arc<CosemObjectCallbackHandlers>,
}

impl ExtendedRegister {
    pub fn new() -> Self {
        Self {
            value: CosemData::Unsigned(0),
            scaler_unit: CosemData::Structure(vec![CosemData::Integer(0), CosemData::Enum(255)]),
            status: CosemData::NullData,
            capture_time: CosemData::NullData,
            callbacks: Arc::new(CosemObjectCallbackHandlers::new()),
        }
    }

    pub fn callback_handlers(&self) -> Arc<CosemObjectCallbackHandlers> {
        Arc::clone(&self.callbacks)
    }
}

impl Default for ExtendedRegister {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for ExtendedRegister {
    fn class_id(&self) -> u16 {
        4
    }

    fn attribute_access_rights(&self) -> Vec<AttributeAccessDescriptor> {
        vec![
            AttributeAccessDescriptor::new(2, AttributeAccessMode::Read),
            AttributeAccessDescriptor::new(3, AttributeAccessMode::Read),
            AttributeAccessDescriptor::new(4, AttributeAccessMode::Read),
            AttributeAccessDescriptor::new(5, AttributeAccessMode::Read),
        ]
    }

    fn method_access_rights(&self) -> Vec<MethodAccessDescriptor> {
        vec![MethodAccessDescriptor::new(1, MethodAccessMode::Access)]
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.value.clone()),
            3 => Some(self.scaler_unit.clone()),
            4 => Some(self.status.clone()),
            5 => Some(self.capture_time.clone()),
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
            3 => {
                self.scaler_unit = data;
                Some(())
            }
            4 => {
                self.status = data;
                Some(())
            }
            5 => {
                self.capture_time = data;
                Some(())
            }
            _ => None,
        }
    }

    fn invoke_method(
        &mut self,
        method_id: CosemObjectMethodId,
        _data: CosemData,
    ) -> Option<CosemData> {
        match method_id {
            1 => self.reset(),
            _ => None,
        }
    }

    fn callbacks(&self) -> Option<Arc<CosemObjectCallbackHandlers>> {
        Some(Arc::clone(&self.callbacks))
    }
}

impl ExtendedRegister {
    fn reset(&mut self) -> Option<CosemData> {
        self.value = CosemData::Unsigned(0);
        Some(CosemData::NullData)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_extended_register_new() {
        let register = ExtendedRegister::new();
        assert_eq!(register.get_attribute(2), Some(CosemData::Unsigned(0)));
        assert_eq!(
            register.get_attribute(3),
            Some(CosemData::Structure(vec![
                CosemData::Integer(0),
                CosemData::Enum(255)
            ]))
        );
        assert_eq!(register.get_attribute(4), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(5), Some(CosemData::NullData));
    }

    #[test]
    fn test_extended_register_set_get() {
        let mut register = ExtendedRegister::new();
        register.set_attribute(2, CosemData::Unsigned(10)).unwrap();
        assert_eq!(register.get_attribute(2), Some(CosemData::Unsigned(10)));
    }

    #[test]
    fn test_extended_register_reset() {
        let mut register = ExtendedRegister::new();
        register.set_attribute(2, CosemData::Unsigned(10)).unwrap();
        assert_eq!(register.get_attribute(2), Some(CosemData::Unsigned(10)));
        register.reset();
        assert_eq!(register.get_attribute(2), Some(CosemData::Unsigned(0)));
    }
}
