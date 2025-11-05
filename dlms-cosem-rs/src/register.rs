use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;

#[derive(Debug)]
pub struct Register {
    value: CosemData,
    scaler_unit: CosemData,
}

impl Register {
    pub fn new() -> Self {
        Self {
            value: CosemData::NullData,
            scaler_unit: CosemData::NullData,
        }
    }
}

impl Default for Register {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for Register {
    fn class_id(&self) -> u16 {
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
            3 => {
                self.scaler_unit = data;
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

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_register_new() {
        let register = Register::new();
        assert_eq!(register.get_attribute(2), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(3), Some(CosemData::NullData));
    }

    #[test]
    fn test_register_set_get() {
        let mut register = Register::new();
        register
            .set_attribute(2, CosemData::Unsigned(10))
            .unwrap();
        assert_eq!(register.get_attribute(2), Some(CosemData::Unsigned(10)));
    }
}
