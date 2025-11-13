use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::cosem_object::{
    AttributeAccessDescriptor, AttributeAccessMode, CosemObject, CosemObjectCallbackHandlers,
};
use crate::types::CosemData;
use std::sync::Arc;

#[derive(Debug)]
pub struct Clock {
    time: CosemData,
    time_zone: CosemData,
    status: CosemData,
    daylight_savings_begin: CosemData,
    daylight_savings_end: CosemData,
    daylight_savings_deviation: CosemData,
    enabled: CosemData,
    callbacks: Arc<CosemObjectCallbackHandlers>,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            time: CosemData::NullData,
            time_zone: CosemData::NullData,
            status: CosemData::NullData,
            daylight_savings_begin: CosemData::NullData,
            daylight_savings_end: CosemData::NullData,
            daylight_savings_deviation: CosemData::NullData,
            enabled: CosemData::NullData,
            callbacks: Arc::new(CosemObjectCallbackHandlers::new()),
        }
    }

    pub fn callback_handlers(&self) -> Arc<CosemObjectCallbackHandlers> {
        Arc::clone(&self.callbacks)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for Clock {
    fn class_id(&self) -> u16 {
        8
    }

    fn attribute_access_rights(&self) -> Vec<AttributeAccessDescriptor> {
        vec![
            AttributeAccessDescriptor::new(2, AttributeAccessMode::ReadWrite),
            AttributeAccessDescriptor::new(3, AttributeAccessMode::ReadWrite),
            AttributeAccessDescriptor::new(4, AttributeAccessMode::Read),
            AttributeAccessDescriptor::new(5, AttributeAccessMode::ReadWrite),
            AttributeAccessDescriptor::new(6, AttributeAccessMode::ReadWrite),
            AttributeAccessDescriptor::new(7, AttributeAccessMode::ReadWrite),
            AttributeAccessDescriptor::new(8, AttributeAccessMode::ReadWrite),
        ]
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.time.clone()),
            3 => Some(self.time_zone.clone()),
            4 => Some(self.status.clone()),
            5 => Some(self.daylight_savings_begin.clone()),
            6 => Some(self.daylight_savings_end.clone()),
            7 => Some(self.daylight_savings_deviation.clone()),
            8 => Some(self.enabled.clone()),
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
                self.time = data;
                Some(())
            }
            3 => {
                self.time_zone = data;
                Some(())
            }
            4 => {
                self.status = data;
                Some(())
            }
            5 => {
                self.daylight_savings_begin = data;
                Some(())
            }
            6 => {
                self.daylight_savings_end = data;
                Some(())
            }
            7 => {
                self.daylight_savings_deviation = data;
                Some(())
            }
            8 => {
                self.enabled = data;
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

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_clock_new() {
        let clock = Clock::new();
        assert_eq!(clock.get_attribute(2), Some(CosemData::NullData));
        assert_eq!(clock.get_attribute(3), Some(CosemData::NullData));
        assert_eq!(clock.get_attribute(4), Some(CosemData::NullData));
        assert_eq!(clock.get_attribute(5), Some(CosemData::NullData));
        assert_eq!(clock.get_attribute(6), Some(CosemData::NullData));
        assert_eq!(clock.get_attribute(7), Some(CosemData::NullData));
        assert_eq!(clock.get_attribute(8), Some(CosemData::NullData));
    }

    #[test]
    fn test_clock_set_get() {
        let mut clock = Clock::new();
        let time = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        clock
            .set_attribute(2, CosemData::DateTime(time.clone()))
            .unwrap();
        assert_eq!(clock.get_attribute(2), Some(CosemData::DateTime(time)));
    }
}
