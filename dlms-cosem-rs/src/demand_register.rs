use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::CosemData;

#[derive(Debug)]
pub struct DemandRegister {
    current_average_value: CosemData,
    last_average_value: CosemData,
    scaler_unit: CosemData,
    status: CosemData,
    capture_time: CosemData,
    start_time_current: CosemData,
    period: CosemData,
    number_of_periods: CosemData,
}

impl DemandRegister {
    pub fn new() -> Self {
        Self {
            current_average_value: CosemData::NullData,
            last_average_value: CosemData::NullData,
            scaler_unit: CosemData::NullData,
            status: CosemData::NullData,
            capture_time: CosemData::NullData,
            start_time_current: CosemData::NullData,
            period: CosemData::NullData,
            number_of_periods: CosemData::NullData,
        }
    }
}

impl Default for DemandRegister {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for DemandRegister {
    fn class_id(&self) -> u16 {
        5
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.current_average_value.clone()),
            3 => Some(self.last_average_value.clone()),
            4 => Some(self.scaler_unit.clone()),
            5 => Some(self.status.clone()),
            6 => Some(self.capture_time.clone()),
            7 => Some(self.start_time_current.clone()),
            8 => Some(self.period.clone()),
            9 => Some(self.number_of_periods.clone()),
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
                self.current_average_value = data;
                Some(())
            }
            3 => {
                self.last_average_value = data;
                Some(())
            }
            4 => {
                self.scaler_unit = data;
                Some(())
            }
            5 => {
                self.status = data;
                Some(())
            }
            6 => {
                self.capture_time = data;
                Some(())
            }
            7 => {
                self.start_time_current = data;
                Some(())
            }
            8 => {
                self.period = data;
                Some(())
            }
            9 => {
                self.number_of_periods = data;
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
    fn test_demand_register_new() {
        let register = DemandRegister::new();
        assert_eq!(register.get_attribute(2), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(3), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(4), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(5), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(6), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(7), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(8), Some(CosemData::NullData));
        assert_eq!(register.get_attribute(9), Some(CosemData::NullData));
    }
}
