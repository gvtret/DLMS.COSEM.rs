use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;

#[derive(Debug)]
pub struct DisconnectControl {
    state: CosemData,
    control_mode: CosemData,
}

impl DisconnectControl {
    pub fn new() -> Self {
        Self {
            state: CosemData::NullData,
            control_mode: CosemData::NullData,
        }
    }
}

impl Default for DisconnectControl {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for DisconnectControl {
    fn class_id(&self) -> u16 {
        70
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.state.clone()),
            3 => Some(self.control_mode.clone()),
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
                self.state = data;
                Some(())
            }
            3 => {
                self.control_mode = data;
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
            1 => self.remote_disconnect(),
            2 => self.remote_reconnect(),
            _ => None,
        }
    }
}

impl DisconnectControl {
    fn remote_disconnect(&mut self) -> Option<CosemData> {
        self.state = CosemData::Boolean(false);
        Some(CosemData::NullData)
    }

    fn remote_reconnect(&mut self) -> Option<CosemData> {
        self.state = CosemData::Boolean(true);
        Some(CosemData::NullData)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_disconnect_control_new() {
        let control = DisconnectControl::new();
        assert_eq!(control.get_attribute(2), Some(CosemData::NullData));
        assert_eq!(control.get_attribute(3), Some(CosemData::NullData));
    }

    #[test]
    fn test_disconnect_control_methods() {
        let mut control = DisconnectControl::new();
        control.remote_disconnect();
        assert_eq!(control.get_attribute(2), Some(CosemData::Boolean(false)));
        control.remote_reconnect();
        assert_eq!(control.get_attribute(2), Some(CosemData::Boolean(true)));
    }
}
