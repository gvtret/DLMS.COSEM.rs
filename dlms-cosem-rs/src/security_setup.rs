use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;

#[derive(Debug)]
pub struct SecuritySetup {
    security_policy: CosemData,
    security_suite: CosemData,
    client_system_title: CosemData,
    server_system_title: CosemData,
}

impl SecuritySetup {
    pub fn new() -> Self {
        Self {
            security_policy: CosemData::NullData,
            security_suite: CosemData::NullData,
            client_system_title: CosemData::NullData,
            server_system_title: CosemData::NullData,
        }
    }
}

impl Default for SecuritySetup {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for SecuritySetup {
    fn class_id(&self) -> u16 {
        64
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.security_policy.clone()),
            3 => Some(self.security_suite.clone()),
            4 => Some(self.client_system_title.clone()),
            5 => Some(self.server_system_title.clone()),
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
                self.security_policy = data;
                Some(())
            }
            3 => {
                self.security_suite = data;
                Some(())
            }
            4 => {
                self.client_system_title = data;
                Some(())
            }
            5 => {
                self.server_system_title = data;
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
    fn test_security_setup_new() {
        let setup = SecuritySetup::new();
        assert_eq!(setup.get_attribute(2), Some(CosemData::NullData));
        assert_eq!(setup.get_attribute(3), Some(CosemData::NullData));
        assert_eq!(setup.get_attribute(4), Some(CosemData::NullData));
        assert_eq!(setup.get_attribute(5), Some(CosemData::NullData));
    }
}
