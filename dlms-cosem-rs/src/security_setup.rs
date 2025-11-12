use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;
use std::vec::Vec;

#[derive(Debug)]
pub struct SecuritySetup {
    security_policy: u8,
    security_suite: u8,
    client_system_title: Vec<u8>,
    server_system_title: Vec<u8>,
}

impl SecuritySetup {
    pub fn new() -> Self {
        Self {
            security_policy: 0,
            security_suite: 0,
            client_system_title: Vec::new(),
            server_system_title: Vec::new(),
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
            2 => Some(CosemData::Unsigned(self.security_policy)),
            3 => Some(CosemData::Unsigned(self.security_suite)),
            4 => Some(CosemData::OctetString(self.client_system_title.clone())),
            5 => Some(CosemData::OctetString(self.server_system_title.clone())),
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
                if let CosemData::Unsigned(policy) = data {
                    self.security_policy = policy;
                    Some(())
                } else {
                    None
                }
            }
            3 => {
                if let CosemData::Unsigned(suite) = data {
                    self.security_suite = suite;
                    Some(())
                } else {
                    None
                }
            }
            4 => {
                if let CosemData::OctetString(title) = data {
                    self.client_system_title = title;
                    Some(())
                } else {
                    None
                }
            }
            5 => {
                if let CosemData::OctetString(title) = data {
                    self.server_system_title = title;
                    Some(())
                } else {
                    None
                }
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
        assert_eq!(setup.get_attribute(2), Some(CosemData::Unsigned(0)));
        assert_eq!(setup.get_attribute(3), Some(CosemData::Unsigned(0)));
        assert_eq!(
            setup.get_attribute(4),
            Some(CosemData::OctetString(Vec::new()))
        );
        assert_eq!(
            setup.get_attribute(5),
            Some(CosemData::OctetString(Vec::new()))
        );
    }

    #[test]
    fn test_security_setup_set_get() {
        let mut setup = SecuritySetup::new();

        setup.set_attribute(2, CosemData::Unsigned(1)).unwrap();
        assert_eq!(setup.get_attribute(2), Some(CosemData::Unsigned(1)));

        setup.set_attribute(3, CosemData::Unsigned(2)).unwrap();
        assert_eq!(setup.get_attribute(3), Some(CosemData::Unsigned(2)));

        let client_title = b"client".to_vec();
        setup
            .set_attribute(4, CosemData::OctetString(client_title.clone()))
            .unwrap();
        assert_eq!(
            setup.get_attribute(4),
            Some(CosemData::OctetString(client_title))
        );

        let server_title = b"server".to_vec();
        setup
            .set_attribute(5, CosemData::OctetString(server_title.clone()))
            .unwrap();
        assert_eq!(
            setup.get_attribute(5),
            Some(CosemData::OctetString(server_title))
        );
    }
}
