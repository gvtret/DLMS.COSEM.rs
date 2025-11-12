use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::cosem_object::CosemObject;
use crate::types::CosemData;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectListEntry {
    pub class_id: u16,
    pub version: u8,
    pub logical_name: [u8; 6],
}

impl ObjectListEntry {
    fn to_cosem_data(&self) -> CosemData {
        CosemData::Structure(vec![
            CosemData::LongUnsigned(self.class_id),
            CosemData::Unsigned(self.version),
            CosemData::OctetString(self.logical_name.to_vec()),
            CosemData::Structure(vec![
                CosemData::Array(Vec::new()),
                CosemData::Array(Vec::new()),
                CosemData::Array(Vec::new()),
            ]),
        ])
    }
}

/// Association LN (Class ID 15)
#[derive(Debug)]
pub struct AssociationLN {
    // Attribute 2: A list of all objects that are accessible through the association.
    // Kept in sync via a shared handle updated by the server.
    object_list: Arc<Mutex<Vec<ObjectListEntry>>>,
    // Attribute 3: Defines the partners of the association.
    // A structure of client_sap (u16) and server_sap (u16).
    associated_partners_id: u32,
    // Attribute 4: Identifies the application context (e.g., LN, SN).
    // An OID encoded as an octet-string.
    application_context_name: Vec<u8>,
    // Attribute 5: Contains information about the xDLMS context (e.g., ciphering info).
    // A structure encoded as an octet-string.
    xdlms_context_info: Vec<u8>,
    // Attribute 6: The name of the authentication mechanism (e.g., Low, High).
    // An OID encoded as an octet-string.
    authentication_mechanism_name: Vec<u8>,
}

impl AssociationLN {
    pub fn new(
        object_list: Arc<Mutex<Vec<ObjectListEntry>>>,
        associated_partners_id: u32,
        application_context_name: Vec<u8>,
        xdlms_context_info: Vec<u8>,
        authentication_mechanism_name: Vec<u8>,
    ) -> Self {
        Self {
            object_list,
            associated_partners_id,
            application_context_name,
            xdlms_context_info,
            authentication_mechanism_name,
        }
    }

    fn reply_to_hls_authentication(&mut self, data: CosemData) -> Option<CosemData> {
        if let CosemData::OctetString(_client_challenge) = data {
            // In a real implementation, we would use the client_challenge and the shared secret
            // to generate a response. For now, we will just return a fixed response.
            let server_response = b"server_response".to_vec();
            Some(CosemData::OctetString(server_response))
        } else {
            None
        }
    }
}

impl Default for AssociationLN {
    fn default() -> Self {
        Self::new(
            Arc::new(Mutex::new(Vec::new())),
            0,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

impl CosemObject for AssociationLN {
    fn class_id(&self) -> u16 {
        15
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => {
                let entries = self.object_list.lock().ok()?;
                let list: Vec<_> = entries.iter().map(ObjectListEntry::to_cosem_data).collect();
                Some(CosemData::Array(list))
            }
            3 => Some(CosemData::DoubleLongUnsigned(self.associated_partners_id)),
            4 => Some(CosemData::OctetString(
                self.application_context_name.clone(),
            )),
            5 => Some(CosemData::OctetString(self.xdlms_context_info.clone())),
            6 => Some(CosemData::OctetString(
                self.authentication_mechanism_name.clone(),
            )),
            _ => None,
        }
    }

    fn set_attribute(
        &mut self,
        attribute_id: CosemObjectAttributeId,
        data: CosemData,
    ) -> Option<()> {
        match attribute_id {
            // Attribute 2 (object_list) is read-only.
            3 => {
                if let CosemData::DoubleLongUnsigned(id) = data {
                    self.associated_partners_id = id;
                    Some(())
                } else {
                    None
                }
            }
            4 => {
                if let CosemData::OctetString(name) = data {
                    self.application_context_name = name;
                    Some(())
                } else {
                    None
                }
            }
            5 => {
                if let CosemData::OctetString(info) = data {
                    self.xdlms_context_info = info;
                    Some(())
                } else {
                    None
                }
            }
            6 => {
                if let CosemData::OctetString(name) = data {
                    self.authentication_mechanism_name = name;
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
        method_id: CosemObjectMethodId,
        data: CosemData,
    ) -> Option<CosemData> {
        match method_id {
            1 => self.reply_to_hls_authentication(data),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn object_list_entry_is_rendered_as_structure() {
        let entry = ObjectListEntry {
            class_id: 3,
            version: 1,
            logical_name: [0, 0, 1, 0, 0, 255],
        };

        let data = entry.to_cosem_data();
        assert_eq!(
            data,
            CosemData::Structure(vec![
                CosemData::LongUnsigned(3),
                CosemData::Unsigned(1),
                CosemData::OctetString(vec![0, 0, 1, 0, 0, 255]),
                CosemData::Structure(vec![
                    CosemData::Array(Vec::new()),
                    CosemData::Array(Vec::new()),
                    CosemData::Array(Vec::new()),
                ]),
            ])
        );
    }

    #[test]
    fn association_ln_exposes_dynamic_object_list() {
        let handle = Arc::new(Mutex::new(vec![ObjectListEntry {
            class_id: 15,
            version: 0,
            logical_name: [0, 0, 40, 0, 0, 255],
        }]));

        let association =
            AssociationLN::new(Arc::clone(&handle), 0, Vec::new(), Vec::new(), Vec::new());

        let attribute = association
            .get_attribute(2)
            .expect("expected object list attribute");

        assert_eq!(
            attribute,
            CosemData::Array(vec![ObjectListEntry {
                class_id: 15,
                version: 0,
                logical_name: [0, 0, 40, 0, 0, 255],
            }
            .to_cosem_data()])
        );

        handle.lock().unwrap().push(ObjectListEntry {
            class_id: 3,
            version: 0,
            logical_name: [1, 0, 0, 0, 0, 255],
        });

        let updated = association
            .get_attribute(2)
            .expect("expected refreshed object list");

        assert_eq!(
            updated,
            CosemData::Array(vec![
                ObjectListEntry {
                    class_id: 15,
                    version: 0,
                    logical_name: [0, 0, 40, 0, 0, 255],
                }
                .to_cosem_data(),
                ObjectListEntry {
                    class_id: 3,
                    version: 0,
                    logical_name: [1, 0, 0, 0, 0, 255],
                }
                .to_cosem_data(),
            ])
        );
    }
}
