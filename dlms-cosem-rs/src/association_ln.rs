use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::Data as CosemData;
use heapless::Vec;

#[derive(Debug)]
pub struct AssociationLN {
    pub object_list: Vec<u8, 2048>,
    pub associated_partners_id: u32,
    pub application_context_name: Vec<u8, 64>,
    pub xdlms_context_info: Vec<u8, 64>,
    pub authentication_mechanism_name: Vec<u8, 64>,
}

impl CosemObject for AssociationLN {
    fn class_id() -> u16 {
        15
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => {
                let mut vec = heapless::Vec::new();
                vec.extend_from_slice(&self.object_list).unwrap();
                Some(CosemData::OctetString(vec))
            }
            _ => None,
        }
    }

    fn set_attribute(
        &mut self,
        _attribute_id: CosemObjectAttributeId,
        _data: CosemData,
    ) -> Option<()> {
        None
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

impl AssociationLN {
    fn reply_to_hls_authentication(&mut self, data: CosemData) -> Option<CosemData> {
        if let CosemData::OctetString(_client_challenge) = data {
            // In a real implementation, we would use the client_challenge and the shared secret
            // to generate a response. For now, we will just return a fixed response.
            let mut server_response = Vec::new();
            server_response.extend_from_slice(b"server_response").unwrap();
            Some(CosemData::OctetString(server_response))
        } else {
            None
        }
    }
}
