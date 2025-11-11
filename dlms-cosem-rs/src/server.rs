use crate::acse::{AarqApdu, AareApdu};
use crate::cosem_object::CosemObject;
use crate::error::DlmsError;
use crate::hdlc::{HdlcFrame, HdlcFrameError};
use crate::security::lls_authenticate;
use crate::security::{hls_decrypt, hls_encrypt, SecurityError};
use crate::transport::Transport;
use crate::xdlms::{
    ActionRequest, ActionResponse, ActionResponseNormal, ActionResult, GetRequest, GetResponse,
    GetResponseNormal, GetDataResult, SetRequest, SetResponse, SetResponseNormal, DataAccessResult,
};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use heapless::Vec;
use rand_core::RngCore;

#[derive(Debug)]
pub enum ServerError<E> {
    HdlcError(HdlcFrameError),
    AcseError,
    TransportError(E),
    SecurityError(SecurityError),
    DlmsError(DlmsError),
}

impl<E> From<HdlcFrameError> for ServerError<E> {
    fn from(e: HdlcFrameError) -> Self {
        ServerError::HdlcError(e)
    }
}

impl<E> From<DlmsError> for ServerError<E> {
    fn from(e: DlmsError) -> Self {
        ServerError::DlmsError(e)
    }
}

pub struct Server<T: Transport> {
    address: u16,
    transport: T,
    password: Option<Vec<u8, 32>>,
    key: Option<Vec<u8, 16>>,
    objects: BTreeMap<[u8; 6], Box<dyn CosemObject>>,
    challenge: Option<Vec<u8, 32>>,
}

impl<T: Transport> Server<T> {
    pub fn new(
        address: u16,
        transport: T,
        password: Option<Vec<u8, 32>>,
        key: Option<Vec<u8, 16>>,
    ) -> Self {
        Server {
            address,
            transport,
            password,
            key,
            objects: BTreeMap::new(),
            challenge: None,
        }
    }

    pub fn register_object(&mut self, instance_id: [u8; 6], object: Box<dyn CosemObject>) {
        self.objects.insert(instance_id, object);
    }

    pub fn run(&mut self) -> Result<(), ServerError<T::Error>> {
        loop {
            let request_bytes = self.transport.receive().map_err(ServerError::TransportError)?;
            let decrypted_request = if let Some(key) = &self.key {
                hls_decrypt(&request_bytes, key).map_err(ServerError::SecurityError)?
            } else {
                request_bytes
            };
            let response_bytes = self.handle_request(&decrypted_request)?;
            let encrypted_response = if let Some(key) = &self.key {
                hls_encrypt(&response_bytes, key).map_err(ServerError::SecurityError)?
            } else {
                response_bytes
            };
            self.transport
                .send(&encrypted_response)
                .map_err(ServerError::TransportError)?;
        }
    }

    fn handle_request(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8, 2048>, ServerError<T::Error>> {
        let request_frame = HdlcFrame::from_bytes(request_bytes)?;

        let response_bytes =
            if let Ok(aarq) = AarqApdu::from_bytes(&request_frame.information) {
                let mut aare = AareApdu {
                    application_context_name: aarq.1.application_context_name.clone(),
                    result: 0,
                    result_source_diagnostic: 0,
                    responding_authentication_value: None,
                    user_information: Vec::new(),
                };
                if let (Some(password), Some(mechanism_name)) =
                    (&self.password, aarq.1.mechanism_name.as_ref())
                {
                    if mechanism_name == b"LLS" {
                        if let Some(auth_value) = aarq.1.calling_authentication_value {
                            let challenge = self
                                .challenge
                                .as_ref()
                                .ok_or(ServerError::AcseError)?
                                .as_slice();
                            match lls_authenticate(password, challenge) {
                                Ok(expected_response) => {
                                    if auth_value == expected_response {
                                        aare.result = 0; // success
                                    } else {
                                        aare.result = 1; // failure
                                    }
                                }
                                Err(_) => aare.result = 1, // failure
                            }
                        } else {
                            let mut challenge_bytes = [0u8; 32];
                            rand_core::OsRng.fill_bytes(&mut challenge_bytes);
                            let challenge: Vec<u8, 32> =
                                Vec::from_slice(&challenge_bytes).map_err(|_| DlmsError::VecIsFull)?;
                            self.challenge = Some(challenge.clone());
                            aare.responding_authentication_value = Some(challenge);
                        }
                    }
                }
                aare.user_information
                    .extend_from_slice(b"user_info")
                    .map_err(|_| DlmsError::VecIsFull)?;
                aare.to_bytes()?
            } else if let Ok(get_req) = GetRequest::from_bytes(&request_frame.information) {
                let GetRequest::Normal(get_req) = get_req else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let Some(object) = self
                    .objects
                    .get_mut(&get_req.cosem_attribute_descriptor.instance_id)
                else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let result =
                    object.get_attribute(get_req.cosem_attribute_descriptor.attribute_id as i8);
                let get_res = GetResponse::Normal(GetResponseNormal {
                    invoke_id_and_priority: get_req.invoke_id_and_priority,
                    result: result.map_or(
                        GetDataResult::DataAccessResult(
                            DataAccessResult::ObjectUnavailable,
                        ),
                        |data| GetDataResult::Data(data),
                    ),
                });
                get_res.to_bytes()?
            } else if let Ok(set_req) = SetRequest::from_bytes(&request_frame.information) {
                let SetRequest::Normal(set_req) = set_req else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let Some(object) = self
                    .objects
                    .get_mut(&set_req.cosem_attribute_descriptor.instance_id)
                else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let result =
                    object.set_attribute(set_req.cosem_attribute_descriptor.attribute_id as i8, set_req.value);
                let set_res = SetResponse::Normal(SetResponseNormal {
                    invoke_id_and_priority: set_req.invoke_id_and_priority,
                    result: result.map_or(
                        DataAccessResult::ObjectUnavailable,
                        |_| DataAccessResult::Success,
                    ),
                });
                set_res.to_bytes()?
            } else if let Ok(action_req) = ActionRequest::from_bytes(&request_frame.information) {
                let ActionRequest::Normal(action_req) = action_req else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let Some(object) = self
                    .objects
                    .get_mut(&action_req.cosem_method_descriptor.instance_id)
                else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let result =
                    object.invoke_method(action_req.cosem_method_descriptor.method_id as i8, action_req.method_invocation_parameters.unwrap_or(crate::types::Data::NullData));
                let action_res = ActionResponse::Normal(ActionResponseNormal {
                    invoke_id_and_priority: action_req.invoke_id_and_priority,
                    single_response: crate::xdlms::ActionResponseWithOptionalData {
                        result: result.as_ref().map_or(ActionResult::ObjectUnavailable, |_| ActionResult::Success),
                        return_parameters: result.map(|data| GetDataResult::Data(data)),
                    },
                });
                action_res.to_bytes()?
            }else {
                return Err(ServerError::DlmsError(DlmsError::Xdlms));
            };

        let response_hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: response_bytes,
        };

        Ok(response_hdlc_frame.to_bytes()?)
    }
}
