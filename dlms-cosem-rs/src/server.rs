use crate::acse::{AareApdu, AarqApdu};
use crate::cosem_object::CosemObject;
use crate::error::DlmsError;
use crate::hdlc::{HdlcFrame, HdlcFrameError};
use crate::security::lls_authenticate;
use crate::security::{hls_decrypt, hls_encrypt, SecurityError};
use crate::transport::Transport;
use crate::xdlms::{
    ActionRequest, ActionResponse, ActionResponseNormal, ActionResult, DataAccessResult,
    GetDataResult, GetRequest, GetResponse, GetResponseNormal, SetRequest, SetResponse,
    SetResponseNormal,
};
use rand_core::{OsRng, RngCore};
use std::boxed::Box;
use std::collections::BTreeMap;
use std::vec::Vec;

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
    password: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    objects: BTreeMap<[u8; 6], Box<dyn CosemObject>>,
    lls_challenges: BTreeMap<u16, Vec<u8>>,
}

impl<T: Transport> Server<T> {
    pub fn new(
        address: u16,
        transport: T,
        password: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
    ) -> Self {
        Server {
            address,
            transport,
            password,
            key,
            objects: BTreeMap::new(),
            lls_challenges: BTreeMap::new(),
        }
    }

    pub fn register_object(&mut self, instance_id: [u8; 6], object: Box<dyn CosemObject>) {
        self.objects.insert(instance_id, object);
    }

    pub fn run(&mut self) -> Result<(), ServerError<T::Error>> {
        loop {
            let request_bytes = self
                .transport
                .receive()
                .map_err(ServerError::TransportError)?;
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

    fn handle_request(&mut self, request_bytes: &[u8]) -> Result<Vec<u8>, ServerError<T::Error>> {
        let request_frame = HdlcFrame::from_bytes(request_bytes)?;

        let response_bytes = if let Ok(aarq) = AarqApdu::from_bytes(&request_frame.information) {
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
                let association_address = request_frame.address;
                if mechanism_name == b"LLS" {
                    if let Some(auth_value) = aarq.1.calling_authentication_value {
                        if let Some(challenge) = self.lls_challenges.get(&association_address) {
                            match lls_authenticate(password, challenge) {
                                Ok(expected_response) => {
                                    if auth_value == expected_response {
                                        aare.result = 0; // success
                                        self.lls_challenges.remove(&association_address);
                                    } else {
                                        aare.result = 1; // failure
                                    }
                                }
                                Err(_) => aare.result = 1, // failure
                            }
                        } else {
                            aare.result = 1; // failure due to missing challenge
                        }
                    } else {
                        let mut challenge = vec![0u8; 16];
                        OsRng.fill_bytes(&mut challenge);
                        self.lls_challenges
                            .insert(association_address, challenge.clone());
                        aare.responding_authentication_value = Some(challenge);
                    }
                }
            }
            aare.user_information.extend_from_slice(b"user_info");
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

            let result = object.get_attribute(get_req.cosem_attribute_descriptor.attribute_id);
            let get_res = GetResponse::Normal(GetResponseNormal {
                invoke_id_and_priority: get_req.invoke_id_and_priority,
                result: result.map_or(
                    GetDataResult::DataAccessResult(DataAccessResult::ObjectUnavailable),
                    GetDataResult::Data,
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

            let result = object.set_attribute(
                set_req.cosem_attribute_descriptor.attribute_id,
                set_req.value,
            );
            let set_res = SetResponse::Normal(SetResponseNormal {
                invoke_id_and_priority: set_req.invoke_id_and_priority,
                result: result.map_or(DataAccessResult::ObjectUnavailable, |_| {
                    DataAccessResult::Success
                }),
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

            let result = object.invoke_method(
                action_req.cosem_method_descriptor.method_id,
                action_req
                    .method_invocation_parameters
                    .unwrap_or(crate::types::CosemData::NullData),
            );
            let action_res = ActionResponse::Normal(ActionResponseNormal {
                invoke_id_and_priority: action_req.invoke_id_and_priority,
                single_response: crate::xdlms::ActionResponseWithOptionalData {
                    result: result
                        .as_ref()
                        .map_or(ActionResult::ObjectUnavailable, |_| ActionResult::Success),
                    return_parameters: result.map(GetDataResult::Data),
                },
            });
            action_res.to_bytes()?
        } else {
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

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[derive(Default)]
    struct DummyTransport;

    impl Transport for DummyTransport {
        type Error = ();

        fn send(&mut self, _bytes: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }
    }

    fn build_hdlc_request(address: u16, aarq: AarqApdu) -> Vec<u8> {
        let frame = HdlcFrame {
            address,
            control: 0,
            information: aarq.to_bytes().expect("failed to serialize aarq"),
        };

        frame.to_bytes().expect("failed to encode frame")
    }

    fn parse_aare(bytes: &[u8]) -> AareApdu {
        let frame = HdlcFrame::from_bytes(bytes).expect("failed to decode frame");
        AareApdu::from_bytes(&frame.information)
            .expect("failed to decode aare")
            .1
    }

    #[test]
    fn lls_challenge_is_issued_and_persisted() {
        let mut server = Server::new(
            0x0001,
            DummyTransport::default(),
            Some(b"password".to_vec()),
            None,
        );

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: b"info".to_vec(),
        };
        let aarq_bytes = aarq.to_bytes().expect("failed to encode aarq");
        assert!(AarqApdu::from_bytes(&aarq_bytes).is_ok());

        let request = build_hdlc_request(0x0002, aarq);

        let frame = HdlcFrame::from_bytes(&request).expect("failed to decode request frame");
        assert!(AarqApdu::from_bytes(&frame.information).is_ok());

        let response = server
            .handle_request(&request)
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response);
        let challenge = aare
            .responding_authentication_value
            .expect("expected challenge in response");

        assert_eq!(challenge.len(), 16);
        let stored = server
            .lls_challenges
            .get(&0x0002)
            .expect("challenge should be stored");
        assert_eq!(stored.as_slice(), challenge.as_slice());
    }

    #[test]
    fn lls_challenge_response_validates_and_clears() {
        let mut server = Server::new(
            0x0001,
            DummyTransport::default(),
            Some(b"password".to_vec()),
            None,
        );

        let association_address = 0x0003;
        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: b"info".to_vec(),
        };
        let aarq_bytes = aarq.to_bytes().expect("failed to encode aarq");
        assert!(AarqApdu::from_bytes(&aarq_bytes).is_ok());

        let initial_request = build_hdlc_request(association_address, aarq);

        let initial_frame =
            HdlcFrame::from_bytes(&initial_request).expect("failed to decode initial frame");
        assert!(AarqApdu::from_bytes(&initial_frame.information).is_ok());

        let initial_response = server
            .handle_request(&initial_request)
            .expect("server failed to issue challenge");
        let issued_challenge = parse_aare(&initial_response)
            .responding_authentication_value
            .expect("expected challenge");

        let expected_response =
            lls_authenticate(b"password", &issued_challenge).expect("failed to compute mac");

        let follow_up_request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: Some(b"LLS".to_vec()),
                calling_authentication_value: Some(expected_response.clone()),
                user_information: b"info".to_vec(),
            },
        );

        let follow_up_response = server
            .handle_request(&follow_up_request)
            .expect("server failed to validate response");
        let aare = parse_aare(&follow_up_response);

        assert_eq!(aare.result, 0);
        assert!(aare.responding_authentication_value.is_none());
        assert!(server.lls_challenges.get(&association_address).is_none());
    }
}
