use crate::acse::{AareApdu, AarqApdu, ArlreApdu, ArlrqApdu};
use crate::cosem_object::CosemObject;
use crate::error::DlmsError;
use crate::hdlc::{HdlcFrame, HdlcFrameError};
use crate::security::lls_authenticate;
use crate::security::{hls_decrypt, hls_encrypt, SecurityError};
use crate::transport::Transport;
use crate::xdlms::{
    ActionRequest, ActionResponse, ActionResponseNormal, ActionResult, AssociationParameters,
    DataAccessResult, GetDataResult, GetRequest, GetResponse, GetResponseNormal, InitiateRequest,
    InitiateResponse, SetRequest, SetResponse, SetResponseNormal,
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
    association_parameters: AssociationParameters,
    active_associations: BTreeMap<u16, AssociationContext>,
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
            association_parameters: AssociationParameters::default(),
            active_associations: BTreeMap::new(),
        }
    }

    pub fn set_association_parameters(&mut self, params: AssociationParameters) {
        self.association_parameters = params;
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

        if request_frame.information.len()
            > self.association_parameters.max_receive_pdu_size as usize
        {
            return Err(ServerError::DlmsError(DlmsError::Xdlms));
        }

        let mut pending_client_limit = None;
        let response_bytes = if let Ok((_, aarq_apdu)) =
            AarqApdu::from_bytes(&request_frame.information)
        {
            let initiate_request =
                InitiateRequest::from_user_information(&aarq_apdu.user_information)?;
            pending_client_limit = Some(initiate_request.client_max_receive_pdu_size);
            let negotiation = self.negotiate_initiate_response(&initiate_request);
            let mut aare = AareApdu {
                application_context_name: aarq_apdu.application_context_name.clone(),
                result: 0,
                result_source_diagnostic: 0,
                responding_authentication_value: None,
                user_information: Vec::new(),
            };
            let mut negotiation_succeeded = false;

            match negotiation {
                Ok(initiate_response) => {
                    aare.user_information = initiate_response.to_user_information()?;
                    negotiation_succeeded = true;
                }
                Err(err) => {
                    aare.result = 1;
                    aare.result_source_diagnostic = err.diagnostic();
                    aare.user_information = self
                        .association_parameters
                        .to_initiate_response(self.association_parameters.conformance.clone())
                        .to_user_information()?;
                }
            }

            let association_address = request_frame.address;
            if aare.result != 0 {
                self.active_associations.remove(&association_address);
                return Ok(HdlcFrame {
                    address: self.address,
                    control: 0,
                    information: aare.to_bytes()?,
                }
                .to_bytes()?);
            }
            if let (Some(password), Some(mechanism_name)) =
                (&self.password, aarq_apdu.mechanism_name.as_ref())
            {
                let association_address = request_frame.address;
                if mechanism_name == b"LLS" {
                    if let Some(auth_value) = aarq_apdu.calling_authentication_value.clone() {
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
                        self.active_associations.remove(&association_address);
                    }
                }
            }
            if aare.responding_authentication_value.is_none() && negotiation_succeeded {
                self.active_associations.insert(
                    association_address,
                    AssociationContext {
                        client_max_receive_pdu_size: initiate_request.client_max_receive_pdu_size,
                    },
                );
            }
            aare.to_bytes()?
        } else if let Ok((_, release_req)) = ArlrqApdu::from_bytes(&request_frame.information) {
            self.active_associations.remove(&request_frame.address);
            self.lls_challenges.remove(&request_frame.address);

            let reason = release_req.reason.unwrap_or(0);
            let rlre = ArlreApdu {
                reason: Some(reason),
                user_information: release_req.user_information,
            };

            rlre.to_bytes()?
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

        let client_limit = pending_client_limit
            .or_else(|| {
                self.active_associations
                    .get(&request_frame.address)
                    .map(|ctx| ctx.client_max_receive_pdu_size)
            })
            .unwrap_or(self.association_parameters.max_receive_pdu_size)
            as usize;

        if response_hdlc_frame.information.len() > client_limit {
            return Err(ServerError::DlmsError(DlmsError::Xdlms));
        }

        Ok(response_hdlc_frame.to_bytes()?)
    }

    fn negotiate_initiate_response(
        &self,
        request: &InitiateRequest,
    ) -> Result<InitiateResponse, InitiateValidationError> {
        if !request.response_allowed {
            return Err(InitiateValidationError::ResponseNotAllowed);
        }

        if request.proposed_dlms_version_number != self.association_parameters.dlms_version {
            return Err(InitiateValidationError::DlmsVersionMismatch);
        }

        if request.client_max_receive_pdu_size == 0 {
            return Err(InitiateValidationError::InvalidClientPduSize);
        }

        let negotiated_conformance = self
            .association_parameters
            .conformance
            .intersection(&request.proposed_conformance);

        if negotiated_conformance.is_empty() {
            return Err(InitiateValidationError::NoCommonConformance);
        }

        let mut response = self
            .association_parameters
            .to_initiate_response(negotiated_conformance);

        if response.negotiated_quality_of_service.is_none() {
            response.negotiated_quality_of_service = request.proposed_quality_of_service;
        }

        Ok(response)
    }
}

#[derive(Debug, Clone)]
struct AssociationContext {
    client_max_receive_pdu_size: u16,
}

#[derive(Debug, Clone, Copy)]
enum InitiateValidationError {
    ResponseNotAllowed,
    DlmsVersionMismatch,
    InvalidClientPduSize,
    NoCommonConformance,
}

impl InitiateValidationError {
    fn diagnostic(self) -> u8 {
        match self {
            InitiateValidationError::ResponseNotAllowed => 1,
            InitiateValidationError::DlmsVersionMismatch => 2,
            InitiateValidationError::InvalidClientPduSize => 3,
            InitiateValidationError::NoCommonConformance => 4,
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;
    use crate::xdlms::{AssociationParameters, Conformance, InitiateRequest, InitiateResponse};

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

    fn parse_rlre(bytes: &[u8]) -> ArlreApdu {
        let frame = HdlcFrame::from_bytes(bytes).expect("failed to decode frame");
        ArlreApdu::from_bytes(&frame.information)
            .expect("failed to decode rlre")
            .1
    }

    fn default_initiate_request() -> InitiateRequest {
        AssociationParameters::default().to_initiate_request()
    }

    #[test]
    fn lls_challenge_is_issued_and_persisted() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let user_information = default_initiate_request()
            .to_user_information()
            .expect("failed to encode initiate request");
        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: user_information.clone(),
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

        let initiate_response = InitiateResponse::from_user_information(&aare.user_information)
            .expect("expected initiate response");
        assert_eq!(initiate_response.negotiated_dlms_version_number, 6);
        assert_eq!(initiate_response.server_max_receive_pdu_size, 0x0400);
        assert_eq!(initiate_response.vaa_name, 0x0007);
        assert_eq!(initiate_response.negotiated_conformance.value, 0x0010_0000);

        assert_eq!(challenge.len(), 16);
        let stored = server
            .lls_challenges
            .get(&0x0002)
            .expect("challenge should be stored");
        assert_eq!(stored.as_slice(), challenge.as_slice());
        assert!(!server.active_associations.contains_key(&0x0002));
    }

    #[test]
    fn lls_challenge_response_validates_and_clears() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let association_address = 0x0003;
        let user_information = default_initiate_request()
            .to_user_information()
            .expect("failed to encode initiate request");
        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: user_information.clone(),
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
                user_information: user_information.clone(),
            },
        );

        let follow_up_response = server
            .handle_request(&follow_up_request)
            .expect("server failed to validate response");
        let aare = parse_aare(&follow_up_response);

        assert_eq!(aare.result, 0);
        assert!(aare.responding_authentication_value.is_none());
        let initiate_response = InitiateResponse::from_user_information(&aare.user_information)
            .expect("expected initiate response");
        assert_eq!(initiate_response.negotiated_dlms_version_number, 6);
        assert_eq!(initiate_response.server_max_receive_pdu_size, 0x0400);
        assert_eq!(initiate_response.negotiated_conformance.value, 0x0010_0000);
        assert!(!server.lls_challenges.contains_key(&association_address));
        let context = server
            .active_associations
            .get(&association_address)
            .expect("expected active association");
        assert_eq!(
            context.client_max_receive_pdu_size,
            default_initiate_request().client_max_receive_pdu_size
        );
    }

    #[test]
    fn successful_initiate_registers_active_association() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0005;

        let request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: None,
                calling_authentication_value: None,
                user_information: default_initiate_request()
                    .to_user_information()
                    .expect("failed to encode initiate request"),
            },
        );

        let response = server
            .handle_request(&request)
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response);
        assert_eq!(aare.result, 0);
        let context = server
            .active_associations
            .get(&association_address)
            .expect("expected active association");
        assert_eq!(
            context.client_max_receive_pdu_size,
            default_initiate_request().client_max_receive_pdu_size
        );
    }

    #[test]
    fn initiate_request_with_incompatible_version_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.proposed_dlms_version_number = 7;

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 2);
    }

    #[test]
    fn failed_initiate_clears_existing_association() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0006;

        let successful_request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: None,
                calling_authentication_value: None,
                user_information: default_initiate_request()
                    .to_user_information()
                    .expect("failed to encode initiate request"),
            },
        );

        let response = server
            .handle_request(&successful_request)
            .expect("server failed to handle aarq");
        assert_eq!(parse_aare(&response).result, 0);
        assert!(server
            .active_associations
            .contains_key(&association_address));

        let mut failing_request = default_initiate_request();
        failing_request.response_allowed = false;
        let response_bytes = server
            .handle_request(&build_hdlc_request(
                association_address,
                AarqApdu {
                    application_context_name: b"CTX".to_vec(),
                    sender_acse_requirements: 0,
                    mechanism_name: None,
                    calling_authentication_value: None,
                    user_information: failing_request
                        .to_user_information()
                        .expect("failed to encode initiate request"),
                },
            ))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert!(!server
            .active_associations
            .contains_key(&association_address));
    }

    #[test]
    fn initiate_request_without_common_conformance_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.proposed_conformance = Conformance { value: 0 };

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 4);
    }

    #[test]
    fn initiate_request_without_response_allowed_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.response_allowed = false;

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 1);
    }

    #[test]
    fn initiate_request_with_zero_client_pdu_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.client_max_receive_pdu_size = 0;

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 3);
        assert!(!server.active_associations.contains_key(&0x0002));
    }

    #[test]
    fn lls_challenge_response_with_wrong_mac_fails() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let association_address = 0x0004;
        let user_information = default_initiate_request()
            .to_user_information()
            .expect("failed to encode initiate request");
        let initial_request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: Some(b"LLS".to_vec()),
                calling_authentication_value: None,
                user_information: user_information.clone(),
            },
        );

        let initial_response = server
            .handle_request(&initial_request)
            .expect("server failed to issue challenge");
        let issued_challenge = parse_aare(&initial_response)
            .responding_authentication_value
            .expect("expected challenge");

        let mut wrong_response =
            lls_authenticate(b"password", &issued_challenge).expect("failed to compute mac");
        wrong_response[0] ^= 0xFF;

        let follow_up_response = server
            .handle_request(&build_hdlc_request(
                association_address,
                AarqApdu {
                    application_context_name: b"CTX".to_vec(),
                    sender_acse_requirements: 0,
                    mechanism_name: Some(b"LLS".to_vec()),
                    calling_authentication_value: Some(wrong_response),
                    user_information,
                },
            ))
            .expect("server failed to process response");

        let aare = parse_aare(&follow_up_response);

        assert_eq!(aare.result, 1);
        assert!(aare.responding_authentication_value.is_none());
        let initiate_response = InitiateResponse::from_user_information(&aare.user_information)
            .expect("expected initiate response");
        assert_eq!(initiate_response.vaa_name, 0x0007);
        assert!(!server
            .lls_challenges
            .get(&association_address)
            .expect("challenge should remain for retry")
            .is_empty());
    }

    #[test]
    fn release_request_clears_active_association() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: default_initiate_request()
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0001, aarq))
            .expect("failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 0);
        assert!(server.active_associations.contains_key(&0x0001));

        let release_req = ArlrqApdu {
            reason: Some(0),
            user_information: None,
        };

        let frame = HdlcFrame {
            address: 0x0001,
            control: 0,
            information: release_req
                .to_bytes()
                .expect("failed to encode release request"),
        };

        let release_frame = frame.to_bytes().expect("failed to encode frame");
        let response_bytes = server
            .handle_request(&release_frame)
            .expect("failed to handle release");
        let rlre = parse_rlre(&response_bytes);
        assert_eq!(rlre.reason, Some(0));
        assert!(server.active_associations.is_empty());
    }

    #[test]
    fn release_request_clears_pending_lls_challenge() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: default_initiate_request()
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0001, aarq))
            .expect("failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert!(aare.responding_authentication_value.is_some());
        assert!(server.lls_challenges.contains_key(&0x0001));

        let release_req = ArlrqApdu {
            reason: None,
            user_information: None,
        };

        let frame = HdlcFrame {
            address: 0x0001,
            control: 0,
            information: release_req
                .to_bytes()
                .expect("failed to encode release request"),
        };

        let release_frame = frame.to_bytes().expect("failed to encode frame");
        let response_bytes = server
            .handle_request(&release_frame)
            .expect("failed to handle release");
        let rlre = parse_rlre(&response_bytes);
        assert_eq!(rlre.reason, Some(0));
        assert!(!server.lls_challenges.contains_key(&0x0001));
    }
}
