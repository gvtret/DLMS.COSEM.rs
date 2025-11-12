use crate::acse::{AareApdu, AarqApdu, ArlreApdu, ArlrqApdu};
use crate::error::DlmsError;
use crate::hdlc::HdlcFrame;
use crate::security::{hls_decrypt, hls_encrypt, lls_authenticate, SecurityError};
use crate::transport::Transport;
use crate::xdlms::{
    ActionRequest, ActionResponse, AssociationParameters, Conformance, GetRequest, GetResponse,
    InitiateResponse, SetRequest, SetResponse,
};
use std::vec::Vec;

#[derive(Debug)]
pub enum ClientError<E> {
    AcseError,
    TransportError(E),
    DlmsError(DlmsError),
    SecurityError(SecurityError),
    AssociationRejected { result: u8, diagnostic: u8 },
    NegotiationFailed(&'static str),
    ReleaseRejected(u8),
    AssociationNotEstablished,
}

impl<E> From<DlmsError> for ClientError<E> {
    fn from(e: DlmsError) -> Self {
        ClientError::DlmsError(e)
    }
}

impl<E> From<SecurityError> for ClientError<E> {
    fn from(e: SecurityError) -> Self {
        ClientError::SecurityError(e)
    }
}

pub struct Client<T: Transport> {
    address: u16,
    transport: T,
    password: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    association_parameters: AssociationParameters,
    negotiated_parameters: Option<NegotiatedAssociationParameters>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedAssociationParameters {
    pub negotiated_quality_of_service: Option<u8>,
    pub negotiated_dlms_version_number: u8,
    pub negotiated_conformance: Conformance,
    pub server_max_receive_pdu_size: u16,
}

impl<T: Transport> Client<T> {
    pub fn new(
        address: u16,
        transport: T,
        password: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
    ) -> Self {
        Client {
            address,
            transport,
            password,
            key,
            association_parameters: AssociationParameters::default(),
            negotiated_parameters: None,
        }
    }

    pub fn set_association_parameters(&mut self, params: AssociationParameters) {
        self.association_parameters = params;
        self.negotiated_parameters = None;
    }

    pub fn association_parameters(&self) -> &AssociationParameters {
        &self.association_parameters
    }

    pub fn negotiated_parameters(&self) -> Option<&NegotiatedAssociationParameters> {
        self.negotiated_parameters.as_ref()
    }

    pub fn associate(&mut self) -> Result<AareApdu, ClientError<T::Error>> {
        let initiate_request = self.association_parameters.to_initiate_request();
        let user_information = initiate_request.to_user_information()?;

        let mut aarq = AarqApdu {
            application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: user_information.clone(),
        };
        if self.password.is_some() {
            aarq.mechanism_name = Some(b"LLS".to_vec());
        }

        let request_bytes = aarq.to_bytes()?;

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_bytes,
        };

        let hdlc_bytes = hdlc_frame.to_bytes()?;
        let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;
        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;
        let aare = AareApdu::from_bytes(&response_frame.information)
            .map_err(|_| ClientError::AcseError)?
            .1;
        let initiate_response = InitiateResponse::from_user_information(&aare.user_information)?;

        if aare.result != 0 {
            return Err(ClientError::AssociationRejected {
                result: aare.result,
                diagnostic: aare.result_source_diagnostic,
            });
        }

        let preview_negotiated = self.verify_initiate_response(&initiate_response)?;

        if let (Some(password), Some(challenge)) = (
            &self.password,
            aare.responding_authentication_value.as_ref(),
        ) {
            let response = lls_authenticate(password, challenge)?;
            let aarq = AarqApdu {
                application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: Some(b"LLS".to_vec()),
                calling_authentication_value: Some(response),
                user_information,
            };

            let request_bytes = aarq.to_bytes()?;
            let hdlc_frame = HdlcFrame {
                address: self.address,
                control: 0,
                information: request_bytes,
            };
            let hdlc_bytes = hdlc_frame.to_bytes()?;
            let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;
            let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;
            let aare = AareApdu::from_bytes(&response_frame.information)
                .map_err(|_| ClientError::AcseError)?
                .1;
            if aare.result != 0 {
                return Err(ClientError::AssociationRejected {
                    result: aare.result,
                    diagnostic: aare.result_source_diagnostic,
                });
            }
            let initiate_response =
                InitiateResponse::from_user_information(&aare.user_information)?;
            let negotiated = self.verify_initiate_response(&initiate_response)?;
            self.negotiated_parameters = Some(negotiated);
            return Ok(aare);
        }

        self.negotiated_parameters = Some(preview_negotiated);
        Ok(aare)
    }

    pub fn send_get_request(
        &mut self,
        request: GetRequest,
    ) -> Result<GetResponse, ClientError<T::Error>> {
        if self.negotiated_parameters.is_none() {
            return Err(ClientError::AssociationNotEstablished);
        }
        let request_bytes = request.to_bytes()?;

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_bytes,
        };

        let hdlc_bytes = hdlc_frame.to_bytes()?;
        let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;
        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;
        let response = GetResponse::from_bytes(&response_frame.information)?;

        Ok(response)
    }

    pub fn send_set_request(
        &mut self,
        request: SetRequest,
    ) -> Result<SetResponse, ClientError<T::Error>> {
        if self.negotiated_parameters.is_none() {
            return Err(ClientError::AssociationNotEstablished);
        }
        let request_bytes = request.to_bytes()?;

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_bytes,
        };

        let hdlc_bytes = hdlc_frame.to_bytes()?;
        let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;
        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;
        let response = SetResponse::from_bytes(&response_frame.information)?;

        Ok(response)
    }

    pub fn send_action_request(
        &mut self,
        request: ActionRequest,
    ) -> Result<ActionResponse, ClientError<T::Error>> {
        if self.negotiated_parameters.is_none() {
            return Err(ClientError::AssociationNotEstablished);
        }
        let request_bytes = request.to_bytes()?;

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_bytes,
        };

        let hdlc_bytes = hdlc_frame.to_bytes()?;
        let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;
        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;
        let response = ActionResponse::from_bytes(&response_frame.information)?;

        Ok(response)
    }

    pub fn release(&mut self) -> Result<(), ClientError<T::Error>> {
        if self.negotiated_parameters.is_none() {
            return Err(ClientError::AssociationNotEstablished);
        }
        let release_req = ArlrqApdu {
            reason: Some(0),
            user_information: None,
        };

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: release_req.to_bytes()?,
        };

        let hdlc_bytes = hdlc_frame.to_bytes()?;
        let response_bytes = self.send_and_receive(&hdlc_bytes)?;
        let response_frame = HdlcFrame::from_bytes(&response_bytes)?;
        let rlre = ArlreApdu::from_bytes(&response_frame.information)
            .map_err(|_| ClientError::AcseError)?
            .1;

        if let Some(reason) = rlre.reason {
            if reason != 0 {
                return Err(ClientError::ReleaseRejected(reason));
            }
        }

        self.negotiated_parameters = None;
        Ok(())
    }

    fn send_and_receive(&mut self, data: &[u8]) -> Result<Vec<u8>, ClientError<T::Error>> {
        if let Some(key) = &self.key {
            let encrypted_data = hls_encrypt(data, key)?;
            self.transport
                .send(&encrypted_data)
                .map_err(ClientError::TransportError)?;
            let encrypted_response = self
                .transport
                .receive()
                .map_err(ClientError::TransportError)?;
            Ok(hls_decrypt(&encrypted_response, key)?)
        } else {
            self.transport
                .send(data)
                .map_err(ClientError::TransportError)?;
            self.transport
                .receive()
                .map_err(ClientError::TransportError)
        }
    }

    fn verify_initiate_response(
        &self,
        response: &InitiateResponse,
    ) -> Result<NegotiatedAssociationParameters, ClientError<T::Error>> {
        if response.negotiated_dlms_version_number != self.association_parameters.dlms_version {
            return Err(ClientError::NegotiationFailed("DLMS version mismatch"));
        }

        if response.negotiated_conformance.is_empty() {
            return Err(ClientError::NegotiationFailed("no negotiated conformance"));
        }

        if !self
            .association_parameters
            .conformance
            .contains(&response.negotiated_conformance)
        {
            return Err(ClientError::NegotiationFailed(
                "unsupported negotiated conformance",
            ));
        }

        if let Some(expected_qos) = self.association_parameters.quality_of_service {
            match response.negotiated_quality_of_service {
                Some(qos) if qos == expected_qos => {}
                _ => {
                    return Err(ClientError::NegotiationFailed(
                        "quality of service mismatch",
                    ))
                }
            }
        }

        if response.server_max_receive_pdu_size == 0 {
            return Err(ClientError::NegotiationFailed("invalid server PDU size"));
        }

        Ok(NegotiatedAssociationParameters {
            negotiated_quality_of_service: response.negotiated_quality_of_service,
            negotiated_dlms_version_number: response.negotiated_dlms_version_number,
            negotiated_conformance: response.negotiated_conformance.clone(),
            server_max_receive_pdu_size: response.server_max_receive_pdu_size,
        })
    }
}
