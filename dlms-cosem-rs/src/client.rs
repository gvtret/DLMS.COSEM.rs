use crate::acse::{AareApdu, AarqApdu};
use crate::error::DlmsError;
use crate::hdlc::HdlcFrame;
use crate::security::{hls_decrypt, hls_encrypt, lls_authenticate, SecurityError};
use crate::transport::Transport;
use crate::xdlms::{
    ActionRequest, ActionResponse, GetRequest, GetResponse, InitiateRequest, InitiateResponse,
    SetRequest, SetResponse,
};
use std::vec::Vec;

#[derive(Debug)]
pub enum ClientError<E> {
    AcseError,
    TransportError(E),
    DlmsError(DlmsError),
    SecurityError(SecurityError),
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
        }
    }

    pub fn associate(&mut self) -> Result<AareApdu, ClientError<T::Error>> {
        let initiate_request = InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_quality_of_service: None,
            proposed_dlms_version_number: 6,
            proposed_conformance: crate::xdlms::Conformance { value: 0x0010_0000 },
            client_max_receive_pdu_size: 0x0400,
        };
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
        let _ = InitiateResponse::from_user_information(&aare.user_information)?;

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
            let _ = InitiateResponse::from_user_information(&aare.user_information)?;
            return Ok(aare);
        }

        Ok(aare)
    }

    pub fn send_get_request(
        &mut self,
        request: GetRequest,
    ) -> Result<GetResponse, ClientError<T::Error>> {
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
}
