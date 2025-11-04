use crate::acse::{AarqApdu, AareApdu};
use crate::hdlc::{HdlcFrame, HdlcFrameError};
use crate::transport::Transport;
use crate::xdlms::{GetRequest, GetResponse};
use heapless::Vec;

#[derive(Debug)]
pub enum ClientError<E> {
    HdlcError(HdlcFrameError),
    AcseError,
    TransportError(E),
}

impl<E> From<HdlcFrameError> for ClientError<E> {
    fn from(e: HdlcFrameError) -> Self {
        ClientError::HdlcError(e)
    }
}

use crate::security::lls_authenticate;

use crate::security::{hls_decrypt, hls_encrypt};

pub struct Client<T: Transport> {
    address: u16,
    transport: T,
    password: Option<Vec<u8, 32>>,
    key: Option<Vec<u8, 16>>,
}

impl<T: Transport> Client<T> {
    pub fn new(
        address: u16,
        transport: T,
        password: Option<Vec<u8, 32>>,
        key: Option<Vec<u8, 16>>,
    ) -> Self {
        Client {
            address,
            transport,
            password,
            key,
        }
    }

    pub fn associate(&mut self) -> Result<AareApdu, ClientError<T::Error>> {
        let mut aarq = AarqApdu {
            application_context_name: Vec::new(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::new(),
        };
        aarq.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();
        if self.password.is_some() {
            aarq.mechanism_name = Some(Vec::from_slice(b"LLS").unwrap());
        }

        let request_bytes = aarq.to_bytes();

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_bytes,
        };

        let hdlc_bytes = hdlc_frame.to_bytes();

        let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;

        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;

        let aare = AareApdu::from_bytes(&response_frame.information)
            .map_err(|_| ClientError::AcseError)?
            .1;

        if let (Some(password), Some(challenge)) = (
            &self.password,
            aare.responding_authentication_value.as_ref(),
        ) {
            let response = lls_authenticate(password, challenge);
            let mut aarq = AarqApdu {
                application_context_name: Vec::new(),
                sender_acse_requirements: 0,
                mechanism_name: Some(Vec::from_slice(b"LLS").unwrap()),
                calling_authentication_value: Some(response),
                user_information: Vec::new(),
            };
            aarq.application_context_name
                .extend_from_slice(b"LN_WITH_NO_CIPHERING")
                .unwrap();

            let request_bytes = aarq.to_bytes();
            let hdlc_frame = HdlcFrame {
                address: self.address,
                control: 0,
                information: request_bytes,
            };
            let hdlc_bytes = hdlc_frame.to_bytes();
            let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;
            let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;
            let aare = AareApdu::from_bytes(&response_frame.information)
                .map_err(|_| ClientError::AcseError)?
                .1;
            return Ok(aare);
        }

        Ok(aare)
    }

    pub fn send_request(
        &mut self,
        request: GetRequest,
    ) -> Result<GetResponse, ClientError<T::Error>> {
        let request_bytes = request.to_bytes();
        let mut request_vec = Vec::new();
        request_vec.extend_from_slice(&request_bytes).unwrap();

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_vec,
        };

        let hdlc_bytes = hdlc_frame.to_bytes();

        let response_hdlc_bytes = self.send_and_receive(&hdlc_bytes)?;

        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;

        let response = GetResponse::from_bytes(&response_frame.information);

        Ok(response)
    }

    fn send_and_receive(
        &mut self,
        data: &[u8],
    ) -> Result<Vec<u8, 2048>, ClientError<T::Error>> {
        if let Some(key) = &self.key {
            let encrypted_data = hls_encrypt(data, key);
            self.transport
                .send(&encrypted_data)
                .map_err(ClientError::TransportError)?;
            let encrypted_response = self
                .transport
                .receive()
                .map_err(ClientError::TransportError)?;
            let decrypted_response = hls_decrypt(&encrypted_response, key);
            Ok(decrypted_response)
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
