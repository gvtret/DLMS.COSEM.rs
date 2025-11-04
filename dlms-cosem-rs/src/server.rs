use crate::acse::{AarqApdu, AareApdu};
use crate::hdlc::{HdlcFrame, HdlcFrameError};
use crate::transport::Transport;
use heapless::Vec;

#[derive(Debug)]
pub enum ServerError<E> {
    HdlcError(HdlcFrameError),
    AcseError,
    TransportError(E),
}

impl<E> From<HdlcFrameError> for ServerError<E> {
    fn from(e: HdlcFrameError) -> Self {
        ServerError::HdlcError(e)
    }
}

use crate::security::lls_authenticate;

use crate::security::{hls_decrypt, hls_encrypt};

pub struct Server<T: Transport> {
    address: u16,
    transport: T,
    password: Option<Vec<u8, 32>>,
    key: Option<Vec<u8, 16>>,
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
        }
    }

    pub fn run(&mut self) -> Result<(), ServerError<T::Error>> {
        loop {
            let request_bytes = self.transport.receive().map_err(ServerError::TransportError)?;
            let decrypted_request = if let Some(key) = &self.key {
                hls_decrypt(&request_bytes, key)
            } else {
                request_bytes
            };
            let response_bytes = self.handle_request(&decrypted_request)?;
            let encrypted_response = if let Some(key) = &self.key {
                hls_encrypt(&response_bytes, key)
            } else {
                response_bytes
            };
            self.transport
                .send(&encrypted_response)
                .map_err(ServerError::TransportError)?;
        }
    }

    fn handle_request(
        &self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8, 2048>, ServerError<T::Error>> {
        let request_frame = HdlcFrame::from_bytes(request_bytes)?;

        let aarq = AarqApdu::from_bytes(&request_frame.information)
            .map_err(|_| ServerError::AcseError)?
            .1;

        let mut aare = AareApdu {
            application_context_name: aarq.application_context_name.clone(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: None,
            user_information: Vec::new(),
        };

        if let (Some(password), Some(mechanism_name)) =
            (&self.password, aarq.mechanism_name.as_ref())
        {
            if mechanism_name == b"LLS" {
                if let Some(auth_value) = aarq.calling_authentication_value {
                    let challenge = aare
                        .responding_authentication_value
                        .as_ref()
                        .unwrap()
                        .as_slice();
                    let expected_response = lls_authenticate(password, challenge);
                    if auth_value == expected_response {
                        aare.result = 0; // success
                    } else {
                        aare.result = 1; // failure
                    }
                } else {
                    let challenge: Vec<u8, 32> = Vec::from_slice(b"challenge").unwrap();
                    aare.responding_authentication_value = Some(challenge);
                }
            }
        }

        aare.user_information
            .extend_from_slice(b"user_info")
            .unwrap();

        let response_bytes = aare.to_bytes();

        let response_hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: response_bytes,
        };

        Ok(response_hdlc_frame.to_bytes())
    }
}
