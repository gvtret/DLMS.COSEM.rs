use crate::acse::{AarqApdu, AareApdu};
use crate::hdlc::{HdlcFrame, HdlcFrameError};
use crate::xdlms::{GetRequest, GetResponse};
use crate::MAX_PDU_SIZE;
use heapless::Vec;

#[derive(Debug)]
pub enum ClientError {
    HdlcError(HdlcFrameError),
    AcseError,
}

impl From<HdlcFrameError> for ClientError {
    fn from(e: HdlcFrameError) -> Self {
        ClientError::HdlcError(e)
    }
}

pub struct Client {
    address: u16,
}

impl Client {
    pub fn new(address: u16) -> Self {
        Client { address }
    }

    pub fn associate(&self) -> Result<AareApdu, ClientError> {
        let mut aarq = AarqApdu {
            application_context_name: Vec::new(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::new(),
        };
        aarq.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();

        let request_bytes = aarq.to_bytes();

        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_bytes,
        };

        let _hdlc_bytes = hdlc_frame.to_bytes();

        // Dummy AARE response for testing
        let mut aare = AareApdu {
            application_context_name: Vec::new(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: None,
            user_information: Vec::new(),
        };
        aare.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();
        let response_bytes = aare.to_bytes();
        let response_hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: response_bytes,
        };
        let response_hdlc_bytes = response_hdlc_frame.to_bytes();


        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;

        let aare = AareApdu::from_bytes(&response_frame.information)
            .map_err(|_| ClientError::AcseError)?
            .1;

        Ok(aare)
    }

    pub fn send_request(&self, request: GetRequest) -> Result<GetResponse, ClientError> {
        let request_bytes = request.to_bytes();
        let mut request_vec = Vec::new();
        request_vec.extend_from_slice(&request_bytes).unwrap();


        let hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: request_vec,
        };

        let hdlc_bytes = hdlc_frame.to_bytes();

        // This is still a placeholder for actual transport logic
        let response_hdlc_bytes = hdlc_bytes;

        let response_frame = HdlcFrame::from_bytes(&response_hdlc_bytes)?;

        // Deserialization of GetResponse is not yet implemented
        let response = GetResponse::Normal(crate::xdlms::GetResponseNormal {
            invoke_id_and_priority: 0,
            result: crate::xdlms::GetDataResult::Data(crate::types::Data::NullData),
        });

        Ok(response)
    }
}
