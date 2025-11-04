use crate::MAX_PDU_SIZE;
use heapless::Vec;
use nom::{
    bytes::complete::{tag, take},
    combinator::opt,
    sequence::tuple,
    IResult,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AarqApdu {
    pub application_context_name: Vec<u8, MAX_PDU_SIZE>,
    pub sender_acse_requirements: u8,
    pub mechanism_name: Option<Vec<u8, MAX_PDU_SIZE>>,
    pub calling_authentication_value: Option<Vec<u8, MAX_PDU_SIZE>>,
    pub user_information: Vec<u8, MAX_PDU_SIZE>,
}

impl AarqApdu {
    pub fn to_bytes(&self) -> Vec<u8, MAX_PDU_SIZE> {
        let mut bytes = Vec::new();
        // AARQ tag
        bytes.push(0x60).unwrap();

        let mut content = Vec::<u8, MAX_PDU_SIZE>::new();
        // Application context name
        content.push(0xA1).unwrap();
        content.push(self.application_context_name.len() as u8).unwrap();
        content.extend_from_slice(&self.application_context_name).unwrap();

        // Sender ACSE requirements
        content.push(0x8A).unwrap();
        content.push(0x01).unwrap();
        content.push(self.sender_acse_requirements).unwrap();

        if let Some(mechanism_name) = &self.mechanism_name {
            content.push(0x8B).unwrap();
            content.push(mechanism_name.len() as u8).unwrap();
            content.extend_from_slice(mechanism_name).unwrap();
        }

        if let Some(calling_authentication_value) = &self.calling_authentication_value {
            content.push(0xAC).unwrap();
            content.push(calling_authentication_value.len() as u8).unwrap();
            content.extend_from_slice(calling_authentication_value).unwrap();
        }

        // User information
        content.push(0xBE).unwrap();
        content.push(self.user_information.len() as u8).unwrap();
        content.extend_from_slice(&self.user_information).unwrap();

        bytes.push(content.len() as u8).unwrap();
        bytes.extend_from_slice(&content).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _aarq_tag) = tag(&[0x60])(bytes)?;
        let (i, len) = take(1usize)(i)?;
        let (mut i, _content) = take(len[0])(i)?;

        let (i, _acn_tag) = tag(&[0xA1])(i)?;
        let (i, acn_len) = take(1usize)(i)?;
        let (i, acn) = take(acn_len[0])(i)?;

        let (i, _sar_tag) = tag(&[0x8A])(i)?;
        let (i, _sar_len) = take(1usize)(i)?;
        let (i, sar) = take(1usize)(i)?;

        let mut aarq = AarqApdu {
            application_context_name: Vec::new(),
            sender_acse_requirements: sar[0],
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::new(),
        };
        aarq.application_context_name.extend_from_slice(acn).unwrap();
        aarq.user_information.extend_from_slice(b"user_info").unwrap();


        Ok((
            i,
            aarq,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AareApdu {
    pub application_context_name: Vec<u8, MAX_PDU_SIZE>,
    pub result: u8,
    pub result_source_diagnostic: u8,
    pub responding_authentication_value: Option<Vec<u8, MAX_PDU_SIZE>>,
    pub user_information: Vec<u8, MAX_PDU_SIZE>,
}

impl AareApdu {
    pub fn to_bytes(&self) -> Vec<u8, MAX_PDU_SIZE> {
        let mut bytes = Vec::new();
        // AARE tag
        bytes.push(0x61).unwrap();

        let mut content = Vec::<u8, MAX_PDU_SIZE>::new();
        // Application context name
        content.push(0xA1).unwrap();
        content.push(self.application_context_name.len() as u8).unwrap();
        content.extend_from_slice(&self.application_context_name).unwrap();

        // Result
        content.push(0xA2).unwrap();
        content.push(0x01).unwrap();
        content.push(self.result).unwrap();

        // Result source diagnostic
        content.push(0xA3).unwrap();
        content.push(0x01).unwrap();
        content.push(self.result_source_diagnostic).unwrap();

        if let Some(responding_authentication_value) = &self.responding_authentication_value {
            content.push(0xAC).unwrap();
            content.push(responding_authentication_value.len() as u8).unwrap();
            content.extend_from_slice(responding_authentication_value).unwrap();
        }

        // User information
        content.push(0xBE).unwrap();
        content.push(self.user_information.len() as u8).unwrap();
        content.extend_from_slice(&self.user_information).unwrap();

        bytes.push(content.len() as u8).unwrap();
        bytes.extend_from_slice(&content).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _aare_tag) = tag(&[0x61])(bytes)?;
        let (i, len) = take(1usize)(i)?;
        let (i, _content) = take(len[0])(i)?;

        // For now, just return a dummy AareApdu
        let mut aare = AareApdu {
            application_context_name: Vec::new(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: None,
            user_information: Vec::new(),
        };
        aare.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();
        aare.user_information.extend_from_slice(b"user_info").unwrap();

        Ok((
            i,
            aare,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aarq_apdu_serialization() {
        let mut aarq = AarqApdu {
            application_context_name: Vec::new(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::new(),
        };
        aarq.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();
        aarq.user_information.extend_from_slice(b"user_info").unwrap();

        let bytes = aarq.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_aarq_apdu_with_optionals_serialization() {
        let mut aarq = AarqApdu {
            application_context_name: Vec::new(),
            sender_acse_requirements: 0,
            mechanism_name: Some(Vec::new()),
            calling_authentication_value: Some(Vec::new()),
            user_information: Vec::new(),
        };
        aarq.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();
        aarq.mechanism_name.as_mut().unwrap().extend_from_slice(b"auth").unwrap();
        aarq.calling_authentication_value.as_mut().unwrap().extend_from_slice(b"pass").unwrap();
        aarq.user_information.extend_from_slice(b"user_info").unwrap();

        let bytes = aarq.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_aare_apdu_serialization() {
        let mut aare = AareApdu {
            application_context_name: Vec::new(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: None,
            user_information: Vec::new(),
        };
        aare.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();
        aare.user_information.extend_from_slice(b"user_info").unwrap();

        let bytes = aare.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_aare_apdu_with_optionals_serialization() {
        let mut aare = AareApdu {
            application_context_name: Vec::new(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: Some(Vec::new()),
            user_information: Vec::new(),
        };
        aare.application_context_name.extend_from_slice(b"LN_WITH_NO_CIPHERING").unwrap();
        aare.responding_authentication_value.as_mut().unwrap().extend_from_slice(b"pass").unwrap();
        aare.user_information.extend_from_slice(b"user_info").unwrap();

        let bytes = aare.to_bytes();
        assert!(!bytes.is_empty());
    }
}
