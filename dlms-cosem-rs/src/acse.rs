use crate::error::DlmsError;
use nom::bytes::complete::{tag, take};
use nom::{IResult, Parser};
use std::vec::Vec;

fn parse_optional(input: &[u8], tag_byte: u8) -> IResult<&[u8], Option<&[u8]>> {
    if let Some(&first) = input.first() {
        if first == tag_byte {
            let (input, _) = tag(&[tag_byte][..]).parse(input)?;
            let (input, len_bytes) = take(1usize)(input)?;
            let length = len_bytes[0] as usize;
            let (input, value) = take(length)(input)?;
            Ok((input, Some(value)))
        } else {
            Ok((input, None))
        }
    } else {
        Ok((input, None))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AarqApdu {
    pub application_context_name: Vec<u8>,
    pub sender_acse_requirements: u8,
    pub mechanism_name: Option<Vec<u8>>,
    pub calling_authentication_value: Option<Vec<u8>>,
    pub user_information: Vec<u8>,
}

impl AarqApdu {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x60);

        let mut content = Vec::new();
        content.push(0xA1);
        content.push(self.application_context_name.len() as u8);
        content.extend_from_slice(&self.application_context_name);
        content.push(0x8A);
        content.push(0x01);
        content.push(self.sender_acse_requirements);

        if let Some(mechanism_name) = &self.mechanism_name {
            content.push(0x8B);
            content.push(mechanism_name.len() as u8);
            content.extend_from_slice(mechanism_name);
        }

        if let Some(calling_authentication_value) = &self.calling_authentication_value {
            content.push(0xAC);
            content.push(calling_authentication_value.len() as u8);
            content.extend_from_slice(calling_authentication_value);
        }

        content.push(0xBE);
        content.push(self.user_information.len() as u8);
        content.extend_from_slice(&self.user_information);

        bytes.push(content.len() as u8);
        bytes.extend_from_slice(&content);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _aarq_tag) = tag(&[0x60u8][..]).parse(bytes)?;
        let (i, len) = take(1usize)(i)?;
        let (i, content) = take(len[0] as usize)(i)?;
        let (content, _acn_tag) = tag(&[0xA1u8][..]).parse(content)?;
        let (content, acn_len) = take(1usize)(content)?;
        let (content, acn) = take(acn_len[0] as usize)(content)?;
        let (content, _sar_tag) = tag(&[0x8Au8][..]).parse(content)?;
        let (content, _sar_len) = take(1usize)(content)?;
        let (content, sar) = take(1usize)(content)?;
        let (content, mn) = parse_optional(content, 0x8B)?;
        let (content, cav) = parse_optional(content, 0xAC)?;
        let (content, _ui_tag) = tag(&[0xBEu8][..]).parse(content)?;
        let (content, ui_len) = take(1usize)(content)?;
        let (_content, ui) = take(ui_len[0] as usize)(content)?;

        let mut aarq = AarqApdu {
            application_context_name: acn.to_vec(),
            sender_acse_requirements: sar[0],
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: ui.to_vec(),
        };

        if let Some(mn_val) = mn {
            aarq.mechanism_name = Some(mn_val.to_vec());
        }

        if let Some(cav_val) = cav {
            aarq.calling_authentication_value = Some(cav_val.to_vec());
        }

        Ok((i, aarq))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AareApdu {
    pub application_context_name: Vec<u8>,
    pub result: u8,
    pub result_source_diagnostic: u8,
    pub responding_authentication_value: Option<Vec<u8>>,
    pub user_information: Vec<u8>,
}

impl AareApdu {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x61);

        let mut content = Vec::new();
        content.push(0xA1);
        content.push(self.application_context_name.len() as u8);
        content.extend_from_slice(&self.application_context_name);
        content.push(0xA2);
        content.push(0x01);
        content.push(self.result);
        content.push(0xA3);
        content.push(0x01);
        content.push(self.result_source_diagnostic);

        if let Some(responding_authentication_value) = &self.responding_authentication_value {
            content.push(0xAC);
            content.push(responding_authentication_value.len() as u8);
            content.extend_from_slice(responding_authentication_value);
        }

        content.push(0xBE);
        content.push(self.user_information.len() as u8);
        content.extend_from_slice(&self.user_information);

        bytes.push(content.len() as u8);
        bytes.extend_from_slice(&content);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _aare_tag) = tag(&[0x61u8][..]).parse(bytes)?;
        let (i, len) = take(1usize)(i)?;
        let (i, content) = take(len[0] as usize)(i)?;
        let (content, _acn_tag) = tag(&[0xA1u8][..]).parse(content)?;
        let (content, acn_len) = take(1usize)(content)?;
        let (content, acn) = take(acn_len[0] as usize)(content)?;
        let (content, _res_tag) = tag(&[0xA2u8][..]).parse(content)?;
        let (content, _res_len) = take(1usize)(content)?;
        let (content, res) = take(1usize)(content)?;
        let (content, _rsd_tag) = tag(&[0xA3u8][..]).parse(content)?;
        let (content, _rsd_len) = take(1usize)(content)?;
        let (content, rsd) = take(1usize)(content)?;
        let (content, rav) = parse_optional(content, 0xAC)?;
        let (content, _ui_tag) = tag(&[0xBEu8][..]).parse(content)?;
        let (content, ui_len) = take(1usize)(content)?;
        let (_content, ui) = take(ui_len[0] as usize)(content)?;

        let mut aare = AareApdu {
            application_context_name: acn.to_vec(),
            result: res[0],
            result_source_diagnostic: rsd[0],
            responding_authentication_value: None,
            user_information: ui.to_vec(),
        };

        if let Some(rav_val) = rav {
            aare.responding_authentication_value = Some(rav_val.to_vec());
        }

        Ok((i, aare))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_aarq_apdu_serialization_deserialization() {
        let aarq = AarqApdu {
            application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: b"user_info".to_vec(),
        };

        let bytes = aarq.to_bytes().unwrap();
        let aarq2 = AarqApdu::from_bytes(&bytes).unwrap().1;

        assert_eq!(aarq, aarq2);
    }

    #[test]
    fn test_aarq_apdu_with_optionals_serialization() {
        let aarq = AarqApdu {
            application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"auth".to_vec()),
            calling_authentication_value: Some(b"pass".to_vec()),
            user_information: b"user_info".to_vec(),
        };

        let bytes = aarq.to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_aare_apdu_serialization_deserialization() {
        let aare = AareApdu {
            application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: None,
            user_information: b"user_info".to_vec(),
        };

        let bytes = aare.to_bytes().unwrap();
        let aare2 = AareApdu::from_bytes(&bytes).unwrap().1;
        assert_eq!(aare, aare2);
    }

    #[test]
    fn test_aare_apdu_with_optionals_serialization() {
        let aare = AareApdu {
            application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: Some(b"pass".to_vec()),
            user_information: b"user_info".to_vec(),
        };

        let bytes = aare.to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }
}
