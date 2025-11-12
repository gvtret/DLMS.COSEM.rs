use crate::error::DlmsError;
use nom::bytes::complete::{tag, take};
use nom::error::ErrorKind;
use nom::number::complete::u8 as parse_u8;
use nom::{Err, IResult, Parser};
use std::vec::Vec;

fn parse_length(input: &[u8]) -> IResult<&[u8], usize> {
    let (input, first_byte) = parse_u8(input)?;
    if first_byte & 0x80 == 0 {
        Ok((input, first_byte as usize))
    } else {
        let num_bytes = (first_byte & 0x7F) as usize;
        if num_bytes == 0 {
            return Err(Err::Error(nom::error::Error::new(
                input,
                ErrorKind::LengthValue,
            )));
        }
        let (input, len_bytes) = take(num_bytes)(input)?;
        let mut length = 0usize;
        for &byte in len_bytes {
            length = (length << 8) | byte as usize;
        }
        Ok((input, length))
    }
}

fn encode_length(buf: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        buf.push(length as u8);
    } else {
        let mut bytes = Vec::new();
        let mut value = length;
        while value > 0 {
            bytes.push((value & 0xFF) as u8);
            value >>= 8;
        }
        bytes.reverse();
        buf.push(0x80 | (bytes.len() as u8));
        buf.extend_from_slice(&bytes);
    }
}

fn parse_optional(input: &[u8], tag_byte: u8) -> IResult<&[u8], Option<&[u8]>> {
    if let Some(&first) = input.first() {
        if first == tag_byte {
            let (input, _) = tag(&[tag_byte][..]).parse(input)?;
            let (input, length) = parse_length(input)?;
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
        encode_length(&mut content, self.application_context_name.len());
        content.extend_from_slice(&self.application_context_name);
        content.push(0x8A);
        encode_length(&mut content, 1);
        content.push(self.sender_acse_requirements);

        if let Some(mechanism_name) = &self.mechanism_name {
            content.push(0x8B);
            encode_length(&mut content, mechanism_name.len());
            content.extend_from_slice(mechanism_name);
        }

        if let Some(calling_authentication_value) = &self.calling_authentication_value {
            content.push(0xAC);
            encode_length(&mut content, calling_authentication_value.len());
            content.extend_from_slice(calling_authentication_value);
        }

        content.push(0xBE);
        encode_length(&mut content, self.user_information.len());
        content.extend_from_slice(&self.user_information);

        encode_length(&mut bytes, content.len());
        bytes.extend_from_slice(&content);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _aarq_tag) = tag(&[0x60u8][..]).parse(bytes)?;
        let (i, length) = parse_length(i)?;
        let (i, content) = take(length)(i)?;
        let (content, _acn_tag) = tag(&[0xA1u8][..]).parse(content)?;
        let (content, acn_len) = parse_length(content)?;
        let (content, acn) = take(acn_len)(content)?;
        let (content, _sar_tag) = tag(&[0x8Au8][..]).parse(content)?;
        let (content, sar_len) = parse_length(content)?;
        let (content, sar) = take(sar_len)(content)?;
        let (content, mn) = parse_optional(content, 0x8B)?;
        let (content, cav) = parse_optional(content, 0xAC)?;
        let (content, _ui_tag) = tag(&[0xBEu8][..]).parse(content)?;
        let (content, ui_len) = parse_length(content)?;
        let (_content, ui) = take(ui_len)(content)?;

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
        encode_length(&mut content, self.application_context_name.len());
        content.extend_from_slice(&self.application_context_name);
        content.push(0xA2);
        encode_length(&mut content, 1);
        content.push(self.result);
        content.push(0xA3);
        encode_length(&mut content, 1);
        content.push(self.result_source_diagnostic);

        if let Some(responding_authentication_value) = &self.responding_authentication_value {
            content.push(0xAC);
            encode_length(&mut content, responding_authentication_value.len());
            content.extend_from_slice(responding_authentication_value);
        }

        content.push(0xBE);
        encode_length(&mut content, self.user_information.len());
        content.extend_from_slice(&self.user_information);

        encode_length(&mut bytes, content.len());
        bytes.extend_from_slice(&content);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _aare_tag) = tag(&[0x61u8][..]).parse(bytes)?;
        let (i, length) = parse_length(i)?;
        let (i, content) = take(length)(i)?;
        let (content, _acn_tag) = tag(&[0xA1u8][..]).parse(content)?;
        let (content, acn_len) = parse_length(content)?;
        let (content, acn) = take(acn_len)(content)?;
        let (content, _res_tag) = tag(&[0xA2u8][..]).parse(content)?;
        let (content, res_len) = parse_length(content)?;
        let (content, res) = take(res_len)(content)?;
        let (content, _rsd_tag) = tag(&[0xA3u8][..]).parse(content)?;
        let (content, rsd_len) = parse_length(content)?;
        let (content, rsd) = take(rsd_len)(content)?;
        let (content, rav) = parse_optional(content, 0xAC)?;
        let (content, _ui_tag) = tag(&[0xBEu8][..]).parse(content)?;
        let (content, ui_len) = parse_length(content)?;
        let (_content, ui) = take(ui_len)(content)?;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArlrqApdu {
    pub reason: Option<u8>,
    pub user_information: Option<Vec<u8>>,
}

impl ArlrqApdu {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x62);

        let mut content = Vec::new();

        if let Some(reason) = self.reason {
            content.push(0x80);
            encode_length(&mut content, 1);
            content.push(reason);
        }

        if let Some(user_information) = &self.user_information {
            content.push(0xBE);
            encode_length(&mut content, user_information.len());
            content.extend_from_slice(user_information);
        }

        encode_length(&mut bytes, content.len());
        bytes.extend_from_slice(&content);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _arlrq_tag) = tag(&[0x62u8][..]).parse(bytes)?;
        let (i, length) = parse_length(i)?;
        let (i, content) = take(length)(i)?;
        let (content, reason) = parse_optional(content, 0x80)?;
        let (_content, user_information) = parse_optional(content, 0xBE)?;

        let reason = match reason {
            Some(bytes) => {
                if bytes.len() != 1 {
                    return Err(Err::Error(nom::error::Error::new(
                        bytes,
                        ErrorKind::LengthValue,
                    )));
                }
                Some(bytes[0])
            }
            None => None,
        };

        Ok((
            i,
            ArlrqApdu {
                reason,
                user_information: user_information.map(|ui| ui.to_vec()),
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArlreApdu {
    pub reason: Option<u8>,
    pub user_information: Option<Vec<u8>>,
}

impl ArlreApdu {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x63);

        let mut content = Vec::new();

        if let Some(reason) = self.reason {
            content.push(0x80);
            encode_length(&mut content, 1);
            content.push(reason);
        }

        if let Some(user_information) = &self.user_information {
            content.push(0xBE);
            encode_length(&mut content, user_information.len());
            content.extend_from_slice(user_information);
        }

        encode_length(&mut bytes, content.len());
        bytes.extend_from_slice(&content);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Self> {
        let (i, _arlre_tag) = tag(&[0x63u8][..]).parse(bytes)?;
        let (i, length) = parse_length(i)?;
        let (i, content) = take(length)(i)?;
        let (content, reason) = parse_optional(content, 0x80)?;
        let (_content, user_information) = parse_optional(content, 0xBE)?;

        let reason = match reason {
            Some(bytes) => {
                if bytes.len() != 1 {
                    return Err(Err::Error(nom::error::Error::new(
                        bytes,
                        ErrorKind::LengthValue,
                    )));
                }
                Some(bytes[0])
            }
            None => None,
        };

        Ok((
            i,
            ArlreApdu {
                reason,
                user_information: user_information.map(|ui| ui.to_vec()),
            },
        ))
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
    fn test_aarq_apdu_with_long_optionals_roundtrip() {
        let mechanism_name: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let calling_authentication_value: Vec<u8> = (0..260)
            .map(|i| 255u8.wrapping_sub((i % 256) as u8))
            .collect();

        let aarq = AarqApdu {
            application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(mechanism_name.clone()),
            calling_authentication_value: Some(calling_authentication_value.clone()),
            user_information: b"user_info".to_vec(),
        };

        let bytes = aarq.to_bytes().unwrap();
        let parsed = AarqApdu::from_bytes(&bytes).unwrap().1;

        assert_eq!(parsed.mechanism_name, Some(mechanism_name));
        assert_eq!(
            parsed.calling_authentication_value,
            Some(calling_authentication_value)
        );
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

    #[test]
    fn test_aare_apdu_with_long_optional_roundtrip() {
        let responding_authentication_value: Vec<u8> = (0..260).map(|i| (i % 200) as u8).collect();

        let aare = AareApdu {
            application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: Some(responding_authentication_value.clone()),
            user_information: b"user_info".to_vec(),
        };

        let bytes = aare.to_bytes().unwrap();
        let parsed = AareApdu::from_bytes(&bytes).unwrap().1;

        assert_eq!(
            parsed.responding_authentication_value,
            Some(responding_authentication_value)
        );
    }

    #[test]
    fn arlrq_round_trip() {
        let apdu = ArlrqApdu {
            reason: Some(0),
            user_information: Some(vec![0x01, 0x02, 0x03]),
        };

        let encoded = apdu.to_bytes().expect("failed to encode A-RLRQ");
        let (_, decoded) = ArlrqApdu::from_bytes(&encoded).expect("failed to decode A-RLRQ");
        assert_eq!(decoded, apdu);
    }

    #[test]
    fn arlre_round_trip() {
        let apdu = ArlreApdu {
            reason: Some(0),
            user_information: None,
        };

        let encoded = apdu.to_bytes().expect("failed to encode A-RLRE");
        let (_, decoded) = ArlreApdu::from_bytes(&encoded).expect("failed to decode A-RLRE");
        assert_eq!(decoded, apdu);
    }
}
