use crate::error::DlmsError;
use crate::MAX_PDU_SIZE;
use heapless::Vec;
use nom::{
    bytes::complete::{tag, take},
    combinator::opt,
    IResult,
    Parser,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AarqApdu {
    pub application_context_name: Vec<u8, MAX_PDU_SIZE>,
    pub sender_acse_requirements: u8,
    pub mechanism_name: Option<Vec<u8, MAX_PDU_SIZE>>,
    pub calling_authentication_value: Option<Vec<u8, 32>>,
    pub user_information: Vec<u8, MAX_PDU_SIZE>,
}

impl AarqApdu {
    pub fn to_bytes(&self) -> Result<Vec<u8, MAX_PDU_SIZE>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x60).map_err(|_| DlmsError::VecIsFull)?;

        let mut content = Vec::<u8, MAX_PDU_SIZE>::new();
        content.push(0xA1).map_err(|_| DlmsError::VecIsFull)?;
        content
            .push(self.application_context_name.len() as u8)
            .map_err(|_| DlmsError::VecIsFull)?;
        content
            .extend_from_slice(&self.application_context_name)
            .map_err(|_| DlmsError::VecIsFull)?;
        content.push(0x8A).map_err(|_| DlmsError::VecIsFull)?;
        content.push(0x01).map_err(|_| DlmsError::VecIsFull)?;
        content
            .push(self.sender_acse_requirements)
            .map_err(|_| DlmsError::VecIsFull)?;

        if let Some(mechanism_name) = &self.mechanism_name {
            content.push(0x8B).map_err(|_| DlmsError::VecIsFull)?;
            content
                .push(mechanism_name.len() as u8)
                .map_err(|_| DlmsError::VecIsFull)?;
            content
                .extend_from_slice(mechanism_name)
                .map_err(|_| DlmsError::VecIsFull)?;
        }

        if let Some(calling_authentication_value) = &self.calling_authentication_value {
            content.push(0xAC).map_err(|_| DlmsError::VecIsFull)?;
            content
                .push(calling_authentication_value.len() as u8)
                .map_err(|_| DlmsError::VecIsFull)?;
            content
                .extend_from_slice(calling_authentication_value)
                .map_err(|_| DlmsError::VecIsFull)?;
        }

        content.push(0xBE).map_err(|_| DlmsError::VecIsFull)?;
        content
            .push(self.user_information.len() as u8)
            .map_err(|_| DlmsError::VecIsFull)?;
        content
            .extend_from_slice(&self.user_information)
            .map_err(|_| DlmsError::VecIsFull)?;

        bytes
            .push(content.len() as u8)
            .map_err(|_| DlmsError::VecIsFull)?;
        bytes
            .extend_from_slice(&content)
            .map_err(|_| DlmsError::VecIsFull)?;
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
        let (content, mn) = opt((tag(&[0x8Bu8][..]), take(1usize), take(1usize))).parse(content)?;
        let (content, cav) = opt((tag(&[0xACu8][..]), take(1usize), take(1usize))).parse(content)?;
        let (content, _ui_tag) = tag(&[0xBEu8][..]).parse(content)?;
        let (content, ui_len) = take(1usize)(content)?;
        let (_content, ui) = take(ui_len[0] as usize)(content)?;

        let mut aarq = AarqApdu {
            application_context_name: Vec::from_slice(acn).map_err(|_| {
                nom::Err::Failure(nom::error::Error::new(acn, nom::error::ErrorKind::Verify))
            })?,
            sender_acse_requirements: sar[0],
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::from_slice(ui).map_err(|_| {
                nom::Err::Failure(nom::error::Error::new(ui, nom::error::ErrorKind::Verify))
            })?,
        };

        if let Some((_, mn_len, mn_val)) = mn {
            let len = u8::from_be_bytes(mn_len[0].to_be_bytes());
            let (mn_val, _) = take(len as usize)(mn_val)?;
            aarq.mechanism_name = Some(Vec::from_slice(mn_val).map_err(|_| {
                nom::Err::Failure(nom::error::Error::new(mn_val, nom::error::ErrorKind::Verify))
            })?);
        }

        if let Some((_, cav_len, cav_val)) = cav {
            let len = u8::from_be_bytes(cav_len[0].to_be_bytes());
            let (cav_val, _) = take(len as usize)(cav_val)?;
            aarq.calling_authentication_value = Some(Vec::from_slice(cav_val).map_err(
                |_| nom::Err::Failure(nom::error::Error::new(cav_val, nom::error::ErrorKind::Verify)),
            )?);
        }

        Ok((i, aarq))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AareApdu {
    pub application_context_name: Vec<u8, MAX_PDU_SIZE>,
    pub result: u8,
    pub result_source_diagnostic: u8,
    pub responding_authentication_value: Option<Vec<u8, 32>>,
    pub user_information: Vec<u8, MAX_PDU_SIZE>,
}

impl AareApdu {
    pub fn to_bytes(&self) -> Result<Vec<u8, MAX_PDU_SIZE>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x61).map_err(|_| DlmsError::VecIsFull)?;

        let mut content = Vec::<u8, MAX_PDU_SIZE>::new();
        content.push(0xA1).map_err(|_| DlmsError::VecIsFull)?;
        content
            .push(self.application_context_name.len() as u8)
            .map_err(|_| DlmsError::VecIsFull)?;
        content
            .extend_from_slice(&self.application_context_name)
            .map_err(|_| DlmsError::VecIsFull)?;
        content.push(0xA2).map_err(|_| DlmsError::VecIsFull)?;
        content.push(0x01).map_err(|_| DlmsError::VecIsFull)?;
        content.push(self.result).map_err(|_| DlmsError::VecIsFull)?;
        content.push(0xA3).map_err(|_| DlmsError::VecIsFull)?;
        content.push(0x01).map_err(|_| DlmsError::VecIsFull)?;
        content
            .push(self.result_source_diagnostic)
            .map_err(|_| DlmsError::VecIsFull)?;

        if let Some(responding_authentication_value) = &self.responding_authentication_value {
            content.push(0xAC).map_err(|_| DlmsError::VecIsFull)?;
            content
                .push(responding_authentication_value.len() as u8)
                .map_err(|_| DlmsError::VecIsFull)?;
            content
                .extend_from_slice(responding_authentication_value)
                .map_err(|_| DlmsError::VecIsFull)?;
        }

        content.push(0xBE).map_err(|_| DlmsError::VecIsFull)?;
        content
            .push(self.user_information.len() as u8)
            .map_err(|_| DlmsError::VecIsFull)?;
        content
            .extend_from_slice(&self.user_information)
            .map_err(|_| DlmsError::VecIsFull)?;

        bytes
            .push(content.len() as u8)
            .map_err(|_| DlmsError::VecIsFull)?;
        bytes
            .extend_from_slice(&content)
            .map_err(|_| DlmsError::VecIsFull)?;
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
        let (content, rav) = opt((tag(&[0xACu8][..]), take(1usize), take(1usize))).parse(content)?;
        let (content, _ui_tag) = tag(&[0xBEu8][..]).parse(content)?;
        let (content, ui_len) = take(1usize)(content)?;
        let (_content, ui) = take(ui_len[0] as usize)(content)?;

        let mut aare = AareApdu {
            application_context_name: Vec::from_slice(acn).map_err(|_| {
                nom::Err::Failure(nom::error::Error::new(acn, nom::error::ErrorKind::Verify))
            })?,
            result: res[0],
            result_source_diagnostic: rsd[0],
            responding_authentication_value: None,
            user_information: Vec::from_slice(ui).map_err(|_| {
                nom::Err::Failure(nom::error::Error::new(ui, nom::error::ErrorKind::Verify))
            })?,
        };

        if let Some((_, rav_len, rav_val)) = rav {
            let len = u8::from_be_bytes(rav_len[0].to_be_bytes());
            let (rav_val, _) = take(len as usize)(rav_val)?;
            aare.responding_authentication_value = Some(Vec::from_slice(rav_val).map_err(
                |_| nom::Err::Failure(nom::error::Error::new(rav_val, nom::error::ErrorKind::Verify)),
            )?);
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
        let mut aarq = AarqApdu {
            application_context_name: Vec::new(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: Vec::new(),
        };
        aarq.application_context_name
            .extend_from_slice(b"LN_WITH_NO_CIPHERING")
            .unwrap();
        aarq.user_information
            .extend_from_slice(b"user_info")
            .unwrap();

        let bytes = aarq.to_bytes().unwrap();
        let aarq2 = AarqApdu::from_bytes(&bytes).unwrap().1;

        assert_eq!(aarq, aarq2);
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
        aarq.application_context_name
            .extend_from_slice(b"LN_WITH_NO_CIPHERING")
            .unwrap();
        aarq.mechanism_name
            .as_mut()
            .unwrap()
            .extend_from_slice(b"auth")
            .unwrap();
        aarq.calling_authentication_value
            .as_mut()
            .unwrap()
            .extend_from_slice(b"pass")
            .unwrap();
        aarq.user_information
            .extend_from_slice(b"user_info")
            .unwrap();

        let bytes = aarq.to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_aare_apdu_serialization_deserialization() {
        let mut aare = AareApdu {
            application_context_name: Vec::new(),
            result: 0,
            result_source_diagnostic: 0,
            responding_authentication_value: None,
            user_information: Vec::new(),
        };
        aare.application_context_name
            .extend_from_slice(b"LN_WITH_NO_CIPHERING")
            .unwrap();
        aare.user_information
            .extend_from_slice(b"user_info")
            .unwrap();

        let bytes = aare.to_bytes().unwrap();
        let aare2 = AareApdu::from_bytes(&bytes).unwrap().1;
        assert_eq!(aare, aare2);
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
        aare.application_context_name
            .extend_from_slice(b"LN_WITH_NO_CIPHERING")
            .unwrap();
        aare.responding_authentication_value
            .as_mut()
            .unwrap()
            .extend_from_slice(b"pass")
            .unwrap();
        aare.user_information
            .extend_from_slice(b"user_info")
            .unwrap();

        let bytes = aare.to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }
}
