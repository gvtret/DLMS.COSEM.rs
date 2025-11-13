use crate::error::DlmsError;
use crate::types::CosemData;
use std::vec::Vec;

pub fn encode_data(data: &CosemData, buffer: &mut Vec<u8>) -> Result<(), DlmsError> {
    match data {
        CosemData::NullData => buffer.push(0),
        CosemData::Boolean(val) => {
            buffer.push(3);
            buffer.push(*val as u8);
        }
        CosemData::Integer(val) => {
            buffer.push(15);
            buffer.push(*val as u8);
        }
        CosemData::Unsigned(val) => {
            buffer.push(17);
            buffer.push(*val);
        }
        CosemData::LongUnsigned(val) => {
            buffer.push(18);
            buffer.extend_from_slice(&val.to_be_bytes());
        }
        CosemData::DoubleLongUnsigned(val) => {
            buffer.push(6);
            buffer.extend_from_slice(&val.to_be_bytes());
        }
        CosemData::Enum(val) => {
            buffer.push(22);
            buffer.push(*val);
        }
        CosemData::OctetString(val) => {
            buffer.push(9);
            buffer.push(val.len() as u8);
            buffer.extend_from_slice(val);
        }
        CosemData::Array(elements) => {
            buffer.push(1);
            buffer.push(elements.len() as u8);
            for element in elements {
                encode_data(element, buffer)?;
            }
        }
        CosemData::Structure(elements) => {
            buffer.push(2);
            buffer.push(elements.len() as u8);
            for element in elements {
                encode_data(element, buffer)?;
            }
        }
        _ => return Err(DlmsError::Xdlms), // not all variants are supported yet
    }
    Ok(())
}

pub fn decode_data(buffer: &[u8]) -> Result<(CosemData, &[u8]), DlmsError> {
    if buffer.is_empty() {
        return Err(DlmsError::Xdlms);
    }

    let (tag, rest) = buffer.split_at(1);
    match tag[0] {
        0 => Ok((CosemData::NullData, rest)),
        3 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(1);
            Ok((CosemData::Boolean(val[0] != 0), rest))
        }
        15 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(1);
            Ok((CosemData::Integer(val[0] as i8), rest))
        }
        17 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(1);
            Ok((CosemData::Unsigned(val[0]), rest))
        }
        18 => {
            if rest.len() < 2 {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(2);
            Ok((
                CosemData::LongUnsigned(u16::from_be_bytes(val.try_into().unwrap())),
                rest,
            ))
        }
        6 => {
            if rest.len() < 4 {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(4);
            Ok((
                CosemData::DoubleLongUnsigned(u32::from_be_bytes(val.try_into().unwrap())),
                rest,
            ))
        }
        22 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(1);
            Ok((CosemData::Enum(val[0]), rest))
        }
        9 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (len, rest) = rest.split_at(1);
            let len = len[0] as usize;
            if rest.len() < len {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(len);
            Ok((CosemData::OctetString(val.to_vec()), rest))
        }
        1 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (len_bytes, mut rest) = rest.split_at(1);
            let len = len_bytes[0] as usize;
            let mut elements = Vec::with_capacity(len);
            for _ in 0..len {
                let (element, new_rest) = decode_data(rest)?;
                elements.push(element);
                rest = new_rest;
            }
            Ok((CosemData::Array(elements), rest))
        }
        2 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (len_bytes, mut rest) = rest.split_at(1);
            let len = len_bytes[0] as usize;
            let mut elements = Vec::with_capacity(len);
            for _ in 0..len {
                let (element, new_rest) = decode_data(rest)?;
                elements.push(element);
                rest = new_rest;
            }
            Ok((CosemData::Structure(elements), rest))
        }

        _ => Err(DlmsError::Xdlms), // not all variants are supported yet
    }
}
