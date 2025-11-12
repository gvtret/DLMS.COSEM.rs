use crate::error::DlmsError;
use crate::types::Data;
use std::vec::Vec;

pub fn encode_data(data: &Data, buffer: &mut Vec<u8>) -> Result<(), DlmsError> {
    match data {
        Data::NullData => buffer.push(0),
        Data::Boolean(val) => {
            buffer.push(3);
            buffer.push(*val as u8);
        }
        Data::Integer(val) => {
            buffer.push(15);
            buffer.push(*val as u8);
        }
        Data::Unsigned(val) => {
            buffer.push(17);
            buffer.push(*val);
        }
        Data::LongUnsigned(val) => {
            buffer.push(18);
            buffer.extend_from_slice(&val.to_be_bytes());
        }
        Data::OctetString(val) => {
            buffer.push(9);
            buffer.push(val.len() as u8);
            buffer.extend_from_slice(val);
        }
        _ => return Err(DlmsError::Xdlms), // not all variants are supported yet
    }
    Ok(())
}

pub fn decode_data(buffer: &[u8]) -> Result<(Data, &[u8]), DlmsError> {
    if buffer.is_empty() {
        return Err(DlmsError::Xdlms);
    }

    let (tag, rest) = buffer.split_at(1);
    match tag[0] {
        0 => Ok((Data::NullData, rest)),
        3 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(1);
            Ok((Data::Boolean(val[0] != 0), rest))
        }
        15 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(1);
            Ok((Data::Integer(val[0] as i8), rest))
        }
        17 => {
            if rest.is_empty() {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(1);
            Ok((Data::Unsigned(val[0]), rest))
        }
        18 => {
            if rest.len() < 2 {
                return Err(DlmsError::Xdlms);
            }
            let (val, rest) = rest.split_at(2);
            Ok((
                Data::LongUnsigned(u16::from_be_bytes(val.try_into().unwrap())),
                rest,
            ))
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
            Ok((Data::OctetString(val.to_vec()), rest))
        }

        _ => Err(DlmsError::Xdlms), // not all variants are supported yet
    }
}
