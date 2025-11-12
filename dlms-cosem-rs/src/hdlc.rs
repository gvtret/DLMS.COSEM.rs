use crate::error::DlmsError;
use crc::Crc;
use std::vec::Vec;

pub const HDLC_FLAG: u8 = 0x7E;
pub const CRC_CCITT_FALSE: crc::Algorithm<u16> = crc::Algorithm {
    width: 16,
    poly: 0x1021,
    init: 0xFFFF,
    refin: false,
    refout: false,
    xorout: 0x0000,
    check: 0x29B1,
    residue: 0x0000,
};
pub const CRC_ALGORITHM: Crc<u16> = Crc::<u16>::new(&CRC_CCITT_FALSE);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdlcFrame {
    pub address: u16,
    pub control: u8,
    pub information: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HdlcFrameError {
    InvalidFrame,
    InvalidFcs,
}

impl From<HdlcFrameError> for DlmsError {
    fn from(e: HdlcFrameError) -> Self {
        match e {
            HdlcFrameError::InvalidFrame => DlmsError::Hdlc,
            HdlcFrameError::InvalidFcs => DlmsError::Hdlc,
        }
    }
}

impl HdlcFrame {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut frame = Vec::new();
        frame.push(HDLC_FLAG);

        let mut data_to_checksum = Vec::new();
        data_to_checksum.extend_from_slice(&self.address.to_be_bytes());
        data_to_checksum.push(self.control);
        data_to_checksum.extend_from_slice(&self.information);

        let checksum = CRC_ALGORITHM.checksum(&data_to_checksum);

        let mut frame_body = Vec::new();
        frame_body.extend_from_slice(&self.address.to_be_bytes());
        frame_body.push(self.control);
        frame_body.extend_from_slice(&self.information);
        frame_body.extend_from_slice(&checksum.to_le_bytes());

        for byte in frame_body {
            if byte == HDLC_FLAG || byte == 0x7D {
                frame.push(0x7D);
                frame.push(byte ^ 0x20);
            } else {
                frame.push(byte);
            }
        }

        frame.push(HDLC_FLAG);

        Ok(frame)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.len() < 6 || bytes[0] != HDLC_FLAG || bytes[bytes.len() - 1] != HDLC_FLAG {
            return Err(HdlcFrameError::InvalidFrame.into());
        }

        let mut frame_body = Vec::new();
        let mut i = 1;
        while i < bytes.len() - 1 {
            if bytes[i] == 0x7D {
                i += 1;
                frame_body.push(bytes[i] ^ 0x20);
            } else {
                frame_body.push(bytes[i]);
            }
            i += 1;
        }

        if frame_body.len() < 4 {
            return Err(HdlcFrameError::InvalidFrame.into());
        }

        let received_checksum_bytes: [u8; 2] = [
            frame_body[frame_body.len() - 2],
            frame_body[frame_body.len() - 1],
        ];
        let received_checksum = u16::from_le_bytes(received_checksum_bytes);
        let data_to_checksum = &frame_body[..frame_body.len() - 2];
        let calculated_checksum = CRC_ALGORITHM.checksum(data_to_checksum);

        if received_checksum != calculated_checksum {
            return Err(HdlcFrameError::InvalidFcs.into());
        }

        let address = u16::from_be_bytes([data_to_checksum[0], data_to_checksum[1]]);
        let control = data_to_checksum[2];
        let information = data_to_checksum[3..].to_vec();

        Ok(HdlcFrame {
            address,
            control,
            information,
        })
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_hdlc_frame_serialization_deserialization() {
        let info = b"hello world".to_vec();
        let frame = HdlcFrame {
            address: 0x1234,
            control: 0xAB,
            information: info,
        };

        let bytes = frame.to_bytes().unwrap();
        let deserialized_frame = HdlcFrame::from_bytes(&bytes).unwrap();

        assert_eq!(frame, deserialized_frame);
    }
}
