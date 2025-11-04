use crate::MAX_PDU_SIZE;
use crc::Crc;
use heapless::Vec;

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
    pub information: Vec<u8, MAX_PDU_SIZE>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HdlcFrameError {
    InvalidFrame,
    InvalidFcs,
}

impl HdlcFrame {
    pub fn to_bytes(&self) -> Vec<u8, MAX_PDU_SIZE> {
        let mut frame = Vec::<u8, MAX_PDU_SIZE>::new();

        frame.push(HDLC_FLAG).unwrap();

        let mut data_to_checksum = Vec::<u8, MAX_PDU_SIZE>::new();
        data_to_checksum.extend_from_slice(&self.address.to_be_bytes()).unwrap();
        data_to_checksum.push(self.control).unwrap();
        data_to_checksum.extend_from_slice(&self.information).unwrap();

        let checksum = CRC_ALGORITHM.checksum(&data_to_checksum);

        let mut frame_body = Vec::<u8, MAX_PDU_SIZE>::new();
        frame_body.extend_from_slice(&self.address.to_be_bytes()).unwrap();
        frame_body.push(self.control).unwrap();
        frame_body.extend_from_slice(&self.information).unwrap();
        frame_body.extend_from_slice(&checksum.to_le_bytes()).unwrap();

        // Byte stuffing
        for byte in frame_body {
            if byte == HDLC_FLAG || byte == 0x7D {
                frame.push(0x7D).unwrap();
                frame.push(byte ^ 0x20).unwrap();
            } else {
                frame.push(byte).unwrap();
            }
        }

        frame.push(HDLC_FLAG).unwrap();

        frame
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HdlcFrameError> {
        if bytes.len() < 6 || bytes[0] != HDLC_FLAG || bytes[bytes.len() - 1] != HDLC_FLAG {
            return Err(HdlcFrameError::InvalidFrame);
        }

        let mut frame_body = Vec::<u8, MAX_PDU_SIZE>::new();
        let mut i = 1;
        while i < bytes.len() - 1 {
            if bytes[i] == 0x7D {
                i += 1;
                frame_body.push(bytes[i] ^ 0x20).unwrap();
            } else {
                frame_body.push(bytes[i]).unwrap();
            }
            i += 1;
        }

        if frame_body.len() < 4 {
            return Err(HdlcFrameError::InvalidFrame);
        }

        let received_checksum_bytes: [u8; 2] = [frame_body[frame_body.len() - 2], frame_body[frame_body.len() - 1]];
        let received_checksum = u16::from_le_bytes(received_checksum_bytes);

        let data_to_checksum = &frame_body[..frame_body.len() - 2];
        let calculated_checksum = CRC_ALGORITHM.checksum(data_to_checksum);

        if received_checksum != calculated_checksum {
            return Err(HdlcFrameError::InvalidFcs);
        }

        let address = u16::from_be_bytes([data_to_checksum[0], data_to_checksum[1]]);
        let control = data_to_checksum[2];
        let information = Vec::<u8, MAX_PDU_SIZE>::from_slice(&data_to_checksum[3..]).unwrap();

        Ok(HdlcFrame {
            address,
            control,
            information,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_hdlc_frame_serialization_deserialization() {
        let mut info = Vec::<u8, MAX_PDU_SIZE>::new();
        info.extend_from_slice(b"hello world").unwrap();
        let frame = HdlcFrame {
            address: 0x1234,
            control: 0xAB,
            information: info,
        };

        let bytes = frame.to_bytes();
        let deserialized_frame = HdlcFrame::from_bytes(&bytes).unwrap();

        assert_eq!(frame, deserialized_frame);
    }
}
