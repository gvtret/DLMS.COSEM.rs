use crate::error::DlmsError;
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

impl From<HdlcFrameError> for DlmsError {
    fn from(e: HdlcFrameError) -> Self {
        match e {
            HdlcFrameError::InvalidFrame => DlmsError::Hdlc,
            HdlcFrameError::InvalidFcs => DlmsError::Hdlc,
        }
    }
}

impl HdlcFrame {
    pub fn to_bytes(&self) -> Result<Vec<u8, MAX_PDU_SIZE>, DlmsError> {
        let info_len = self.information.len();
        // Frame Format (2) + Address (2) + Control (1) + Information (info_len) + FCS (2)
        let frame_len = 2 + 2 + 1 + info_len + 2;

        if frame_len > 2047 {
            return Err(DlmsError::VecIsFull);
        }

        // Frame Type: 1010 (binary) for I-frame/UI-frame, no segmentation
        let format_field: u16 = 0b1010_0000_0000_0000 | (frame_len as u16);

        let mut data_to_checksum = Vec::<u8, MAX_PDU_SIZE>::new();
        data_to_checksum
            .extend_from_slice(&format_field.to_be_bytes())
            .map_err(|_| DlmsError::VecIsFull)?;
        data_to_checksum
            .extend_from_slice(&self.address.to_be_bytes())
            .map_err(|_| DlmsError::VecIsFull)?;
        data_to_checksum
            .push(self.control)
            .map_err(|_| DlmsError::VecIsFull)?;
        data_to_checksum
            .extend_from_slice(&self.information)
            .map_err(|_| DlmsError::VecIsFull)?;

        let fcs = CRC_ALGORITHM.checksum(&data_to_checksum);

        let mut frame = Vec::<u8, MAX_PDU_SIZE>::new();
        frame.push(HDLC_FLAG).map_err(|_| DlmsError::VecIsFull)?;
        frame
            .extend_from_slice(&data_to_checksum)
            .map_err(|_| DlmsError::VecIsFull)?;
        frame
            .extend_from_slice(&fcs.to_le_bytes())
            .map_err(|_| DlmsError::VecIsFull)?;
        frame.push(HDLC_FLAG).map_err(|_| DlmsError::VecIsFull)?;

        Ok(frame)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.len() < 9 || bytes[0] != HDLC_FLAG || bytes[bytes.len() - 1] != HDLC_FLAG {
            return Err(HdlcFrameError::InvalidFrame.into());
        }

        let frame_body = &bytes[1..bytes.len() - 1];

        // Extract format field and declared length
        let format_field = u16::from_be_bytes([frame_body[0], frame_body[1]]);
        let declared_len = (format_field & 0x07FF) as usize;

        if frame_body.len() != declared_len {
            return Err(HdlcFrameError::InvalidFrame.into());
        }

        let data_to_checksum = &frame_body[..frame_body.len() - 2];
        let received_fcs_bytes: [u8; 2] =
            [frame_body[frame_body.len() - 2], frame_body[frame_body.len() - 1]];
        let received_fcs = u16::from_le_bytes(received_fcs_bytes);

        let calculated_fcs = CRC_ALGORITHM.checksum(data_to_checksum);

        if received_fcs != calculated_fcs {
            return Err(HdlcFrameError::InvalidFcs.into());
        }

        // data_to_checksum is: format(2) + address(2) + control(1) + information(...)
        if data_to_checksum.len() < 5 {
            return Err(HdlcFrameError::InvalidFrame.into());
        }

        let address = u16::from_be_bytes([data_to_checksum[2], data_to_checksum[3]]);
        let control = data_to_checksum[4];
        let information = Vec::<u8, MAX_PDU_SIZE>::from_slice(&data_to_checksum[5..])
            .map_err(|_| DlmsError::VecIsFull)?;

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
        let mut info = Vec::<u8, MAX_PDU_SIZE>::new();
        info.extend_from_slice(b"hello world").unwrap();
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
