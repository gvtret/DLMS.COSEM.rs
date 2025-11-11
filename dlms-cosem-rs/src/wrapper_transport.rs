#![cfg(feature = "std")]

use crate::transport::Transport;
use crate::MAX_PDU_SIZE;
use heapless::Vec;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum WrapperTransportError {
    Io(std::io::Error),
    VecIsFull,
    FrameTooLarge,
}

impl From<std::io::Error> for WrapperTransportError {
    fn from(e: std::io::Error) -> Self {
        WrapperTransportError::Io(e)
    }
}

pub struct WrapperTransport<T: Read + Write> {
    stream: T,
}

impl<T: Read + Write> WrapperTransport<T> {
    pub fn new(stream: T) -> Self {
        Self { stream }
    }
}

impl<T: Read + Write> Transport for WrapperTransport<T> {
    type Error = WrapperTransportError;

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let len = bytes.len() as u16;
        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(bytes)?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8, MAX_PDU_SIZE>, Self::Error> {
        let mut len_bytes = [0u8; 2];
        self.stream.read_exact(&mut len_bytes)?;
        let len = u16::from_be_bytes(len_bytes) as usize;

        if len > MAX_PDU_SIZE {
            return Err(WrapperTransportError::FrameTooLarge);
        }

        let mut vec = Vec::new();
        vec.resize_default(len)
            .map_err(|_| WrapperTransportError::VecIsFull)?;
        self.stream.read_exact(&mut vec)?;

        Ok(vec)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;

    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_wrapper_transport_send_receive() {
        let mut data_to_send = Vec::<u8, MAX_PDU_SIZE>::new();
        data_to_send.extend_from_slice(b"hello world").unwrap();

        let mut mock_stream = Cursor::new(std::vec::Vec::<u8>::new());

        // Test send
        {
            let mut transport = WrapperTransport::new(&mut mock_stream);
            transport.send(&data_to_send).unwrap();
        }

        // Check what was written to the stream
        let written_data = mock_stream.into_inner();
        let expected_len: u16 = 11;
        assert_eq!(&written_data[0..2], &expected_len.to_be_bytes());
        assert_eq!(&written_data[2..], b"hello world");

        // Rewind and test receive
        let mut mock_stream = Cursor::new(written_data);

        let mut transport = WrapperTransport::new(&mut mock_stream);
        let received_data = transport.receive().unwrap();

        assert_eq!(data_to_send.as_slice(), received_data.as_slice());
    }

    #[test]
    fn test_receive_frame_too_large() {
        let mut data = std::vec::Vec::<u8>::new();
        let len: u16 = (MAX_PDU_SIZE + 1) as u16;
        data.extend_from_slice(&len.to_be_bytes());
        let mut mock_stream = Cursor::new(data);

        let mut transport = WrapperTransport::new(&mut mock_stream);
        let result = transport.receive();
        assert!(matches!(
            result,
            Err(WrapperTransportError::FrameTooLarge)
        ));
    }
}
