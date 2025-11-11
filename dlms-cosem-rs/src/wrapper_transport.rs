#![cfg(feature = "std")]

use crate::transport::Transport;
use heapless::Vec;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum WrapperTransportError {
    Io(std::io::Error),
    VecIsFull,
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

    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error> {
        let mut len_bytes = [0u8; 2];
        self.stream.read_exact(&mut len_bytes)?;
        let len = u16::from_be_bytes(len_bytes) as usize;

        let mut buffer = [0u8; 2048];
        if len > buffer.len() {
            return Err(WrapperTransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Frame too large",
            )));
        }
        self.stream.read_exact(&mut buffer[..len])?;

        let mut vec = Vec::new();
        vec.extend_from_slice(&buffer[..len])
            .map_err(|_| WrapperTransportError::VecIsFull)?;

        Ok(vec)
    }
}
