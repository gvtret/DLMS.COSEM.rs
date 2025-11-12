#![cfg(feature = "std")]

use crate::transport::Transport;
use std::io::{Read, Write};
use std::vec::Vec;

#[derive(Debug)]
pub enum WrapperTransportError {
    Io(std::io::Error),
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

    fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        let mut len_bytes = [0u8; 2];
        self.stream.read_exact(&mut len_bytes)?;
        let len = u16::from_be_bytes(len_bytes) as usize;

        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer)?;

        Ok(buffer)
    }
}
