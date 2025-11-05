#![cfg(feature = "std")]

use crate::hdlc::HDLC_FLAG;
use crate::transport::Transport;
use heapless::Vec;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum HdlcTransportError {
    Io(std::io::Error),
    VecIsFull,
}

impl From<std::io::Error> for HdlcTransportError {
    fn from(e: std::io::Error) -> Self {
        HdlcTransportError::Io(e)
    }
}

pub struct HdlcTransport<T: Read + Write> {
    stream: T,
}

impl<T: Read + Write> HdlcTransport<T> {
    pub fn new(stream: T) -> Self {
        Self { stream }
    }
}

impl<T: Read + Write> Transport for HdlcTransport<T> {
    type Error = HdlcTransportError;

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.stream.write_all(bytes)?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error> {
        let mut buffer = Vec::new();
        let mut byte_buffer = [0u8; 1];
        let mut in_frame = false;

        loop {
            self.stream.read_exact(&mut byte_buffer)?;
            let byte = byte_buffer[0];

            if byte == HDLC_FLAG {
                if in_frame {
                    if buffer.len() >= 2 {
                        buffer
                            .push(HDLC_FLAG)
                            .map_err(|_| HdlcTransportError::VecIsFull)?;
                        return Ok(buffer);
                    } else {
                        buffer.clear();
                        in_frame = false;
                    }
                } else {
                    in_frame = true;
                    buffer
                        .push(HDLC_FLAG)
                        .map_err(|_| HdlcTransportError::VecIsFull)?;
                }
            } else if in_frame {
                buffer
                    .push(byte)
                    .map_err(|_| HdlcTransportError::VecIsFull)?;
            }
        }
    }
}
