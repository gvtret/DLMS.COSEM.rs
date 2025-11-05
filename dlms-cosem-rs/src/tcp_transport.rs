#![cfg(feature = "std")]

use crate::hdlc::HDLC_FLAG;
use crate::transport::Transport;
use heapless::Vec;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub enum TcpTransportError {
    Io(std::io::Error),
    VecIsFull,
}

impl From<std::io::Error> for TcpTransportError {
    fn from(e: std::io::Error) -> Self {
        TcpTransportError::Io(e)
    }
}

pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn new(addr: &str) -> Result<Self, TcpTransportError> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self { stream })
    }
}

impl Transport for TcpTransport {
    type Error = TcpTransportError;

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
                            .map_err(|_| TcpTransportError::VecIsFull)?;
                        return Ok(buffer);
                    } else {
                        buffer.clear();
                        in_frame = false;
                    }
                } else {
                    in_frame = true;
                    buffer
                        .push(HDLC_FLAG)
                        .map_err(|_| TcpTransportError::VecIsFull)?;
                }
            } else if in_frame {
                buffer
                    .push(byte)
                    .map_err(|_| TcpTransportError::VecIsFull)?;
            }
        }
    }
}
