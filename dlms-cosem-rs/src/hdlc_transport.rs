#![cfg(feature = "serialport")]

use crate::hdlc::HDLC_FLAG;
use crate::transport::Transport;
use heapless::Vec;
use serialport::{Error as SerialError, SerialPort};
use std::io;

#[derive(Debug)]
pub enum HdlcTransportError {
    Serial(SerialError),
    Io(io::Error),
    VecIsFull,
    FrameTooShort,
}

impl From<SerialError> for HdlcTransportError {
    fn from(e: SerialError) -> Self {
        HdlcTransportError::Serial(e)
    }
}

impl From<io::Error> for HdlcTransportError {
    fn from(e: io::Error) -> Self {
        HdlcTransportError::Io(e)
    }
}

pub struct HdlcTransport {
    port: Box<dyn SerialPort>,
}

impl HdlcTransport {
    pub fn new(port_path: &str, baud_rate: u32) -> Result<Self, HdlcTransportError> {
        let port = serialport::new(port_path, baud_rate).open()?;
        Ok(Self { port })
    }

    #[cfg(test)]
    pub fn with_port(port: Box<dyn SerialPort>) -> Self {
        Self { port }
    }
}

impl Transport for HdlcTransport {
    type Error = HdlcTransportError;

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.port.write_all(bytes)?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error> {
        let mut buffer = Vec::new();
        let mut byte_buffer = [0u8; 1];
        let mut in_frame = false;

        loop {
            self.port.read_exact(&mut byte_buffer)?;
            let byte = byte_buffer[0];

            if byte == HDLC_FLAG {
                if in_frame {
                    if buffer.len() >= 2 {
                        buffer
                            .push(HDLC_FLAG)
                            .map_err(|_| HdlcTransportError::VecIsFull)?;
                        return Ok(buffer);
                    } else {
                        // Frame is too short, reset and continue
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
