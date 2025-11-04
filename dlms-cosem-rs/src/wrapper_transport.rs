use crate::transport::Transport;
use heapless::Vec;

#[derive(Debug)]
pub struct WrapperTransport {}

impl Transport for WrapperTransport {
    type Error = ();

    fn send(&mut self, _bytes: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error> {
        Ok(Vec::new())
    }
}
