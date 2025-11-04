use heapless::Vec;

pub trait Transport {
    type Error;

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error>;
}
