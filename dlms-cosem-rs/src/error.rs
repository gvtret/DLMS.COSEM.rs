#[derive(Debug)]
pub enum DlmsError {
    // I/O and transport related errors
    Transport,
    // HDLC framing errors
    Hdlc,
    // ACSE and xDLMS PDU parsing errors
    Acse,
    Xdlms,
    // COSEM object access errors
    Cosem,
    // Security and authentication errors
    Security,
    // Heapless vector is full
    VecIsFull,
    // Parsing error
    ParseError,
}

impl<'a> From<nom::Err<nom::error::Error<&'a [u8]>>> for DlmsError {
    fn from(_: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        DlmsError::ParseError
    }
}
