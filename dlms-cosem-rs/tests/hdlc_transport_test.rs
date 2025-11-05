use dlms_cosem::hdlc::HDLC_FLAG;
use dlms_cosem::transport::Transport;
use heapless::Vec;
use std::io;
use std::vec::Vec as StdVec;

struct MockHdlcTransport {
    data_to_read: StdVec<u8>,
    read_index: usize,
}

impl Transport for MockHdlcTransport {
    type Error = io::Error;

    fn send(&mut self, _bytes: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error> {
        let mut buffer = Vec::new();
        let mut in_frame = false;

        while self.read_index < self.data_to_read.len() {
            let byte = self.data_to_read[self.read_index];
            self.read_index += 1;

            if byte == HDLC_FLAG {
                if in_frame {
                    if buffer.len() >= 2 {
                        buffer.push(HDLC_FLAG).unwrap();
                        return Ok(buffer);
                    } else {
                        buffer.clear();
                        in_frame = false;
                    }
                } else {
                    in_frame = true;
                    buffer.push(HDLC_FLAG).unwrap();
                }
            } else if in_frame {
                buffer.push(byte).unwrap();
            }
        }

        Err(io::Error::new(io::ErrorKind::TimedOut, "No more data"))
    }
}

#[test]
fn test_hdlc_transport_receive_single_frame() {
    let frame_data = vec![
        HDLC_FLAG,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        HDLC_FLAG,
    ];
    let mut transport = MockHdlcTransport {
        data_to_read: frame_data,
        read_index: 0,
    };

    let received_frame = transport.receive().unwrap();

    assert_eq!(
        received_frame.as_slice(),
        &[HDLC_FLAG, 0x01, 0x02, 0x03, 0x04, 0x05, HDLC_FLAG]
    );
}

#[test]
fn test_hdlc_transport_receive_frame_with_stuffing() {
    let frame_data = vec![
        HDLC_FLAG,
        0x01,
        0x7D,
        0x5E,
        0x03,
        0x7D,
        0x5D,
        0x05,
        HDLC_FLAG,
    ];
    let mut transport = MockHdlcTransport {
        data_to_read: frame_data,
        read_index: 0,
    };

    let received_frame = transport.receive().unwrap();

    assert_eq!(
        received_frame.as_slice(),
        &[
            HDLC_FLAG,
            0x01,
            0x7D,
            0x5E,
            0x03,
            0x7D,
            0x5D,
            0x05,
            HDLC_FLAG
        ]
    );
}
