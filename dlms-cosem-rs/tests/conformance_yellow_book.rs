#![cfg(feature = "std")]

use dlms_cosem::client::Client;
use dlms_cosem::hdlc_transport::HdlcTransport;
use dlms_cosem::server::Server;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;

struct MockStream {
    tx: mpsc::Sender<u8>,
    rx: mpsc::Receiver<u8>,
}

impl Read for MockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while i < buf.len() {
            match self.rx.recv() {
                Ok(byte) => {
                    buf[i] = byte;
                    i += 1;
                }
                Err(_) => break,
            }
        }
        Ok(i)
    }
}

impl Write for MockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for byte in buf {
            self.tx.send(*byte).unwrap();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn yellow_book_conformance_test_application_association() {
    let (server_tx, client_rx) = mpsc::channel();
    let (client_tx, server_rx) = mpsc::channel();

    let client_stream = MockStream {
        tx: client_tx,
        rx: client_rx,
    };
    let server_stream = MockStream {
        tx: server_tx,
        rx: server_rx,
    };

    let client_transport = HdlcTransport::new(client_stream);
    let server_transport = HdlcTransport::new(server_stream);

    let mut client = Client::new(1, client_transport, None, None);
    let mut server = Server::new(1, server_transport, None, None);

    let _server_thread = thread::spawn(move || {
        let _ = server.run();
    });

    let aare = client.associate().expect("Association failed");
    assert_eq!(aare.result, 0);
}
