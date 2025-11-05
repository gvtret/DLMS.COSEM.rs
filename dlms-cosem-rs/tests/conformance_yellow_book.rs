#![cfg(feature = "std")]

use dlms_cosem::client::Client;
use dlms_cosem::server::Server;
use dlms_cosem::transport::Transport;
use heapless::Vec;
use std::sync::mpsc;
use std::thread;

struct SharedMockTransport {
    tx: mpsc::Sender<Vec<u8, 2048>>,
    rx: mpsc::Receiver<Vec<u8, 2048>>,
}

impl Transport for SharedMockTransport {
    type Error = ();

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let mut vec = Vec::new();
        vec.extend_from_slice(bytes).map_err(|_| ())?;
        self.tx.send(vec).map_err(|_| ())
    }

    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error> {
        self.rx.recv().map_err(|_| ())
    }
}

#[test]
fn yellow_book_conformance_test_application_association() {
    let (server_tx, client_rx) = mpsc::channel();
    let (client_tx, server_rx) = mpsc::channel();

    let client_transport = SharedMockTransport {
        tx: client_tx,
        rx: client_rx,
    };
    let server_transport = SharedMockTransport {
        tx: server_tx,
        rx: server_rx,
    };

    let mut client = Client::new(1, client_transport, None, None);
    let mut server = Server::new(1, server_transport, None, None);

    let _server_thread = thread::spawn(move || {
        let _ = server.run();
    });

    let aare = client.associate().expect("Association failed");
    assert_eq!(aare.result, 0);
}
