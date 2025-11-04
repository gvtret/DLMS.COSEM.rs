use dlms_cosem::client::Client;
use dlms_cosem::server::Server;
use dlms_cosem::transport::Transport;
use heapless::Vec;
use std::sync::mpsc;

struct SharedMockTransport {
    tx: mpsc::Sender<Vec<u8, 2048>>,
    rx: mpsc::Receiver<Vec<u8, 2048>>,
}

impl Transport for SharedMockTransport {
    type Error = ();

    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let mut vec = Vec::new();
        vec.extend_from_slice(bytes).unwrap();
        self.tx.send(vec).unwrap();
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8, 2048>, Self::Error> {
        Ok(self.rx.recv().unwrap())
    }
}

use std::thread;

#[test]
fn test_association() {
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

    let aare = client.associate().unwrap();
    assert_eq!(aare.result, 0);

    // Not the best way to end the test, but it will do for now
    // server_thread.join().unwrap();
}
