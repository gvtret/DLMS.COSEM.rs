use dlms_cosem::client::Client;
use dlms_cosem::hdlc_transport::HdlcTransport;
use dlms_cosem::server::Server;
use dlms_cosem::transport::Transport;
use dlms_cosem::wrapper_transport::WrapperTransport;
use std::io::{Read, Write};
use std::net::TcpListener;
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
fn test_association() {
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

#[test]
fn test_wrapper_transport_send_receive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut transport = WrapperTransport::new(stream);
        let received = transport.receive().unwrap();
        transport.send(&received).unwrap();
    });

    let stream = std::net::TcpStream::connect(addr).unwrap();
    let mut transport = WrapperTransport::new(stream);
    let data_to_send = b"hello world";
    transport.send(data_to_send).unwrap();
    let received_data = transport.receive().unwrap();

    assert_eq!(data_to_send, received_data.as_slice());

    server_thread.join().unwrap();
}
