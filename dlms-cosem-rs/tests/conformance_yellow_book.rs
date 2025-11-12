#![cfg(feature = "std")]

use dlms_cosem::client::Client;
use dlms_cosem::cosem::{CosemAttributeDescriptor, CosemMethodDescriptor};
use dlms_cosem::cosem_object::CosemObject;
use dlms_cosem::hdlc_transport::HdlcTransport;
use dlms_cosem::register::Register;
use dlms_cosem::server::Server;
use dlms_cosem::types::CosemData;
use dlms_cosem::xdlms::{
    ActionRequest, ActionRequestNormal, GetRequest, GetRequestNormal, SetRequest, SetRequestNormal,
};
use std::boxed::Box;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::vec::Vec;

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

#[test]
fn yellow_book_conformance_test_get_request() {
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

    let instance_id = [0, 0, 1, 0, 0, 255];
    let mut register = Register::new();
    register.set_attribute(2, CosemData::Unsigned(10)).unwrap();
    server.register_object(instance_id, Box::new(register));

    let _server_thread = thread::spawn(move || {
        let _ = server.run();
    });

    client.associate().expect("Association failed");

    let req = GetRequest::Normal(GetRequestNormal {
        invoke_id_and_priority: 1,
        cosem_attribute_descriptor: CosemAttributeDescriptor {
            class_id: 3,
            instance_id,
            attribute_id: 2,
        },
        access_selection: None,
    });

    let res = client.send_get_request(req).unwrap();
    if let dlms_cosem::xdlms::GetResponse::Normal(res) = res {
        if let dlms_cosem::xdlms::GetDataResult::Data(data) = res.result {
            assert_eq!(data, CosemData::Unsigned(10));
        } else {
            panic!("Incorrect response type");
        }
    } else {
        panic!("Incorrect response type");
    }
}

#[test]
fn yellow_book_conformance_test_set_request() {
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

    let instance_id = [0, 0, 1, 0, 0, 255];
    let register = Register::new();
    server.register_object(instance_id, Box::new(register));

    let _server_thread = thread::spawn(move || {
        let _ = server.run();
    });

    client.associate().expect("Association failed");

    let req = SetRequest::Normal(SetRequestNormal {
        invoke_id_and_priority: 1,
        cosem_attribute_descriptor: CosemAttributeDescriptor {
            class_id: 3,
            instance_id,
            attribute_id: 2,
        },
        access_selection: None,
        value: CosemData::Unsigned(20),
    });
    client.send_set_request(req).unwrap();

    let req = GetRequest::Normal(GetRequestNormal {
        invoke_id_and_priority: 1,
        cosem_attribute_descriptor: CosemAttributeDescriptor {
            class_id: 3,
            instance_id,
            attribute_id: 2,
        },
        access_selection: None,
    });

    let res = client.send_get_request(req).unwrap();
    if let dlms_cosem::xdlms::GetResponse::Normal(res) = res {
        if let dlms_cosem::xdlms::GetDataResult::Data(data) = res.result {
            assert_eq!(data, CosemData::Unsigned(20));
        } else {
            panic!("Incorrect response type");
        }
    } else {
        panic!("Incorrect response type");
    }
}

#[test]
fn yellow_book_conformance_test_action_request() {
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

    let instance_id = [0, 0, 15, 0, 0, 255];
    let association_ln = dlms_cosem::association_ln::AssociationLN::new(
        Arc::new(Mutex::new(Vec::new())),
        0,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    server.register_object(instance_id, Box::new(association_ln));

    let _server_thread = thread::spawn(move || {
        let _ = server.run();
    });

    client.associate().expect("Association failed");

    let mut challenge = Vec::new();
    challenge.extend_from_slice(b"client_challenge");
    let req = ActionRequest::Normal(ActionRequestNormal {
        invoke_id_and_priority: 1,
        cosem_method_descriptor: CosemMethodDescriptor {
            class_id: 15,
            instance_id,
            method_id: 1,
        },
        method_invocation_parameters: Some(CosemData::OctetString(challenge)),
    });

    let res = client.send_action_request(req).unwrap();
    if let dlms_cosem::xdlms::ActionResponse::Normal(res) = res {
        assert_eq!(
            res.single_response.result,
            dlms_cosem::xdlms::ActionResult::Success
        );
        if let Some(dlms_cosem::xdlms::GetDataResult::Data(CosemData::OctetString(response))) =
            res.single_response.return_parameters
        {
            assert_eq!(response.as_slice(), b"server_response");
        } else {
            panic!("Incorrect response type");
        }
    } else {
        panic!("Incorrect response type");
    }
}
