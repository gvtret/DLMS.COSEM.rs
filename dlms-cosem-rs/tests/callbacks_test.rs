use dlms_cosem::acse::{AareApdu, AarqApdu};
use dlms_cosem::cosem::{
    CosemAttributeDescriptor, CosemMethodDescriptor, CosemObjectAttributeId, CosemObjectMethodId,
};
use dlms_cosem::cosem_object::{
    AttributeAccessDescriptor, AttributeAccessMode, CosemObject, CosemObjectCallbackHandlers,
    MethodAccessDescriptor, MethodAccessMode,
};
use dlms_cosem::hdlc::HdlcFrame;
use dlms_cosem::server::Server;
use dlms_cosem::transport::Transport;
use dlms_cosem::types::CosemData;
use dlms_cosem::xdlms::{
    ActionRequest, ActionRequestNormal, ActionResponse, ActionResult, AssociationParameters,
    DataAccessResult, GetDataResult, GetRequest, GetRequestNormal, GetResponse,
    InvokeIdAndPriority, SetRequest, SetRequestNormal, SetResponse,
};
use std::sync::{Arc, Mutex};

const SERVER_ADDRESS: u16 = 1;
const LOGICAL_NAME: [u8; 6] = [0, 0, 0, 1, 0, 0];
const CLASS_ID: u16 = 99;
const ATTRIBUTE_ID: CosemObjectAttributeId = 2;
const METHOD_ID: CosemObjectMethodId = 1;
const INVOKE_ID: InvokeIdAndPriority = 0x01;

struct DummyTransport;

impl Transport for DummyTransport {
    type Error = ();

    fn send(&mut self, _bytes: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        Ok(Vec::new())
    }
}

struct TestObject {
    value: Arc<Mutex<CosemData>>,
    action_inputs: Arc<Mutex<Vec<CosemData>>>,
    log: Arc<Mutex<Vec<&'static str>>>,
    callbacks: Arc<CosemObjectCallbackHandlers>,
}

impl TestObject {
    fn new(initial: CosemData) -> Self {
        Self {
            value: Arc::new(Mutex::new(initial)),
            action_inputs: Arc::new(Mutex::new(Vec::new())),
            log: Arc::new(Mutex::new(Vec::new())),
            callbacks: Arc::new(CosemObjectCallbackHandlers::new()),
        }
    }

    fn value_handle(&self) -> Arc<Mutex<CosemData>> {
        Arc::clone(&self.value)
    }

    fn action_inputs(&self) -> Arc<Mutex<Vec<CosemData>>> {
        Arc::clone(&self.action_inputs)
    }

    fn log(&self) -> Arc<Mutex<Vec<&'static str>>> {
        Arc::clone(&self.log)
    }

    fn callback_handlers(&self) -> Arc<CosemObjectCallbackHandlers> {
        Arc::clone(&self.callbacks)
    }
}

impl CosemObject for TestObject {
    fn class_id(&self) -> u16 {
        CLASS_ID
    }

    fn attribute_access_rights(&self) -> Vec<AttributeAccessDescriptor> {
        vec![AttributeAccessDescriptor::new(
            ATTRIBUTE_ID,
            AttributeAccessMode::ReadWrite,
        )]
    }

    fn method_access_rights(&self) -> Vec<MethodAccessDescriptor> {
        vec![MethodAccessDescriptor::new(
            METHOD_ID,
            MethodAccessMode::Access,
        )]
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        (attribute_id == ATTRIBUTE_ID).then(|| self.value.lock().unwrap().clone())
    }

    fn set_attribute(
        &mut self,
        attribute_id: CosemObjectAttributeId,
        data: CosemData,
    ) -> Option<()> {
        (attribute_id == ATTRIBUTE_ID).then(|| {
            *self.value.lock().unwrap() = data;
        })
    }

    fn invoke_method(
        &mut self,
        method_id: CosemObjectMethodId,
        data: CosemData,
    ) -> Option<CosemData> {
        (method_id == METHOD_ID).then(|| {
            self.action_inputs.lock().unwrap().push(data);
            CosemData::Integer(0)
        })
    }

    fn callbacks(&self) -> Option<Arc<CosemObjectCallbackHandlers>> {
        Some(Arc::clone(&self.callbacks))
    }
}

fn send_frame(server: &mut Server<DummyTransport>, information: Vec<u8>) -> Vec<u8> {
    let frame = HdlcFrame {
        address: SERVER_ADDRESS,
        control: 0,
        information,
    };
    server
        .handle_frame(&frame.to_bytes().expect("hdlc frame serialization"))
        .expect("server response")
}

fn establish_association(server: &mut Server<DummyTransport>) {
    let params = AssociationParameters::default();
    let initiate_request = params.to_initiate_request();
    let user_information = initiate_request
        .to_user_information()
        .expect("initiate request encoding");

    let aarq = AarqApdu {
        application_context_name: b"LN_WITH_NO_CIPHERING".to_vec(),
        sender_acse_requirements: 0,
        mechanism_name: None,
        calling_authentication_value: None,
        user_information,
    };

    let response = send_frame(server, aarq.to_bytes().expect("aarq encoding"));
    let frame = HdlcFrame::from_bytes(&response).expect("response frame");
    let (_, aare) = AareApdu::from_bytes(&frame.information).expect("aare decoding");
    assert_eq!(aare.result, 0);
}

fn decode_get_response(bytes: Vec<u8>) -> GetResponse {
    let frame = HdlcFrame::from_bytes(&bytes).expect("get response frame");
    GetResponse::from_bytes(&frame.information).expect("get response decoding")
}

fn decode_set_response(bytes: Vec<u8>) -> SetResponse {
    let frame = HdlcFrame::from_bytes(&bytes).expect("set response frame");
    SetResponse::from_bytes(&frame.information).expect("set response decoding")
}

fn decode_action_response(bytes: Vec<u8>) -> ActionResponse {
    let frame = HdlcFrame::from_bytes(&bytes).expect("action response frame");
    ActionResponse::from_bytes(&frame.information).expect("action response decoding")
}

#[test]
fn callbacks_success_flow() {
    let transport = DummyTransport;
    let mut server = Server::new(SERVER_ADDRESS, transport, None, None);

    let test_object = TestObject::new(CosemData::Integer(5));
    let value_handle = test_object.value_handle();
    let action_inputs = test_object.action_inputs();
    let log_handle = test_object.log();
    let callbacks = test_object.callback_handlers();

    callbacks.set_pre_read({
        let log = Arc::clone(&log_handle);
        move |_, attribute_id| {
            log.lock().unwrap().push("pre_read");
            assert_eq!(attribute_id, ATTRIBUTE_ID);
            Ok(())
        }
    });

    callbacks.set_post_read({
        let log = Arc::clone(&log_handle);
        move |_, attribute_id, result| {
            log.lock().unwrap().push("post_read");
            assert_eq!(attribute_id, ATTRIBUTE_ID);
            *result = Some(CosemData::Integer(123));
            Ok(())
        }
    });

    callbacks.set_pre_write({
        let log = Arc::clone(&log_handle);
        move |_, attribute_id, value| {
            log.lock().unwrap().push("pre_write");
            assert_eq!(attribute_id, ATTRIBUTE_ID);
            *value = CosemData::Integer(7);
            Ok(())
        }
    });

    callbacks.set_post_write({
        let log = Arc::clone(&log_handle);
        move |_, attribute_id, value| {
            log.lock().unwrap().push("post_write");
            assert_eq!(attribute_id, ATTRIBUTE_ID);
            assert_eq!(*value, CosemData::Integer(7));
            Ok(())
        }
    });

    callbacks.set_pre_action({
        let log = Arc::clone(&log_handle);
        move |_, method_id, parameters| {
            log.lock().unwrap().push("pre_action");
            assert_eq!(method_id, METHOD_ID);
            *parameters = CosemData::Integer(99);
            Ok(())
        }
    });

    callbacks.set_post_action({
        let log = Arc::clone(&log_handle);
        move |_, method_id, result| {
            log.lock().unwrap().push("post_action");
            assert_eq!(method_id, METHOD_ID);
            *result = Some(CosemData::Integer(42));
            Ok(())
        }
    });

    server.register_object(LOGICAL_NAME, Box::new(test_object));
    establish_association(&mut server);

    let get_request = GetRequest::Normal(GetRequestNormal {
        invoke_id_and_priority: INVOKE_ID,
        cosem_attribute_descriptor: CosemAttributeDescriptor {
            class_id: CLASS_ID,
            instance_id: LOGICAL_NAME,
            attribute_id: ATTRIBUTE_ID,
        },
        access_selection: None,
    });
    let get_response = decode_get_response(send_frame(
        &mut server,
        get_request.to_bytes().expect("get request encoding"),
    ));
    match get_response {
        GetResponse::Normal(normal) => match normal.result {
            GetDataResult::Data(data) => assert_eq!(data, CosemData::Integer(123)),
            other => panic!("unexpected get result: {:?}", other),
        },
        other => panic!("unexpected get response: {:?}", other),
    }

    let set_request = SetRequest::Normal(SetRequestNormal {
        invoke_id_and_priority: INVOKE_ID,
        cosem_attribute_descriptor: CosemAttributeDescriptor {
            class_id: CLASS_ID,
            instance_id: LOGICAL_NAME,
            attribute_id: ATTRIBUTE_ID,
        },
        access_selection: None,
        value: CosemData::Integer(9),
    });
    let set_response = decode_set_response(send_frame(
        &mut server,
        set_request.to_bytes().expect("set request encoding"),
    ));
    match set_response {
        SetResponse::Normal(normal) => {
            assert_eq!(normal.result, DataAccessResult::Success);
        }
        other => panic!("unexpected set response: {:?}", other),
    }
    assert_eq!(*value_handle.lock().unwrap(), CosemData::Integer(7));

    let action_request = ActionRequest::Normal(ActionRequestNormal {
        invoke_id_and_priority: INVOKE_ID,
        cosem_method_descriptor: CosemMethodDescriptor {
            class_id: CLASS_ID,
            instance_id: LOGICAL_NAME,
            method_id: METHOD_ID,
        },
        method_invocation_parameters: Some(CosemData::Integer(1)),
    });
    let action_response = decode_action_response(send_frame(
        &mut server,
        action_request.to_bytes().expect("action request encoding"),
    ));
    match action_response {
        ActionResponse::Normal(normal) => {
            assert_eq!(normal.single_response.result, ActionResult::Success);
            let return_value = normal
                .single_response
                .return_parameters
                .expect("expected return value");
            match return_value {
                GetDataResult::Data(data) => assert_eq!(data, CosemData::Integer(42)),
                other => panic!("unexpected action return: {:?}", other),
            }
        }
        other => panic!("unexpected action response: {:?}", other),
    }

    assert_eq!(
        action_inputs.lock().unwrap().as_slice(),
        &[CosemData::Integer(99)]
    );
    assert_eq!(
        log_handle.lock().unwrap().as_slice(),
        &[
            "pre_read",
            "post_read",
            "pre_write",
            "post_write",
            "pre_action",
            "post_action"
        ]
    );
}

#[test]
fn callbacks_error_flow() {
    let transport = DummyTransport;
    let mut server = Server::new(SERVER_ADDRESS, transport, None, None);

    let test_object = TestObject::new(CosemData::Integer(0));
    let value_handle = test_object.value_handle();
    let callbacks = test_object.callback_handlers();

    callbacks.set_pre_read(|_, _| Err(DataAccessResult::TemporaryFailure));

    server.register_object(LOGICAL_NAME, Box::new(test_object));
    establish_association(&mut server);

    let get_request = GetRequest::Normal(GetRequestNormal {
        invoke_id_and_priority: INVOKE_ID,
        cosem_attribute_descriptor: CosemAttributeDescriptor {
            class_id: CLASS_ID,
            instance_id: LOGICAL_NAME,
            attribute_id: ATTRIBUTE_ID,
        },
        access_selection: None,
    });
    let get_response = decode_get_response(send_frame(
        &mut server,
        get_request.to_bytes().expect("get request encoding"),
    ));
    match get_response {
        GetResponse::Normal(normal) => match normal.result {
            GetDataResult::DataAccessResult(result) => {
                assert_eq!(result, DataAccessResult::TemporaryFailure)
            }
            other => panic!("unexpected get result: {:?}", other),
        },
        other => panic!("unexpected get response: {:?}", other),
    }

    callbacks.clear_pre_read();
    callbacks.set_pre_write(|_, _, _| Err(DataAccessResult::TemporaryFailure));

    let set_request = SetRequest::Normal(SetRequestNormal {
        invoke_id_and_priority: INVOKE_ID,
        cosem_attribute_descriptor: CosemAttributeDescriptor {
            class_id: CLASS_ID,
            instance_id: LOGICAL_NAME,
            attribute_id: ATTRIBUTE_ID,
        },
        access_selection: None,
        value: CosemData::Integer(3),
    });
    let set_response = decode_set_response(send_frame(
        &mut server,
        set_request.to_bytes().expect("set request encoding"),
    ));
    match set_response {
        SetResponse::Normal(normal) => {
            assert_eq!(normal.result, DataAccessResult::TemporaryFailure);
        }
        other => panic!("unexpected set response: {:?}", other),
    }
    assert_eq!(*value_handle.lock().unwrap(), CosemData::Integer(0));

    callbacks.clear_pre_write();
    callbacks.set_post_action(|_, _, _| Err(ActionResult::TemporaryFailure));

    let action_request = ActionRequest::Normal(ActionRequestNormal {
        invoke_id_and_priority: INVOKE_ID,
        cosem_method_descriptor: CosemMethodDescriptor {
            class_id: CLASS_ID,
            instance_id: LOGICAL_NAME,
            method_id: METHOD_ID,
        },
        method_invocation_parameters: Some(CosemData::Integer(0)),
    });
    let action_response = decode_action_response(send_frame(
        &mut server,
        action_request.to_bytes().expect("action request encoding"),
    ));
    match action_response {
        ActionResponse::Normal(normal) => {
            assert_eq!(
                normal.single_response.result,
                ActionResult::TemporaryFailure
            );
            assert!(normal.single_response.return_parameters.is_none());
        }
        other => panic!("unexpected action response: {:?}", other),
    }
}
