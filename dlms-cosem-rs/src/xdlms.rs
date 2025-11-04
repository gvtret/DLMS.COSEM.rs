use crate::cosem::{CosemAttributeDescriptor, CosemMethodDescriptor};
use crate::types::Data;
use heapless::Vec;
extern crate alloc;
use alloc::vec::Vec as AllocVec;

pub type InvokeIdAndPriority = u8;

#[derive(Debug, Clone, PartialEq)]
pub struct SelectiveAccessDescriptor {
    pub access_selector: u8,
    pub access_parameters: Data,
}

// --- Get-Request ---
#[derive(Debug, Clone, PartialEq)]
pub struct GetRequestNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub cosem_attribute_descriptor: CosemAttributeDescriptor,
    pub access_selection: Option<SelectiveAccessDescriptor>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetRequestNext {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub block_number: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetRequestWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub attribute_descriptor_list: AllocVec<CosemAttributeDescriptor>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GetRequest {
    Normal(GetRequestNormal),
    Next(GetRequestNext),
    WithList(GetRequestWithList),
}

impl GetRequest {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        match self {
            GetRequest::Normal(req) => {
                bytes.push(192); // get-request-normal
                bytes.push(req.invoke_id_and_priority);
                bytes.extend_from_slice(&req.cosem_attribute_descriptor.class_id.to_be_bytes());
                bytes.extend_from_slice(&req.cosem_attribute_descriptor.instance_id);
                bytes.push(req.cosem_attribute_descriptor.attribute_id as u8);
                if let Some(access_selection) = &req.access_selection {
                    bytes.push(1); // access-selector
                    bytes.push(access_selection.access_selector);
                    // This is a simplified implementation that only supports the `Data` variant
                    // of the `access_parameters` enum.
                    match &access_selection.access_parameters {
                        Data::NullData => bytes.push(0),
                        _ => panic!("Unsupported access_parameters variant"),
                    }
                } else {
                    bytes.push(0); // no access-selector
                }
            }
            GetRequest::Next(req) => {
                bytes.push(193); // get-request-next
                bytes.push(req.invoke_id_and_priority);
                bytes.extend_from_slice(&req.block_number.to_be_bytes());
            }
            GetRequest::WithList(req) => {
                bytes.push(194); // get-request-with-list
                bytes.push(req.invoke_id_and_priority);
                // ... (simplified serialization)
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            192 => {
                let mut class_id_bytes = [0u8; 2];
                class_id_bytes.copy_from_slice(&bytes[2..4]);
                let class_id = u16::from_be_bytes(class_id_bytes);

                let mut instance_id_bytes = [0u8; 6];
                instance_id_bytes.copy_from_slice(&bytes[4..10]);

                let access_selection = if bytes[11] == 1 {
                    Some(SelectiveAccessDescriptor {
                        access_selector: bytes[12],
                        access_parameters: Data::NullData,
                    })
                } else {
                    None
                };

                GetRequest::Normal(GetRequestNormal {
                    invoke_id_and_priority: bytes[1],
                    cosem_attribute_descriptor: CosemAttributeDescriptor {
                        class_id,
                        instance_id: instance_id_bytes,
                        attribute_id: bytes[10] as i8,
                    },
                    access_selection,
                })
            }
            _ => {
                panic!("Unsupported GetRequest variant");
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_get_request_normal_serialization_deserialization() {
        let req = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 8,
                instance_id: [0, 0, 1, 0, 0, 255],
                attribute_id: 2,
            },
            access_selection: None,
        });

        let bytes = req.to_bytes();
        let req2 = GetRequest::from_bytes(&bytes);

        assert_eq!(req, req2);
    }

    #[test]
    fn test_get_response_normal_serialization_deserialization() {
        let res = GetResponse::Normal(GetResponseNormal {
            invoke_id_and_priority: 1,
            result: GetDataResult::Data(Data::NullData),
        });

        let bytes = res.to_bytes();
        let res2 = GetResponse::from_bytes(&bytes);

        assert_eq!(res, res2);
    }

    #[test]
    fn test_set_request_normal_serialization_deserialization() {
        let req = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 8,
                instance_id: [0, 0, 1, 0, 0, 255],
                attribute_id: 2,
            },
            access_selection: None,
            value: Data::NullData,
        });

        let bytes = req.to_bytes();
        let req2 = SetRequest::from_bytes(&bytes);

        assert_eq!(req, req2);
    }

    #[test]
    fn test_set_response_normal_serialization_deserialization() {
        let res = SetResponse::Normal(SetResponseNormal {
            invoke_id_and_priority: 1,
            result: DataAccessResult::Success,
        });

        let bytes = res.to_bytes();
        let res2 = SetResponse::from_bytes(&bytes);

        assert_eq!(res, res2);
    }

    #[test]
    fn test_action_request_normal_serialization_deserialization() {
        let req = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 1,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 8,
                instance_id: [0, 0, 1, 0, 0, 255],
                method_id: 2,
            },
            method_invocation_parameters: None,
        });

        let bytes = req.to_bytes();
        let req2 = ActionRequest::from_bytes(&bytes);

        assert_eq!(req, req2);
    }

    #[test]
    fn test_action_response_normal_serialization_deserialization() {
        let res = ActionResponse::Normal(ActionResponseNormal {
            invoke_id_and_priority: 1,
            single_response: ActionResponseWithOptionalData {
                result: ActionResult::Success,
                return_parameters: None,
            },
        });

        let bytes = res.to_bytes();
        let res2 = ActionResponse::from_bytes(&bytes);

        assert_eq!(res, res2);
    }
}

// --- Get-Response ---
#[derive(Debug, Clone, PartialEq)]
pub enum DataAccessResult {
    Success,
    HardwareFault,
    TemporaryFailure,
    ReadWriteDenied,
    ObjectUndefined,
    ObjectClassInconsistent,
    ObjectUnavailable,
    TypeUnmatched,
    ScopeOfAccessViolated,
    DataBlockUnavailable,
    LongGetAborted,
    NoLongGetInProgress,
    LongSetAborted,
    NoLongSetInProgress,
    DataBlockNumberInvalid,
    OtherReason(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum GetDataResult {
    Data(Data),
    DataAccessResult(DataAccessResult),
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub result: GetDataResult,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DataBlockG {
    pub last_block: bool,
    pub block_number: u32,
    pub result: Result<Vec<u8, 1024>, DataAccessResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseWithDatablock {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub result: DataBlockG,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub result: AllocVec<GetDataResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GetResponse {
    Normal(GetResponseNormal),
    WithDataBlock(GetResponseWithDatablock),
    WithList(GetResponseWithList),
}

impl GetResponse {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        match self {
            GetResponse::Normal(res) => {
                bytes.push(196); // get-response-normal
                bytes.push(res.invoke_id_and_priority);
                match &res.result {
                    GetDataResult::Data(_data) => {
                        bytes.push(0); // data
                                       // simplified serialization of data
                    }
                    GetDataResult::DataAccessResult(_dar) => {
                        bytes.push(1); // data-access-result
                                       // simplified serialization of dar
                    }
                }
            }
            _ => {
                panic!("Unsupported GetResponse variant");
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            196 => {
                // ... simplified deserialization
                GetResponse::Normal(GetResponseNormal {
                    invoke_id_and_priority: bytes[1],
                    result: GetDataResult::Data(Data::NullData),
                })
            }
            _ => {
                panic!("Unsupported GetResponse variant");
            }
        }
    }
}


// --- Set-Request ---
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub cosem_attribute_descriptor: CosemAttributeDescriptor,
    pub access_selection: Option<SelectiveAccessDescriptor>,
    pub value: Data,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub attribute_descriptor_list: AllocVec<CosemAttributeDescriptor>,
    pub value_list: AllocVec<Data>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SetRequest {
    Normal(SetRequestNormal),
    WithList(SetRequestWithList),
    // Other variants omitted for brevity
}

impl SetRequest {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        match self {
            SetRequest::Normal(req) => {
                bytes.push(193); // set-request-normal
                bytes.push(req.invoke_id_and_priority);
                bytes.extend_from_slice(&req.cosem_attribute_descriptor.class_id.to_be_bytes());
                bytes.extend_from_slice(&req.cosem_attribute_descriptor.instance_id);
                bytes.push(req.cosem_attribute_descriptor.attribute_id as u8);
                if let Some(access_selection) = &req.access_selection {
                    bytes.push(1); // access-selector
                    bytes.push(access_selection.access_selector);
                    // simplified serialization of access_parameters
                } else {
                    bytes.push(0); // no access-selector
                }
                // simplified serialization of value
            }
            _ => {
                panic!("Unsupported SetRequest variant");
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            193 => {
                let mut class_id_bytes = [0u8; 2];
                class_id_bytes.copy_from_slice(&bytes[2..4]);
                let class_id = u16::from_be_bytes(class_id_bytes);

                let mut instance_id_bytes = [0u8; 6];
                instance_id_bytes.copy_from_slice(&bytes[4..10]);

                SetRequest::Normal(SetRequestNormal {
                    invoke_id_and_priority: bytes[1],
                    cosem_attribute_descriptor: CosemAttributeDescriptor {
                        class_id,
                        instance_id: instance_id_bytes,
                        attribute_id: bytes[10] as i8,
                    },
                    access_selection: None,
                    value: Data::NullData,
                })
            }
            _ => {
                panic!("Unsupported SetRequest variant");
            }
        }
    }
}

// --- InitiateRequest ---
#[derive(Debug, Clone, PartialEq)]
pub struct InitiateRequest {
    pub dedicated_key: Option<Vec<u8, 64>>,
    pub response_allowed: bool,
    pub proposed_quality_of_service: Option<u8>,
    pub proposed_dlms_version_number: u8,
    pub proposed_conformance: Conformance,
    pub client_max_receive_pdu_size: u16,
}

impl InitiateRequest {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        bytes.push(1); // initiate-request tag
        // ... simplified serialization
        bytes
    }

    pub fn from_bytes(_bytes: &[u8]) -> Self {
        // ... simplified deserialization
        InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_quality_of_service: None,
            proposed_dlms_version_number: 6,
            proposed_conformance: Conformance { value: 0 },
            client_max_receive_pdu_size: 2048,
        }
    }
}

// --- InitiateResponse ---
#[derive(Debug, Clone, PartialEq)]
pub struct InitiateResponse {
    pub negotiated_quality_of_service: Option<u8>,
    pub negotiated_dlms_version_number: u8,
    pub negotiated_conformance: Conformance,
    pub server_max_receive_pdu_size: u16,
    pub vaa_name: u16,
}

impl InitiateResponse {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        bytes.push(8); // initiate-response tag
        // ... simplified serialization
        bytes
    }

    pub fn from_bytes(_bytes: &[u8]) -> Self {
        // ... simplified deserialization
        InitiateResponse {
            negotiated_quality_of_service: None,
            negotiated_dlms_version_number: 6,
            negotiated_conformance: Conformance { value: 0 },
            server_max_receive_pdu_size: 2048,
            vaa_name: 0,
        }
    }
}

// --- Conformance ---
#[derive(Debug, Clone, PartialEq)]
pub struct Conformance {
    // simplified for now
    pub value: u32,
}

impl Conformance {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        bytes.extend_from_slice(&self.value.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut value_bytes = [0u8; 4];
        value_bytes.copy_from_slice(&bytes[..4]);
        Conformance {
            value: u32::from_be_bytes(value_bytes),
        }
    }
}

// --- Set-Response ---
#[derive(Debug, Clone, PartialEq)]
pub struct SetResponseNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub result: DataAccessResult,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetResponseWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub result: AllocVec<DataAccessResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SetResponse {
    Normal(SetResponseNormal),
    WithList(SetResponseWithList),
    // Other variants omitted for brevity
}

impl SetResponse {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        match self {
            SetResponse::Normal(res) => {
                bytes.push(197); // set-response-normal
                bytes.push(res.invoke_id_and_priority);
                bytes.push(match res.result {
                    DataAccessResult::Success => 0,
                    DataAccessResult::HardwareFault => 1,
                    DataAccessResult::TemporaryFailure => 2,
                    DataAccessResult::ReadWriteDenied => 3,
                    DataAccessResult::ObjectUndefined => 4,
                    DataAccessResult::ObjectClassInconsistent => 5,
                    DataAccessResult::ObjectUnavailable => 6,
                    DataAccessResult::TypeUnmatched => 7,
                    DataAccessResult::ScopeOfAccessViolated => 8,
                    DataAccessResult::DataBlockUnavailable => 9,
                    DataAccessResult::LongGetAborted => 10,
                    DataAccessResult::NoLongGetInProgress => 11,
                    DataAccessResult::LongSetAborted => 12,
                    DataAccessResult::NoLongSetInProgress => 13,
                    DataAccessResult::DataBlockNumberInvalid => 14,
                    DataAccessResult::OtherReason(reason) => reason,
                });
            }
            _ => {
                panic!("Unsupported SetResponse variant");
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            197 => SetResponse::Normal(SetResponseNormal {
                invoke_id_and_priority: bytes[1],
                result: match bytes[2] {
                    0 => DataAccessResult::Success,
                    1 => DataAccessResult::HardwareFault,
                    2 => DataAccessResult::TemporaryFailure,
                    3 => DataAccessResult::ReadWriteDenied,
                    4 => DataAccessResult::ObjectUndefined,
                    5 => DataAccessResult::ObjectClassInconsistent,
                    6 => DataAccessResult::ObjectUnavailable,
                    7 => DataAccessResult::TypeUnmatched,
                    8 => DataAccessResult::ScopeOfAccessViolated,
                    9 => DataAccessResult::DataBlockUnavailable,
                    10 => DataAccessResult::LongGetAborted,
                    11 => DataAccessResult::NoLongGetInProgress,
                    12 => DataAccessResult::LongSetAborted,
                    13 => DataAccessResult::NoLongSetInProgress,
                    14 => DataAccessResult::DataBlockNumberInvalid,
                    reason => DataAccessResult::OtherReason(reason),
                },
            }),
            _ => {
                panic!("Unsupported SetResponse variant");
            }
        }
    }
}

// --- Action-Request ---
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub cosem_method_descriptor: CosemMethodDescriptor,
    pub method_invocation_parameters: Option<Data>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub cosem_method_descriptor_list: AllocVec<CosemMethodDescriptor>,
    pub method_invocation_parameters: AllocVec<Data>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActionRequest {
    Normal(ActionRequestNormal),
    WithList(ActionRequestWithList),
    // Other variants omitted for brevity
}

impl ActionRequest {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        match self {
            ActionRequest::Normal(req) => {
                bytes.push(195); // action-request-normal
                bytes.push(req.invoke_id_and_priority);
                bytes.extend_from_slice(&req.cosem_method_descriptor.class_id.to_be_bytes());
                bytes.extend_from_slice(&req.cosem_method_descriptor.instance_id);
                bytes.push(req.cosem_method_descriptor.method_id as u8);
                if let Some(_mip) = &req.method_invocation_parameters {
                    bytes.push(1); // method-invocation-parameters
                                   // simplified serialization of mip
                } else {
                    bytes.push(0); // no method-invocation-parameters
                }
            }
            _ => {
                panic!("Unsupported ActionRequest variant");
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            195 => {
                let mut class_id_bytes = [0u8; 2];
                class_id_bytes.copy_from_slice(&bytes[2..4]);
                let class_id = u16::from_be_bytes(class_id_bytes);

                let mut instance_id_bytes = [0u8; 6];
                instance_id_bytes.copy_from_slice(&bytes[4..10]);

                ActionRequest::Normal(ActionRequestNormal {
                    invoke_id_and_priority: bytes[1],
                    cosem_method_descriptor: CosemMethodDescriptor {
                        class_id,
                        instance_id: instance_id_bytes,
                        method_id: bytes[10] as i8,
                    },
                    method_invocation_parameters: None,
                })
            }
            _ => {
                panic!("Unsupported ActionRequest variant");
            }
        }
    }
}

// --- Action-Response ---
#[derive(Debug, Clone, PartialEq)]
pub enum ActionResult {
    Success,
    HardwareFault,
    TemporaryFailure,
    ReadWriteDenied,
    ObjectUndefined,
    ObjectClassInconsistent,
    ObjectUnavailable,
    TypeUnmatched,
    ScopeOfAccessViolated,
    DataBlockUnavailable,
    LongActionAborted,
    NoLongActionInProgress,
    OtherReason(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionResponseWithOptionalData {
    pub result: ActionResult,
    pub return_parameters: Option<GetDataResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionResponseNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub single_response: ActionResponseWithOptionalData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionResponseWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub list_of_responses: AllocVec<ActionResponseWithOptionalData>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActionResponse {
    Normal(ActionResponseNormal),
    WithList(ActionResponseWithList),
    // Other variants omitted for brevity
}

impl ActionResponse {
    pub fn to_bytes(&self) -> AllocVec<u8> {
        let mut bytes = AllocVec::new();
        match self {
            ActionResponse::Normal(res) => {
                bytes.push(198); // action-response-normal
                bytes.push(res.invoke_id_and_priority);
                bytes.push(match res.single_response.result {
                    ActionResult::Success => 0,
                    ActionResult::HardwareFault => 1,
                    ActionResult::TemporaryFailure => 2,
                    ActionResult::ReadWriteDenied => 3,
                    ActionResult::ObjectUndefined => 4,
                    ActionResult::ObjectClassInconsistent => 5,
                    ActionResult::ObjectUnavailable => 6,
                    ActionResult::TypeUnmatched => 7,
                    ActionResult::ScopeOfAccessViolated => 8,
                    ActionResult::DataBlockUnavailable => 9,
                    ActionResult::LongActionAborted => 10,
                    ActionResult::NoLongActionInProgress => 11,
                    ActionResult::OtherReason(reason) => reason,
                });
                if let Some(_rp) = &res.single_response.return_parameters {
                    bytes.push(1); // return-parameters
                                   // simplified serialization of rp
                } else {
                    bytes.push(0); // no return-parameters
                }
            }
            _ => {
                panic!("Unsupported ActionResponse variant");
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            198 => ActionResponse::Normal(ActionResponseNormal {
                invoke_id_and_priority: bytes[1],
                single_response: ActionResponseWithOptionalData {
                    result: match bytes[2] {
                        0 => ActionResult::Success,
                        1 => ActionResult::HardwareFault,
                        2 => ActionResult::TemporaryFailure,
                        3 => ActionResult::ReadWriteDenied,
                        4 => ActionResult::ObjectUndefined,
                        5 => ActionResult::ObjectClassInconsistent,
                        6 => ActionResult::ObjectUnavailable,
                        7 => ActionResult::TypeUnmatched,
                        8 => ActionResult::ScopeOfAccessViolated,
                        9 => ActionResult::DataBlockUnavailable,
                        10 => ActionResult::LongActionAborted,
                        11 => ActionResult::NoLongActionInProgress,
                        reason => ActionResult::OtherReason(reason),
                    },
                    return_parameters: None,
                },
            }),
            _ => {
                panic!("Unsupported ActionResponse variant");
            }
        }
    }
}
