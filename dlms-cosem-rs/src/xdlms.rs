use crate::cosem::{CosemAttributeDescriptor, CosemMethodDescriptor};
use crate::types::Data;
use nom::{
    bytes::complete::{tag, take},
    combinator::{map, opt},
    sequence::tuple,
    IResult,
};
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
                // ... (simplified serialization)
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
