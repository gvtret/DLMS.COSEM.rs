use crate::axdr::{decode_data, encode_data};
use crate::cosem::{CosemAttributeDescriptor, CosemMethodDescriptor};
use crate::error::DlmsError;
use crate::types::CosemData;
use std::vec::Vec;

fn encode_object_count(len: usize, buffer: &mut Vec<u8>) {
    if len < 0x80 {
        buffer.push(len as u8);
        return;
    }

    let mut bytes = Vec::new();
    let mut value = len;
    while value > 0 {
        bytes.push((value & 0xFF) as u8);
        value >>= 8;
    }
    bytes.reverse();

    buffer.push(0x80 | (bytes.len() as u8));
    buffer.extend_from_slice(&bytes);
}

fn decode_object_count(bytes: &[u8]) -> Result<(usize, usize), DlmsError> {
    if bytes.is_empty() {
        return Err(DlmsError::Xdlms);
    }

    let first = bytes[0];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }

    let count_len = (first & 0x7F) as usize;
    if bytes.len() < 1 + count_len {
        return Err(DlmsError::Xdlms);
    }

    let mut value = 0usize;
    for &byte in &bytes[1..=count_len] {
        value = (value << 8) | byte as usize;
    }

    Ok((value, 1 + count_len))
}

fn decode_octet_string(bytes: &[u8]) -> Result<(&[u8], usize), DlmsError> {
    if bytes.is_empty() || bytes[0] != 0x04 {
        return Err(DlmsError::Xdlms);
    }

    let (len, consumed) = decode_object_count(&bytes[1..])?;
    let start = 1 + consumed;
    let end = start + len;
    if bytes.len() < end {
        return Err(DlmsError::Xdlms);
    }

    Ok((&bytes[start..end], end))
}

pub type InvokeIdAndPriority = u8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conformance {
    pub value: u32,
}

impl Conformance {
    pub fn to_bytes(&self) -> [u8; 3] {
        [
            ((self.value >> 16) & 0xFF) as u8,
            ((self.value >> 8) & 0xFF) as u8,
            (self.value & 0xFF) as u8,
        ]
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.len() < 3 {
            return Err(DlmsError::Xdlms);
        }

        Ok(Conformance {
            value: ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32,
        })
    }

    pub fn intersection(&self, other: &Conformance) -> Conformance {
        Conformance {
            value: self.value & other.value,
        }
    }

    pub fn contains(&self, other: &Conformance) -> bool {
        self.value & other.value == other.value
    }

    pub fn is_empty(&self) -> bool {
        self.value == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationParameters {
    pub dlms_version: u8,
    pub conformance: Conformance,
    pub max_receive_pdu_size: u16,
    pub quality_of_service: Option<u8>,
}

impl Default for AssociationParameters {
    fn default() -> Self {
        AssociationParameters {
            dlms_version: 6,
            conformance: Conformance { value: 0x0010_0000 },
            max_receive_pdu_size: 0x0400,
            quality_of_service: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SelectiveAccessDescriptor {
    pub access_selector: u8,
    pub access_parameters: CosemData,
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
    pub attribute_descriptor_list: Vec<CosemAttributeDescriptor>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GetRequest {
    Normal(GetRequestNormal),
    Next(GetRequestNext),
    WithList(GetRequestWithList),
}

impl GetRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
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
                    encode_data(&access_selection.access_parameters, &mut bytes)?;
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
                bytes.push(req.attribute_descriptor_list.len() as u8);
                for desc in &req.attribute_descriptor_list {
                    bytes.extend_from_slice(&desc.class_id.to_be_bytes());
                    bytes.extend_from_slice(&desc.instance_id);
                    bytes.push(desc.attribute_id as u8);
                }
            }
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() {
            return Err(DlmsError::Xdlms);
        }
        let (tag, rest) = bytes.split_at(1);
        match tag[0] {
            192 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (class_id, rest) = rest.split_at(2);
                let (instance_id, rest) = rest.split_at(6);
                let (attribute_id, rest) = rest.split_at(1);
                let (has_access_selection, rest) = rest.split_at(1);

                let access_selection = if has_access_selection[0] == 1 {
                    let (access_selector, rest) = rest.split_at(1);
                    let (access_parameters, _) = decode_data(rest)?;
                    Some(SelectiveAccessDescriptor {
                        access_selector: access_selector[0],
                        access_parameters,
                    })
                } else {
                    None
                };

                let mut class_id_bytes = [0u8; 2];
                class_id_bytes.copy_from_slice(class_id);

                let mut instance_id_bytes = [0u8; 6];
                instance_id_bytes.copy_from_slice(instance_id);

                Ok(GetRequest::Normal(GetRequestNormal {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    cosem_attribute_descriptor: CosemAttributeDescriptor {
                        class_id: u16::from_be_bytes(class_id_bytes),
                        instance_id: instance_id_bytes,
                        attribute_id: attribute_id[0] as i8,
                    },
                    access_selection,
                }))
            }
            194 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (len, mut rest) = rest.split_at(1);
                let mut attribute_descriptor_list = Vec::new();
                for _ in 0..len[0] {
                    let (class_id, r) = rest.split_at(2);
                    let (instance_id, r) = r.split_at(6);
                    let (attribute_id, r) = r.split_at(1);
                    rest = r;

                    let mut class_id_bytes = [0u8; 2];
                    class_id_bytes.copy_from_slice(class_id);

                    let mut instance_id_bytes = [0u8; 6];
                    instance_id_bytes.copy_from_slice(instance_id);

                    attribute_descriptor_list.push(CosemAttributeDescriptor {
                        class_id: u16::from_be_bytes(class_id_bytes),
                        instance_id: instance_id_bytes,
                        attribute_id: attribute_id[0] as i8,
                    });
                }
                Ok(GetRequest::WithList(GetRequestWithList {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    attribute_descriptor_list,
                }))
            }
            _ => Err(DlmsError::Xdlms),
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

        let bytes = req.to_bytes().unwrap();
        let req2 = GetRequest::from_bytes(&bytes).unwrap();

        assert_eq!(req, req2);
    }

    #[test]
    fn test_get_request_with_list_serialization_deserialization() {
        let list = vec![
            CosemAttributeDescriptor {
                class_id: 8,
                instance_id: [0, 0, 1, 0, 0, 255],
                attribute_id: 2,
            },
            CosemAttributeDescriptor {
                class_id: 3,
                instance_id: [0, 0, 2, 0, 0, 255],
                attribute_id: 3,
            },
        ];

        let req = GetRequest::WithList(GetRequestWithList {
            invoke_id_and_priority: 1,
            attribute_descriptor_list: list,
        });

        let bytes = req.to_bytes().unwrap();
        let req2 = GetRequest::from_bytes(&bytes).unwrap();

        assert_eq!(req, req2);
    }

    #[test]
    fn test_get_response_normal_serialization_deserialization() {
        let res = GetResponse::Normal(GetResponseNormal {
            invoke_id_and_priority: 1,
            result: GetDataResult::Data(CosemData::NullData),
        });

        let bytes = res.to_bytes().unwrap();
        let res2 = GetResponse::from_bytes(&bytes).unwrap();

        assert_eq!(res, res2);
    }

    #[test]
    fn test_get_response_with_list_serialization_deserialization() {
        let list = vec![
            GetDataResult::Data(CosemData::NullData),
            GetDataResult::DataAccessResult(DataAccessResult::Success),
        ];

        let res = GetResponse::WithList(GetResponseWithList {
            invoke_id_and_priority: 1,
            result: list,
        });

        let bytes = res.to_bytes().unwrap();
        let res2 = GetResponse::from_bytes(&bytes).unwrap();

        assert_eq!(res, res2);
    }

    #[test]
    fn test_get_response_with_datablock_serialization_deserialization() {
        let mut data = Vec::new();
        data.extend_from_slice(b"hello world");
        let res = GetResponse::WithDataBlock(GetResponseWithDatablock {
            invoke_id_and_priority: 1,
            result: DataBlockG {
                last_block: true,
                block_number: 1,
                raw_data: data,
            },
        });

        let bytes = res.to_bytes().unwrap();
        let res2 = GetResponse::from_bytes(&bytes).unwrap();

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
            value: CosemData::NullData,
        });

        let bytes = req.to_bytes().unwrap();
        let req2 = SetRequest::from_bytes(&bytes).unwrap();

        assert_eq!(req, req2);
    }

    #[test]
    fn test_set_response_normal_serialization_deserialization() {
        let res = SetResponse::Normal(SetResponseNormal {
            invoke_id_and_priority: 1,
            result: DataAccessResult::Success,
        });

        let bytes = res.to_bytes().unwrap();
        let res2 = SetResponse::from_bytes(&bytes).unwrap();

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

        let bytes = req.to_bytes().unwrap();
        let req2 = ActionRequest::from_bytes(&bytes).unwrap();

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

        let bytes = res.to_bytes().unwrap();
        let res2 = ActionResponse::from_bytes(&bytes).unwrap();

        assert_eq!(res, res2);
    }

    #[test]
    fn test_initiate_request_round_trip() {
        let req = InitiateRequest {
            dedicated_key: Some(vec![0x01, 0x02, 0x03, 0x04]),
            response_allowed: false,
            proposed_quality_of_service: Some(0x05),
            proposed_dlms_version_number: 6,
            proposed_conformance: Conformance { value: 0x0001_0203 },
            client_max_receive_pdu_size: 0x0400,
        };

        let bytes = req.to_bytes().unwrap();
        let decoded = InitiateRequest::from_bytes(&bytes).unwrap();
        assert_eq!(req, decoded);

        let user_information = req.to_user_information().unwrap();
        let decoded_from_ui = InitiateRequest::from_user_information(&user_information).unwrap();
        assert_eq!(req, decoded_from_ui);
    }

    #[test]
    fn test_initiate_response_round_trip() {
        let res = InitiateResponse {
            negotiated_quality_of_service: Some(0x01),
            negotiated_dlms_version_number: 6,
            negotiated_conformance: Conformance { value: 0x0010_0000 },
            server_max_receive_pdu_size: 0x0800,
            vaa_name: 0x0007,
        };

        let bytes = res.to_bytes().unwrap();
        let decoded = InitiateResponse::from_bytes(&bytes).unwrap();
        assert_eq!(res, decoded);

        let user_information = res.to_user_information().unwrap();
        let decoded_from_ui = InitiateResponse::from_user_information(&user_information).unwrap();
        assert_eq!(res, decoded_from_ui);
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

impl From<DataAccessResult> for u8 {
    fn from(val: DataAccessResult) -> Self {
        match val {
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
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum GetDataResult {
    Data(CosemData),
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
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseWithDatablock {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub result: DataBlockG,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetResponseWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub result: Vec<GetDataResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GetResponse {
    Normal(GetResponseNormal),
    WithDataBlock(GetResponseWithDatablock),
    WithList(GetResponseWithList),
}

impl GetResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        match self {
            GetResponse::Normal(res) => {
                bytes.push(196); // get-response-normal
                bytes.push(res.invoke_id_and_priority);
                match &res.result {
                    GetDataResult::Data(data) => {
                        bytes.push(0); // data
                        encode_data(data, &mut bytes)?;
                    }
                    GetDataResult::DataAccessResult(dar) => {
                        bytes.push(1); // data-access-result
                        bytes.push(dar.clone().into());
                    }
                }
            }
            GetResponse::WithList(res) => {
                bytes.push(198); // get-response-with-list
                bytes.push(res.invoke_id_and_priority);
                bytes.push(res.result.len() as u8);
                for item in &res.result {
                    match item {
                        GetDataResult::Data(data) => {
                            bytes.push(0); // data
                            encode_data(data, &mut bytes)?;
                        }
                        GetDataResult::DataAccessResult(dar) => {
                            bytes.push(1); // data-access-result
                            bytes.push(dar.clone().into());
                        }
                    }
                }
            }
            GetResponse::WithDataBlock(res) => {
                bytes.push(197); // get-response-with-datablock
                bytes.push(res.invoke_id_and_priority);
                bytes.push(res.result.last_block as u8);
                bytes.extend_from_slice(&res.result.block_number.to_be_bytes());
                bytes.extend_from_slice(&res.result.raw_data);
            }
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() {
            return Err(DlmsError::Xdlms);
        }
        let (tag, rest) = bytes.split_at(1);
        match tag[0] {
            196 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (result_type, rest) = rest.split_at(1);
                let result = if result_type[0] == 0 {
                    let (data, _) = decode_data(rest)?;
                    GetDataResult::Data(data)
                } else {
                    let (dar, _) = rest.split_at(1);
                    GetDataResult::DataAccessResult(match dar[0] {
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
                    })
                };
                Ok(GetResponse::Normal(GetResponseNormal {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    result,
                }))
            }
            198 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (len, mut rest) = rest.split_at(1);
                let mut result = Vec::new();
                for _ in 0..len[0] {
                    let (result_type, r) = rest.split_at(1);
                    rest = r;
                    let item = if result_type[0] == 0 {
                        let (data, r) = decode_data(rest)?;
                        rest = r;
                        GetDataResult::Data(data)
                    } else {
                        let (dar, r) = rest.split_at(1);
                        rest = r;
                        GetDataResult::DataAccessResult(match dar[0] {
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
                        })
                    };
                    result.push(item);
                }
                Ok(GetResponse::WithList(GetResponseWithList {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    result,
                }))
            }
            197 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (last_block, rest) = rest.split_at(1);
                let (block_number, rest) = rest.split_at(4);
                let raw_data = rest.to_vec();

                let mut block_number_bytes = [0u8; 4];
                block_number_bytes.copy_from_slice(block_number);

                Ok(GetResponse::WithDataBlock(GetResponseWithDatablock {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    result: DataBlockG {
                        last_block: last_block[0] != 0,
                        block_number: u32::from_be_bytes(block_number_bytes),
                        raw_data,
                    },
                }))
            }
            _ => Err(DlmsError::Xdlms),
        }
    }
}

// --- Set-Request ---
#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub cosem_attribute_descriptor: CosemAttributeDescriptor,
    pub access_selection: Option<SelectiveAccessDescriptor>,
    pub value: CosemData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetRequestWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub attribute_descriptor_list: Vec<CosemAttributeDescriptor>,
    pub value_list: Vec<CosemData>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SetRequest {
    Normal(SetRequestNormal),
    WithList(SetRequestWithList),
}

impl SetRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
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
                    encode_data(&access_selection.access_parameters, &mut bytes)?;
                } else {
                    bytes.push(0); // no access-selector
                }
                encode_data(&req.value, &mut bytes)?;
            }
            _ => return Err(DlmsError::Xdlms),
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() {
            return Err(DlmsError::Xdlms);
        }
        let (tag, rest) = bytes.split_at(1);
        match tag[0] {
            193 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (class_id, rest) = rest.split_at(2);
                let (instance_id, rest) = rest.split_at(6);
                let (attribute_id, rest) = rest.split_at(1);
                let (has_access_selection, rest) = rest.split_at(1);

                let (access_selection, rest) = if has_access_selection[0] == 1 {
                    let (access_selector, rest) = rest.split_at(1);
                    let (access_parameters, rest) = decode_data(rest)?;
                    (
                        Some(SelectiveAccessDescriptor {
                            access_selector: access_selector[0],
                            access_parameters,
                        }),
                        rest,
                    )
                } else {
                    (None, rest)
                };

                let (value, _) = decode_data(rest)?;

                let mut class_id_bytes = [0u8; 2];
                class_id_bytes.copy_from_slice(class_id);

                let mut instance_id_bytes = [0u8; 6];
                instance_id_bytes.copy_from_slice(instance_id);

                Ok(SetRequest::Normal(SetRequestNormal {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    cosem_attribute_descriptor: CosemAttributeDescriptor {
                        class_id: u16::from_be_bytes(class_id_bytes),
                        instance_id: instance_id_bytes,
                        attribute_id: attribute_id[0] as i8,
                    },
                    access_selection,
                    value,
                }))
            }
            _ => Err(DlmsError::Xdlms),
        }
    }
}

// --- InitiateRequest ---
#[derive(Debug, Clone, PartialEq)]
pub struct InitiateRequest {
    pub dedicated_key: Option<Vec<u8>>,
    pub response_allowed: bool,
    pub proposed_quality_of_service: Option<u8>,
    pub proposed_dlms_version_number: u8,
    pub proposed_conformance: Conformance,
    pub client_max_receive_pdu_size: u16,
}

impl InitiateRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x01);

        if let Some(key) = &self.dedicated_key {
            bytes.push(0x01);
            encode_object_count(key.len(), &mut bytes);
            bytes.extend_from_slice(key);
        } else {
            bytes.push(0x00);
        }

        if self.response_allowed {
            bytes.push(0x00);
        } else {
            bytes.push(0x01);
            bytes.push(0x00);
        }

        if let Some(qos) = self.proposed_quality_of_service {
            bytes.push(0x01);
            bytes.push(qos);
        } else {
            bytes.push(0x00);
        }

        bytes.push(self.proposed_dlms_version_number);
        bytes.push(0x5F);
        bytes.push(0x1F);
        bytes.push(0x04);
        bytes.push(0x00);
        bytes.extend_from_slice(&self.proposed_conformance.to_bytes());
        bytes.extend_from_slice(&self.client_max_receive_pdu_size.to_be_bytes());

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() || bytes[0] != 0x01 {
            return Err(DlmsError::Xdlms);
        }

        let mut index = 1;
        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }

        let dedicated_key_flag = bytes[index];
        index += 1;
        let dedicated_key = if dedicated_key_flag == 0 {
            None
        } else {
            let (len, consumed) = decode_object_count(&bytes[index..])?;
            index += consumed;
            if bytes.len() < index + len {
                return Err(DlmsError::Xdlms);
            }
            let key = bytes[index..index + len].to_vec();
            index += len;
            Some(key)
        };

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let response_flag = bytes[index];
        index += 1;
        let response_allowed = if response_flag == 0 {
            true
        } else {
            if index >= bytes.len() {
                return Err(DlmsError::Xdlms);
            }
            let value = bytes[index];
            index += 1;
            value != 0
        };

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let qos_flag = bytes[index];
        index += 1;
        let proposed_quality_of_service = if qos_flag == 0 {
            None
        } else {
            if index >= bytes.len() {
                return Err(DlmsError::Xdlms);
            }
            let value = bytes[index];
            index += 1;
            Some(value)
        };

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let proposed_dlms_version_number = bytes[index];
        index += 1;

        if bytes.len() < index + 2 {
            return Err(DlmsError::Xdlms);
        }
        if bytes[index] != 0x5F || bytes[index + 1] != 0x1F {
            return Err(DlmsError::Xdlms);
        }
        index += 2;

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let conformance_length = bytes[index];
        index += 1;
        if conformance_length != 0x04 {
            return Err(DlmsError::Xdlms);
        }

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let unused_bits = bytes[index];
        index += 1;
        if unused_bits != 0x00 {
            return Err(DlmsError::Xdlms);
        }

        if bytes.len() < index + 3 {
            return Err(DlmsError::Xdlms);
        }
        let proposed_conformance = Conformance::from_bytes(&bytes[index..index + 3])?;
        index += 3;

        if bytes.len() < index + 2 {
            return Err(DlmsError::Xdlms);
        }
        let client_max_receive_pdu_size = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        index += 2;

        if index != bytes.len() {
            return Err(DlmsError::Xdlms);
        }

        Ok(InitiateRequest {
            dedicated_key,
            response_allowed,
            proposed_quality_of_service,
            proposed_dlms_version_number,
            proposed_conformance,
            client_max_receive_pdu_size,
        })
    }

    pub fn to_user_information(&self) -> Result<Vec<u8>, DlmsError> {
        let apdu = self.to_bytes()?;
        let mut buffer = Vec::with_capacity(apdu.len() + 2);
        buffer.push(0x04);
        encode_object_count(apdu.len(), &mut buffer);
        buffer.extend_from_slice(&apdu);
        Ok(buffer)
    }

    pub fn from_user_information(bytes: &[u8]) -> Result<Self, DlmsError> {
        let (apdu, consumed) = decode_octet_string(bytes)?;
        if consumed != bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        InitiateRequest::from_bytes(apdu)
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        bytes.push(0x08);

        if let Some(qos) = self.negotiated_quality_of_service {
            bytes.push(0x01);
            bytes.push(qos);
        } else {
            bytes.push(0x00);
        }

        bytes.push(self.negotiated_dlms_version_number);
        bytes.push(0x5F);
        bytes.push(0x1F);
        bytes.push(0x04);
        bytes.push(0x00);
        bytes.extend_from_slice(&self.negotiated_conformance.to_bytes());
        bytes.extend_from_slice(&self.server_max_receive_pdu_size.to_be_bytes());
        bytes.extend_from_slice(&self.vaa_name.to_be_bytes());

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() || bytes[0] != 0x08 {
            return Err(DlmsError::Xdlms);
        }

        let mut index = 1;
        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }

        let qos_flag = bytes[index];
        index += 1;
        let negotiated_quality_of_service = if qos_flag == 0 {
            None
        } else {
            if index >= bytes.len() {
                return Err(DlmsError::Xdlms);
            }
            let value = bytes[index];
            index += 1;
            Some(value)
        };

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let negotiated_dlms_version_number = bytes[index];
        index += 1;

        if bytes.len() < index + 2 {
            return Err(DlmsError::Xdlms);
        }
        if bytes[index] != 0x5F || bytes[index + 1] != 0x1F {
            return Err(DlmsError::Xdlms);
        }
        index += 2;

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let conformance_length = bytes[index];
        index += 1;
        if conformance_length != 0x04 {
            return Err(DlmsError::Xdlms);
        }

        if index >= bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        let unused_bits = bytes[index];
        index += 1;
        if unused_bits != 0x00 {
            return Err(DlmsError::Xdlms);
        }

        if bytes.len() < index + 3 {
            return Err(DlmsError::Xdlms);
        }
        let negotiated_conformance = Conformance::from_bytes(&bytes[index..index + 3])?;
        index += 3;

        if bytes.len() < index + 2 {
            return Err(DlmsError::Xdlms);
        }
        let server_max_receive_pdu_size = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        index += 2;

        if bytes.len() < index + 2 {
            return Err(DlmsError::Xdlms);
        }
        let vaa_name = u16::from_be_bytes([bytes[index], bytes[index + 1]]);
        index += 2;

        if index != bytes.len() {
            return Err(DlmsError::Xdlms);
        }

        Ok(InitiateResponse {
            negotiated_quality_of_service,
            negotiated_dlms_version_number,
            negotiated_conformance,
            server_max_receive_pdu_size,
            vaa_name,
        })
    }

    pub fn to_user_information(&self) -> Result<Vec<u8>, DlmsError> {
        let apdu = self.to_bytes()?;
        let mut buffer = Vec::with_capacity(apdu.len() + 2);
        buffer.push(0x04);
        encode_object_count(apdu.len(), &mut buffer);
        buffer.extend_from_slice(&apdu);
        Ok(buffer)
    }

    pub fn from_user_information(bytes: &[u8]) -> Result<Self, DlmsError> {
        let (apdu, consumed) = decode_octet_string(bytes)?;
        if consumed != bytes.len() {
            return Err(DlmsError::Xdlms);
        }
        InitiateResponse::from_bytes(apdu)
    }
}

impl AssociationParameters {
    pub fn to_initiate_request(&self) -> InitiateRequest {
        InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_quality_of_service: self.quality_of_service,
            proposed_dlms_version_number: self.dlms_version,
            proposed_conformance: self.conformance.clone(),
            client_max_receive_pdu_size: self.max_receive_pdu_size,
        }
    }

    pub fn to_initiate_response(&self, negotiated_conformance: Conformance) -> InitiateResponse {
        InitiateResponse {
            negotiated_quality_of_service: self.quality_of_service,
            negotiated_dlms_version_number: self.dlms_version,
            negotiated_conformance,
            server_max_receive_pdu_size: self.max_receive_pdu_size,
            vaa_name: 0x0007,
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
    pub result: Vec<DataAccessResult>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SetResponse {
    Normal(SetResponseNormal),
    WithList(SetResponseWithList),
}

impl SetResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        match self {
            SetResponse::Normal(res) => {
                bytes.push(197); // set-response-normal
                bytes.push(res.invoke_id_and_priority);
                bytes.push(res.result.clone().into());
            }
            _ => return Err(DlmsError::Xdlms),
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() {
            return Err(DlmsError::Xdlms);
        }
        let (tag, rest) = bytes.split_at(1);
        match tag[0] {
            197 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (result, _) = rest.split_at(1);
                Ok(SetResponse::Normal(SetResponseNormal {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    result: match result[0] {
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
                }))
            }
            _ => Err(DlmsError::Xdlms),
        }
    }
}

// --- Action-Request ---
#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestNormal {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub cosem_method_descriptor: CosemMethodDescriptor,
    pub method_invocation_parameters: Option<CosemData>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionRequestWithList {
    pub invoke_id_and_priority: InvokeIdAndPriority,
    pub cosem_method_descriptor_list: Vec<CosemMethodDescriptor>,
    pub method_invocation_parameters: Vec<CosemData>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActionRequest {
    Normal(ActionRequestNormal),
    WithList(ActionRequestWithList),
}

impl ActionRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        match self {
            ActionRequest::Normal(req) => {
                bytes.push(195); // action-request-normal
                bytes.push(req.invoke_id_and_priority);
                bytes.extend_from_slice(&req.cosem_method_descriptor.class_id.to_be_bytes());
                bytes.extend_from_slice(&req.cosem_method_descriptor.instance_id);
                bytes.push(req.cosem_method_descriptor.method_id as u8);
                if let Some(mip) = &req.method_invocation_parameters {
                    bytes.push(1); // method-invocation-parameters
                    encode_data(mip, &mut bytes)?;
                } else {
                    bytes.push(0); // no method-invocation-parameters
                }
            }
            _ => return Err(DlmsError::Xdlms),
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() {
            return Err(DlmsError::Xdlms);
        }
        let (tag, rest) = bytes.split_at(1);
        match tag[0] {
            195 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (class_id, rest) = rest.split_at(2);
                let (instance_id, rest) = rest.split_at(6);
                let (method_id, rest) = rest.split_at(1);
                let (has_mip, rest) = rest.split_at(1);

                let method_invocation_parameters = if has_mip[0] == 1 {
                    let (mip, _) = decode_data(rest)?;
                    Some(mip)
                } else {
                    None
                };

                let mut class_id_bytes = [0u8; 2];
                class_id_bytes.copy_from_slice(class_id);

                let mut instance_id_bytes = [0u8; 6];
                instance_id_bytes.copy_from_slice(instance_id);

                Ok(ActionRequest::Normal(ActionRequestNormal {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    cosem_method_descriptor: CosemMethodDescriptor {
                        class_id: u16::from_be_bytes(class_id_bytes),
                        instance_id: instance_id_bytes,
                        method_id: method_id[0] as i8,
                    },
                    method_invocation_parameters,
                }))
            }
            _ => Err(DlmsError::Xdlms),
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

impl From<ActionResult> for u8 {
    fn from(val: ActionResult) -> Self {
        match val {
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
        }
    }
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
    pub list_of_responses: Vec<ActionResponseWithOptionalData>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActionResponse {
    Normal(ActionResponseNormal),
    WithList(ActionResponseWithList),
}

impl ActionResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DlmsError> {
        let mut bytes = Vec::new();
        match self {
            ActionResponse::Normal(res) => {
                bytes.push(198); // action-response-normal
                bytes.push(res.invoke_id_and_priority);
                bytes.push(res.single_response.result.clone().into());
                if let Some(rp) = &res.single_response.return_parameters {
                    bytes.push(1); // return-parameters
                    match rp {
                        GetDataResult::Data(data) => {
                            encode_data(data, &mut bytes)?;
                        }
                        GetDataResult::DataAccessResult(dar) => {
                            bytes.push(dar.clone().into());
                        }
                    }
                } else {
                    bytes.push(0); // no return-parameters
                }
            }
            _ => return Err(DlmsError::Xdlms),
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DlmsError> {
        if bytes.is_empty() {
            return Err(DlmsError::Xdlms);
        }
        let (tag, rest) = bytes.split_at(1);
        match tag[0] {
            198 => {
                let (invoke_id_and_priority, rest) = rest.split_at(1);
                let (result, rest) = rest.split_at(1);
                let (has_return_params, rest) = rest.split_at(1);

                let return_parameters = if has_return_params[0] == 1 {
                    let (data, _) = decode_data(rest)?;
                    Some(GetDataResult::Data(data))
                } else {
                    None
                };

                Ok(ActionResponse::Normal(ActionResponseNormal {
                    invoke_id_and_priority: invoke_id_and_priority[0],
                    single_response: ActionResponseWithOptionalData {
                        result: match result[0] {
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
                        return_parameters,
                    },
                }))
            }
            _ => Err(DlmsError::Xdlms),
        }
    }
}
