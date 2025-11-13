use crate::acse::{AareApdu, AarqApdu, ArlreApdu, ArlrqApdu};
use crate::association_ln::{AssociationLN, ObjectListEntry};
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::cosem_object::{
    AttributeAccessDescriptor, AttributeAccessMode, CosemObject, MethodAccessDescriptor,
    MethodAccessMode,
};
use crate::error::DlmsError;
use crate::hdlc::{HdlcFrame, HdlcFrameError};
use crate::security::lls_authenticate;
use crate::security::{hls_decrypt, hls_encrypt, SecurityError};
use crate::transport::Transport;
use crate::types::CosemData;
use crate::xdlms::{
    ActionRequest, ActionResponse, ActionResponseNormal, ActionResult, AssociationParameters,
    DataAccessResult, GetDataResult, GetRequest, GetResponse, GetResponseNormal, InitiateRequest,
    InitiateResponse, SetRequest, SetResponse, SetResponseNormal,
};
use rand_core::{OsRng, RngCore};
use std::sync::{Arc, Mutex};

// Clause 6.3 of СТО 34.01-5.1-013-2023 prescribes the standard HDLC client SAPs
// for public (16), meter reader (32), and configurator (48) associations.
const PUBLIC_CLIENT_SAP: u16 = 0x0010;
const METER_READER_CLIENT_SAP: u16 = 0x0020;
const CONFIGURATOR_CLIENT_SAP: u16 = 0x0030;

const PUBLIC_ASSOCIATION_LN: [u8; 6] = [0x00, 0x00, 0x28, 0x00, 0x01, 0xFF];
const METER_READER_ASSOCIATION_LN: [u8; 6] = [0x00, 0x00, 0x28, 0x00, 0x02, 0xFF];
const CONFIGURATOR_ASSOCIATION_LN: [u8; 6] = [0x00, 0x00, 0x28, 0x00, 0x03, 0xFF];
use std::boxed::Box;
use std::collections::BTreeMap;
use std::vec::Vec;

#[derive(Debug)]
pub enum ServerError<E> {
    HdlcError(HdlcFrameError),
    AcseError,
    TransportError(E),
    SecurityError(SecurityError),
    DlmsError(DlmsError),
}

impl<E> From<HdlcFrameError> for ServerError<E> {
    fn from(e: HdlcFrameError) -> Self {
        ServerError::HdlcError(e)
    }
}

impl<E> From<DlmsError> for ServerError<E> {
    fn from(e: DlmsError) -> Self {
        ServerError::DlmsError(e)
    }
}

pub struct Server<T: Transport> {
    address: u16,
    transport: T,
    password: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    objects: BTreeMap<[u8; 6], Box<dyn CosemObject>>,
    association_logical_names: BTreeMap<u16, [u8; 6]>,
    association_templates: BTreeMap<[u8; 6], AssociationLN>,
    client_association_instances: BTreeMap<u16, Box<dyn CosemObject>>,
    lls_challenges: BTreeMap<u16, Vec<u8>>,
    association_parameters: AssociationParameters,
    active_associations: BTreeMap<u16, AssociationContext>,
    association_object_list: Arc<Mutex<Vec<ObjectListEntry>>>,
}

impl<T: Transport> Server<T> {
    pub fn new(
        address: u16,
        transport: T,
        password: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
    ) -> Self {
        let association_object_list = Arc::new(Mutex::new(Vec::new()));
        let auth_mechanism_name = if password.is_some() {
            b"LLS".to_vec()
        } else {
            b"NO_AUTH".to_vec()
        };

        let mut server = Server {
            address,
            transport,
            password,
            key,
            objects: BTreeMap::new(),
            association_logical_names: BTreeMap::new(),
            association_templates: BTreeMap::new(),
            client_association_instances: BTreeMap::new(),
            lls_challenges: BTreeMap::new(),
            association_parameters: AssociationParameters::default(),
            active_associations: BTreeMap::new(),
            association_object_list,
        };

        let mut register_predefined_association = |client_sap: u16, logical_name: [u8; 6]| {
            let association = AssociationLN::new(
                Arc::clone(&server.association_object_list),
                ((client_sap as u32) << 16) | address as u32,
                b"LN_WITH_NO_CIPHERING".to_vec(),
                Vec::new(),
                auth_mechanism_name.clone(),
            );

            server.register_association_for_client(client_sap, logical_name, association);
        };

        register_predefined_association(PUBLIC_CLIENT_SAP, PUBLIC_ASSOCIATION_LN);
        register_predefined_association(METER_READER_CLIENT_SAP, METER_READER_ASSOCIATION_LN);
        register_predefined_association(CONFIGURATOR_CLIENT_SAP, CONFIGURATOR_ASSOCIATION_LN);
        server
    }

    pub fn set_association_parameters(&mut self, params: AssociationParameters) {
        self.association_parameters = params;
    }

    pub fn register_object(&mut self, instance_id: [u8; 6], object: Box<dyn CosemObject>) {
        self.register_object_internal(instance_id, object);
    }

    pub fn register_association_for_client(
        &mut self,
        client_sap: u16,
        logical_name: [u8; 6],
        association: AssociationLN,
    ) {
        self.association_logical_names
            .insert(client_sap, logical_name);
        self.association_templates
            .insert(logical_name, association.clone());
        self.register_object_internal(logical_name, Box::new(association));
    }

    pub fn handle_frame(&mut self, request_bytes: &[u8]) -> Result<Vec<u8>, ServerError<T::Error>> {
        self.handle_request(request_bytes)
    }

    fn register_object_internal(&mut self, instance_id: [u8; 6], object: Box<dyn CosemObject>) {
        self.objects.insert(instance_id, object);
        self.rebuild_association_object_list();
    }

    fn rebuild_association_object_list(&self) {
        let mut list = self
            .association_object_list
            .lock()
            .expect("association object list poisoned");
        list.clear();
        for (logical_name, object) in &self.objects {
            list.push(ObjectListEntry {
                class_id: object.class_id(),
                version: object.version(),
                logical_name: *logical_name,
                attribute_access: object.attribute_access_rights(),
                method_access: object.method_access_rights(),
            });
        }
    }

    pub fn run(&mut self) -> Result<(), ServerError<T::Error>> {
        loop {
            let request_bytes = self
                .transport
                .receive()
                .map_err(ServerError::TransportError)?;
            let decrypted_request = if let Some(key) = &self.key {
                hls_decrypt(&request_bytes, key).map_err(ServerError::SecurityError)?
            } else {
                request_bytes
            };
            let response_bytes = self.handle_request(&decrypted_request)?;
            let encrypted_response = if let Some(key) = &self.key {
                hls_encrypt(&response_bytes, key).map_err(ServerError::SecurityError)?
            } else {
                response_bytes
            };
            self.transport
                .send(&encrypted_response)
                .map_err(ServerError::TransportError)?;
        }
    }

    fn handle_request(&mut self, request_bytes: &[u8]) -> Result<Vec<u8>, ServerError<T::Error>> {
        let request_frame = HdlcFrame::from_bytes(request_bytes)?;

        if request_frame.information.len()
            > self.association_parameters.max_receive_pdu_size as usize
        {
            return Err(ServerError::DlmsError(DlmsError::Xdlms));
        }

        let mut pending_client_limit = None;
        let response_bytes = if let Ok((_, aarq_apdu)) =
            AarqApdu::from_bytes(&request_frame.information)
        {
            let initiate_request =
                InitiateRequest::from_user_information(&aarq_apdu.user_information)?;
            pending_client_limit = Some(initiate_request.client_max_receive_pdu_size);
            let negotiation = self.negotiate_initiate_response(&initiate_request);
            let mut aare = AareApdu {
                application_context_name: aarq_apdu.application_context_name.clone(),
                result: 0,
                result_source_diagnostic: 0,
                responding_authentication_value: None,
                user_information: Vec::new(),
            };
            let mut negotiation_succeeded = false;

            match negotiation {
                Ok(initiate_response) => {
                    aare.user_information = initiate_response.to_user_information()?;
                    negotiation_succeeded = true;
                }
                Err(err) => {
                    aare.result = 1;
                    aare.result_source_diagnostic = err.diagnostic();
                    aare.user_information = self
                        .association_parameters
                        .to_initiate_response(self.association_parameters.conformance.clone())
                        .to_user_information()?;
                }
            }

            let association_address = request_frame.address;
            if aare.result != 0 {
                self.active_associations.remove(&association_address);
                self.client_association_instances
                    .remove(&association_address);
                return Ok(HdlcFrame {
                    address: self.address,
                    control: 0,
                    information: aare.to_bytes()?,
                }
                .to_bytes()?);
            }
            if let (Some(password), Some(mechanism_name)) =
                (&self.password, aarq_apdu.mechanism_name.as_ref())
            {
                let association_address = request_frame.address;
                if mechanism_name == b"LLS" {
                    if let Some(auth_value) = aarq_apdu.calling_authentication_value.clone() {
                        if let Some(challenge) = self.lls_challenges.get(&association_address) {
                            match lls_authenticate(password, challenge) {
                                Ok(expected_response) => {
                                    if auth_value == expected_response {
                                        aare.result = 0; // success
                                        self.lls_challenges.remove(&association_address);
                                    } else {
                                        aare.result = 1; // failure
                                    }
                                }
                                Err(_) => aare.result = 1, // failure
                            }
                        } else {
                            aare.result = 1; // failure due to missing challenge
                        }
                    } else {
                        let mut challenge = vec![0u8; 16];
                        OsRng.fill_bytes(&mut challenge);
                        self.lls_challenges
                            .insert(association_address, challenge.clone());
                        aare.responding_authentication_value = Some(challenge);
                        self.active_associations.remove(&association_address);
                        self.client_association_instances
                            .remove(&association_address);
                    }
                }
            }
            if aare.responding_authentication_value.is_none() && negotiation_succeeded {
                self.active_associations.insert(
                    association_address,
                    AssociationContext {
                        client_max_receive_pdu_size: initiate_request.client_max_receive_pdu_size,
                    },
                );

                let logical_name = if let Some(&logical_name) =
                    self.association_logical_names.get(&association_address)
                {
                    logical_name
                } else {
                    self.association_logical_names
                        .insert(association_address, PUBLIC_ASSOCIATION_LN);
                    PUBLIC_ASSOCIATION_LN
                };

                let template = self
                    .association_templates
                    .get(&logical_name)
                    .cloned()
                    .or_else(|| {
                        self.association_templates
                            .get(&PUBLIC_ASSOCIATION_LN)
                            .cloned()
                    });

                let Some(template) = template else {
                    self.client_association_instances
                        .remove(&association_address);
                    self.active_associations.remove(&association_address);
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let partners_id = ((association_address as u32) << 16) | self.address as u32;

                let entry = self
                    .client_association_instances
                    .entry(association_address)
                    .or_insert_with(|| Box::new(template.clone()) as Box<dyn CosemObject>);

                let _ = entry
                    .as_mut()
                    .set_attribute(3, CosemData::DoubleLongUnsigned(partners_id));
            }
            aare.to_bytes()?
        } else if let Ok((_, release_req)) = ArlrqApdu::from_bytes(&request_frame.information) {
            self.active_associations.remove(&request_frame.address);
            self.lls_challenges.remove(&request_frame.address);
            self.client_association_instances
                .remove(&request_frame.address);

            let reason = release_req.reason.unwrap_or(0);
            let rlre = ArlreApdu {
                reason: Some(reason),
                user_information: release_req.user_information,
            };

            rlre.to_bytes()?
        } else if let Ok(get_req) = GetRequest::from_bytes(&request_frame.information) {
            let GetRequest::Normal(get_req) = get_req else {
                return Err(ServerError::DlmsError(DlmsError::Xdlms));
            };

            if !self
                .active_associations
                .contains_key(&request_frame.address)
            {
                let denial = GetResponse::Normal(GetResponseNormal {
                    invoke_id_and_priority: get_req.invoke_id_and_priority,
                    result: GetDataResult::DataAccessResult(DataAccessResult::ReadWriteDenied),
                });
                denial.to_bytes()?
            } else {
                let instance_id = get_req.cosem_attribute_descriptor.instance_id;
                let Some(object) = self.resolve_object(request_frame.address, instance_id) else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let attribute_access = object.attribute_access_rights();
                let attribute_id = get_req.cosem_attribute_descriptor.attribute_id;
                if !Self::attribute_operation_allowed(
                    &attribute_access,
                    attribute_id,
                    AttributeOperation::Read,
                ) {
                    let denial = GetResponse::Normal(GetResponseNormal {
                        invoke_id_and_priority: get_req.invoke_id_and_priority,
                        result: GetDataResult::DataAccessResult(DataAccessResult::ReadWriteDenied),
                    });
                    denial.to_bytes()?
                } else {
                    if let Some(callbacks) = object.callbacks() {
                        if let Err(result_code) = callbacks.call_pre_read(&*object, attribute_id) {
                            let denial = GetResponse::Normal(GetResponseNormal {
                                invoke_id_and_priority: get_req.invoke_id_and_priority,
                                result: GetDataResult::DataAccessResult(result_code),
                            });
                            return self.build_response_frame(denial.to_bytes()?);
                        }
                    }

                    let mut result = object.get_attribute(attribute_id);

                    if let Some(callbacks) = object.callbacks() {
                        if let Err(result_code) =
                            callbacks.call_post_read(&*object, attribute_id, &mut result)
                        {
                            let denial = GetResponse::Normal(GetResponseNormal {
                                invoke_id_and_priority: get_req.invoke_id_and_priority,
                                result: GetDataResult::DataAccessResult(result_code),
                            });
                            return self.build_response_frame(denial.to_bytes()?);
                        }
                    }

                    let get_res = GetResponse::Normal(GetResponseNormal {
                        invoke_id_and_priority: get_req.invoke_id_and_priority,
                        result: result.map_or(
                            GetDataResult::DataAccessResult(DataAccessResult::ObjectUnavailable),
                            GetDataResult::Data,
                        ),
                    });
                    get_res.to_bytes()?
                }
            }
        } else if let Ok(set_req) = SetRequest::from_bytes(&request_frame.information) {
            let SetRequest::Normal(set_req) = set_req else {
                return Err(ServerError::DlmsError(DlmsError::Xdlms));
            };

            if !self
                .active_associations
                .contains_key(&request_frame.address)
            {
                let denial = SetResponse::Normal(SetResponseNormal {
                    invoke_id_and_priority: set_req.invoke_id_and_priority,
                    result: DataAccessResult::ReadWriteDenied,
                });
                denial.to_bytes()?
            } else {
                let instance_id = set_req.cosem_attribute_descriptor.instance_id;
                let Some(object) = self.resolve_object(request_frame.address, instance_id) else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let attribute_access = object.attribute_access_rights();
                let attribute_id = set_req.cosem_attribute_descriptor.attribute_id;
                if !Self::attribute_operation_allowed(
                    &attribute_access,
                    attribute_id,
                    AttributeOperation::Write,
                ) {
                    let denial = SetResponse::Normal(SetResponseNormal {
                        invoke_id_and_priority: set_req.invoke_id_and_priority,
                        result: DataAccessResult::ReadWriteDenied,
                    });
                    denial.to_bytes()?
                } else {
                    let mut value = set_req.value;
                    if let Some(callbacks) = object.callbacks() {
                        if let Err(result_code) =
                            callbacks.call_pre_write(object, attribute_id, &mut value)
                        {
                            let denial = SetResponse::Normal(SetResponseNormal {
                                invoke_id_and_priority: set_req.invoke_id_and_priority,
                                result: result_code,
                            });
                            return self.build_response_frame(denial.to_bytes()?);
                        }
                    }

                    let result = object.set_attribute(attribute_id, value.clone());
                    let response_code = result.map_or(DataAccessResult::ObjectUnavailable, |_| {
                        if let Some(callbacks) = object.callbacks() {
                            if let Err(result_code) =
                                callbacks.call_post_write(object, attribute_id, &value)
                            {
                                return result_code;
                            }
                        }
                        DataAccessResult::Success
                    });
                    let set_res = SetResponse::Normal(SetResponseNormal {
                        invoke_id_and_priority: set_req.invoke_id_and_priority,
                        result: response_code,
                    });
                    set_res.to_bytes()?
                }
            }
        } else if let Ok(action_req) = ActionRequest::from_bytes(&request_frame.information) {
            let ActionRequest::Normal(action_req) = action_req else {
                return Err(ServerError::DlmsError(DlmsError::Xdlms));
            };

            if !self
                .active_associations
                .contains_key(&request_frame.address)
            {
                let denial = ActionResponse::Normal(ActionResponseNormal {
                    invoke_id_and_priority: action_req.invoke_id_and_priority,
                    single_response: crate::xdlms::ActionResponseWithOptionalData {
                        result: ActionResult::ReadWriteDenied,
                        return_parameters: None,
                    },
                });
                denial.to_bytes()?
            } else {
                let instance_id = action_req.cosem_method_descriptor.instance_id;
                let Some(object) = self.resolve_object(request_frame.address, instance_id) else {
                    return Err(ServerError::DlmsError(DlmsError::Xdlms));
                };

                let method_access = object.method_access_rights();
                let method_id = action_req.cosem_method_descriptor.method_id;
                if !Self::method_operation_allowed(&method_access, method_id) {
                    let denial = ActionResponse::Normal(ActionResponseNormal {
                        invoke_id_and_priority: action_req.invoke_id_and_priority,
                        single_response: crate::xdlms::ActionResponseWithOptionalData {
                            result: ActionResult::ReadWriteDenied,
                            return_parameters: None,
                        },
                    });
                    denial.to_bytes()?
                } else {
                    let mut parameters = action_req
                        .method_invocation_parameters
                        .unwrap_or(crate::types::CosemData::NullData);
                    if let Some(callbacks) = object.callbacks() {
                        if let Err(result_code) =
                            callbacks.call_pre_action(object, method_id, &mut parameters)
                        {
                            let denial = ActionResponse::Normal(ActionResponseNormal {
                                invoke_id_and_priority: action_req.invoke_id_and_priority,
                                single_response: crate::xdlms::ActionResponseWithOptionalData {
                                    result: result_code,
                                    return_parameters: None,
                                },
                            });
                            return self.build_response_frame(denial.to_bytes()?);
                        }
                    }

                    let mut result = object.invoke_method(method_id, parameters);

                    if let Some(callbacks) = object.callbacks() {
                        if let Err(result_code) =
                            callbacks.call_post_action(object, method_id, &mut result)
                        {
                            let denial = ActionResponse::Normal(ActionResponseNormal {
                                invoke_id_and_priority: action_req.invoke_id_and_priority,
                                single_response: crate::xdlms::ActionResponseWithOptionalData {
                                    result: result_code,
                                    return_parameters: None,
                                },
                            });
                            return self.build_response_frame(denial.to_bytes()?);
                        }
                    }
                    let action_res = ActionResponse::Normal(ActionResponseNormal {
                        invoke_id_and_priority: action_req.invoke_id_and_priority,
                        single_response: crate::xdlms::ActionResponseWithOptionalData {
                            result: result
                                .as_ref()
                                .map_or(ActionResult::ObjectUnavailable, |_| ActionResult::Success),
                            return_parameters: result.map(GetDataResult::Data),
                        },
                    });
                    action_res.to_bytes()?
                }
            }
        } else {
            return Err(ServerError::DlmsError(DlmsError::Xdlms));
        };

        let response_hdlc_frame = HdlcFrame {
            address: self.address,
            control: 0,
            information: response_bytes,
        };

        let client_limit = pending_client_limit
            .or_else(|| {
                self.active_associations
                    .get(&request_frame.address)
                    .map(|ctx| ctx.client_max_receive_pdu_size)
            })
            .unwrap_or(self.association_parameters.max_receive_pdu_size)
            as usize;

        if response_hdlc_frame.information.len() > client_limit {
            return Err(ServerError::DlmsError(DlmsError::Xdlms));
        }

        Ok(response_hdlc_frame.to_bytes()?)
    }

    fn build_response_frame(&self, information: Vec<u8>) -> Result<Vec<u8>, ServerError<T::Error>> {
        Ok(HdlcFrame {
            address: self.address,
            control: 0,
            information,
        }
        .to_bytes()?)
    }

    fn resolve_object(
        &mut self,
        client_address: u16,
        logical_name: [u8; 6],
    ) -> Option<&mut dyn CosemObject> {
        if self
            .association_logical_names
            .get(&client_address)
            .is_some_and(|ln| *ln == logical_name)
        {
            if let Some(association) = self.client_association_instances.get_mut(&client_address) {
                return Some(association.as_mut());
            }
        }

        if let Some(object) = self.objects.get_mut(&logical_name) {
            return Some(object.as_mut());
        }

        None
    }

    fn negotiate_initiate_response(
        &self,
        request: &InitiateRequest,
    ) -> Result<InitiateResponse, InitiateValidationError> {
        if !request.response_allowed {
            return Err(InitiateValidationError::ResponseNotAllowed);
        }

        if request.proposed_dlms_version_number != self.association_parameters.dlms_version {
            return Err(InitiateValidationError::DlmsVersionMismatch);
        }

        if request.client_max_receive_pdu_size == 0 {
            return Err(InitiateValidationError::InvalidClientPduSize);
        }

        let negotiated_conformance = self
            .association_parameters
            .conformance
            .intersection(&request.proposed_conformance);

        if negotiated_conformance.is_empty() {
            return Err(InitiateValidationError::NoCommonConformance);
        }

        let mut response = self
            .association_parameters
            .to_initiate_response(negotiated_conformance);

        if response.negotiated_quality_of_service.is_none() {
            response.negotiated_quality_of_service = request.proposed_quality_of_service;
        }

        Ok(response)
    }

    fn attribute_operation_allowed(
        descriptors: &[AttributeAccessDescriptor],
        attribute_id: CosemObjectAttributeId,
        operation: AttributeOperation,
    ) -> bool {
        descriptors
            .iter()
            .find(|descriptor| descriptor.attribute_id == attribute_id)
            .is_some_and(|descriptor| match operation {
                AttributeOperation::Read => matches!(
                    descriptor.access_mode,
                    AttributeAccessMode::Read | AttributeAccessMode::ReadWrite
                ),
                AttributeOperation::Write => matches!(
                    descriptor.access_mode,
                    AttributeAccessMode::Write | AttributeAccessMode::ReadWrite
                ),
            })
    }

    fn method_operation_allowed(
        descriptors: &[MethodAccessDescriptor],
        method_id: CosemObjectMethodId,
    ) -> bool {
        descriptors.iter().any(|descriptor| {
            descriptor.method_id == method_id
                && matches!(descriptor.access_mode, MethodAccessMode::Access)
        })
    }
}

#[derive(Debug, Clone)]
struct AssociationContext {
    client_max_receive_pdu_size: u16,
}

#[derive(Debug, Clone, Copy)]
enum AttributeOperation {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy)]
enum InitiateValidationError {
    ResponseNotAllowed,
    DlmsVersionMismatch,
    InvalidClientPduSize,
    NoCommonConformance,
}

impl InitiateValidationError {
    fn diagnostic(self) -> u8 {
        match self {
            InitiateValidationError::ResponseNotAllowed => 1,
            InitiateValidationError::DlmsVersionMismatch => 2,
            InitiateValidationError::InvalidClientPduSize => 3,
            InitiateValidationError::NoCommonConformance => 4,
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;
    use crate::activity_calendar::ActivityCalendar;
    use crate::clock::Clock;
    use crate::cosem::{CosemAttributeDescriptor, CosemMethodDescriptor};
    use crate::demand_register::DemandRegister;
    use crate::disconnect_control::DisconnectControl;
    use crate::extended_register::ExtendedRegister;
    use crate::profile_generic::ProfileGeneric;
    use crate::register::Register;
    use crate::sap_assignment::SapAssignment;
    use crate::security_setup::SecuritySetup;
    use crate::types::CosemData;
    use crate::xdlms::{
        ActionRequest, ActionRequestNormal, ActionResponse, ActionResult, AssociationParameters,
        Conformance, DataAccessResult, GetDataResult, GetRequest, GetRequestNormal, GetResponse,
        InitiateRequest, InitiateResponse, SetRequest, SetRequestNormal, SetResponse,
    };

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

    fn build_hdlc_request(address: u16, aarq: AarqApdu) -> Vec<u8> {
        let frame = HdlcFrame {
            address,
            control: 0,
            information: aarq.to_bytes().expect("failed to serialize aarq"),
        };

        frame.to_bytes().expect("failed to encode frame")
    }

    fn parse_aare(bytes: &[u8]) -> AareApdu {
        let frame = HdlcFrame::from_bytes(bytes).expect("failed to decode frame");
        AareApdu::from_bytes(&frame.information)
            .expect("failed to decode aare")
            .1
    }

    fn parse_rlre(bytes: &[u8]) -> ArlreApdu {
        let frame = HdlcFrame::from_bytes(bytes).expect("failed to decode frame");
        ArlreApdu::from_bytes(&frame.information)
            .expect("failed to decode rlre")
            .1
    }

    fn default_initiate_request() -> InitiateRequest {
        AssociationParameters::default().to_initiate_request()
    }

    fn activate_association(server: &mut Server<DummyTransport>, address: u16) {
        server.active_associations.insert(
            address,
            AssociationContext {
                client_max_receive_pdu_size: server.association_parameters.max_receive_pdu_size,
            },
        );
    }

    #[test]
    fn association_object_list_tracks_registered_objects() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        {
            let list = server
                .association_object_list
                .lock()
                .expect("association list poisoned");
            let logical_names: Vec<[u8; 6]> = list.iter().map(|entry| entry.logical_name).collect();
            assert_eq!(logical_names.len(), 3);
            assert!(logical_names.contains(&PUBLIC_ASSOCIATION_LN));
            assert!(logical_names.contains(&METER_READER_ASSOCIATION_LN));
            assert!(logical_names.contains(&CONFIGURATOR_ASSOCIATION_LN));
            for entry in list.iter().filter(|entry| entry.class_id == 15) {
                assert!(!entry.attribute_access.is_empty());
            }
        }

        let logical_name = [0, 0, 1, 0, 0, 255];
        server.register_object(logical_name, Box::new(Register::new()));

        let list = server
            .association_object_list
            .lock()
            .expect("association list poisoned");
        assert_eq!(list.len(), 4);
        let register_entry = list
            .iter()
            .find(|entry| entry.logical_name == logical_name)
            .expect("register not present in association list");
        assert_eq!(register_entry.class_id, 3);
        assert_eq!(register_entry.version, 0);
        assert_eq!(register_entry.attribute_access.len(), 2);
        assert_eq!(register_entry.method_access.len(), 1);
    }

    #[test]
    fn association_ln_instances_are_client_specific() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let secondary_client = METER_READER_CLIENT_SAP;
        let secondary_logical_name = METER_READER_ASSOCIATION_LN;

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: default_initiate_request()
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let default_response = server
            .handle_request(&build_hdlc_request(PUBLIC_CLIENT_SAP, aarq.clone()))
            .expect("default association aarq failed");
        assert_eq!(parse_aare(&default_response).result, 0);

        let secondary_response = server
            .handle_request(&build_hdlc_request(secondary_client, aarq))
            .expect("secondary association aarq failed");
        assert_eq!(parse_aare(&secondary_response).result, 0);

        let default_get = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 15,
                instance_id: PUBLIC_ASSOCIATION_LN,
                attribute_id: 3,
            },
            access_selection: None,
        });

        let default_frame = HdlcFrame {
            address: PUBLIC_CLIENT_SAP,
            control: 0,
            information: default_get
                .to_bytes()
                .expect("failed to encode default get request"),
        };

        let default_get_response = server
            .handle_request(&default_frame.to_bytes().expect("failed to encode frame"))
            .expect("default association get failed");

        let default_data = match GetResponse::from_bytes(
            &HdlcFrame::from_bytes(&default_get_response)
                .expect("failed to decode response frame")
                .information,
        )
        .expect("failed to decode default get")
        {
            GetResponse::Normal(GetResponseNormal { result, .. }) => result,
            other => panic!("unexpected response: {other:?}"),
        };

        let secondary_get = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 15,
                instance_id: secondary_logical_name,
                attribute_id: 3,
            },
            access_selection: None,
        });

        let secondary_frame = HdlcFrame {
            address: secondary_client,
            control: 0,
            information: secondary_get
                .to_bytes()
                .expect("failed to encode secondary get request"),
        };

        let secondary_get_response = server
            .handle_request(&secondary_frame.to_bytes().expect("failed to encode frame"))
            .expect("secondary association get failed");

        let secondary_data = match GetResponse::from_bytes(
            &HdlcFrame::from_bytes(&secondary_get_response)
                .expect("failed to decode response frame")
                .information,
        )
        .expect("failed to decode secondary get")
        {
            GetResponse::Normal(GetResponseNormal { result, .. }) => result,
            other => panic!("unexpected response: {other:?}"),
        };

        match default_data {
            GetDataResult::Data(CosemData::DoubleLongUnsigned(value)) => {
                assert_eq!(
                    value,
                    ((PUBLIC_CLIENT_SAP as u32) << 16) | server.address as u32
                );
            }
            other => panic!("unexpected data: {other:?}"),
        }

        match secondary_data {
            GetDataResult::Data(CosemData::DoubleLongUnsigned(value)) => {
                assert_eq!(
                    value,
                    ((secondary_client as u32) << 16) | server.address as u32
                );
            }
            other => panic!("unexpected data: {other:?}"),
        }
    }

    #[test]
    fn lls_challenge_is_issued_and_persisted() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let user_information = default_initiate_request()
            .to_user_information()
            .expect("failed to encode initiate request");
        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: user_information.clone(),
        };
        let aarq_bytes = aarq.to_bytes().expect("failed to encode aarq");
        assert!(AarqApdu::from_bytes(&aarq_bytes).is_ok());

        let request = build_hdlc_request(0x0002, aarq);

        let frame = HdlcFrame::from_bytes(&request).expect("failed to decode request frame");
        assert!(AarqApdu::from_bytes(&frame.information).is_ok());

        let response = server
            .handle_request(&request)
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response);
        let challenge = aare
            .responding_authentication_value
            .expect("expected challenge in response");

        let initiate_response = InitiateResponse::from_user_information(&aare.user_information)
            .expect("expected initiate response");
        assert_eq!(initiate_response.negotiated_dlms_version_number, 6);
        assert_eq!(initiate_response.server_max_receive_pdu_size, 0x0400);
        assert_eq!(initiate_response.vaa_name, 0x0007);
        assert_eq!(initiate_response.negotiated_conformance.value, 0x0010_0000);

        assert_eq!(challenge.len(), 16);
        let stored = server
            .lls_challenges
            .get(&0x0002)
            .expect("challenge should be stored");
        assert_eq!(stored.as_slice(), challenge.as_slice());
        assert!(!server.active_associations.contains_key(&0x0002));
    }

    #[test]
    fn lls_challenge_response_validates_and_clears() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let association_address = 0x0003;
        let user_information = default_initiate_request()
            .to_user_information()
            .expect("failed to encode initiate request");
        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: user_information.clone(),
        };
        let aarq_bytes = aarq.to_bytes().expect("failed to encode aarq");
        assert!(AarqApdu::from_bytes(&aarq_bytes).is_ok());

        let initial_request = build_hdlc_request(association_address, aarq);

        let initial_frame =
            HdlcFrame::from_bytes(&initial_request).expect("failed to decode initial frame");
        assert!(AarqApdu::from_bytes(&initial_frame.information).is_ok());

        let initial_response = server
            .handle_request(&initial_request)
            .expect("server failed to issue challenge");
        let issued_challenge = parse_aare(&initial_response)
            .responding_authentication_value
            .expect("expected challenge");

        let expected_response =
            lls_authenticate(b"password", &issued_challenge).expect("failed to compute mac");

        let follow_up_request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: Some(b"LLS".to_vec()),
                calling_authentication_value: Some(expected_response.clone()),
                user_information: user_information.clone(),
            },
        );

        let follow_up_response = server
            .handle_request(&follow_up_request)
            .expect("server failed to validate response");
        let aare = parse_aare(&follow_up_response);

        assert_eq!(aare.result, 0);
        assert!(aare.responding_authentication_value.is_none());
        let initiate_response = InitiateResponse::from_user_information(&aare.user_information)
            .expect("expected initiate response");
        assert_eq!(initiate_response.negotiated_dlms_version_number, 6);
        assert_eq!(initiate_response.server_max_receive_pdu_size, 0x0400);
        assert_eq!(initiate_response.negotiated_conformance.value, 0x0010_0000);
        assert!(!server.lls_challenges.contains_key(&association_address));
        let context = server
            .active_associations
            .get(&association_address)
            .expect("expected active association");
        assert_eq!(
            context.client_max_receive_pdu_size,
            default_initiate_request().client_max_receive_pdu_size
        );
    }

    #[test]
    fn successful_initiate_registers_active_association() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0005;

        let request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: None,
                calling_authentication_value: None,
                user_information: default_initiate_request()
                    .to_user_information()
                    .expect("failed to encode initiate request"),
            },
        );

        let response = server
            .handle_request(&request)
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response);
        assert_eq!(aare.result, 0);
        let context = server
            .active_associations
            .get(&association_address)
            .expect("expected active association");
        assert_eq!(
            context.client_max_receive_pdu_size,
            default_initiate_request().client_max_receive_pdu_size
        );
    }

    #[test]
    fn initiate_request_with_incompatible_version_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.proposed_dlms_version_number = 7;

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 2);
    }

    #[test]
    fn failed_initiate_clears_existing_association() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0006;

        let successful_request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: None,
                calling_authentication_value: None,
                user_information: default_initiate_request()
                    .to_user_information()
                    .expect("failed to encode initiate request"),
            },
        );

        let response = server
            .handle_request(&successful_request)
            .expect("server failed to handle aarq");
        assert_eq!(parse_aare(&response).result, 0);
        assert!(server
            .active_associations
            .contains_key(&association_address));

        let mut failing_request = default_initiate_request();
        failing_request.response_allowed = false;
        let response_bytes = server
            .handle_request(&build_hdlc_request(
                association_address,
                AarqApdu {
                    application_context_name: b"CTX".to_vec(),
                    sender_acse_requirements: 0,
                    mechanism_name: None,
                    calling_authentication_value: None,
                    user_information: failing_request
                        .to_user_information()
                        .expect("failed to encode initiate request"),
                },
            ))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert!(!server
            .active_associations
            .contains_key(&association_address));
    }

    #[test]
    fn initiate_request_without_common_conformance_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.proposed_conformance = Conformance { value: 0 };

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 4);
    }

    #[test]
    fn initiate_request_without_response_allowed_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.response_allowed = false;

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 1);
    }

    #[test]
    fn initiate_request_with_zero_client_pdu_is_rejected() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let mut request = default_initiate_request();
        request.client_max_receive_pdu_size = 0;

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: request
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0002, aarq))
            .expect("server failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 1);
        assert_eq!(aare.result_source_diagnostic, 3);
        assert!(!server.active_associations.contains_key(&0x0002));
    }

    #[test]
    fn get_request_without_active_association_is_denied() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 1,
                instance_id: [0, 0, 0, 0, 0, 1],
                attribute_id: 2,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: 0x0002,
            control: 0,
            information: request.to_bytes().expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        assert_eq!(
            response.result,
            GetDataResult::DataAccessResult(DataAccessResult::ReadWriteDenied)
        );
    }

    #[test]
    fn set_request_without_active_association_is_denied() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 1,
                instance_id: [0, 0, 0, 0, 0, 1],
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::NullData,
        });

        let frame = HdlcFrame {
            address: 0x0002,
            control: 0,
            information: request.to_bytes().expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn action_request_without_active_association_is_denied() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 1,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 1,
                instance_id: [0, 0, 0, 0, 0, 1],
                method_id: 1,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: 0x0002,
            control: 0,
            information: request.to_bytes().expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(
            response.single_response.result,
            ActionResult::ReadWriteDenied
        );
        assert!(response.single_response.return_parameters.is_none());
    }

    #[test]
    fn get_request_respects_attribute_access_rights() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0100;
        let logical_name = [0, 0, 1, 0, 0, 255];
        server.register_object(logical_name, Box::new(Register::new()));
        activate_association(&mut server, association_address);

        let request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 3,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: request.to_bytes().expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        match response.result {
            GetDataResult::Data(data) => assert_eq!(data, CosemData::Unsigned(0)),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn get_request_denied_without_read_access() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0101;
        let logical_name = [0, 0, 1, 0, 0, 254];
        server.register_object(logical_name, Box::new(Register::new()));
        activate_association(&mut server, association_address);

        let request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 3,
                instance_id: logical_name,
                attribute_id: 1,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: request.to_bytes().expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        assert_eq!(
            response.result,
            GetDataResult::DataAccessResult(DataAccessResult::ReadWriteDenied)
        );
    }

    #[test]
    fn set_request_respects_attribute_access_rights() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0102;
        let logical_name = [0, 0, 1, 0, 0, 253];
        server.register_object(logical_name, Box::new(Register::new()));
        activate_association(&mut server, association_address);

        let request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 3,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::Unsigned(42),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: request.to_bytes().expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::Success);

        let register = server
            .objects
            .get(&logical_name)
            .expect("missing register after set");
        assert_eq!(register.get_attribute(2), Some(CosemData::Unsigned(42)));
    }

    #[test]
    fn set_request_denied_without_write_access() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0103;
        let logical_name = [0, 0, 1, 0, 0, 252];
        server.register_object(logical_name, Box::new(Register::new()));
        activate_association(&mut server, association_address);

        let request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 3,
                instance_id: logical_name,
                attribute_id: 1,
            },
            access_selection: None,
            value: CosemData::Unsigned(7),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: request.to_bytes().expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn action_request_respects_method_access_rights() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0104;
        let logical_name = [0, 0, 1, 0, 0, 251];
        server.register_object(logical_name, Box::new(Register::new()));
        activate_association(&mut server, association_address);

        let request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 1,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 3,
                instance_id: logical_name,
                method_id: 1,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: request.to_bytes().expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(response.single_response.result, ActionResult::Success);
        assert_eq!(
            response.single_response.return_parameters,
            Some(GetDataResult::Data(CosemData::NullData))
        );
    }

    #[test]
    fn action_request_denied_without_method_access() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0105;
        let logical_name = [0, 0, 1, 0, 0, 250];
        server.register_object(logical_name, Box::new(Register::new()));
        activate_association(&mut server, association_address);

        let request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 1,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 3,
                instance_id: logical_name,
                method_id: 2,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: request.to_bytes().expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(
            response.single_response.result,
            ActionResult::ReadWriteDenied
        );
        assert!(response.single_response.return_parameters.is_none());
    }

    #[test]
    fn extended_register_attribute_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0106;
        let logical_name = [0, 0, 1, 0, 0, 249];
        server.register_object(logical_name, Box::new(ExtendedRegister::new()));
        activate_association(&mut server, association_address);

        {
            let register = server
                .objects
                .get_mut(&logical_name)
                .expect("missing extended register");
            register
                .set_attribute(2, CosemData::Unsigned(77))
                .expect("failed to seed register value");
        }

        let get_request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 4,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: get_request
                .to_bytes()
                .expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        match response.result {
            GetDataResult::Data(CosemData::Unsigned(value)) => assert_eq!(value, 77),
            other => panic!("unexpected get response: {other:?}"),
        };

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 4,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::NullData,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn extended_register_method_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0107;
        let logical_name = [0, 0, 1, 0, 0, 248];
        server.register_object(logical_name, Box::new(ExtendedRegister::new()));
        activate_association(&mut server, association_address);

        {
            let register = server
                .objects
                .get_mut(&logical_name)
                .expect("missing extended register");
            register
                .set_attribute(2, CosemData::Unsigned(15))
                .expect("failed to seed register value");
        }

        let request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 2,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 4,
                instance_id: logical_name,
                method_id: 1,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: request.to_bytes().expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(response.single_response.result, ActionResult::Success);
        assert_eq!(
            response.single_response.return_parameters,
            Some(GetDataResult::Data(CosemData::NullData))
        );
        let register = server
            .objects
            .get(&logical_name)
            .expect("missing extended register");
        assert_eq!(register.get_attribute(2), Some(CosemData::Unsigned(0)));

        let denied_request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 3,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 4,
                instance_id: logical_name,
                method_id: 2,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(
            response.single_response.result,
            ActionResult::ReadWriteDenied
        );
    }

    #[test]
    fn demand_register_attribute_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0108;
        let logical_name = [0, 0, 1, 0, 0, 247];
        server.register_object(logical_name, Box::new(DemandRegister::new()));
        activate_association(&mut server, association_address);

        let writable_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 5,
                instance_id: logical_name,
                attribute_id: 8,
            },
            access_selection: None,
            value: CosemData::LongUnsigned(900),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: writable_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::Success);

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 5,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::Unsigned(1),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn profile_generic_attribute_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x0109;
        let logical_name = [0, 0, 1, 0, 0, 246];
        server.register_object(logical_name, Box::new(ProfileGeneric::new()));
        activate_association(&mut server, association_address);

        {
            let profile = server
                .objects
                .get_mut(&logical_name)
                .expect("missing profile generic");
            profile
                .set_attribute(3, CosemData::Array(Vec::new()))
                .expect("failed to seed capture objects");
        }

        let get_request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 7,
                instance_id: logical_name,
                attribute_id: 3,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: get_request
                .to_bytes()
                .expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        match response.result {
            GetDataResult::Data(CosemData::Array(values)) => assert!(values.is_empty()),
            other => panic!("unexpected get response: {other:?}"),
        };

        let writable_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 7,
                instance_id: logical_name,
                attribute_id: 4,
            },
            access_selection: None,
            value: CosemData::DoubleLongUnsigned(900),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: writable_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::Success);
        let profile = server
            .objects
            .get(&logical_name)
            .expect("missing profile generic");
        assert_eq!(
            profile.get_attribute(4),
            Some(CosemData::DoubleLongUnsigned(900))
        );

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 3,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 7,
                instance_id: logical_name,
                attribute_id: 3,
            },
            access_selection: None,
            value: CosemData::Array(Vec::new()),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn clock_attribute_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x010A;
        let logical_name = [0, 0, 1, 0, 0, 245];
        server.register_object(logical_name, Box::new(Clock::new()));
        activate_association(&mut server, association_address);

        let writable_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 8,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::OctetString(vec![0; 12]),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: writable_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::Success);

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 8,
                instance_id: logical_name,
                attribute_id: 4,
            },
            access_selection: None,
            value: CosemData::Enum(0),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn activity_calendar_attribute_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x010B;
        let logical_name = [0, 0, 1, 0, 0, 244];
        server.register_object(logical_name, Box::new(ActivityCalendar::new()));
        activate_association(&mut server, association_address);

        {
            let calendar = server
                .objects
                .get_mut(&logical_name)
                .expect("missing activity calendar");
            calendar
                .set_attribute(2, CosemData::OctetString(b"ACTIVE".to_vec()))
                .expect("failed to seed calendar name");
        }

        let get_request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 20,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: get_request
                .to_bytes()
                .expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        match response.result {
            GetDataResult::Data(CosemData::OctetString(value)) => {
                assert_eq!(value, b"ACTIVE".to_vec());
            }
            other => panic!("unexpected get result: {:?}", other),
        }

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 20,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::OctetString(b"UPDATED".to_vec()),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn disconnect_control_access_rights_and_methods_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x010C;
        let logical_name = [0, 0, 1, 0, 0, 243];
        server.register_object(logical_name, Box::new(DisconnectControl::new()));
        activate_association(&mut server, association_address);

        let writable_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 70,
                instance_id: logical_name,
                attribute_id: 3,
            },
            access_selection: None,
            value: CosemData::Enum(1),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: writable_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::Success);

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 70,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::Boolean(true),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);

        let disconnect_request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 3,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 70,
                instance_id: logical_name,
                method_id: 1,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: disconnect_request
                .to_bytes()
                .expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(response.single_response.result, ActionResult::Success);
        assert_eq!(
            response.single_response.return_parameters,
            Some(GetDataResult::Data(CosemData::NullData))
        );
        let control = server
            .objects
            .get(&logical_name)
            .expect("missing disconnect control");
        assert_eq!(control.get_attribute(2), Some(CosemData::Boolean(false)));

        let reconnect_request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 4,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 70,
                instance_id: logical_name,
                method_id: 2,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: reconnect_request
                .to_bytes()
                .expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(response.single_response.result, ActionResult::Success);
        assert_eq!(
            response.single_response.return_parameters,
            Some(GetDataResult::Data(CosemData::NullData))
        );
        let control = server
            .objects
            .get(&logical_name)
            .expect("missing disconnect control");
        assert_eq!(control.get_attribute(2), Some(CosemData::Boolean(true)));

        let denied_method_request = ActionRequest::Normal(ActionRequestNormal {
            invoke_id_and_priority: 5,
            cosem_method_descriptor: CosemMethodDescriptor {
                class_id: 70,
                instance_id: logical_name,
                method_id: 3,
            },
            method_invocation_parameters: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_method_request
                .to_bytes()
                .expect("failed to encode action request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle action request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response = ActionResponse::from_bytes(&response_frame.information)
            .expect("failed to decode action response");

        let ActionResponse::Normal(response) = response else {
            panic!("expected normal action response");
        };

        assert_eq!(
            response.single_response.result,
            ActionResult::ReadWriteDenied
        );
    }

    #[test]
    fn security_setup_attribute_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x010D;
        let logical_name = [0, 0, 1, 0, 0, 242];
        server.register_object(logical_name, Box::new(SecuritySetup::new()));
        activate_association(&mut server, association_address);

        {
            let setup = server
                .objects
                .get_mut(&logical_name)
                .expect("missing security setup");
            setup
                .set_attribute(2, CosemData::Unsigned(2))
                .expect("failed to seed security policy");
        }

        let get_request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 64,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: get_request
                .to_bytes()
                .expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        match response.result {
            GetDataResult::Data(CosemData::Unsigned(value)) => assert_eq!(value, 2),
            other => panic!("unexpected get response: {other:?}"),
        };

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 64,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::Unsigned(3),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn sap_assignment_attribute_access_rights_enforced() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);
        let association_address = 0x010E;
        let logical_name = [0, 0, 1, 0, 0, 241];
        server.register_object(
            logical_name,
            Box::new(SapAssignment::with_logical_device_names(b"LN".to_vec())),
        );
        activate_association(&mut server, association_address);

        let get_request = GetRequest::Normal(GetRequestNormal {
            invoke_id_and_priority: 1,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 21,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: get_request
                .to_bytes()
                .expect("failed to encode get request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle get request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            GetResponse::from_bytes(&response_frame.information).expect("failed to decode get");

        let GetResponse::Normal(response) = response else {
            panic!("expected normal get response");
        };

        match response.result {
            GetDataResult::Data(CosemData::OctetString(value)) => assert_eq!(value, b"LN".to_vec()),
            other => panic!("unexpected get response: {other:?}"),
        };

        let denied_request = SetRequest::Normal(SetRequestNormal {
            invoke_id_and_priority: 2,
            cosem_attribute_descriptor: CosemAttributeDescriptor {
                class_id: 21,
                instance_id: logical_name,
                attribute_id: 2,
            },
            access_selection: None,
            value: CosemData::OctetString(b"UPDATED".to_vec()),
        });

        let frame = HdlcFrame {
            address: association_address,
            control: 0,
            information: denied_request
                .to_bytes()
                .expect("failed to encode set request"),
        };

        let response_bytes = server
            .handle_request(&frame.to_bytes().expect("failed to encode frame"))
            .expect("server failed to handle set request");

        let response_frame =
            HdlcFrame::from_bytes(&response_bytes).expect("failed to decode response frame");
        let response =
            SetResponse::from_bytes(&response_frame.information).expect("failed to decode set");

        let SetResponse::Normal(response) = response else {
            panic!("expected normal set response");
        };

        assert_eq!(response.result, DataAccessResult::ReadWriteDenied);
    }

    #[test]
    fn lls_challenge_response_with_wrong_mac_fails() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let association_address = 0x0004;
        let user_information = default_initiate_request()
            .to_user_information()
            .expect("failed to encode initiate request");
        let initial_request = build_hdlc_request(
            association_address,
            AarqApdu {
                application_context_name: b"CTX".to_vec(),
                sender_acse_requirements: 0,
                mechanism_name: Some(b"LLS".to_vec()),
                calling_authentication_value: None,
                user_information: user_information.clone(),
            },
        );

        let initial_response = server
            .handle_request(&initial_request)
            .expect("server failed to issue challenge");
        let issued_challenge = parse_aare(&initial_response)
            .responding_authentication_value
            .expect("expected challenge");

        let mut wrong_response =
            lls_authenticate(b"password", &issued_challenge).expect("failed to compute mac");
        wrong_response[0] ^= 0xFF;

        let follow_up_response = server
            .handle_request(&build_hdlc_request(
                association_address,
                AarqApdu {
                    application_context_name: b"CTX".to_vec(),
                    sender_acse_requirements: 0,
                    mechanism_name: Some(b"LLS".to_vec()),
                    calling_authentication_value: Some(wrong_response),
                    user_information,
                },
            ))
            .expect("server failed to process response");

        let aare = parse_aare(&follow_up_response);

        assert_eq!(aare.result, 1);
        assert!(aare.responding_authentication_value.is_none());
        let initiate_response = InitiateResponse::from_user_information(&aare.user_information)
            .expect("expected initiate response");
        assert_eq!(initiate_response.vaa_name, 0x0007);
        assert!(!server
            .lls_challenges
            .get(&association_address)
            .expect("challenge should remain for retry")
            .is_empty());
    }

    #[test]
    fn release_request_clears_active_association() {
        let mut server = Server::new(0x0001, DummyTransport, None, None);

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: None,
            calling_authentication_value: None,
            user_information: default_initiate_request()
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0001, aarq))
            .expect("failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert_eq!(aare.result, 0);
        assert!(server.active_associations.contains_key(&0x0001));

        let release_req = ArlrqApdu {
            reason: Some(0),
            user_information: None,
        };

        let frame = HdlcFrame {
            address: 0x0001,
            control: 0,
            information: release_req
                .to_bytes()
                .expect("failed to encode release request"),
        };

        let release_frame = frame.to_bytes().expect("failed to encode frame");
        let response_bytes = server
            .handle_request(&release_frame)
            .expect("failed to handle release");
        let rlre = parse_rlre(&response_bytes);
        assert_eq!(rlre.reason, Some(0));
        assert!(server.active_associations.is_empty());
    }

    #[test]
    fn release_request_clears_pending_lls_challenge() {
        let mut server = Server::new(0x0001, DummyTransport, Some(b"password".to_vec()), None);

        let aarq = AarqApdu {
            application_context_name: b"CTX".to_vec(),
            sender_acse_requirements: 0,
            mechanism_name: Some(b"LLS".to_vec()),
            calling_authentication_value: None,
            user_information: default_initiate_request()
                .to_user_information()
                .expect("failed to encode initiate request"),
        };

        let response_bytes = server
            .handle_request(&build_hdlc_request(0x0001, aarq))
            .expect("failed to handle aarq");
        let aare = parse_aare(&response_bytes);
        assert!(aare.responding_authentication_value.is_some());
        assert!(server.lls_challenges.contains_key(&0x0001));

        let release_req = ArlrqApdu {
            reason: None,
            user_information: None,
        };

        let frame = HdlcFrame {
            address: 0x0001,
            control: 0,
            information: release_req
                .to_bytes()
                .expect("failed to encode release request"),
        };

        let release_frame = frame.to_bytes().expect("failed to encode frame");
        let response_bytes = server
            .handle_request(&release_frame)
            .expect("failed to handle release");
        let rlre = parse_rlre(&response_bytes);
        assert_eq!(rlre.reason, Some(0));
        assert!(!server.lls_challenges.contains_key(&0x0001));
    }
}
