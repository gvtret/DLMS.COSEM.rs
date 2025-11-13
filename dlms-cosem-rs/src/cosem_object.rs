use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::CosemData;
use crate::xdlms::{ActionResult, DataAccessResult};
use std::boxed::Box;
use std::fmt;
use std::sync::{Arc, Mutex};

type PreReadCallback =
    Box<dyn FnMut(&dyn CosemObject, CosemObjectAttributeId) -> Result<(), DataAccessResult> + Send>;
type PostReadCallback = Box<
    dyn FnMut(
            &dyn CosemObject,
            CosemObjectAttributeId,
            &mut Option<CosemData>,
        ) -> Result<(), DataAccessResult>
        + Send,
>;
type PreWriteCallback = Box<
    dyn FnMut(
            &mut dyn CosemObject,
            CosemObjectAttributeId,
            &mut CosemData,
        ) -> Result<(), DataAccessResult>
        + Send,
>;
type PostWriteCallback = Box<
    dyn FnMut(
            &mut dyn CosemObject,
            CosemObjectAttributeId,
            &CosemData,
        ) -> Result<(), DataAccessResult>
        + Send,
>;
type PreActionCallback = Box<
    dyn FnMut(&mut dyn CosemObject, CosemObjectMethodId, &mut CosemData) -> Result<(), ActionResult>
        + Send,
>;
type PostActionCallback = Box<
    dyn FnMut(
            &mut dyn CosemObject,
            CosemObjectMethodId,
            &mut Option<CosemData>,
        ) -> Result<(), ActionResult>
        + Send,
>;

pub struct CosemObjectCallbackHandlers {
    pre_read: Mutex<Option<PreReadCallback>>,
    post_read: Mutex<Option<PostReadCallback>>,
    pre_write: Mutex<Option<PreWriteCallback>>,
    post_write: Mutex<Option<PostWriteCallback>>,
    pre_action: Mutex<Option<PreActionCallback>>,
    post_action: Mutex<Option<PostActionCallback>>,
}

impl CosemObjectCallbackHandlers {
    pub fn new() -> Self {
        Self {
            pre_read: Mutex::new(None),
            post_read: Mutex::new(None),
            pre_write: Mutex::new(None),
            post_write: Mutex::new(None),
            pre_action: Mutex::new(None),
            post_action: Mutex::new(None),
        }
    }

    pub fn set_pre_read<F>(&self, callback: F)
    where
        F: FnMut(&dyn CosemObject, CosemObjectAttributeId) -> Result<(), DataAccessResult>
            + Send
            + 'static,
    {
        *self.pre_read.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn set_post_read<F>(&self, callback: F)
    where
        F: FnMut(
                &dyn CosemObject,
                CosemObjectAttributeId,
                &mut Option<CosemData>,
            ) -> Result<(), DataAccessResult>
            + Send
            + 'static,
    {
        *self.post_read.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn set_pre_write<F>(&self, callback: F)
    where
        F: FnMut(
                &mut dyn CosemObject,
                CosemObjectAttributeId,
                &mut CosemData,
            ) -> Result<(), DataAccessResult>
            + Send
            + 'static,
    {
        *self.pre_write.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn set_post_write<F>(&self, callback: F)
    where
        F: FnMut(
                &mut dyn CosemObject,
                CosemObjectAttributeId,
                &CosemData,
            ) -> Result<(), DataAccessResult>
            + Send
            + 'static,
    {
        *self.post_write.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn set_pre_action<F>(&self, callback: F)
    where
        F: FnMut(
                &mut dyn CosemObject,
                CosemObjectMethodId,
                &mut CosemData,
            ) -> Result<(), ActionResult>
            + Send
            + 'static,
    {
        *self.pre_action.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn set_post_action<F>(&self, callback: F)
    where
        F: FnMut(
                &mut dyn CosemObject,
                CosemObjectMethodId,
                &mut Option<CosemData>,
            ) -> Result<(), ActionResult>
            + Send
            + 'static,
    {
        *self.post_action.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn clear_pre_read(&self) {
        self.pre_read.lock().unwrap().take();
    }

    pub fn clear_post_read(&self) {
        self.post_read.lock().unwrap().take();
    }

    pub fn clear_pre_write(&self) {
        self.pre_write.lock().unwrap().take();
    }

    pub fn clear_post_write(&self) {
        self.post_write.lock().unwrap().take();
    }

    pub fn clear_pre_action(&self) {
        self.pre_action.lock().unwrap().take();
    }

    pub fn clear_post_action(&self) {
        self.post_action.lock().unwrap().take();
    }

    pub fn call_pre_read(
        &self,
        object: &dyn CosemObject,
        attribute_id: CosemObjectAttributeId,
    ) -> Result<(), DataAccessResult> {
        if let Some(callback) = self.pre_read.lock().unwrap().as_mut() {
            callback(object, attribute_id)
        } else {
            Ok(())
        }
    }

    pub fn call_post_read(
        &self,
        object: &dyn CosemObject,
        attribute_id: CosemObjectAttributeId,
        result: &mut Option<CosemData>,
    ) -> Result<(), DataAccessResult> {
        if let Some(callback) = self.post_read.lock().unwrap().as_mut() {
            callback(object, attribute_id, result)
        } else {
            Ok(())
        }
    }

    pub fn call_pre_write(
        &self,
        object: &mut dyn CosemObject,
        attribute_id: CosemObjectAttributeId,
        value: &mut CosemData,
    ) -> Result<(), DataAccessResult> {
        if let Some(callback) = self.pre_write.lock().unwrap().as_mut() {
            callback(object, attribute_id, value)
        } else {
            Ok(())
        }
    }

    pub fn call_post_write(
        &self,
        object: &mut dyn CosemObject,
        attribute_id: CosemObjectAttributeId,
        value: &CosemData,
    ) -> Result<(), DataAccessResult> {
        if let Some(callback) = self.post_write.lock().unwrap().as_mut() {
            callback(object, attribute_id, value)
        } else {
            Ok(())
        }
    }

    pub fn call_pre_action(
        &self,
        object: &mut dyn CosemObject,
        method_id: CosemObjectMethodId,
        parameters: &mut CosemData,
    ) -> Result<(), ActionResult> {
        if let Some(callback) = self.pre_action.lock().unwrap().as_mut() {
            callback(object, method_id, parameters)
        } else {
            Ok(())
        }
    }

    pub fn call_post_action(
        &self,
        object: &mut dyn CosemObject,
        method_id: CosemObjectMethodId,
        result: &mut Option<CosemData>,
    ) -> Result<(), ActionResult> {
        if let Some(callback) = self.post_action.lock().unwrap().as_mut() {
            callback(object, method_id, result)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for CosemObjectCallbackHandlers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CosemObjectCallbackHandlers")
            .finish_non_exhaustive()
    }
}

impl Default for CosemObjectCallbackHandlers {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeAccessMode {
    NoAccess = 0,
    Read = 1,
    Write = 2,
    ReadWrite = 3,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttributeAccessDescriptor {
    pub attribute_id: CosemObjectAttributeId,
    pub access_mode: AttributeAccessMode,
    pub selective_access_descriptor: Option<CosemData>,
}

impl AttributeAccessDescriptor {
    pub fn new(attribute_id: CosemObjectAttributeId, access_mode: AttributeAccessMode) -> Self {
        Self {
            attribute_id,
            access_mode,
            selective_access_descriptor: None,
        }
    }

    pub fn with_selective_access(
        attribute_id: CosemObjectAttributeId,
        access_mode: AttributeAccessMode,
        selective_access_descriptor: Option<CosemData>,
    ) -> Self {
        Self {
            attribute_id,
            access_mode,
            selective_access_descriptor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodAccessMode {
    NoAccess = 0,
    Access = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodAccessDescriptor {
    pub method_id: CosemObjectMethodId,
    pub access_mode: MethodAccessMode,
}

impl MethodAccessDescriptor {
    pub fn new(method_id: CosemObjectMethodId, access_mode: MethodAccessMode) -> Self {
        Self {
            method_id,
            access_mode,
        }
    }
}

pub trait CosemObject: Send {
    fn class_id(&self) -> u16;
    fn version(&self) -> u8 {
        0
    }
    fn attribute_access_rights(&self) -> Vec<AttributeAccessDescriptor> {
        Vec::new()
    }
    fn method_access_rights(&self) -> Vec<MethodAccessDescriptor> {
        Vec::new()
    }
    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData>;
    fn set_attribute(
        &mut self,
        attribute_id: CosemObjectAttributeId,
        data: CosemData,
    ) -> Option<()>;
    fn invoke_method(
        &mut self,
        method_id: CosemObjectMethodId,
        data: CosemData,
    ) -> Option<CosemData>;
    fn callbacks(&self) -> Option<Arc<CosemObjectCallbackHandlers>> {
        None
    }
}
