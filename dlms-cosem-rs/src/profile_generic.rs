use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::CosemData;

#[derive(Debug)]
pub struct ProfileGeneric {
    buffer: CosemData,
    capture_objects: CosemData,
    capture_period: CosemData,
    sort_method: CosemData,
    sort_object: CosemData,
    entries_in_use: CosemData,
    profile_entries: CosemData,
}

impl ProfileGeneric {
    pub fn new() -> Self {
        Self {
            buffer: CosemData::NullData,
            capture_objects: CosemData::NullData,
            capture_period: CosemData::NullData,
            sort_method: CosemData::NullData,
            sort_object: CosemData::NullData,
            entries_in_use: CosemData::NullData,
            profile_entries: CosemData::NullData,
        }
    }
}

impl Default for ProfileGeneric {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for ProfileGeneric {
    fn class_id(&self) -> u16 {
        7
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.buffer.clone()),
            3 => Some(self.capture_objects.clone()),
            4 => Some(self.capture_period.clone()),
            5 => Some(self.sort_method.clone()),
            6 => Some(self.sort_object.clone()),
            7 => Some(self.entries_in_use.clone()),
            8 => Some(self.profile_entries.clone()),
            _ => None,
        }
    }

    fn set_attribute(
        &mut self,
        attribute_id: CosemObjectAttributeId,
        data: CosemData,
    ) -> Option<()> {
        match attribute_id {
            2 => {
                self.buffer = data;
                Some(())
            }
            3 => {
                self.capture_objects = data;
                Some(())
            }
            4 => {
                self.capture_period = data;
                Some(())
            }
            5 => {
                self.sort_method = data;
                Some(())
            }
            6 => {
                self.sort_object = data;
                Some(())
            }
            7 => {
                self.entries_in_use = data;
                Some(())
            }
            8 => {
                self.profile_entries = data;
                Some(())
            }
            _ => None,
        }
    }

    fn invoke_method(
        &mut self,
        _method_id: CosemObjectMethodId,
        _data: CosemData,
    ) -> Option<CosemData> {
        None
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_profile_generic_new() {
        let profile = ProfileGeneric::new();
        assert_eq!(profile.get_attribute(2), Some(CosemData::NullData));
        assert_eq!(profile.get_attribute(3), Some(CosemData::NullData));
        assert_eq!(profile.get_attribute(4), Some(CosemData::NullData));
        assert_eq!(profile.get_attribute(5), Some(CosemData::NullData));
        assert_eq!(profile.get_attribute(6), Some(CosemData::NullData));
        assert_eq!(profile.get_attribute(7), Some(CosemData::NullData));
        assert_eq!(profile.get_attribute(8), Some(CosemData::NullData));
    }
}
