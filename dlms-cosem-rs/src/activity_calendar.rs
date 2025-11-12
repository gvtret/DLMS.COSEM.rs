use crate::cosem_object::CosemObject;
use crate::cosem::{CosemObjectAttributeId, CosemObjectMethodId};
use crate::types::CosemData;

#[derive(Debug)]
pub struct ActivityCalendar {
    calendar_name: CosemData,
    season_profile: CosemData,
    week_profile: CosemData,
    day_profile: CosemData,
}

impl ActivityCalendar {
    pub fn new() -> Self {
        Self {
            calendar_name: CosemData::NullData,
            season_profile: CosemData::NullData,
            week_profile: CosemData::NullData,
            day_profile: CosemData::NullData,
        }
    }
}

impl Default for ActivityCalendar {
    fn default() -> Self {
        Self::new()
    }
}

impl CosemObject for ActivityCalendar {
    fn class_id(&self) -> u16 {
        20
    }

    fn get_attribute(&self, attribute_id: CosemObjectAttributeId) -> Option<CosemData> {
        match attribute_id {
            2 => Some(self.calendar_name.clone()),
            3 => Some(self.season_profile.clone()),
            4 => Some(self.week_profile.clone()),
            5 => Some(self.day_profile.clone()),
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
                self.calendar_name = data;
                Some(())
            }
            3 => {
                self.season_profile = data;
                Some(())
            }
            4 => {
                self.week_profile = data;
                Some(())
            }
            5 => {
                self.day_profile = data;
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
    fn test_activity_calendar_new() {
        let calendar = ActivityCalendar::new();
        assert_eq!(calendar.get_attribute(2), Some(CosemData::NullData));
        assert_eq!(calendar.get_attribute(3), Some(CosemData::NullData));
        assert_eq!(calendar.get_attribute(4), Some(CosemData::NullData));
        assert_eq!(calendar.get_attribute(5), Some(CosemData::NullData));
    }
}
