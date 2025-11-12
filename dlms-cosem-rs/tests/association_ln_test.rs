use dlms_cosem::association_ln::{AssociationLN, ObjectListEntry};
use dlms_cosem::cosem_object::{
    AttributeAccessDescriptor, AttributeAccessMode, CosemObject, MethodAccessDescriptor,
    MethodAccessMode,
};
use dlms_cosem::types::CosemData;
use std::sync::{Arc, Mutex};

#[test]
fn test_association_ln_new() {
    let object_list = Arc::new(Mutex::new(vec![ObjectListEntry {
        class_id: 3,
        version: 0,
        logical_name: [0, 0, 1, 0, 0, 255],
        attribute_access: vec![
            AttributeAccessDescriptor::new(2, AttributeAccessMode::ReadWrite),
            AttributeAccessDescriptor::new(3, AttributeAccessMode::ReadWrite),
        ],
        method_access: vec![MethodAccessDescriptor::new(1, MethodAccessMode::Access)],
    }]));
    let app_context_name = b"app_context".to_vec();
    let xdlms_context_info = b"xdlms_info".to_vec();
    let auth_mech_name = b"auth_mech".to_vec();

    let association_ln = AssociationLN::new(
        Arc::clone(&object_list),
        12345,
        app_context_name.clone(),
        xdlms_context_info.clone(),
        auth_mech_name.clone(),
    );

    assert_eq!(association_ln.class_id(), 15);
    assert_eq!(
        association_ln.get_attribute(2),
        Some(CosemData::Array(vec![CosemData::Structure(vec![
            CosemData::LongUnsigned(3),
            CosemData::Unsigned(0),
            CosemData::OctetString(vec![0, 0, 1, 0, 0, 255]),
            CosemData::Structure(vec![
                CosemData::Array(vec![
                    CosemData::Structure(vec![
                        CosemData::Integer(2),
                        CosemData::Enum(AttributeAccessMode::ReadWrite as u8),
                        CosemData::NullData,
                    ]),
                    CosemData::Structure(vec![
                        CosemData::Integer(3),
                        CosemData::Enum(AttributeAccessMode::ReadWrite as u8),
                        CosemData::NullData,
                    ]),
                ]),
                CosemData::Array(Vec::new()),
                CosemData::Array(vec![CosemData::Structure(vec![
                    CosemData::Integer(1),
                    CosemData::Enum(MethodAccessMode::Access as u8),
                ]),]),
            ]),
        ])]))
    );
    assert_eq!(
        association_ln.get_attribute(3),
        Some(CosemData::DoubleLongUnsigned(12345))
    );
    assert_eq!(
        association_ln.get_attribute(4),
        Some(CosemData::OctetString(app_context_name))
    );
    assert_eq!(
        association_ln.get_attribute(5),
        Some(CosemData::OctetString(xdlms_context_info))
    );
    assert_eq!(
        association_ln.get_attribute(6),
        Some(CosemData::OctetString(auth_mech_name))
    );
}

#[test]
fn test_association_ln_set_attribute() {
    let mut association_ln = AssociationLN::default();

    // Test setting associated_partners_id
    association_ln
        .set_attribute(3, CosemData::DoubleLongUnsigned(54321))
        .unwrap();
    assert_eq!(
        association_ln.get_attribute(3),
        Some(CosemData::DoubleLongUnsigned(54321))
    );

    // Test setting application_context_name
    let new_app_context = b"new_app_context".to_vec();
    association_ln
        .set_attribute(4, CosemData::OctetString(new_app_context.clone()))
        .unwrap();
    assert_eq!(
        association_ln.get_attribute(4),
        Some(CosemData::OctetString(new_app_context))
    );

    // Test that object_list (attribute 2) is read-only
    assert_eq!(association_ln.set_attribute(2, CosemData::NullData), None);
}
