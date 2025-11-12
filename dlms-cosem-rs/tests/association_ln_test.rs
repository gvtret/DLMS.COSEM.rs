use dlms_cosem::association_ln::AssociationLN;
use dlms_cosem::cosem_object::CosemObject;
use dlms_cosem::types::Data as CosemData;

#[test]
fn test_association_ln_new() {
    let object_list = b"test_list".to_vec();
    let app_context_name = b"app_context".to_vec();
    let xdlms_context_info = b"xdlms_info".to_vec();
    let auth_mech_name = b"auth_mech".to_vec();

    let association_ln = AssociationLN::new(
        object_list.clone(),
        12345,
        app_context_name.clone(),
        xdlms_context_info.clone(),
        auth_mech_name.clone(),
    );

    assert_eq!(association_ln.class_id(), 15);
    assert_eq!(
        association_ln.get_attribute(2),
        Some(CosemData::OctetString(object_list))
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
    let object_list = b"some_list".to_vec();
    assert_eq!(
        association_ln.set_attribute(2, CosemData::OctetString(object_list)),
        None
    );
}
