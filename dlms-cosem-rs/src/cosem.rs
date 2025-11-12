pub type CosemClassId = u16;
pub type CosemObjectInstanceId = [u8; 6];
pub type CosemObjectAttributeId = i8;
pub type CosemObjectMethodId = i8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosemAttributeDescriptor {
    pub class_id: CosemClassId,
    pub instance_id: CosemObjectInstanceId,
    pub attribute_id: CosemObjectAttributeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosemMethodDescriptor {
    pub class_id: CosemClassId,
    pub instance_id: CosemObjectInstanceId,
    pub method_id: CosemObjectMethodId,
}
