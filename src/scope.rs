use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

macro_rules! scoped_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
        pub struct $name(ObjectId);

        impl $name {
            pub fn new() -> Self { Self(ObjectId::new()) }
            pub fn from_object_id(id: ObjectId) -> Self { Self(id) }
            pub fn value(self) -> ObjectId { self.0 }
            pub fn parse_str(value: &str) -> Result<Self, mongodb::bson::oid::Error> {
                Ok(Self(ObjectId::from_str(value)?))
            }
        }

        impl From<ObjectId> for $name {
            fn from(value: ObjectId) -> Self { Self(value) }
        }

        impl From<$name> for ObjectId {
            fn from(value: $name) -> Self { value.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0)
            }
        }
    };
}

scoped_id!(OrganizationId);
scoped_id!(TenantId);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Scope {
    Platform,
    Organization { organization_id: OrganizationId },
    Tenant { organization_id: OrganizationId, tenant_id: TenantId },
    Personal { user_id: crate::UserID },
}

impl Scope {
    pub fn organization_id(&self) -> Option<OrganizationId> {
        match self {
            Self::Organization { organization_id } | Self::Tenant { organization_id, .. } => Some(*organization_id),
            Self::Platform | Self::Personal { .. } => None,
        }
    }

    pub fn tenant_id(&self) -> Option<TenantId> {
        match self { Self::Tenant { tenant_id, .. } => Some(*tenant_id), _ => None }
    }
}