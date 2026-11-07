use crate::{AuthID, UserID};
use crate::scope::Scope;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuthorizationError {
    InvalidScope,
    MissingPermission,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActorId { User(UserID), Service(AuthID) }

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActorType { User, OrganizationWorker, OrganizationAdmin, PlatformAdmin, Service }

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceContext {
    pub request_id: String,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub scope: Scope,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PermissionSet(pub Vec<Permission>);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    pub actor_id: ActorId,
    pub actor_type: ActorType,
    pub on_behalf_of: Option<UserID>,
    pub scope: Scope,
    pub permissions: PermissionSet,
    pub trace: TraceContext,
}

impl RequestContext {
    pub fn new(actor_id: ActorId, actor_type: ActorType, scope: Scope, trace: TraceContext) -> Self {
        Self { actor_id, actor_type, on_behalf_of: None, scope, permissions: PermissionSet::default(), trace }
    }

    pub fn with_permissions(mut self, permissions: PermissionSet) -> Self {
        self.permissions = permissions;
        self
    }

    pub fn with_on_behalf_of(mut self, user_id: UserID) -> Self {
        self.on_behalf_of = Some(user_id);
        self
    }

    pub fn validate(&self) -> Result<(), AuthorizationError> {
        if matches!(self.scope, Scope::Tenant { .. }) && self.scope.tenant_id().is_none() {
            return Err(AuthorizationError::InvalidScope);
        }
        Ok(())
    }

    pub fn authorize(&self, permission: &str, required_scope: &Scope) -> Result<(), AuthorizationError> {
        self.validate()?;
        if self.scope != *required_scope {
            return Err(AuthorizationError::InvalidScope);
        }
        if self.permissions.0.iter().any(|entry| entry.name == permission && entry.scope == *required_scope) {
            Ok(())
        } else {
            Err(AuthorizationError::MissingPermission)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OrganizationId, Scope, TenantId};

    fn context(scope: Scope) -> RequestContext {
        RequestContext::new(
            ActorId::Service(AuthID::new()), ActorType::Service, scope.clone(),
            TraceContext { request_id: "request-1".into(), source: Some("gateway".into()) },
        ).with_permissions(PermissionSet(vec![Permission { name: "records.read".into(), scope }]))
    }

    #[test]
    fn authorizes_only_matching_scope() {
        let scope = Scope::Organization { organization_id: OrganizationId::new() };
        let request = context(scope.clone());
        assert!(request.authorize("records.read", &scope).is_ok());
        assert!(request.authorize("records.read", &Scope::Platform).is_err());
    }

    #[test]
    fn tenant_scope_keeps_organization_boundary() {
        let first = Scope::Tenant { organization_id: OrganizationId::new(), tenant_id: TenantId::new() };
        let second = Scope::Tenant { organization_id: OrganizationId::new(), tenant_id: TenantId::new() };
        let request = context(first.clone());
        assert!(request.authorize("records.read", &first).is_ok());
        assert!(request.authorize("records.read", &second).is_err());
    }
}