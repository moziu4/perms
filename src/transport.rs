use crate::{ActorId, ActorType, PermissionSet, RequestContext, Scope, TraceContext, UserID};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextClaims {
    pub actor_id: ActorId,
    pub actor_type: ActorType,
    pub on_behalf_of: Option<UserID>,
    pub scope: Scope,
    pub permissions: PermissionSet,
    pub trace: TraceContext,
    pub iss: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
    pub jti: String,
    pub kid: String,
}

#[derive(Debug)]
pub enum ContextVerificationError {
    Jwt(jsonwebtoken::errors::Error),
    InvalidKeyId,
    InvalidContext(crate::AuthorizationError),
}

pub fn verify_context(
    token: &str,
    public_key_pem: &[u8],
    issuer: &str,
    audience: &str,
    expected_key_id: &str,
) -> Result<RequestContext, ContextVerificationError> {
    let header = decode_header(token).map_err(ContextVerificationError::Jwt)?;
    if header.alg != Algorithm::RS256 || header.kid.as_deref() != Some(expected_key_id) {
        return Err(ContextVerificationError::InvalidKeyId);
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    let claims = decode::<ContextClaims>(token, &DecodingKey::from_rsa_pem(public_key_pem).map_err(ContextVerificationError::Jwt)?, &validation)
        .map_err(ContextVerificationError::Jwt)?
        .claims;
    let context = RequestContext {
        actor_id: claims.actor_id,
        actor_type: claims.actor_type,
        on_behalf_of: claims.on_behalf_of,
        scope: claims.scope,
        permissions: claims.permissions,
        trace: claims.trace,
    };
    context.validate().map_err(ContextVerificationError::InvalidContext)?;
    Ok(context)
}