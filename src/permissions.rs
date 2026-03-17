use actix_web::HttpRequest;
use crate::token::Claims;

pub async fn has_permission(secret: String, req: HttpRequest, permission: &str) -> bool
{
    if let Some(auth_header) = req.headers().get("Authorization")
    {
        if let Ok(auth_str) = auth_header.to_str()
        {
            if auth_str.starts_with("Bearer ")
            {
                let token = &auth_str[7..];
                let validation = jsonwebtoken::Validation::default();
                if let Ok(token_data) =
                    jsonwebtoken::decode::<Claims>(&token,
                                                   &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
                                                   &validation)
                {
                    let claims = token_data.claims;
                    
                    let permissions = claims.permissions.iter().any(|p| p == permission);
                    return permissions;
                }
            }
        }
    }
    false
}

pub fn encode_perm(perms: Vec<String>)->Vec<String>
{
    perms
}

pub fn decode_perm(bits: Vec<String>) -> Vec<String>
{
    bits
}