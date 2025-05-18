use actix_web::HttpRequest;
use crate::token::Claims;

pub async fn has_permission(req: HttpRequest, permission: u32) -> bool
{
    if let Some(auth_header) = req.headers().get("Authorization")
    {
        if let Ok(auth_str) = auth_header.to_str()
        {
            if auth_str.starts_with("Bearer ")
            {
                let token = &auth_str[7..];
                let secret = std::env::var("SECRET_KEY").unwrap().to_string();
                let validation = jsonwebtoken::Validation::default();
                if let Ok(token_data) =
                    jsonwebtoken::decode::<Claims>(&token,
                                                   &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
                                                   &validation)
                {
                    let claims = token_data.claims;
                    
                    let permissions_decoded = decode_perm(claims.permissions);
                    let permissions = permissions_decoded.contains(&permission);
                    return permissions;
                }
            }
        }
    }
    false
}

pub fn encode_perm(perms: Vec<u32>)->Vec<u64>
{
    let mut bitfield = vec![];
    for perm in perms {
        let index = (perm / 64) as usize;
        let bit = 1u64 << (perm % 64);
        if bitfield.len() <= index {
            bitfield.resize(index + 1, 0);
        }
        bitfield[index] |= bit;
    }
    bitfield
}

pub fn decode_perm(bits: Vec<u64>) -> Vec<u32>
{
    let mut result = vec![];
    for (i, &chunk) in bits.iter().enumerate()
    {
        for j in 0..64 {
            if (chunk >>j) & 1 == 1
            {result.push (i as u32 * 64 + j as u32);
            }
        }
    }
    result
}