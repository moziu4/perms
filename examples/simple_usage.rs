use perms::{ActorId, ActorType, AuthID, Claims, OrganizationId, Permission, PermissionSet, RequestContext, Role, Scope, TraceContext};

fn main() {
    // 1. Simular un token generado (esto lo haría el servicio de usuarios)
    // En este ejemplo, solo mostramos cómo usar la librería para entenderlo.
    
    let role = Role::AgencyAdmin;
    let role_id = role.to_id();
    
    println!("Rol: {} (ID: {})", role, role_id);
    
    // 2. Cómo otro servicio decodificaría el token
    // Supongamos que recibimos este token en una petición
    // let token = "..."; 
    // let claims = decode_token(token, secret).expect("Token inválido");
    
    // 3. Verificar permisos de forma manual si no se usa actix-web
    let claims = Claims {
        sub: "user_123".to_string(),
        exp: 10000000000,
        permissions: vec!["1".into(), "2".into(), "3".into()],
        role_id,
    };
    
    if claims.permissions.contains(&"2".to_string()) {
        println!("El usuario tiene el permiso 2");
    }
    
    // 4. Convertir de ID a Role
    if let Some(r) = Role::from_id(3) {
        println!("El ID 3 corresponde al rol: {}", r);
    }

    // 5. Nuevo flujo: el contexto verificado se autoriza explícitamente por scope.
    let scope = Scope::Organization { organization_id: OrganizationId::new() };
    let context = RequestContext::new(
        ActorId::Service(AuthID::new()),
        ActorType::Service,
        scope.clone(),
        TraceContext { request_id: "request-123".into(), source: Some("gateway".into()) },
    ).with_permissions(PermissionSet(vec![Permission { name: "records.read".into(), scope: scope.clone() }]));

    context.authorize("records.read", &scope).expect("Permiso insuficiente");
}
