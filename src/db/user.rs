use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::error::Error;

pub struct AdminAuth;

impl AdminAuth {
    pub fn hash_password(password: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Failed to hash password with Argon2id: {}", e))?
            .to_string();
        Ok(password_hash)
    }

    pub fn verify_password(password: &str, password_hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(password_hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let pass = "SUp3r_S3cur3_P@ssw0rd!#";
        let hash = AdminAuth::hash_password(pass).unwrap();
        assert!(AdminAuth::verify_password(pass, &hash));
        assert!(!AdminAuth::verify_password("wrong_password", &hash));
    }
}
