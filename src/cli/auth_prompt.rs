use std::io::{self, Write};

pub struct AuthPrompt;

impl AuthPrompt {
    pub fn prompt_password(prompt: &str) -> io::Result<String> {
        print!("{}", prompt);
        io::stdout().flush()?;
        rpassword::read_password()
    }

    pub fn prompt_new_password() -> io::Result<String> {
        loop {
            let p1 = Self::prompt_password("Enter new admin password for SauronEye: ")?;
            if p1.trim().len() < 12 {
                println!("❌ Password must be at least 12 characters long. Please try again.");
                continue;
            }

            let p2 = Self::prompt_password("Confirm new admin password: ")?;
            if p1 != p2 {
                println!("❌ Passwords do not match. Please try again.");
                continue;
            }

            return Ok(p1);
        }
    }
}
