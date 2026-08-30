use std::fs::File;
use std::hash::Hasher;
use std::io::{self, BufReader, Read};
use std::path::Path;
use twox_hash::XxHash64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Blake3,
    Xxh3,
}

impl HashAlgorithm {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "xxh3" | "xxhash" => HashAlgorithm::Xxh3,
            _ => HashAlgorithm::Blake3,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Blake3 => "blake3",
            HashAlgorithm::Xxh3 => "xxh3",
        }
    }
}

/// Computes file hash in a fast and streaming manner without loading entire large files to memory.
/// Compatible with scalar and legacy CPU architectures (zero AVX instruction trap).
pub fn compute_file_hash<P: AsRef<Path>>(path: P, algorithm: HashAlgorithm) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);
    let mut buffer = [0u8; 64 * 1024];

    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        HashAlgorithm::Xxh3 => {
            let mut hasher = XxHash64::default();
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.write(&buffer[..bytes_read]);
            }
            Ok(format!("{:016x}", hasher.finish()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_compute_hashes() {
        let temp_path =
            std::env::temp_dir().join(format!("sauroneye_test_{}", rand::random::<u64>()));
        {
            let mut file = std::fs::File::create(&temp_path).unwrap();
            writeln!(file, "SauronEye Sentinel Verification").unwrap();
        }

        let b3 = compute_file_hash(&temp_path, HashAlgorithm::Blake3).unwrap();
        assert!(!b3.is_empty());
        assert_eq!(b3.len(), 64);

        let xx = compute_file_hash(&temp_path, HashAlgorithm::Xxh3).unwrap();
        assert!(!xx.is_empty());
        assert_eq!(xx.len(), 16);

        let _ = std::fs::remove_file(&temp_path);
    }
}
