use hex;
use bs58;
use std::fs::File;
use std::io::{BufRead, BufReader};
use k256::PublicKey;
use num_bigint::BigUint;
use num_traits::Num; // For BigUint::from_str_radix

pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_string_to_bytes(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex_str)
}

pub fn bytes_to_base58_string(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

pub fn base58_string_to_bytes(s: &str) -> Result<Vec<u8>, bs58::decode::Error> {
    bs58::decode(s).into_vec()
}

pub fn read_public_keys_from_file(file_path: &str) -> Result<Vec<PublicKey>, String> {
    let file = File::open(file_path).map_err(|e| format!("Failed to open file '{}': {}", file_path, e))?;
    let reader = BufReader::new(file);
    let mut public_keys = Vec::new();
    let mut line_number = 0;

    for line_result in reader.lines() {
        line_number += 1;
        let line = line_result.map_err(|e| format!("Failed to read line {}: {}", line_number, e))?;
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        match hex_string_to_bytes(trimmed_line) {
            Ok(bytes) => {
                match PublicKey::from_sec1_bytes(&bytes) {
                    Ok(pk) => public_keys.push(pk),
                    Err(e) => return Err(format!("Line {}: Invalid public key format: {} (hex: {})", line_number, e, trimmed_line)),
                }
            }
            Err(e) => return Err(format!("Line {}: Invalid hex string: {} (error: {})", line_number, trimmed_line, e)),
        }
    }
    Ok(public_keys)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::fs::File as StdFile;
    // num_bigint and num_traits already imported at file scope for the function itself

    #[test]
    fn test_bytes_to_hex_string() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(bytes_to_hex_string(&bytes), "deadbeef");
    }

    #[test]
    fn test_hex_string_to_bytes_valid() {
        let hex_str = "deadbeef";
        let expected_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(hex_string_to_bytes(hex_str).unwrap(), expected_bytes);
    }

    #[test]
    fn test_hex_string_to_bytes_invalid() {
        let hex_str = "invalid hex";
        assert!(hex_string_to_bytes(hex_str).is_err());
    }

    #[test]
    fn test_hex_string_to_bytes_odd_length() {
        let hex_str = "abc";
        assert!(hex_string_to_bytes(hex_str).is_err());
    }

    #[test]
    fn test_bytes_to_base58_string() {
        let data = hex_string_to_bytes("00010966776006953D5567439E5E39F86A0D273BEED61967F6").unwrap();
        let expected_b58 = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
        assert_eq!(bytes_to_base58_string(&data), expected_b58);
    }

    #[test]
    fn test_base58_string_to_bytes_valid() {
        let b58_str = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
        let expected_bytes = hex_string_to_bytes("00010966776006953D5567439E5E39F86A0D273BEED61967F6").unwrap();
        assert_eq!(base58_string_to_bytes(b58_str).unwrap(), expected_bytes);
    }

    #[test]
    fn test_base58_string_to_bytes_invalid_char() {
        let b58_str = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM0";
        assert!(base58_string_to_bytes(b58_str).is_err());
    }

     #[test]
    fn test_base58_string_to_bytes_empty() {
        let b58_str = "";
        assert_eq!(base58_string_to_bytes(b58_str).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_read_public_keys_from_file() {
        let file_path = "test_pubkeys.txt";
        let mut file = StdFile::create(file_path).unwrap();
        // Valid compressed
        writeln!(file, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        // Valid uncompressed
        writeln!(file, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
        writeln!(file, "   # This is a comment").unwrap();
        writeln!(file, "  ").unwrap(); // Empty line
        // Invalid hex
        writeln!(file, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179X").unwrap();

        let result = read_public_keys_from_file(file_path);
        assert!(result.is_err(), "Should fail due to invalid hex in file");
        assert!(result.unwrap_err().contains("Line 5: Invalid hex string"));

        // Create a valid file
        let mut valid_file = StdFile::create(file_path).unwrap();
        writeln!(valid_file, "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd").unwrap();
        writeln!(valid_file, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap();

        let pks = read_public_keys_from_file(file_path).expect("Should read valid pubkeys");
        assert_eq!(pks.len(), 2);

        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn test_parse_range_str_valid() {
        let range_str = "10:FF";
        let (start, end) = parse_range_str(range_str).unwrap();
        assert_eq!(start, BigUint::from(16u32));
        assert_eq!(end, BigUint::from(255u32));

        let range_str_large = "010000000000000000:FFFFFFFFFFFFFFFFFFFF";
        let (start_large, end_large) = parse_range_str(range_str_large).unwrap();
        assert_eq!(start_large, BigUint::from_str_radix("010000000000000000", 16).unwrap());
        assert_eq!(end_large, BigUint::from_str_radix("FFFFFFFFFFFFFFFFFFFF", 16).unwrap());
    }

    #[test]
    fn test_parse_range_str_invalid_format() {
        assert!(parse_range_str("10FF").is_err()); // Missing colon
        assert!(parse_range_str(":FF").is_err());  // Empty start
        assert!(parse_range_str("10:").is_err());  // Empty end
        assert!(parse_range_str("10:FF:00").is_err()); // Too many parts
    }

    #[test]
    fn test_parse_range_str_invalid_hex() {
        assert!(parse_range_str("10:GX").is_err()); // Invalid hex char 'X'
        assert!(parse_range_str("GZ:FF").is_err()); // Invalid hex char 'Z'
    }
}


pub fn parse_range_str(range_str: &str) -> Result<(BigUint, BigUint), String> {
    let parts: Vec<&str> = range_str.split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid range format. Expected START:END, got '{}'", range_str));
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    if start_str.is_empty() {
        return Err("Start of range cannot be empty".to_string());
    }
    if end_str.is_empty() {
        return Err("End of range cannot be empty".to_string());
    }

    let start = BigUint::from_str_radix(start_str, 16)
        .map_err(|e| format!("Failed to parse start of range '{}': {}", start_str, e))?;
    let end = BigUint::from_str_radix(end_str, 16)
        .map_err(|e| format!("Failed to parse end of range '{}': {}", end_str, e))?;

    if start > end {
        return Err(format!("Start of range ({}) cannot be greater than end of range ({})", start_str, end_str));
    }

    Ok((start, end))
}
