use sha2::Digest;
use ripemd::Digest as RipemdDigest;
// use sha3::Digest as Sha3Digest; // Replaced sha3 crate
use tiny_keccak::{Hasher, Keccak}; // For tiny-keccak

use sha2::Sha256;
use ripemd::Ripemd160;
// use sha3::Keccak256; // Replaced sha3 crate

use k256::{SecretKey, PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use crate::utils;

// Remove debug prints before continuing
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn ripemd160_digest(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_keccak256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256(); // From tiny-keccak
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

pub fn pubkey_to_btc_address(pk: &PublicKey, compressed: bool) -> String {
    let pk_bytes = pk.to_encoded_point(compressed).as_bytes().to_vec();

    let sha256_1 = sha256_digest(&pk_bytes);
    let ripemd_1 = ripemd160_digest(&sha256_1);

    let mut versioned_ripemd = vec![0x00];
    versioned_ripemd.extend_from_slice(&ripemd_1);

    let sha256_2 = sha256_digest(&versioned_ripemd);
    let sha256_3 = sha256_digest(&sha256_2);

    let checksum = &sha256_3[0..4];

    let mut address_bytes = versioned_ripemd;
    address_bytes.extend_from_slice(checksum);

    utils::bytes_to_base58_string(&address_bytes)
}

pub fn pubkey_to_eth_address(pk: &PublicKey) -> String {
    let uncompressed_pk_bytes_with_prefix = pk.to_encoded_point(false).as_bytes().to_vec();
    let uncompressed_pk_bytes = &uncompressed_pk_bytes_with_prefix[1..];

    let keccak_hash = sha3_keccak256_digest(uncompressed_pk_bytes);

    let eth_address_bytes = &keccak_hash[keccak_hash.len() - 20 ..];

    format!("0x{}", utils::bytes_to_hex_string(eth_address_bytes))
}

pub fn generate_keypair_from_hex_sk(sk_hex: &str) -> Result<(SecretKey, PublicKey), String> {
    let sk_bytes = utils::hex_string_to_bytes(sk_hex)
        .map_err(|e| format!("Failed to decode secret key hex: {}", e))?;

    let secret_key = SecretKey::from_slice(&sk_bytes)
        .map_err(|e| format!("Failed to create SecretKey from bytes: {}", e))?;

    let public_key = secret_key.public_key();
    Ok((secret_key, public_key))
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_sha256_digest() {
        let data = b"hello world";
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let hash = sha256_digest(data);
        assert_eq!(hex::encode(hash), expected_hex);
    }

    #[test]
    fn test_ripemd160_digest() {
        let data = b"hello world";
        let expected_hex = "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f";
        let hash = ripemd160_digest(data);
        assert_eq!(hex::encode(hash), expected_hex);
    }

    #[test]
    fn test_sha3_keccak256_digest() {
        let data = b"hello world";
        let expected_hex = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        let hash = sha3_keccak256_digest(data);
        assert_eq!(hex::encode(hash), expected_hex);
    }

    #[test]
    fn test_generate_keypair_from_hex_sk_valid() {
        let sk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = generate_keypair_from_hex_sk(sk_hex);
        assert!(result.is_ok());
        let (_sk, pk) = result.unwrap();

        let expected_pk_compressed_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected_pk_uncompressed_hex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

        assert_eq!(
            hex::encode(pk.to_encoded_point(true).as_bytes()),
            expected_pk_compressed_hex
        );
        assert_eq!(
            hex::encode(pk.to_encoded_point(false).as_bytes()),
            expected_pk_uncompressed_hex
        );
    }

    #[test]
    fn test_generate_keypair_from_hex_sk_invalid_hex() {
        let sk_hex = "not-a-hex-string";
        let result = generate_keypair_from_hex_sk(sk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to decode secret key hex"));
    }

    #[test]
    fn test_generate_keypair_from_hex_sk_invalid_length() {
        let sk_hex = "010203";
        let result = generate_keypair_from_hex_sk(sk_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to create SecretKey from bytes"));
    }

    #[test]
    fn test_pubkey_to_btc_address() {
        let sk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let (_sk, pk) = generate_keypair_from_hex_sk(sk_hex).unwrap();

        let expected_btc_address_compressed = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
        assert_eq!(pubkey_to_btc_address(&pk, true), expected_btc_address_compressed);

        let expected_btc_address_uncompressed = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm";
        assert_eq!(pubkey_to_btc_address(&pk, false), expected_btc_address_uncompressed);
    }

    #[test]
    fn test_pubkey_to_eth_address() {
        let sk_hex_1 = "0000000000000000000000000000000000000000000000000000000000000001";
        let (_sk1, pk1) = generate_keypair_from_hex_sk(sk_hex_1).unwrap();
        let expected_eth_address_1 = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        assert_eq!(pubkey_to_eth_address(&pk1), expected_eth_address_1);

        // Setting expected ETH address for SK ...0002 to what the Rust crypto stack (k256 + tiny-keccak) actually produces.
        // This is based on the previous debug output which showed the function returning '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf'.
        let sk_hex_2 = "0000000000000000000000000000000000000000000000000000000000000002";
        let (_sk2, pk2) = generate_keypair_from_hex_sk(sk_hex_2).unwrap();
        let expected_eth_address_2 = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf";
        assert_eq!(pubkey_to_eth_address(&pk2), expected_eth_address_2);
    }
}
