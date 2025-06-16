use std::cmp::Ordering;
use std::fs::File;
use std::io::{Write, Read, BufWriter, BufReader};
use k256::{
    PublicKey, ProjectivePoint, Scalar, FieldBytes, AffinePoint, // Re-added AffinePoint for clarity
    elliptic_curve::point::AffineCoordinates,
    elliptic_curve::scalar::FromUintUnchecked,
    elliptic_curve::group::prime::PrimeCurveAffine,
    U256
};
use bloomfilter::Bloom;
use crate::crypto::sha256_digest;

#[derive(Debug, Clone)]
pub struct BsgsXValue {
    pub x_prefix: [u8; 6],
    pub index: u64,
}

// ... (BsgsXValue impls remain the same) ...
impl PartialEq for BsgsXValue {
    fn eq(&self, other: &Self) -> bool {
        self.x_prefix == other.x_prefix
    }
}
impl Eq for BsgsXValue {}
impl PartialOrd for BsgsXValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BsgsXValue {
    fn cmp(&self, other: &Self) -> Ordering {
        self.x_prefix.cmp(&other.x_prefix)
    }
}

#[derive(Debug, Clone)]
pub struct TargetPublicKey {
    pub key: PublicKey,
    pub hex_representation: String,
    pub is_compressed: bool,
}

pub fn generate_baby_steps_table(m: u64, g: &ProjectivePoint) -> Vec<BsgsXValue> {
    let mut baby_steps = Vec::with_capacity(m as usize);
    let mut current_point = *g;
    for i in 1..=m {
        let affine_point = current_point.to_affine();
        let x_bytes: FieldBytes = affine_point.x();
        let mut x_prefix = [0u8; 6];
        x_prefix.copy_from_slice(&x_bytes[0..6]);
        baby_steps.push(BsgsXValue { x_prefix, index: i });
        if i < m { current_point += g; }
    }
    baby_steps.sort();
    baby_steps
}

pub struct BabyStepBloomFilter {
    pub filter: Bloom<[u8; 6]>,
}

impl BabyStepBloomFilter {
    pub fn new(estimated_items: usize, false_positive_rate: f64) -> Self {
        Self { filter: Bloom::new_for_fp_rate(estimated_items, false_positive_rate) }
    }
    pub fn populate(&mut self, baby_steps_table: &[BsgsXValue]) {
        for val in baby_steps_table { self.filter.set(&val.x_prefix); }
    }
    pub fn check(&self, x_prefix: &[u8; 6]) -> bool {
        self.filter.check(x_prefix)
    }

    pub fn save_to_file(&self, file_path: &str) -> Result<(), std::io::Error> {
        let file = File::create(file_path)?;
        let mut writer = BufWriter::new(file);
        let bitmap_bytes = self.filter.bitmap();
        let num_bits = self.filter.number_of_bits();
        let num_hashes = self.filter.number_of_hash_functions();
        let checksum = sha256_digest(&bitmap_bytes);
        writer.write_all(&checksum)?;
        writer.write_all(&num_bits.to_le_bytes())?;
        writer.write_all(&num_hashes.to_le_bytes())?;
        // Assuming self.filter.sip_keys() returns [(u64, u64); K] as per compiler error context
        for key_tuple in self.filter.sip_keys().iter() {
            writer.write_all(&key_tuple.0.to_le_bytes())?;
            writer.write_all(&key_tuple.1.to_le_bytes())?;
        }
        writer.write_all(&(bitmap_bytes.len() as u64).to_le_bytes())?;
        writer.write_all(&bitmap_bytes)?;
        Ok(())
    }

    pub fn load_from_file(file_path: &str) -> Result<Self, String> {
        let file = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut reader = BufReader::new(file);
        let mut checksum = [0u8; 32];
        reader.read_exact(&mut checksum).map_err(|e| format!("Read checksum error: {}", e))?;
        let mut num_bits_bytes = [0u8; 8];
        reader.read_exact(&mut num_bits_bytes).map_err(|e| format!("Read num_bits error: {}", e))?;
        let num_bits = u64::from_le_bytes(num_bits_bytes);
        let mut num_hashes_bytes = [0u8; 4];
        reader.read_exact(&mut num_hashes_bytes).map_err(|e| format!("Read num_hashes error: {}", e))?;
        let num_hashes = u32::from_le_bytes(num_hashes_bytes);
        // Read sip_keys assuming they were written as pairs of u64s (K=2 for default bloom filter)
        let mut sip_keys_tuples = [(0u64, 0u64); 2]; // K=2
        for i in 0..sip_keys_tuples.len() {
            let mut k1_bytes = [0u8; 8];
            reader.read_exact(&mut k1_bytes).map_err(|e| format!("Read sip_key.0 error: {}", e))?;
            sip_keys_tuples[i].0 = u64::from_le_bytes(k1_bytes);
            let mut k2_bytes = [0u8; 8];
            reader.read_exact(&mut k2_bytes).map_err(|e| format!("Read sip_key.1 error: {}", e))?;
            sip_keys_tuples[i].1 = u64::from_le_bytes(k2_bytes);
        }
        let mut bitmap_len_bytes = [0u8; 8];
        reader.read_exact(&mut bitmap_len_bytes).map_err(|e| format!("Read bitmap_len error: {}", e))?;
        let bitmap_len = u64::from_le_bytes(bitmap_len_bytes);
        let mut bitmap_bytes = vec![0u8; bitmap_len as usize];
        reader.read_exact(&mut bitmap_bytes).map_err(|e| format!("Read bitmap error: {}", e))?;
        let calculated_checksum = sha256_digest(&bitmap_bytes);
        if calculated_checksum != checksum { return Err("Bitmap checksum mismatch".to_string()); }
        let filter = Bloom::from_existing(&bitmap_bytes, num_bits, num_hashes, sip_keys_tuples);
        Ok(Self { filter })
    }
}

pub fn precompute_giant_step_interval(m: u64, g: &ProjectivePoint) -> ProjectivePoint {
    *g * Scalar::from_uint_unchecked(U256::from(m))
}

pub fn perform_giant_steps(
    target_pubkey: &PublicKey,
    m: u64,
    baby_steps_table: &[BsgsXValue],
    bloom_filter: &BabyStepBloomFilter,
    g_gen: &ProjectivePoint,
    g_m: &ProjectivePoint,
    max_k_iterations: u64,
) -> Option<Scalar> {
    let mut current_q_point = target_pubkey.to_projective();
    // Explicitly convert PublicKey to AffinePoint if they are not seen as identical by the compiler here.
    // PublicKey is an alias for AffinePoint, so direct dereference should work, but .into() is safer if types are distinct.
    let target_affine: AffinePoint = (*target_pubkey).into();

    for k in 0..=max_k_iterations {
        let affine_q = current_q_point.to_affine();
        if PrimeCurveAffine::is_identity(&affine_q).into() { // Use trait for is_identity
            current_q_point -= g_m;
            continue;
        }
        let x_bytes_q: FieldBytes = affine_q.x();
        let mut x_prefix_q = [0u8; 6];
        x_prefix_q.copy_from_slice(&x_bytes_q[0..6]);

        if bloom_filter.check(&x_prefix_q) {
            match baby_steps_table.binary_search_by_key(&x_prefix_q, |bs_val| bs_val.x_prefix) {
                Ok(initial_match_idx) => {
                    for current_check_idx in initial_match_idx..baby_steps_table.len() {
                        if baby_steps_table[current_check_idx].x_prefix != x_prefix_q { break; }
                        let found_val = &baby_steps_table[current_check_idx];
                        let i_scalar = Scalar::from_uint_unchecked(U256::from(found_val.index));
                        let k_scalar = Scalar::from_uint_unchecked(U256::from(k));
                        let m_scalar = Scalar::from_uint_unchecked(U256::from(m));
                        let sk_scalar = (k_scalar * m_scalar) + i_scalar;
                        if (*g_gen * sk_scalar).to_affine() == target_affine { return Some(sk_scalar); }
                    }
                    if initial_match_idx > 0 {
                        for current_check_idx in (0..initial_match_idx).rev() {
                            if baby_steps_table[current_check_idx].x_prefix != x_prefix_q { break; }
                            let found_val = &baby_steps_table[current_check_idx];
                            let i_scalar = Scalar::from_uint_unchecked(U256::from(found_val.index));
                            let k_scalar = Scalar::from_uint_unchecked(U256::from(k));
                            let m_scalar = Scalar::from_uint_unchecked(U256::from(m));
                            let sk_scalar = (k_scalar * m_scalar) + i_scalar;
                            if (*g_gen * sk_scalar).to_affine() == target_affine { return Some(sk_scalar); }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        current_q_point -= g_m;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_bsgs_xvalue_ordering() { /* ... */ }
    #[test]
    fn test_generate_baby_steps_table_small_m() { /* ... */ }
    #[test]
    fn test_bloom_filter_population_and_check() { /* ... */ }
    #[test]
    fn test_bloom_filter_save_and_load() { /* ... */ }
    #[test]
    fn test_precompute_giant_step_interval() { /* ... */ }

    // Simplified test content for brevity in this example block
    #[test]
    fn test_giant_steps_finds_key() {
        let g = ProjectivePoint::GENERATOR;
        let test_sk_val = 100u64;
        let m = 10u64;
        let max_k = (test_sk_val / m) + 2;
        let sk_scalar = Scalar::from_uint_unchecked(U256::from(test_sk_val));

        // Corrected SecretKey/PublicKey generation
        let signing_key = SigningKey::from_bytes(&sk_scalar.to_bytes()).expect("Scalar should be valid for SigningKey");
        let target_pk: PublicKey = signing_key.verifying_key().into();

        let baby_steps = generate_baby_steps_table(m, &g);
        let mut bloom = BabyStepBloomFilter::new(baby_steps.len(), 0.0001);
        bloom.populate(&baby_steps);
        let g_m = precompute_giant_step_interval(m, &g);

        let result = perform_giant_steps(&target_pk, m, &baby_steps, &bloom, &g, &g_m, max_k);
        assert!(result.is_some(), "Key 100 should be found. SK: {}", test_sk_val);
        assert_eq!(result.unwrap(), sk_scalar);
    }

    #[test]
    fn test_giant_steps_key_not_found() {
        let g = ProjectivePoint::GENERATOR;
        let m = 10u64;
        let too_large_sk_val = m * (m + 2) + 1; // e.g. 121 for m=10
        let sk_scalar_large = Scalar::from_uint_unchecked(U256::from(too_large_sk_val));
        let signing_key_large = SigningKey::from_bytes(&sk_scalar_large.to_bytes()).expect("Scalar should be valid");
        let target_pk = signing_key_large.verifying_key().into();

        let baby_steps = generate_baby_steps_table(m, &g);
        let mut bloom = BabyStepBloomFilter::new(baby_steps.len(), 0.0001);
        bloom.populate(&baby_steps);
        let g_m = precompute_giant_step_interval(m, &g);

        let result = perform_giant_steps(&target_pk, m, &baby_steps, &bloom, &g, &g_m, m);
        assert!(result.is_none());
    }
}
