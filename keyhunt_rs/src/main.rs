use crate::bsgs::{generate_baby_steps_table, BabyStepBloomFilter, precompute_giant_step_interval};
use crate::utils::{read_public_keys_from_file, parse_range_str};
use k256::{ProjectivePoint, PublicKey as K256PublicKey, Scalar, FieldBytes, U256}; // Removed K256Scalar alias
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::group::prime::PrimeCurveAffine; // For is_identity
use num_bigint::BigUint;
use num_traits::{Num, FromPrimitive, ToPrimitive};
use rayon::prelude::*;

pub mod bsgs;
pub mod crypto;
pub mod utils;

use clap::Parser;
use k256::elliptic_curve::sec1::ToEncodedPoint; // For public key printing examples

/// Keyhunt_rs: A Rust implementation for searching private keys.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Mode of operation (e.g., bsgs, address, range)
    #[arg(short, long, value_name = "MODE", default_value = "bsgs")]
    mode: String,

    /// File containing public keys (one per line, hex encoded)
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    public_key_file: Option<String>,

    /// Search for a private key ending in a specific number of bits (e.g., for puzzle transactions)
    #[arg(short, long, value_name = "BITS")]
    bits: Option<u32>,

    /// Range of private keys to search (e.g., START_HEX:END_HEX)
    #[arg(short, long, value_name = "START:END")]
    range: Option<String>,

    /// K-factor for BSGS m value calculation (m = sqrt(N) * k_factor)
    #[arg(short = 'k', long, value_name = "KFACTOR", default_value_t = 1)]
    k_factor: u64,

    /// Search space size N for BSGS (hex or decimal string)
    #[arg(short = 'n', long = "nval", value_name = "N_VALUE")]
    n_value_str: Option<String>,

    /// Number of threads to use
    #[arg(short = 't', long, value_name = "THREADS", default_value_t = 1)]
    threads: usize,

    /// Save baby steps table and bloom filter to file / Load if existing
    #[arg(short = 'S', long)]
    save_load_tables: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("Parsed CLI arguments: {:?}", cli);

    let mut target_public_keys: Vec<K256PublicKey> = Vec::new();

    if let Some(file_path) = &cli.public_key_file {
        match read_public_keys_from_file(file_path) {
            Ok(pks) => {
                println!("Successfully read {} public keys from {}.", pks.len(), file_path);
                target_public_keys = pks;
            }
            Err(e) => {
                eprintln!("Error reading public key file: {}", e);
                return;
            }
        }
    }

    if let Some(range_str) = &cli.range {
        match parse_range_str(range_str) {
            Ok((start, end)) => {
                println!("Parsed range: {} to {}", start.to_str_radix(16), end.to_str_radix(16));
                // Further logic for range mode would go here
            }
            Err(e) => {
                eprintln!("Error parsing range string: {}", e);
                return;
            }
        }
    }

    // Determine N for BSGS
    let n_bsgs: BigUint = match &cli.n_value_str {
        Some(n_str) => {
            if n_str.starts_with("0x") {
                BigUint::from_str_radix(&n_str[2..], 16).unwrap_or_else(|e| {
                    eprintln!("Failed to parse hex N value: {}. Using default.", e);
                    BigUint::from_u64(0x100000000000).unwrap() // 2^44
                })
            } else {
                BigUint::from_str_radix(n_str, 10).unwrap_or_else(|e| {
                    eprintln!("Failed to parse decimal N value: {}. Using default.", e);
                    BigUint::from_u64(0x100000000000).unwrap() // 2^44
                })
            }
        }
        None => BigUint::from_u64(0x100000000000).unwrap(), // Default N = 2^44
    };
    println!("BSGS N value: {} (0x{})", n_bsgs, n_bsgs.to_str_radix(16));

    // Calculate m for BSGS
    let m_bigint = n_bsgs.sqrt() * BigUint::from(cli.k_factor);
    let m_u64 = m_bigint.to_u64().unwrap_or_else(|| {
        eprintln!("Calculated m value ({}) is too large for u64. Clamping to u64::MAX.", m_bigint);
        u64::MAX
    });
    if m_u64 == 0 {
        eprintln!("Calculated m value is 0, which is invalid for BSGS. Please check N and k-factor.");
        return;
    }
    println!("BSGS m value: {} (0x{})", m_u64, m_u64.to_string()); // Print m in decimal for now

    // --- Basic BSGS Execution Flow ---
    if cli.mode == "bsgs" && !target_public_keys.is_empty() {
        let target_pk_to_search = &target_public_keys[0]; // Take the first public key
        println!("\nAttempting BSGS search for public key: {:?}", target_pk_to_search);

        let g = ProjectivePoint::GENERATOR;

        println!("Generating baby steps table with m = {}...", m_u64);
        let baby_steps_table = generate_baby_steps_table(m_u64, &g);
        println!("Baby steps table generated with {} entries.", baby_steps_table.len());

        println!("Populating Bloom filter...");
        let mut bloom_filter = BabyStepBloomFilter::new(baby_steps_table.len(), 0.0000001); // Lower FP rate
        bloom_filter.populate(&baby_steps_table);
        println!("Bloom filter populated.");

        println!("Precomputing giant step interval (mG)...");
        let g_m = precompute_giant_step_interval(m_u64, &g);
        println!("mG precomputed.");

        // Determine max_k_iterations. For a search space N, and m steps, k goes up to m.
        // N = m * m effectively. So k_max should be around m.
        // If sk = k*m + i, and sk_max = N, then k_max*m + i_max ~ N. k_max*m ~ N. k_max ~ N/m = m.
        let max_k_iterations = m_u64;
        println!("Performing giant steps in parallel (up to {} iterations, using {} threads)...", max_k_iterations, cli.threads);

        // Variables to be captured by the parallel closure
        // Ensure they are Sync or cloned if necessary.
        // baby_steps_table is a Vec, its slice &[BsgsXValue] is Sync.
        // bloom_filter contains Bloom which should be Sync.
        // g, g_m, target_pk_projective are ProjectivePoint, which are Send + Sync.
        // m_scalar is Scalar, which is Send + Sync.

        let target_pk_projective = target_pk_to_search.to_projective();
        let m_scalar_captured = Scalar::from_uint_unchecked(U256::from(m_u64)); // Use Scalar directly
        let g_captured = g.clone();
        // let baby_steps_table_captured = &baby_steps_table;
        // let bloom_filter_captured = &bloom_filter; // Ref is Sync if BabyStepBloomFilter is Sync (depends on Bloom)
        // let g_m_captured = &g_m;

        rayon::ThreadPoolBuilder::new().num_threads(cli.threads).build_global().unwrap();

        let found_sk_scalar_option = (0..=max_k_iterations)
            .into_par_iter()
            .find_map_any(|k_val| {
                let k_scalar = Scalar::from_uint_unchecked(U256::from(k_val)); // Use Scalar directly
                let kmg_point = g_m * k_scalar;
                let current_q_point = target_pk_projective - kmg_point;
                let affine_q = current_q_point.to_affine();

                if PrimeCurveAffine::is_identity(&affine_q).into() {
                    return None;
                }

                // let affine_q = current_q_point.to_affine(); // Moved up
                let x_bytes_q: FieldBytes = affine_q.x();
                let mut x_prefix_q = [0u8; 6];
                let prefix_len = std::cmp::min(6, x_bytes_q.len());
                x_prefix_q[..prefix_len].copy_from_slice(&x_bytes_q[..prefix_len]);

                if bloom_filter.check(&x_prefix_q) {
                    match baby_steps_table.binary_search_by_key(&x_prefix_q, |bs_val| bs_val.x_prefix) {
                        Ok(initial_match_idx) => {
                            let mut current_idx = initial_match_idx;
                            // Check backward
                            while current_idx > 0 && baby_steps_table[current_idx - 1].x_prefix == x_prefix_q {
                                current_idx -= 1;
                            }
                            // Iterate through all matches
                            while current_idx < baby_steps_table.len() && baby_steps_table[current_idx].x_prefix == x_prefix_q {
                                let i_val = baby_steps_table[current_idx].index;
                                let i_scalar = Scalar::from_uint_unchecked(U256::from(i_val)); // Use Scalar directly
                                let potential_sk_scalar = (k_scalar * m_scalar_captured) + i_scalar;

                                let calculated_pk_affine = (g_captured * potential_sk_scalar).to_affine();
                                let target_pk_affine_for_cmp = target_pk_to_search.to_projective().to_affine();
                                if calculated_pk_affine == target_pk_affine_for_cmp {
                                    return Some(potential_sk_scalar);
                                }
                                current_idx += 1;
                            }
                            None
                        }
                        Err(_) => None,
                    }
                } else {
                    None
                }
            });

        match found_sk_scalar_option {
            Some(found_sk_scalar) => {
                let sk_bytes = found_sk_scalar.to_bytes();
                let sk_hex = utils::bytes_to_hex_string(sk_bytes.as_slice());
                println!("SUCCESS! Private key found: 0x{}", sk_hex);
            }
            None => {
                println!("Private key not found within the searched range (N={} m={}).", n_bsgs, m_u64);
            }
        }

    } else if cli.mode == "bsgs" && target_public_keys.is_empty() {
        println!("BSGS mode selected, but no target public keys provided via -f/--file.");
    }


    // Example usage of crypto and utils (can be removed or conditionalized later)
    // The following lines related to 'data', 'hex_str', 'b58_data' are removed as 'data' is undefined
    // and they are not essential for the current CLI/BSGS focus.
    // A specific example for keypair generation and address derivation is kept for now.

    println!("\n--- Example Key Derivation ---");
    let example_sk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    match crypto::generate_keypair_from_hex_sk(example_sk_hex) {
        Ok((_sk, pk)) => {
            println!("For SK: {}", example_sk_hex);
            println!("  Public Key (compressed): {}", utils::bytes_to_hex_string(pk.to_encoded_point(true).as_bytes()));
            println!("  Public Key (uncompressed): {}", utils::bytes_to_hex_string(pk.to_encoded_point(false).as_bytes()));
            println!("  Bitcoin Address (compressed): {}", crypto::pubkey_to_btc_address(&pk, true));
            println!("  Bitcoin Address (uncompressed): {}", crypto::pubkey_to_btc_address(&pk, false));
            println!("  Ethereum Address: {}", crypto::pubkey_to_eth_address(&pk));
        }
        Err(e) => println!("Keypair generation error for example SK: {}", e),
    }
}
