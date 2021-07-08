//! Constants used in the circuits.

use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::Group;
use lazy_static::{initialize, lazy_static};

use crate::group_hash::group_hash;

// Personalisation strings.
/// Personalisation string for the address PRF.
pub const PERSONALISATION_PRF_ADDR: &[u8; 8] = b"PRF_ADDR";
/// Personalisation string for the note nullifier PRF.
pub const PERSONALISATION_PRF_ETA: &[u8; 8] = b"PRF_ETA_";
/// Personalisation string for the memory nullifier PRF.
pub const PERSONALISATION_PRF_MU: &[u8; 8] = b"_PRF_MU_";
/// Personalisation string for the memory nullifier PRF.
pub const PERSONALISATION_PRF_KAPPA: &[u8; 8] = b"PRFKAPPA";
/// Personalisation string for both the inner and outer hash of the credential commitment.
pub const PERSONALISATION_COMM_CRED: &[u8; 8] = b"COMMCRED";
/// Personalisation string for both the inner and outer hash of the note commitment.
pub const PERSONALISATION_COMM_NOTE: &[u8; 8] = b"COMMNOTE";
/// Personalisation string for both the inner and outer hash of the note commitment.
pub const PERSONALISATION_COMM_MEM: &[u8; 8] = b"COMM_MEM";
/// Personalisation string for the CRH of the Credential Merkle Tree.
pub const PERSONALISATION_CREDENTIAL_MERKLE_TREE_HASH: &[u8; 8] = b"CRED_MT?";
/// Personalisation string for the CRH of the Note Merkle Tree.
pub const PERSONALISATION_NOTE_MERKLE_TREE_HASH: &[u8; 8] = b"NOTE_MT?";
/// Personalisation string for the CRH of the Memory Merkle Tree.
pub const PERSONALISATION_MEMORY_MERKLE_TREE_HASH: &[u8; 8] = b"MEM_MT_?";
/// Personalisation string for the blake2s in group hash used for the pedersen hash.
pub const PERSONALISATION_PEDERSEN_HASH_GENERATORS: &[u8; 8] = b"PED_GENS";
/// Salt for the KDF used in encryption of secret transaction values.
pub const SALT_ENCRYPTION: &[u8; 8] = b"TXCRYPTO";
/// Personalisation string for the public signature key k;
pub const PERSONALISATION_K: &[u8; 8] = b"PKSIGTOK";

// Other constants.
/// Randomness used for the blake2s hash in group hash.
pub const GROUP_HASH_RANDOMNESS: &[u8; 64] =
    b"b82633c5897fec44fa1817756ee419a0476a43df3efc901c21f9790a3e44b1bb";
/// Credential Merkle Tree depth.
pub const CREDENTIAL_MT_DEPTH: usize = 20;
/// Note Merkle Tree depth.
pub const NOTE_MT_DEPTH: usize = 32;
/// Memory Merkle Tree depth.
pub const MEMORY_MT_DEPTH: usize = 32;
/// Block size for a SAVER message. Should be smaller than NUM_BITS.
pub const SAVER_BLOCK_SIZE: u32 = 16;
/// Spend limit (in €).
pub const SPEND_LIMIT: u64 = 1000;
/// Time frame for spend limit (in s).
pub const TIME_LIMIT: u64 = 60;

// Jubjub constants; The part below is copied from Zcash (and slightly adapted):
// https://github.com/zcash/librustzcash/blob/master/zcash_primitives/src/constants.rs

/// The maximum number of chunks per segment of the Pedersen hash.
pub const PEDERSEN_HASH_CHUNKS_PER_GENERATOR: usize = 63;

/// The window size for exponentiation of Pedersen hash generators outside the circuit.
pub const PEDERSEN_HASH_EXP_WINDOW_SIZE: u32 = 8;

lazy_static! {
    /// Fixed generators of the Jubjub curve of unknown exponent.
    static ref FIXED_BASE_GENERATORS: Vec<jubjub::SubgroupPoint> = fixed_base_generators();

    /// The credential commitment is randomized over this generator.
    pub static ref CRED_COMMITMENT_RANDOMNESS_GENERATOR: jubjub::SubgroupPoint = FIXED_BASE_GENERATORS[0];

    /// The note commitment is randomized over this generator.
    pub static ref NOTE_COMMITMENT_RANDOMNESS_GENERATOR: jubjub::SubgroupPoint = FIXED_BASE_GENERATORS[1];

    /// The memory commitment is randomized over this generator.
    pub static ref MEM_COMMITMENT_RANDOMNESS_GENERATOR: jubjub::SubgroupPoint = FIXED_BASE_GENERATORS[2];
}

lazy_static! {
    /// The generators (for each segment) used in all Pedersen commitments.
    pub static ref PEDERSEN_HASH_GENERATORS: Vec<jubjub::SubgroupPoint> =
        generate_pedersen_hash_generators();
}

lazy_static! {
    /// The exp table for [`PEDERSEN_HASH_GENERATORS`].
    pub static ref PEDERSEN_HASH_EXP_TABLE: Vec<Vec<Vec<jubjub::SubgroupPoint>>> =
        generate_pedersen_hash_exp_table();
}

/// Initialise all static references for the Jubjub curve that are used outside the circuit.
pub fn initialise_jubjub_constants() {
    initialize(&CRED_COMMITMENT_RANDOMNESS_GENERATOR);
    initialize(&NOTE_COMMITMENT_RANDOMNESS_GENERATOR);
    initialize(&MEM_COMMITMENT_RANDOMNESS_GENERATOR);
    initialize(&PEDERSEN_HASH_GENERATORS);
    initialize(&PEDERSEN_HASH_EXP_TABLE);
}

/// Generate the fixed base generators.
fn fixed_base_generators() -> Vec<jubjub::SubgroupPoint> {
    let fixed_base_generators = vec![
        find_group_hash(
            PERSONALISATION_COMM_CRED,
            PERSONALISATION_PEDERSEN_HASH_GENERATORS,
        ),
        find_group_hash(
            PERSONALISATION_COMM_NOTE,
            PERSONALISATION_PEDERSEN_HASH_GENERATORS,
        ),
        find_group_hash(
            PERSONALISATION_COMM_MEM,
            PERSONALISATION_PEDERSEN_HASH_GENERATORS,
        ),
    ];

    // Check for duplicates, far worse than spec inconsistencies!
    for (i, p1) in fixed_base_generators.iter().enumerate() {
        if p1.is_identity().into() {
            panic!("Neutral element!");
        }

        for p2 in fixed_base_generators.iter().skip(i + 1) {
            if p1 == p2 {
                panic!("Duplicate generator!");
            }
        }
    }
    fixed_base_generators
}

/// Generate the Pedersen hash generators.
fn generate_pedersen_hash_generators() -> Vec<jubjub::SubgroupPoint> {
    // 3 generators can hold 567 bits (3*63=189 per generators), should be sufficient for our use
    let pedersen_hash_generators = (0..3)
        .map(|m| {
            let mut segment_number = [0u8; 4];
            (&mut segment_number[0..4])
                .write_u32::<LittleEndian>(m)
                .unwrap();
            find_group_hash(&segment_number, PERSONALISATION_PEDERSEN_HASH_GENERATORS)
        })
        .collect::<Vec<_>>();
    // Check that the parameters are safe
    check_consistency_of_pedersen_hash_generators(pedersen_hash_generators.as_slice());
    pedersen_hash_generators
}

/// Creates the exp table for the Pedersen hash generators.
fn generate_pedersen_hash_exp_table() -> Vec<Vec<Vec<jubjub::SubgroupPoint>>> {
    let window = PEDERSEN_HASH_EXP_WINDOW_SIZE;

    PEDERSEN_HASH_GENERATORS
        .iter()
        .cloned()
        .map(|mut g| {
            let mut tables = vec![];

            let mut num_bits = 0;
            while num_bits <= jubjub::Scalar::NUM_BITS {
                let mut table = Vec::with_capacity(1 << window);
                let mut base = jubjub::SubgroupPoint::identity();

                for _ in 0..(1 << window) {
                    table.push(base);
                    base += g;
                }

                tables.push(table);
                num_bits += window;

                for _ in 0..window {
                    g = g.double();
                }
            }

            tables
        })
        .collect()
}

/// Find a valid generator given the tag and the personalisation.
fn find_group_hash(m: &[u8], personalisation: &[u8; 8]) -> jubjub::SubgroupPoint {
    let mut tag = m.to_vec();
    let i = tag.len();
    tag.push(0u8);

    loop {
        let gh = group_hash(&tag, personalisation);

        // We don't want to overflow and start reusing generators
        assert_ne!(tag[i], u8::MAX);
        tag[i] += 1;

        if let Some(gh) = gh {
            break gh;
        }
    }
}

/// Check for simple relations between the generators, that make finding collisions easy;
/// far worse than spec inconsistencies!
fn check_consistency_of_pedersen_hash_generators(
    pedersen_hash_generators: &[jubjub::SubgroupPoint],
) {
    for (i, p1) in pedersen_hash_generators.iter().enumerate() {
        if p1.is_identity().into() {
            panic!("Neutral element!");
        }
        for p2 in pedersen_hash_generators.iter().skip(i + 1) {
            if p1 == p2 {
                panic!("Duplicate generator!");
            }
            if *p1 == -p2 {
                panic!("Inverse generator!");
            }
        }

        // check for a generator being the sum of any other two
        for (j, p2) in pedersen_hash_generators.iter().enumerate() {
            if j == i {
                continue;
            }
            for (k, p3) in pedersen_hash_generators.iter().enumerate() {
                if k == j || k == i {
                    continue;
                }
                let sum = p2 + p3;
                if sum == *p1 {
                    panic!("Linear relation between generators!");
                }
            }
        }
    }
}
