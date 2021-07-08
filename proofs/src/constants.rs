//! Adapted copy from [ZCash][zcash].
//!
//! Jubjub proof constants.
//!
//! [zcash]: https://github.com/zcash/librustzcash/blob/master/zcash_proofs/src/constants.rs

use ff::Field;
use group::{Curve, Group};
use lazy_static::{initialize, lazy_static};

use primitives::constants::{PEDERSEN_HASH_CHUNKS_PER_GENERATOR, PEDERSEN_HASH_GENERATORS};

/// The `d` constant of the twisted Edwards curve.
pub const EDWARDS_D: bls12_381::Scalar = bls12_381::Scalar::from_raw([
    0x0106_5fd6_d634_3eb1,
    0x292d_7f6d_3757_9d26,
    0xf5fd_9207_e6bd_7fd4,
    0x2a93_18e7_4bfa_2b48,
]);

/// The `A` constant of the birationally equivalent Montgomery curve.
pub const MONTGOMERY_A: bls12_381::Scalar = bls12_381::Scalar::from_raw([
    0x0000_0000_0000_a002,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

/// The scaling factor used for conversion to and from the Montgomery form.
pub const MONTGOMERY_SCALE: bls12_381::Scalar = bls12_381::Scalar::from_raw([
    0x8f45_35f7_cf82_b8d9,
    0xce40_6970_3da8_8abd,
    0x31de_341e_77d7_64e5,
    0x2762_de61_e862_645e,
]);

/// The number of chunks needed to represent a full scalar during fixed-base
/// exponentiation.
const FIXED_BASE_CHUNKS_PER_GENERATOR: usize = 84;

/// Reference to a circuit version of a generator for fixed-base scalar multiplication.
pub type FixedGenerator = &'static [Vec<(bls12_381::Scalar, bls12_381::Scalar)>];

/// Circuit version of a generator for fixed-base scalar multiplication.
pub type FixedGeneratorOwned = Vec<Vec<(bls12_381::Scalar, bls12_381::Scalar)>>;

lazy_static! {
    pub static ref CRED_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*primitives::constants::CRED_COMMITMENT_RANDOMNESS_GENERATOR);

    pub static ref NOTE_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*primitives::constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR);

    pub static ref MEM_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(*primitives::constants::MEM_COMMITMENT_RANDOMNESS_GENERATOR);

    /// The pre-computed window tables `[-4, 3, 2, 1, 1, 2, 3, 4]` of different magnitudes
    /// of the Pedersen hash segment generators.
    pub static ref PEDERSEN_CIRCUIT_GENERATORS: Vec<Vec<Vec<(bls12_381::Scalar, bls12_381::Scalar)>>> =
        generate_pedersen_circuit_generators();
}

/// Initialise all static references for the Jubjub curve that are used inside the circuit.
pub fn initialise_jubjub_constants() {
    initialize(&CRED_COMMITMENT_RANDOMNESS_GENERATOR);
    initialize(&NOTE_COMMITMENT_RANDOMNESS_GENERATOR);
    initialize(&MEM_COMMITMENT_RANDOMNESS_GENERATOR);
    initialize(&PEDERSEN_HASH_GENERATORS);
    initialize(&PEDERSEN_CIRCUIT_GENERATORS)
}

/// Creates the 3-bit window table `[0, 1, ..., 8]` for different magnitudes of a fixed
/// generator.
fn generate_circuit_generator(mut gen: jubjub::SubgroupPoint) -> FixedGeneratorOwned {
    let mut windows = vec![];

    for _ in 0..FIXED_BASE_CHUNKS_PER_GENERATOR {
        let mut coeffs = vec![(bls12_381::Scalar::zero(), bls12_381::Scalar::one())];
        let mut g = gen;
        for _ in 0..7 {
            let g_affine = jubjub::ExtendedPoint::from(g).to_affine();
            coeffs.push((g_affine.get_u(), g_affine.get_v()));
            g += gen;
        }
        windows.push(coeffs);

        // gen = gen * 8
        gen = g;
    }

    windows
}

/// Returns the coordinates of this point's Montgomery curve representation, or `None` if
/// it is the point at infinity.
pub fn to_montgomery_coords(
    g: jubjub::ExtendedPoint,
) -> Option<(bls12_381::Scalar, bls12_381::Scalar)> {
    let g = g.to_affine();
    let (x, y) = (g.get_u(), g.get_v());

    if y == bls12_381::Scalar::one() {
        // The only solution for y = 1 is x = 0. (0, 1) is the neutral element, so we map
        // this to the point at infinity.
        None
    } else {
        // The map from a twisted Edwards curve is defined as
        // (x, y) -> (u, v) where
        //      u = (1 + y) / (1 - y)
        //      v = u / x
        //
        // This mapping is not defined for y = 1 and for x = 0.
        //
        // We have that y != 1 above. If x = 0, the only
        // solutions for y are 1 (contradiction) or -1.
        if x.is_zero() {
            // (0, -1) is the point of order two which is not
            // the neutral element, so we map it to (0, 0) which is
            // the only affine point of order 2.
            Some((bls12_381::Scalar::zero(), bls12_381::Scalar::zero()))
        } else {
            // The mapping is defined as above.
            //
            // (x, y) -> (u, v) where
            //      u = (1 + y) / (1 - y)
            //      v = u / x

            let u =
                (bls12_381::Scalar::one() + y) * (bls12_381::Scalar::one() - y).invert().unwrap();
            let v = u * x.invert().unwrap();

            // Scale it into the correct curve constants
            // scaling factor = sqrt(4 / (a - d))
            Some((u, v * MONTGOMERY_SCALE))
        }
    }
}

/// Creates the 2-bit window table lookups for each 4-bit "chunk" in each segment of the
/// Pedersen hash.
fn generate_pedersen_circuit_generators() -> Vec<Vec<Vec<(bls12_381::Scalar, bls12_381::Scalar)>>> {
    // Process each segment
    PEDERSEN_HASH_GENERATORS
        .iter()
        .cloned()
        .map(|mut gen| {
            let mut windows = vec![];

            for _ in 0..PEDERSEN_HASH_CHUNKS_PER_GENERATOR {
                // Create (x, y) coeffs for this chunk
                let mut coeffs = vec![];
                let mut g = gen;

                // coeffs = g, g*2, g*3, g*4
                for _ in 0..4 {
                    coeffs.push(
                        to_montgomery_coords(g.into())
                            .expect("we never encounter the point at infinity"),
                    );
                    g += gen;
                }
                windows.push(coeffs);

                // Our chunks are separated by 2 bits to prevent overlap.
                for _ in 0..4 {
                    gen = gen.double();
                }
            }

            windows
        })
        .collect()
}
