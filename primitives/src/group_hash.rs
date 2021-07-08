//! This file is a minor adaptation on the version from [ZCash][zcash].
//!
//! Implementation of [group hashing into Jubjub][grouphash].
//!
//! [zcash]: https://github.com/zcash/librustzcash/blob/master/zcash_primitives/src/sapling/group_hash.rs
//! [grouphash]: https://zips.z.cash/protocol/protocol.pdf#concretegrouphashjubjub

use blake2s_simd::Params;
use bls12_381::Scalar;
use ff::PrimeField;
use group::cofactor::CofactorGroup;
use group::{Group, GroupEncoding};

use crate::constants;

/// Produces a random point in the Jubjub curve.
/// The point is guaranteed to be prime order
/// and not the identity.
pub fn group_hash(tag: &[u8], personalisation: &[u8]) -> Option<jubjub::SubgroupPoint> {
    assert_eq!(personalisation.len(), 8);

    // Check to see that scalar field is 255 bits
    assert_eq!(Scalar::NUM_BITS, 255);

    let h = Params::new()
        .hash_length(32)
        .personal(personalisation)
        .to_state()
        .update(constants::GROUP_HASH_RANDOMNESS)
        .update(tag)
        .finalize();

    let p = jubjub::ExtendedPoint::from_bytes(h.as_array());
    if p.is_some().into() {
        // <ExtendedPoint as CofactorGroup>::clear_cofactor is implemented using
        // ExtendedPoint::mul_by_cofactor in the jubjub crate.
        let p = CofactorGroup::clear_cofactor(&p.unwrap());

        if p.is_identity().into() {
            None
        } else {
            Some(p)
        }
    } else {
        None
    }
}
