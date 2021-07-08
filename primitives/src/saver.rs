//! Out-circuit SAVER functionality.

use std::fmt::Formatter;
use std::io::{Read, Write};
use std::{iter, thread};

use bellman::gadgets::multipack::bytes_to_bits;
use bellman::groth16::{create_random_proof, generate_parameters, Parameters, Proof, VerifyingKey};
use bellman::{Circuit, SynthesisError, VerificationError};
use bit_vec::BitVec;
use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::{Curve, Group, GroupEncoding, UncompressedEncoding, WnafGroup};
use pairing::{Engine, MillerLoopResult, MultiMillerLoop};
use rand_core::RngCore;

use crate::constants::SAVER_BLOCK_SIZE;
use crate::serialise::{u64_array_to_u8_vector, u8_array_to_u64};

/// SAVER public key
pub struct SaverPublicKey<E: Engine> {
    h: E::G2Affine,
    // This is not originally here, but actually belongs to the CRS.
    x0: E::G1Affine,
    xis: Vec<E::G1Affine>,
    yis: Vec<E::G1Affine>,
    zis: Vec<E::G2Affine>,
    p1: E::G1Affine,
    p2: E::G1Affine,
}

impl<E: Engine> SaverPublicKey<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.h.to_uncompressed().as_ref())?;
        writer.write_all(self.x0.to_uncompressed().as_ref())?;
        writer.write_all(&u64_array_to_u8_vector(&[self.xis.len() as u64]))?;
        for xi in self.xis.iter() {
            writer.write_all(xi.to_uncompressed().as_ref())?;
        }
        writer.write_all(&u64_array_to_u8_vector(&[self.yis.len() as u64]))?;
        for yi in self.yis.iter() {
            writer.write_all(yi.to_uncompressed().as_ref())?;
        }
        writer.write_all(&u64_array_to_u8_vector(&[self.zis.len() as u64]))?;
        for zi in self.zis.iter() {
            writer.write_all(zi.to_uncompressed().as_ref())?;
        }
        writer.write_all(self.p1.to_uncompressed().as_ref())?;
        writer.write_all(self.p2.to_uncompressed().as_ref())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut g1_repr = <E::G1Affine as UncompressedEncoding>::Uncompressed::default();
        let mut g2_repr = <E::G2Affine as UncompressedEncoding>::Uncompressed::default();
        let mut vec_len = [0; 8];

        let g1_repr_into_affine =
            |g1_repr: &<E::G1Affine as UncompressedEncoding>::Uncompressed| {
                let affine = E::G1Affine::from_uncompressed(&g1_repr);
                if affine.is_some().into() {
                    Ok(affine.unwrap())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid G2",
                    ))
                }
            };
        let g2_repr_into_affine =
            |g2_repr: &<E::G2Affine as UncompressedEncoding>::Uncompressed| {
                let affine = E::G2Affine::from_uncompressed(&g2_repr);
                if affine.is_some().into() {
                    Ok(affine.unwrap())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid G2",
                    ))
                }
            };

        reader.read_exact(g2_repr.as_mut())?;
        let h = g2_repr_into_affine(&g2_repr)?;
        reader.read_exact(g1_repr.as_mut())?;
        let x0 = g1_repr_into_affine(&g1_repr)?;
        reader.read_exact(&mut vec_len)?;
        let mut xis = vec![];
        for _ in 0..u8_array_to_u64(&vec_len) {
            reader.read_exact(g1_repr.as_mut())?;
            xis.push(g1_repr_into_affine(&g1_repr)?);
        }
        reader.read_exact(&mut vec_len)?;
        let mut yis = vec![];
        for _ in 0..u8_array_to_u64(&vec_len) {
            reader.read_exact(g1_repr.as_mut())?;
            yis.push(g1_repr_into_affine(&g1_repr)?);
        }
        reader.read_exact(&mut vec_len)?;
        let mut zis = vec![];
        for _ in 0..u8_array_to_u64(&vec_len) {
            reader.read_exact(g2_repr.as_mut())?;
            zis.push(g2_repr_into_affine(&g2_repr)?);
        }
        reader.read_exact(g1_repr.as_mut())?;
        let p1 = g1_repr_into_affine(&g1_repr)?;
        reader.read_exact(g1_repr.as_mut())?;
        let p2 = g1_repr_into_affine(&g1_repr)?;
        Ok(Self {
            h,
            x0,
            xis,
            yis,
            zis,
            p1,
            p2,
        })
    }
}

/// SAVER secret key
pub struct SaverSecretKey<E: Engine> {
    rho: E::Fr,
}

impl<E: Engine> SaverSecretKey<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.rho.to_repr().as_ref())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut rho = E::Fr::zero().to_repr();
        reader.read_exact(rho.as_mut())?;
        let rho = match E::Fr::from_repr(rho) {
            Some(rho) => rho,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid conversion from repr to fr.",
                ))
            }
        };
        Ok(Self { rho })
    }
}

/// SAVER verification key
pub struct SaverVerificationKey<E: Engine> {
    v0: E::G2Affine,
    vis_one: Vec<E::G2Affine>,
    vis_two: Vec<E::G2Affine>,
}

impl<E: Engine> SaverVerificationKey<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.v0.to_uncompressed().as_ref())?;
        writer.write_all(&u64_array_to_u8_vector(&[self.vis_one.len() as u64]))?;
        for vi_one in self.vis_one.iter() {
            writer.write_all(vi_one.to_uncompressed().as_ref())?;
        }
        writer.write_all(&u64_array_to_u8_vector(&[self.vis_two.len() as u64]))?;
        for vi_two in self.vis_two.iter() {
            writer.write_all(vi_two.to_uncompressed().as_ref())?;
        }
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut g2_repr = <E::G2Affine as UncompressedEncoding>::Uncompressed::default();
        let mut vec_len = [0; 8];

        let g2_repr_into_affine =
            |g2_repr: &<E::G2Affine as UncompressedEncoding>::Uncompressed| {
                let affine = E::G2Affine::from_uncompressed(&g2_repr);
                if affine.is_some().into() {
                    Ok(affine.unwrap())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid G2",
                    ))
                }
            };

        reader.read_exact(g2_repr.as_mut())?;
        let v0 = g2_repr_into_affine(&g2_repr)?;
        reader.read_exact(&mut vec_len)?;
        let mut vis_one = vec![];
        for _ in 0..u8_array_to_u64(&vec_len) {
            reader.read_exact(g2_repr.as_mut())?;
            vis_one.push(g2_repr_into_affine(&g2_repr)?);
        }
        reader.read_exact(&mut vec_len)?;
        let mut vis_two = vec![];
        for _ in 0..u8_array_to_u64(&vec_len) {
            reader.read_exact(g2_repr.as_mut())?;
            vis_two.push(g2_repr_into_affine(&g2_repr)?);
        }
        Ok(Self {
            v0,
            vis_one,
            vis_two,
        })
    }
}

/// SAVER key triplet
pub struct SaverKeys<E: Engine> {
    pub pk: SaverPublicKey<E>,
    pub sk: SaverSecretKey<E>,
    pub vk: SaverVerificationKey<E>,
}

impl<E: Engine> SaverKeys<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.pk.write(writer.by_ref())?;
        self.sk.write(writer.by_ref())?;
        self.vk.write(writer.by_ref())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        Ok(Self {
            pk: SaverPublicKey::read(reader.by_ref())?,
            sk: SaverSecretKey::read(reader.by_ref())?,
            vk: SaverVerificationKey::read(reader.by_ref())?,
        })
    }
}

/// SAVER ciphertext
pub struct SaverCiphertext<E: Engine> {
    pub ct0: E::G1Affine,
    pub ctis: Vec<E::G1Affine>,
    pub psi: E::G1Affine,
}

impl<E: Engine> SaverCiphertext<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(self.ct0.to_uncompressed().as_ref())?;
        writer.write_all(&u64_array_to_u8_vector(&[self.ctis.len() as u64]))?;
        for cti in self.ctis.iter() {
            writer.write_all(cti.to_uncompressed().as_ref())?;
        }
        writer.write_all(self.psi.to_uncompressed().as_ref())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut g1_repr = <E::G1Affine as UncompressedEncoding>::Uncompressed::default();
        let mut vec_len = [0; 8];

        let g1_repr_into_affine =
            |g1_repr: &<E::G1Affine as UncompressedEncoding>::Uncompressed| {
                let affine = E::G1Affine::from_uncompressed(&g1_repr);
                if affine.is_some().into() {
                    Ok(affine.unwrap())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid G2",
                    ))
                }
            };

        reader.read_exact(g1_repr.as_mut())?;
        let ct0 = g1_repr_into_affine(&g1_repr)?;
        reader.read_exact(&mut vec_len)?;
        let mut ctis = vec![];
        for _ in 0..u8_array_to_u64(&vec_len) {
            reader.read_exact(g1_repr.as_mut())?;
            ctis.push(g1_repr_into_affine(&g1_repr)?);
        }
        reader.read_exact(g1_repr.as_mut())?;
        let psi = g1_repr_into_affine(&g1_repr)?;
        Ok(Self { ct0, ctis, psi })
    }
}

impl<E: Engine> std::fmt::Display for SaverCiphertext<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut as_u8 = vec![];
        as_u8.extend_from_slice(self.ct0.to_bytes().as_ref());
        for cti in self.ctis.iter() {
            as_u8.extend_from_slice(cti.to_bytes().as_ref());
        }
        as_u8.extend_from_slice(self.psi.to_bytes().as_ref());
        writeln!(f, "0x{}", hex::encode(as_u8))
    }
}

/// SAVER plaintext
pub struct SaverPlaintext<E: Engine> {
    pub mis: Vec<E::Fr>,
    pub nu: E::G1Affine,
}

impl<E: Engine> SaverPlaintext<E> {
    pub fn as_u8(&self) -> (Vec<u8>, Vec<u8>) {
        let mut message: Vec<bool> = vec![];
        for mi in &self.mis {
            message.extend(
                bytes_to_bits(
                    mi.to_repr()
                        .as_ref()
                        .iter()
                        .copied()
                        .rev()
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .into_iter()
                .rev()
                .collect::<Vec<_>>()[0..SAVER_BLOCK_SIZE as usize]
                    .iter(),
            )
        }
        let message = message.into_iter().collect::<BitVec>().to_bytes();
        let nu = self.nu.to_bytes().as_ref().to_vec();
        (message, nu)
    }
}

/// Prepared verifying key for SAVER purposes (copied from bellman crate groth16\mod.rs)
pub struct PreparedVerifyingKeySaver<E: MultiMillerLoop> {
    /// Pairing result of alpha*beta
    alpha_g1_beta_g2: E::Gt,
    /// -gamma in G2
    neg_gamma_g2: E::G2Prepared,
    /// -delta in G2
    neg_delta_g2: E::G2Prepared,
    /// Copy of IC from `VerifyingKey`.
    ic: Vec<E::G1Affine>,
}

/// Prepare verifying key for SAVER purposes (copied from bellman crate groth16\verifier.rs)
pub fn prepare_verifying_key_saver<E: MultiMillerLoop>(
    vk: &VerifyingKey<E>,
) -> PreparedVerifyingKeySaver<E> {
    let gamma = -vk.gamma_g2;
    let delta = -vk.delta_g2;

    PreparedVerifyingKeySaver {
        alpha_g1_beta_g2: E::pairing(&vk.alpha_g1, &vk.beta_g2),
        neg_gamma_g2: gamma.into(),
        neg_delta_g2: delta.into(),
        ic: vk.ic.clone(),
    }
}

/// Generate Groth16 parameters and SAVER keys.
pub fn generate_groth16_and_saver_parameters<E: Engine, C: Circuit<E::Fr>, R: RngCore>(
    circuit: C,
    no_message_blocks: u64,
    mut rng: &mut R,
) -> Result<(Parameters<E>, SaverKeys<E>), SynthesisError>
where
    E::G1: WnafGroup,
    E::G2: WnafGroup,
{
    // Do the same as groth16::generate_random_parameters(circuit, &mut rng)
    let g1 = E::G1::random(&mut rng);
    let g2 = E::G2::random(&mut rng);
    let alpha = E::Fr::random(&mut rng);
    let beta = E::Fr::random(&mut rng);
    let gamma = E::Fr::random(&mut rng);
    let delta = E::Fr::random(&mut rng);
    let tau = E::Fr::random(&mut rng);
    let params = generate_parameters::<E, C>(circuit, g1, g2, alpha, beta, gamma, delta, tau)?;

    let saver_keys = keygen(
        &params,
        g1.to_affine(),
        g2.to_affine(),
        gamma,
        no_message_blocks,
        rng,
    );

    Ok((params, saver_keys))
}

/// Creates the Groth16 proof for the `circuit` and adapts it to work with SAVER. Also creates
/// encryption of `message` using the `saver_public_key`.
pub fn create_groth16_proof_and_saver_encryption<E: Engine, C: Circuit<E::Fr>, R: RngCore>(
    circuit: C,
    message: Vec<E::Fr>,
    params: &Parameters<E>,
    saver_public_key: &SaverPublicKey<E>,
    mut rng: &mut R,
) -> Result<(Proof<E>, SaverCiphertext<E>), SynthesisError> {
    let r = E::Fr::random(&mut rng);
    create_random_proof(circuit, params, &mut rng).map(|mut proof| {
        proof.c = (proof.c.to_curve() + (saver_public_key.p2 * r).to_affine()).to_affine();
        (proof, encrypt(message, params, saver_public_key, r))
    })
}

/// Verifies a SAVER adapted Groth16 proof `proof`, accompanied by SAVER ciphertext `ct` and with
/// public inputs `public_inputs`.
pub fn verify_groth16_proof_and_saver_encryption<E: MultiMillerLoop>(
    pvk: &PreparedVerifyingKeySaver<E>,
    saver_public_key: &SaverPublicKey<E>,
    proof: &Proof<E>,
    ct: &SaverCiphertext<E>,
    public_inputs: &[E::Fr],
) -> Result<bool, VerificationError> {
    if (ct.ctis.len() + public_inputs.len() + 1) != pvk.ic.len() {
        return Err(VerificationError::InvalidVerifyingKey);
    }

    // verify ciphertext
    if E::multi_miller_loop(
        iter::once(&ct.ct0)
            .chain(ct.ctis.iter())
            .zip(
                saver_public_key
                    .zis
                    .iter()
                    .map(|&x| x.into())
                    .collect::<Vec<_>>()
                    .iter(),
            )
            .collect::<Vec<_>>()
            .as_slice(),
    )
    .final_exponentiation()
        != E::pairing(&ct.psi, &saver_public_key.h)
    {
        return Ok(false);
    }

    // verify proof (adaptation of verify_proof from bellman groth16\verifier.rs)
    let mut acc = pvk.ic[0].to_curve();

    for cti in iter::once(&ct.ct0).chain(ct.ctis.iter()) {
        acc += cti
    }

    for (input, &gi) in public_inputs
        .iter()
        .zip(pvk.ic.iter().skip(1 + ct.ctis.len()))
    {
        acc += &(gi * input).to_affine()
    }

    // The original verification equation is:
    // A * B = alpha * beta + inputs * gamma + C * delta
    // ... however, we rearrange it so that it is:
    // A * B - inputs * gamma - C * delta = alpha * beta
    // or equivalently:
    // A * B + inputs * (-gamma) + C * (-delta) = alpha * beta
    // which allows us to do a single final exponentiation.

    Ok(pvk.alpha_g1_beta_g2
        == E::multi_miller_loop(&[
            (&proof.a, &proof.b.into()),
            (&acc.to_affine(), &pvk.neg_gamma_g2),
            (&proof.c, &pvk.neg_delta_g2),
        ])
        .final_exponentiation())
}

/// Generate SAVER key pair, given Groth16 CRS `params`, G1 generator `g`, G2 generator `h`, `gamma`,
/// number of plaintext blocks `n` and PRG `rng`.
pub fn keygen<E: Engine, R: RngCore>(
    params: &Parameters<E>,
    g: E::G1Affine,
    h: E::G2Affine,
    gamma: E::Fr,
    n: u64,
    mut rng: &mut R,
) -> SaverKeys<E> {
    // key randomness
    let sis: Vec<E::Fr> = (0..n).map(|_| E::Fr::random(&mut rng)).collect();
    let vis: Vec<E::Fr> = (0..n).map(|_| E::Fr::random(&mut rng)).collect();
    let tis: Vec<E::Fr> = (0..n + 1).map(|_| E::Fr::random(&mut rng)).collect();
    let rho = E::Fr::random(&mut rng);

    // PK
    let pk = SaverPublicKey {
        h,
        x0: params.vk.delta_g1,
        xis: sis
            .iter()
            .map(|si| (params.vk.delta_g1 * si).to_affine())
            .collect(),
        yis: tis
            .iter()
            .skip(1)
            .zip(params.vk.ic.iter().skip(1))
            .map(|(ti, &gi)| (gi * ti).to_affine())
            .collect(),
        zis: tis.iter().map(|ti| (h * ti).to_affine()).collect(),
        p1: (params.vk.delta_g1
            * tis
                .iter()
                .skip(1)
                .zip(sis.iter())
                .fold(tis[0], |acc, (&ti, si)| acc + (ti * si)))
        .to_affine(),
        p2: (g * (-gamma * sis.iter().fold(E::Fr::one(), |acc, si| acc + si))).to_affine(),
    };

    // SK
    let sk = SaverSecretKey { rho };

    // VK
    let vk = SaverVerificationKey {
        v0: (h * rho).to_affine(),
        vis_one: sis
            .iter()
            .zip(vis.iter())
            .map(|(&si, vi)| (h * (si * vi)).to_affine())
            .collect(),
        vis_two: vis.iter().map(|vi| (h * (rho * vi)).to_affine()).collect(),
    };

    // final key triplet
    SaverKeys { pk, sk, vk }
}

/// Encrypt `message` using Groth16 CRS `params` and SAVER public key `public_key` using randomness
/// `r`.
pub fn encrypt<E: Engine>(
    m: Vec<E::Fr>,
    params: &Parameters<E>,
    public_key: &SaverPublicKey<E>,
    r: E::Fr,
) -> SaverCiphertext<E> {
    SaverCiphertext {
        ct0: (public_key.x0 * r).to_affine(),
        ctis: public_key
            .xis
            .iter()
            .zip(params.vk.ic.iter().skip(1))
            .zip(m.iter())
            .map(|((&xi, &gi), mi)| (xi * r + (gi * mi).to_affine()).to_affine())
            .collect(),
        psi: public_key
            .yis
            .iter()
            .zip(m.iter())
            .fold(public_key.p1 * r, |acc, (&yi, mi)| {
                acc + (yi * mi).to_affine()
            })
            .to_affine(),
    }
}

/// Decrypt a SAVER ciphertext `ct` to the original plaintext and a decryption proof. Makes use of
/// the Groth16 CRS `params`, SAVER secret key `secret_key` and verification key `verification_key`.
pub fn decrypt<E: Engine>(
    ct: &SaverCiphertext<E>,
    params: &Parameters<E>,
    secret_key: &SaverSecretKey<E>,
    verification_key: &SaverVerificationKey<E>,
) -> Result<SaverPlaintext<E>, ()>
where
    E::Gt: Group<Scalar = E::Fr>,
{
    // Determine the discrete log of a certain value `result`, and base `base`.
    fn discrete_log<E: Engine>(base: E::Gt, result: E::Gt) -> Result<E::Fr, ()> {
        if result == E::Gt::identity() {
            return Ok(E::Fr::zero());
        } else if result == base {
            return Ok(E::Fr::one());
        }
        let mut cur_guess = base;
        for exponent in 2..2_u64.pow(SAVER_BLOCK_SIZE) {
            cur_guess += &base;
            if result == cur_guess {
                return Ok(<E::Fr as From<u64>>::from(exponent));
            }
        }
        Err(())
    }

    let mut threads = vec![];
    let rho = secret_key.rho;
    let ct0 = ct.ct0;
    for (((&cti, &vi_one), &vi_two), &gi) in ct
        .ctis
        .iter()
        .zip(verification_key.vis_one.iter())
        .zip(verification_key.vis_two.iter())
        .zip(params.vk.ic.iter().skip(1))
    {
        threads.push(thread::spawn(move || {
            let result = E::pairing(&cti, &vi_two) - (E::pairing(&ct0, &vi_one) * rho);
            discrete_log::<E>(E::pairing(&gi, &vi_two), result)
        }))
    }
    let mut mis = vec![];
    for thread in threads {
        mis.push(thread.join().unwrap()?)
    }

    Ok(SaverPlaintext {
        mis,
        nu: (ct.ct0 * secret_key.rho).to_affine(),
    })
}

/// Verify correct SAVER decryption `m` of ciphertext `ct`.
pub fn verify_decryption<E: Engine>(
    m: &SaverPlaintext<E>,
    ct: &SaverCiphertext<E>,
    params: &Parameters<E>,
    public_key: &SaverPublicKey<E>,
    verification_key: &SaverVerificationKey<E>,
) -> bool
where
    E::Gt: Group<Scalar = E::Fr>,
{
    let nu = m.nu;
    let h = public_key.h;
    let ct0 = ct.ct0;
    let v0 = verification_key.v0;
    // verify decryption proof
    let mut threads = vec![thread::spawn(move || {
        E::pairing(&nu, &h) == E::pairing(&ct0, &v0)
    })];

    // verify decryption
    for ((((&mi, &cti), &vi_one), &vi_two), &gi) in m
        .mis
        .iter()
        .zip(ct.ctis.iter())
        .zip(verification_key.vis_one.iter())
        .zip(verification_key.vis_two.iter())
        .zip(params.vk.ic.iter().skip(1))
    {
        threads.push(thread::spawn(move || {
            E::pairing(&cti, &vi_two) - (E::pairing(&nu, &vi_one)) == E::pairing(&gi, &vi_two) * mi
        }))
    }
    for thread in threads {
        if !thread.join().unwrap() {
            return false;
        }
    }

    true
}
