//! Definitions of variables and some basic generation functionality.

use std::convert::TryInto;
use std::fmt::Formatter;
use std::io::{Read, Write};

use bls12_381::Scalar;
use chrono::{Local, TimeZone};
use ff::{Field, PrimeField};
use rand::Rng;

use crate::serialise::{u64_array_to_u8_vector, u8_array_to_u64};

/// Merkle Tree
pub type MerkleRoot = Scalar;

pub struct MerkleWitness {
    pub path: Vec<(Scalar, bool)>,
    pub position: u128,
}

/// Credentials
pub type AddressPublicKey = [u8; 32];
pub type NoteValue = [u8; 8];
pub type CredentialCommitment = Scalar;

pub struct Credentials {
    pub sk_addr: [u8; 32],
    pub pk_addr: AddressPublicKey,
    pub s_cred: jubjub::Scalar,
}

/// Note
pub type NoteNullifier = [u8; 32];
pub type NoteCommitment = Scalar;

pub struct Note {
    pub pk_addr: AddressPublicKey,
    pub v_note: NoteValue,
    pub s_note: jubjub::Scalar,
    pub t_note: TransactionTime,
    pub t_delta: [u8; 8],
}

/// Memory
pub type MemoryNullifier = [u8; 32];
pub type MemoryCommitment = Scalar;

pub struct Memory {
    pub pk_addr: AddressPublicKey,
    pub v_mem: [u8; 8],
    pub s_mem: jubjub::Scalar,
    pub t_mem: TransactionTime,
    pub c_mem: [u8; 8],
}

/// Signature
pub type SignatureKeyHash = [u8; 32];
pub type SignatureKeyLink = [u8; 32];

/// Time
pub struct TransactionTime(pub [u8; 8]);

/// Generation functionality for certain structs.

impl Credentials {
    /// Generate credentials from `sk_addr` and `s_cred`.
    pub fn generate_from(sk_addr: [u8; 32], s_cred: jubjub::Scalar) -> Self {
        Self {
            sk_addr,
            pk_addr: Self::prf_addr(&sk_addr),
            s_cred,
        }
    }

    /// Generate completely random credentials.
    pub fn generate_random<R: Rng>(rng: &mut R) -> Self {
        Self::generate_from(rng.gen(), jubjub::Scalar::random(rng))
    }
}

impl Note {
    /// Generate a note from `pk_addr`, `v_note`, and `s_note`.
    pub fn generate_from(
        pk_addr: [u8; 32],
        v_note: [u8; 8],
        s_note: jubjub::Scalar,
        t_note: TransactionTime,
        t_delta: [u8; 8],
    ) -> Self {
        Self {
            pk_addr,
            v_note,
            s_note,
            t_note,
            t_delta,
        }
    }

    /// Generate a note with random s_note, and given `pk_addr`, `v_note`, `t_note` and `t_delta`.
    pub fn generate_random_from_pk_v_t_and_t_delta<R: Rng>(
        pk_addr: [u8; 32],
        v_note: [u8; 8],
        t_note: TransactionTime,
        t_delta: [u8; 8],
        rng: &mut R,
    ) -> Self {
        Self::generate_from(
            pk_addr,
            v_note,
            jubjub::Scalar::random(rng),
            t_note,
            t_delta,
        )
    }

    /// Generate a note with random s_note, and given `pk_addr`, `v_note` and `t_delta`.
    pub fn generate_random_from_pk_v_and_t_delta<R: Rng>(
        pk_addr: [u8; 32],
        v_note: [u8; 8],
        t_delta: [u8; 8],
        rng: &mut R,
    ) -> Self {
        Self::generate_from(
            pk_addr,
            v_note,
            jubjub::Scalar::random(rng),
            TransactionTime::current(),
            t_delta,
        )
    }

    /// Generate a note with random s_note, and given `pk_addr` and `v_note`.
    pub fn generate_random_from_pk_and_v<R: Rng>(
        pk_addr: [u8; 32],
        v_note: [u8; 8],
        rng: &mut R,
    ) -> Self {
        Self::generate_from(
            pk_addr,
            v_note,
            jubjub::Scalar::random(rng),
            TransactionTime::current(),
            [0; 8],
        )
    }

    /// Generate a note with random s_note and v_note, and given `pk_addr`.
    pub fn generate_random_from_pk<R: Rng>(pk_addr: [u8; 32], rng: &mut R) -> Self {
        Self::generate_from(
            pk_addr,
            rng.gen(),
            jubjub::Scalar::random(rng),
            TransactionTime::current(),
            [0; 8],
        )
    }

    /// Generate a note with random s_note and pk_addr, and given `v_note` and `t_delta`.
    pub fn generate_random_from_v_and_t_delta<R: Rng>(
        v_note: [u8; 8],
        t_delta: [u8; 8],
        rng: &mut R,
    ) -> Self {
        Self::generate_from(
            rng.gen(),
            v_note,
            jubjub::Scalar::random(rng),
            TransactionTime::current(),
            t_delta,
        )
    }

    /// Generate a note with random s_note and pk_addr, and given `v_note`.
    pub fn generate_random_from_v<R: Rng>(v_note: [u8; 8], rng: &mut R) -> Self {
        Self::generate_from(
            rng.gen(),
            v_note,
            jubjub::Scalar::random(rng),
            TransactionTime::current(),
            [0; 8],
        )
    }

    /// Generate a completely random note.
    pub fn generate_random<R: Rng>(rng: &mut R) -> Self {
        Self::generate_from(
            rng.gen(),
            rng.gen(),
            jubjub::Scalar::random(rng),
            TransactionTime::current(),
            [0; 8],
        )
    }

    /// Generate a note with v_note and s_note set to zero, and given `pk_addr`.
    pub fn empty_from_pk(pk_addr: [u8; 32]) -> Self {
        Self::generate_from(
            pk_addr,
            [0; 8],
            jubjub::Scalar::zero(),
            TransactionTime::current(),
            [0; 8],
        )
    }
}

impl Memory {
    /// Generate memory with given `pk_addr`, `v_mem`, `s_mem`, `t_mem` and
    /// c_mem = `c_mem_old` + `v_mem`.
    pub fn generate_from(
        pk_addr: [u8; 32],
        v_mem: [u8; 8],
        s_mem: jubjub::Scalar,
        t_mem: TransactionTime,
        c_mem: [u8; 8],
    ) -> Self {
        Self {
            pk_addr,
            v_mem,
            s_mem,
            t_mem,
            c_mem,
        }
    }

    /// Generate memory with random s_mem, and given `pk_addr`, `v_mem`,time `t_mem` and `c_mem`.
    pub fn generate_random_from_pk_v_t_and_c<R: Rng>(
        pk_addr: [u8; 32],
        v_mem: [u8; 8],
        t_mem: TransactionTime,
        c_mem: [u8; 8],
        rng: &mut R,
    ) -> Self {
        Self::generate_from(pk_addr, v_mem, jubjub::Scalar::random(rng), t_mem, c_mem)
    }

    /// Generate memory with random s_mem, and given `pk_addr`,`v_mem`, and `c_mem`
    pub fn generate_random_from_pk_v_and_c<R: Rng>(
        pk_addr: [u8; 32],
        v_mem: [u8; 8],
        c_mem: [u8; 8],
        rng: &mut R,
    ) -> Self {
        Self::generate_from(
            pk_addr,
            v_mem,
            jubjub::Scalar::random(rng),
            TransactionTime::current(),
            c_mem,
        )
    }

    /// Generate memory with v_mem, c_mem and s_mem set to zero, and given `pk_addr` and `t_mem`.
    pub fn empty_from_pk_and_t(pk_addr: [u8; 32], t_mem: TransactionTime) -> Self {
        Self::generate_from(pk_addr, [0; 8], jubjub::Scalar::zero(), t_mem, [0; 8])
    }

    /// Generate memory with v_mem, c_mem and s_mem set to zero, and given `pk_addr`.
    pub fn empty_from_pk(pk_addr: [u8; 32]) -> Self {
        Self::generate_from(
            pk_addr,
            [0; 8],
            jubjub::Scalar::zero(),
            TransactionTime::current(),
            [0; 8],
        )
    }
}

impl TransactionTime {
    pub fn current() -> Self {
        TransactionTime(
            u64_array_to_u8_vector(&[Local::now()
                .timestamp()
                .try_into()
                .expect("Time travel is not possible.")])
            .as_slice()
            .try_into()
            .expect("This should fit."),
        )
    }

    pub fn before_time_limit() -> Self {
        TransactionTime([0; 8])
    }

    pub fn before_time_lock(t_delta: [u8; 8]) -> Self {
        TransactionTime(
            u64_array_to_u8_vector(&[Local::now().timestamp() as u64 - u8_array_to_u64(&t_delta)])
                .as_slice()
                .try_into()
                .expect("This should fit."),
        )
    }
}

impl Credentials {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.sk_addr)?;
        writer.write_all(&self.pk_addr)?;
        writer.write_all(&self.s_cred.to_repr())?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut sk_addr = [0; 32];
        let mut pk_addr = [0; 32];
        let mut s_cred = [0; 32];
        reader.read_exact(&mut sk_addr)?;
        reader.read_exact(&mut pk_addr)?;
        reader.read_exact(&mut s_cred)?;
        let s_cred = match jubjub::Scalar::from_repr(s_cred) {
            Some(s) => s,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Conversion from repr to element failed.",
                ))
            }
        };
        Ok(Credentials {
            sk_addr,
            pk_addr,
            s_cred,
        })
    }
}

impl Note {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.pk_addr)?;
        writer.write_all(&self.v_note)?;
        writer.write_all(&self.s_note.to_repr())?;
        writer.write_all(&self.t_note.0)?;
        writer.write_all(&self.t_delta)?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut pk_addr = [0; 32];
        let mut v_note = [0; 8];
        let mut s_note = [0; 32];
        let mut t_note = [0; 8];
        let mut t_delta = [0; 8];
        reader.read_exact(&mut pk_addr)?;
        reader.read_exact(&mut v_note)?;
        reader.read_exact(&mut s_note)?;
        let s_note = match jubjub::Scalar::from_repr(s_note) {
            Some(s) => s,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Conversion from repr to element failed.",
                ))
            }
        };
        reader.read_exact(&mut t_note)?;
        let t_note = TransactionTime(t_note);
        reader.read_exact(&mut t_delta)?;
        Ok(Note {
            pk_addr,
            v_note,
            s_note,
            t_note,
            t_delta,
        })
    }
}

impl Memory {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.pk_addr)?;
        writer.write_all(&self.v_mem)?;
        writer.write_all(&self.s_mem.to_repr())?;
        writer.write_all(&self.t_mem.0)?;
        writer.write_all(&self.c_mem)?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut pk_addr = [0; 32];
        let mut v_mem = [0; 8];
        let mut s_mem = [0; 32];
        let mut t_mem = [0; 8];
        let mut c_mem = [0; 8];
        reader.read_exact(&mut pk_addr)?;
        reader.read_exact(&mut v_mem)?;
        reader.read_exact(&mut s_mem)?;
        let s_mem = match jubjub::Scalar::from_repr(s_mem) {
            Some(s) => s,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Conversion from repr to element failed.",
                ))
            }
        };
        reader.read_exact(&mut t_mem)?;
        let t_mem = TransactionTime(t_mem);
        reader.read_exact(&mut c_mem)?;
        Ok(Memory {
            pk_addr,
            v_mem,
            s_mem,
            t_mem,
            c_mem,
        })
    }
}

impl std::fmt::Display for Credentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "   Secret address key:      0x{}",
            hex::encode(self.sk_addr)
        )?;
        writeln!(
            f,
            "   Public address key:      0x{}",
            hex::encode(self.pk_addr)
        )?;
        writeln!(
            f,
            "   Commitment randomness:   0x{}",
            hex::encode(self.s_cred.to_repr())
        )?;
        Ok(())
    }
}

impl std::fmt::Display for Note {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "   Public address key:      0x{}",
            hex::encode(self.pk_addr)
        )?;
        writeln!(
            f,
            "   Value:                   €{}",
            u8_array_to_u64(&self.v_note)
        )?;
        writeln!(
            f,
            "   Commitment randomness:   0x{}",
            hex::encode(self.s_note.to_repr())
        )?;
        writeln!(f, "   Last update time:        {}", self.t_note)?;
        writeln!(
            f,
            "   Locked for:              {} seconds",
            u8_array_to_u64(&self.t_delta)
        )?;
        Ok(())
    }
}

impl std::fmt::Display for Memory {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "   Public address key:      0x{}",
            hex::encode(self.pk_addr)
        )?;
        writeln!(
            f,
            "   Balance:                 €{}",
            u8_array_to_u64(&self.v_mem)
        )?;
        writeln!(
            f,
            "   Commitment randomness:   0x{}",
            hex::encode(self.s_mem.to_repr())
        )?;
        writeln!(f, "   Last update time:        {}", self.t_mem)?;
        writeln!(
            f,
            "   Total value spent:       €{}",
            u8_array_to_u64(&self.c_mem)
        )?;
        Ok(())
    }
}

impl std::fmt::Display for TransactionTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Local.timestamp(u8_array_to_u64(&self.0) as i64, 0))?;
        Ok(())
    }
}
