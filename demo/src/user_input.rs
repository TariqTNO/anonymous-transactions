use std::cmp::max;
use std::convert::TryInto;
use std::fmt::Formatter;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::mem::replace;
use std::net::TcpStream;
use std::time::Instant;

use bellman::groth16::Proof;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use ring::agreement::{EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::test::rand::FixedSliceRandom;

use primitives::constants::{CREDENTIAL_MT_DEPTH, MEMORY_MT_DEPTH, NOTE_MT_DEPTH, TIME_LIMIT};
use primitives::definitions::{
    AddressPublicKey, Credentials, Memory, MerkleRoot, MerkleWitness, Note, SignatureKeyHash,
    TransactionTime,
};
use primitives::encryption::encrypt;
use primitives::merkle_trees::{IncrementalMerkleWitness, TreeType};
use primitives::prfs::prf_kappa;
use primitives::serialise::{fr_from_repr, u64_array_to_u8_vector, u8_array_to_u64};
use primitives::signature::{compute_k, sign};
use primitives::{encryption, signature};
use proofs::{convert_from, convert_to, credential, transfer};

use crate::blockchain::{
    Block, BlockChain, CFromTransaction, CredTransaction, TransferTransaction,
};
use crate::commands::Command;
use crate::constants;

/// Object to store the relevant data of user `name`.
pub struct UserData<'a> {
    pub name: &'a str,
    pub cred: Credentials,
    pub private_key_input: [u8; 32],
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey,
    pub blockchain: BlockChain,
    pub cred_witness: Option<IncrementalMerkleWitness>,
    pub notes: Vec<Note>,
    pub note_witnesses: Vec<IncrementalMerkleWitness>,
    pub memory: Option<Memory>,
    pub memory_witness: Option<IncrementalMerkleWitness>,
    pub ceil_memories: Vec<Memory>,
    pub ceil_memory_witnesses: Vec<IncrementalMerkleWitness>,
}

impl<'a> UserData<'a> {
    /// Obtain a usable copy of the user's private key.
    pub fn private_key(&self) -> EphemeralPrivateKey {
        let rng = FixedSliceRandom {
            bytes: &self.private_key_input,
        };
        EphemeralPrivateKey::generate(&X25519, &rng).unwrap()
    }

    /// Obtain the correct ceiling memory cell and corresponding witness (if there is one) on input
    /// the current time `t_new`.
    pub fn obtain_ceil_memory(
        &self,
        t_new: &TransactionTime,
    ) -> Option<(&Memory, &IncrementalMerkleWitness)> {
        let t_new = u8_array_to_u64(&t_new.0);
        for (ceil_memory, ceil_memory_witness) in self
            .ceil_memories
            .iter()
            .zip(self.ceil_memory_witnesses.iter())
            .rev()
        {
            if u8_array_to_u64(&ceil_memory.t_mem.0) < t_new - TIME_LIMIT {
                return Some((ceil_memory, ceil_memory_witness));
            }
        }
        None
    }

    /// Write the user's data to the user's .data file, replacing the old file.
    pub fn write(&self) -> std::io::Result<()> {
        let mut file = BufWriter::new(File::create(format!("{}.data", self.name))?);
        self.cred.write(file.by_ref())?;
        file.write_all(&self.private_key_input)?;
        match &self.cred_witness {
            None => file.write_all(&[0])?,
            Some(witness) => {
                file.write_all(&[1])?;
                witness.write(file.by_ref())?;
            }
        }
        file.write_all(&u64_array_to_u8_vector(&[self.notes.len() as u64]))?;
        for (note, witness) in self.notes.iter().zip(self.note_witnesses.iter()) {
            note.write(file.by_ref())?;
            witness.write(file.by_ref())?;
        }
        match &self.memory {
            None => file.write_all(&[0])?,
            Some(memory) => {
                file.write_all(&[1])?;
                memory.write(file.by_ref())?;
            }
        };
        match &self.memory_witness {
            None => file.write_all(&[0])?,
            Some(memory_witness) => {
                file.write_all(&[1])?;
                memory_witness.write(file.by_ref())?;
            }
        }
        file.write_all(&u64_array_to_u8_vector(&[self.ceil_memories.len() as u64]))?;
        for (memory, witness) in self
            .ceil_memories
            .iter()
            .zip(self.ceil_memory_witnesses.iter())
        {
            memory.write(file.by_ref())?;
            witness.write(file.by_ref())?;
        }
        file.flush()?;
        Ok(())
    }

    /// Read a user's data, from the user's .data file, into a `UserData` struct.
    pub fn read<R: Read>(mut reader: R, name: &'a str) -> std::io::Result<UserData<'a>> {
        let cred = Credentials::read(reader.by_ref())?;
        let mut private_key_input = [0; 32];
        reader.read_exact(&mut private_key_input)?;
        let rng = FixedSliceRandom {
            bytes: &private_key_input,
        };
        let (private_key, public_key) =
            encryption::generate_keypair(&rng).expect("Keypair generation should not fail.");
        let mut option = [0; 1];
        reader.read_exact(&mut option)?;
        let cred_witness = match option[0] {
            0 => None,
            1 => Some(IncrementalMerkleWitness::read(
                reader.by_ref(),
                TreeType::Credential,
                CREDENTIAL_MT_DEPTH,
            )?),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Cannot read option.",
                ))
            }
        };
        let mut note_amount = [0; 8];
        reader.read_exact(&mut note_amount)?;
        let note_amount = u8_array_to_u64(&note_amount);
        let mut notes = vec![];
        let mut note_witnesses = vec![];
        for _ in 0..note_amount {
            notes.push(Note::read(reader.by_ref())?);
            note_witnesses.push(IncrementalMerkleWitness::read(
                reader.by_ref(),
                TreeType::Note,
                NOTE_MT_DEPTH,
            )?)
        }
        reader.read_exact(&mut option)?;
        let memory = match option[0] {
            0 => None,
            1 => Some(Memory::read(reader.by_ref())?),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Cannot read option.",
                ))
            }
        };
        reader.read_exact(&mut option)?;
        let memory_witness = match option[0] {
            0 => None,
            1 => Some(IncrementalMerkleWitness::read(
                reader.by_ref(),
                TreeType::Memory,
                MEMORY_MT_DEPTH,
            )?),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Cannot read option.",
                ))
            }
        };
        let mut memory_amount = [0; 8];
        reader.read_exact(&mut memory_amount)?;
        let memory_amount = u8_array_to_u64(&memory_amount);
        let mut ceil_memories = vec![];
        let mut ceil_memory_witnesses = vec![];
        for _ in 0..memory_amount {
            ceil_memories.push(Memory::read(reader.by_ref())?);
            ceil_memory_witnesses.push(IncrementalMerkleWitness::read(
                reader.by_ref(),
                TreeType::Memory,
                MEMORY_MT_DEPTH,
            )?);
        }
        let blockchain =
            BlockChain::read(BufReader::new(File::open(format!("{}.blockchain", name))?))?;
        Ok(UserData {
            name,
            cred,
            private_key_input,
            private_key,
            public_key,
            blockchain,
            cred_witness,
            notes,
            note_witnesses,
            memory,
            memory_witness,
            ceil_memories,
            ceil_memory_witnesses,
        })
    }
}

impl<'a> std::fmt::Display for UserData<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Name:                       {}", self.name)?;
        writeln!(f, "Credentials:")?;
        writeln!(f, "{}", self.cred)?;
        writeln!(
            f,
            "Encryption private key:     0x{}",
            hex::encode(self.private_key_input)
        )?;
        writeln!(
            f,
            "Encryption public key:      0x{}",
            hex::encode(self.public_key.as_ref())
        )?;
        writeln!(f, "Notes:")?;
        if self.notes.is_empty() {
            writeln!(f, "   -")?;
        }
        for note in &self.notes {
            writeln!(f, "{}", note)?;
        }
        writeln!(f, "Account:")?;
        match &self.memory {
            Some(memory) => writeln!(f, "{}", memory)?,
            None => {
                writeln!(
                    f,
                    "   Public address key:      0x{}",
                    hex::encode(self.cred.pk_addr)
                )?;
                writeln!(f, "   Balance:                 €0")?;
                writeln!(
                    f,
                    "   Last update time:        {}",
                    TransactionTime::current()
                )?;
                writeln!(f, "   Total value spent:       €0")?;
            }
        }
        writeln!(f, "Old memory cells:")?;
        if self.ceil_memories.is_empty() {
            writeln!(f, "   -")?;
        }
        for memory in &self.ceil_memories {
            writeln!(f, "{}", memory)?;
        }
        Ok(())
    }
}

/// Send the `command` to the server and handle the return value.
fn send(stream: &mut TcpStream, command: Command) -> std::io::Result<()> {
    let command = [command as u8];
    stream.write_all(&command)?;
    let mut rcv = [0; 1];
    stream.read_exact(&mut rcv)?;
    match rcv {
        _ if rcv == command => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unexpected reply.",
        )),
    }
}

/// Send a credential transaction to the server, to be included on the blockchain.
/// Returns the created `Credentials` on success.
pub fn send_cred() -> std::io::Result<Option<Credentials>> {
    let mut stream = TcpStream::connect(format!("{}:{}", constants::HOST, constants::PORT))?;
    send(&mut stream, Command::Cred)?;
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let mut rng = OsRng;
    let cred = Credentials::generate_random(&mut rng);
    let time_start = Instant::now();
    let proof = credential::prover::create_proof(&cred, &constants::CRED_PARAMS);
    let duration = time_start.elapsed();
    println!("Proof generation took {} seconds.", duration.as_secs_f64());
    stream_writer.write_all(&cred.pk_addr)?;
    let cm_cred = cred.comm_cred();
    stream_writer.write_all(&cm_cred.to_bytes())?;
    proof.write(stream_writer.by_ref())?;
    stream_writer.flush()?;
    let mut result = [0; 1];
    stream_reader.read_exact(&mut result)?;
    match result[0] {
        1 => {
            let mut t_new = [0; 8];
            stream_reader.read_exact(&mut t_new)?;
            let t_new = TransactionTime(t_new);
            let mut vec_len = [0; 8];
            stream_reader.read_exact(&mut vec_len)?;
            let mut signature = vec![0; u8_array_to_u64(&vec_len) as usize];
            stream_reader.read_exact(&mut signature)?;
            println!("Transaction sent:");
            println!(
                "{}",
                CredTransaction {
                    cm_cred,
                    pk_addr: cred.pk_addr,
                    t_new,
                    proof,
                    signature,
                }
            );
            Ok(Some(cred))
        }
        _ => Ok(None),
    }
}

/// Send a convert_to transaction to the server, to be included on the blockchain.
/// Returns the result of the proof verification.
pub fn send_c_to(data: &mut UserData) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect(format!("{}:{}", constants::HOST, constants::PORT))?;
    send(&mut stream, Command::CTo)?;
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    print!("Deposit amount:   €");
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    match value.trim().parse::<u64>() {
        Ok(value) => {
            let v_note: [u8; 8] = u64_array_to_u8_vector(&[value])
                .as_slice()
                .try_into()
                .expect("Value should fit");
            stream_writer.write_all(&data.cred.pk_addr)?;
            stream_writer.write_all(data.public_key.as_ref())?;
            stream_writer.write_all(&v_note)?;
            stream_writer.flush()?;
            let mut cm_note = [0; 32];
            stream_reader.read_exact(&mut cm_note)?;
            let proof = Proof::<Bls12>::read(stream_reader.by_ref())?;
            let cm_note = fr_from_repr(cm_note)?;
            let time_start = Instant::now();
            let result = convert_to::verifier::verify_proof(&proof, &cm_note, &constants::C_TO_PVK);
            let duration = time_start.elapsed();
            println!("Proof validation took {} seconds.", duration.as_secs_f64());
            stream_writer.write_all(&[result as u8])?;
            stream_writer.flush()?;
            Ok(result)
        }
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }
}

/// Send a convert_from transaction to the server, to be included on the blockchain.
/// Returns the result of the proof verification.
/// Note: This method is only user by a server.
pub fn send_c_from(
    sk_addr: [u8; 32],
    pk_addr: AddressPublicKey,
    note: &Note,
    witness: MerkleWitness,
    rt_note: MerkleRoot,
    pk_addr_sndr: AddressPublicKey,
) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect(format!("{}:{}", constants::HOST, constants::PORT))?;
    send(&mut stream, Command::CFrom)?;
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let cred = Credentials {
        sk_addr,
        pk_addr,
        s_cred: jubjub::Scalar::zero(),
    };
    let time_start = Instant::now();
    let proof =
        convert_from::prover::create_proof(&cred, note, &witness, &constants::C_FROM_PARAMS);
    let duration = time_start.elapsed();
    println!("Proof generation took {} seconds.", duration.as_secs_f64());
    let eta = cred.prf_eta(&witness);
    let t_new = TransactionTime::current();
    stream_writer.write_all(&rt_note.to_bytes())?;
    stream_writer.write_all(&eta)?;
    stream_writer.write_all(&cred.pk_addr)?;
    stream_writer.write_all(&t_new.0)?;
    proof.write(stream_writer.by_ref())?;
    stream_writer.flush()?;
    let mut result = [0; 1];
    stream_reader.read_exact(&mut result)?;
    match result[0] {
        1 => {
            let mut vec_len = [0; 8];
            stream_reader.read_exact(&mut vec_len)?;
            let mut signature = vec![0; u8_array_to_u64(&vec_len) as usize];
            stream_reader.read_exact(&mut signature)?;
            println!("Transaction sent:");
            println!(
                "{}",
                CFromTransaction {
                    rt_note,
                    eta,
                    pk_addr: cred.pk_addr,
                    t_new,
                    proof,
                    signature,
                }
            );
            println!(
                "€{} transferred back to regular account of user with public address key 0x{}.",
                u8_array_to_u64(&note.v_note),
                hex::encode(pk_addr_sndr)
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Send a transfer transaction to the server, to be included on the blockchain.
/// Returns the result of the proof verification.
pub fn send_transfer(data: &mut UserData, withdraw: bool) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect(format!("{}:{}", constants::HOST, constants::PORT))?;
    send(&mut stream, Command::Transfer)?;
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let cred_witness = match &data.cred_witness {
        Some(witness) => witness.witness(),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Credentials should be accepted on the blockchain.",
            ))
        }
    };
    let mut pk_addr_new: AddressPublicKey = [0; 32];
    let mut pk_enc_new = [0; 32];
    stream_writer.write_all(&[withdraw as u8])?;
    stream_writer.flush()?;
    match withdraw {
        true => {
            stream_reader.read_exact(&mut pk_addr_new)?;
            stream_reader.read_exact(&mut pk_enc_new)?;
        }
        false => {
            print!("Receiver public address key:      ");
            std::io::stdout().flush()?;
            let mut address = String::new();
            std::io::stdin().read_line(&mut address)?;
            let address = &address.trim()[2..];
            match address.len() {
                64 => match hex::decode(address) {
                    Ok(address) => {
                        pk_addr_new = address.as_slice().try_into().expect("Address should fit.")
                    }
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Invalid address key.",
                    ))
                }
            }
            print!("Receiver public encryption key:   ");
            std::io::stdout().flush()?;
            let mut pk_enc = String::new();
            std::io::stdin().read_line(&mut pk_enc)?;
            let pk_enc = &pk_enc.trim()[2..];
            match pk_enc.len() {
                64 => match hex::decode(pk_enc) {
                    Ok(pk_enc) => {
                        pk_enc_new = pk_enc
                            .as_slice()
                            .try_into()
                            .expect("Encryption key should fit.")
                    }
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                },
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Invalid encryption key.",
                    ))
                }
            }
        }
    }
    let pk_enc_new = UnparsedPublicKey::new(&X25519, pk_enc_new);
    println!("Available input notes:");
    for (i, note) in data.notes.iter().enumerate() {
        println!("Note {}", i);
        println!("{}", note);
    }
    print!("Which note do you want to spend? [<index>/none]?   ");
    std::io::stdout().flush()?;
    let mut index = String::new();
    std::io::stdin().read_line(&mut index)?;
    let (note_old, note_merkle_witness, note_index) = match index.trim() {
        "none" | "n" => (None, None, None),
        index => match index.parse::<usize>() {
            Ok(index) => {
                if index < data.notes.len() {
                    (
                        Some(&data.notes[index]),
                        Some(&data.note_witnesses[index]),
                        Some(index),
                    )
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Index too high.",
                    ));
                }
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid input.",
                ))
            }
        },
    };
    let rt_mem = if let Some(memory) = &data.memory {
        println!("Account:");
        println!("{}", memory);
        None
    } else {
        Some(data.blockchain.tree_mem.root_value())
    };
    print!("Output value?   €");
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let v_note_new: [u8; 8] = match value.trim().parse::<u64>() {
        Ok(value) => {
            let v_note_old = if let Some(note) = note_old {
                u8_array_to_u64(&note.v_note)
            } else {
                0
            };
            if value
                <= v_note_old
                    + data
                        .memory
                        .as_ref()
                        .map_or(0, |x| u8_array_to_u64(&x.v_mem))
            {
                u64_array_to_u8_vector(&[value])
                    .as_slice()
                    .try_into()
                    .expect("Value should fit.")
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Your output is higher than your input.",
                ));
            }
        }
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    };
    let (t_delta_new, use_saver) = match withdraw {
        true => ([0; 8], true),
        false => {
            // determine the note lock
            print!("Lock the output note? [N/y]   ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let t_delta_new = match input.to_ascii_lowercase().trim() {
                "n" | "no" | "" => [0; 8],
                "y" | "yes" => {
                    print!("For how many seconds?   ");
                    std::io::stdout().flush()?;
                    let mut t_delta = String::new();
                    std::io::stdin().read_line(&mut t_delta)?;
                    match t_delta.trim().parse::<u64>() {
                        Ok(t_delta) => u64_array_to_u8_vector(&[t_delta])
                            .as_slice()
                            .try_into()
                            .expect("Value should fit."),
                        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                    }
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Invalid argument.",
                    ))
                }
            };

            // determine the use of SAVER
            print!("Enclose encrypted transaction details? [N/y]   ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let use_saver = match input.to_ascii_lowercase().trim() {
                "n" | "no" | "" => false,
                "y" | "yes" => true,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Invalid argument.",
                    ))
                }
            };
            (t_delta_new, use_saver)
        }
    };
    let mut rng = OsRng;
    let note_new =
        Note::generate_random_from_pk_v_and_t_delta(pk_addr_new, v_note_new, t_delta_new, &mut rng);
    let mut v_mem_new = 0;
    let mut c_mem_old = [0; 8];
    if let Some(mem_old) = &data.memory {
        v_mem_new += u8_array_to_u64(&mem_old.v_mem);
        c_mem_old = mem_old.c_mem;
    };
    if let Some(note_old) = note_old {
        v_mem_new += u8_array_to_u64(&note_old.v_note);
    };
    v_mem_new -= u8_array_to_u64(&note_new.v_note);
    let v_mem_new: [u8; 8] = u64_array_to_u8_vector(&[v_mem_new])
        .as_slice()
        .try_into()
        .expect("Value should fit.");
    let c_mem_new = match use_saver {
        true => c_mem_old,
        false => {
            u64_array_to_u8_vector(&[u8_array_to_u64(&c_mem_old) + u8_array_to_u64(&v_note_new)])
                .as_slice()
                .try_into()
                .expect("Value should fit.")
        }
    };
    let mem_new =
        Memory::generate_random_from_pk_v_and_c(data.cred.pk_addr, v_mem_new, c_mem_new, &mut rng);
    let (mem_ceil, memory_ceil_merkle_witness) = data
        .obtain_ceil_memory(&mem_new.t_mem)
        .map_or((None, None), |(mem, witness)| {
            (Some(mem), Some(witness.witness()))
        });
    let signature_keypair = Ed25519KeyPair::from_pkcs8(
        signature::generate_keypair(&SystemRandom::new())
            .expect("Key generation should not fail.")
            .as_ref(),
    )
    .expect("Key generation should not fail.");
    let k: SignatureKeyHash = compute_k(signature_keypair.public_key());

    let time_start = Instant::now();
    let (proof, data_saver) = transfer::prover::create_proof(
        &data.cred,
        note_old,
        data.memory.as_ref(),
        mem_ceil,
        &cred_witness,
        note_merkle_witness.map(|x| x.witness()).as_ref(),
        data.memory_witness.as_ref().map(|x| x.witness()).as_ref(),
        memory_ceil_merkle_witness.as_ref(),
        rt_mem.as_ref(),
        &note_new,
        &mem_new,
        &k,
        use_saver,
        &constants::TRANSFER_PARAMS,
        &constants::SAVER_KEYS.pk,
    );
    let duration = time_start.elapsed();
    println!(
        "Proof generation (incl. SAVER ciphertext) took {} seconds.",
        duration.as_secs_f64()
    );
    let mut data_note = vec![];
    data_note.extend(&note_new.s_note.to_bytes());
    data_note.extend(&note_new.v_note);
    match withdraw {
        true => data_note.extend(&data.cred.pk_addr),
        false => {
            let pk_addr: AddressPublicKey = [0; 32];
            data_note.extend(&pk_addr);
        }
    };
    data_note.extend(&note_new.t_delta);
    let mut context = vec![];
    proof.write(context.by_ref())?;
    let epk_note = encrypt(&mut data_note, &context, &pk_enc_new).unwrap();
    let mut data_mem = vec![];
    data_mem.extend(&mem_new.s_mem.to_bytes());
    let epk_mem = encrypt(
        &mut data_mem,
        &context,
        &UnparsedPublicKey::new(&X25519, &data.public_key),
    )
    .unwrap();
    let rt_cred = data.blockchain.tree_cred.root_value();
    let rt_note = note_merkle_witness.map(|x| x.root_value());
    let rt_mem = rt_mem.unwrap_or_else(|| data.blockchain.tree_mem.root_value());
    let eta = note_merkle_witness.map(|x| data.cred.prf_eta(&x.witness()));
    let mu = data.cred.prf_mu(
        &data
            .memory_witness
            .as_ref()
            .map_or(MerkleWitness::empty(MEMORY_MT_DEPTH), |x| x.witness()),
        data.memory.is_some(),
    );
    let cm_note_new = note_new.comm_note();
    let cm_mem_new = mem_new.comm_mem();
    let kappa = prf_kappa(&data.cred, &k);
    let t_new = TransactionTime(
        u64_array_to_u8_vector(&[max(
            u8_array_to_u64(&mem_new.t_mem.0),
            u8_array_to_u64(&note_new.t_note.0),
        )])
        .as_slice()
        .try_into()
        .expect("This should fit."),
    );
    let pk_sig = signature_keypair.public_key().as_ref().to_vec();
    stream_writer.write_all(&rt_cred.to_bytes())?;
    match &rt_note {
        None => stream_writer.write_all(&[0])?,
        Some(rt_note) => {
            stream_writer.write_all(&[1])?;
            stream_writer.write_all(&rt_note.to_bytes())?;
        }
    };
    stream_writer.write_all(&rt_mem.to_bytes())?;
    match eta {
        None => stream_writer.write_all(&[0])?,
        Some(eta) => {
            stream_writer.write_all(&[1])?;
            stream_writer.write_all(&eta)?;
        }
    };
    stream_writer.write_all(&mu)?;
    stream_writer.write_all(&cm_note_new.to_bytes())?;
    stream_writer.write_all(&cm_mem_new.to_bytes())?;
    stream_writer.write_all(&t_new.0)?;
    stream_writer.write_all(&k)?;
    stream_writer.write_all(&kappa)?;
    proof.write(stream_writer.by_ref())?;
    stream_writer.write_all(&u64_array_to_u8_vector(&[data_note.len() as u64]))?;
    stream_writer.write_all(&data_note)?;
    stream_writer.write_all(&epk_note.bytes().as_ref())?;
    stream_writer.write_all(&u64_array_to_u8_vector(&[data_mem.len() as u64]))?;
    stream_writer.write_all(&data_mem)?;
    stream_writer.write_all(&epk_mem.bytes().as_ref())?;
    data_saver.write(stream_writer.by_ref())?;

    let mut message = vec![];
    message.extend_from_slice(&rt_cred.to_bytes());
    if let Some(rt_note) = rt_note {
        message.extend_from_slice(&rt_note.to_bytes());
    }
    message.extend_from_slice(&rt_mem.to_bytes());
    if let Some(eta) = eta {
        message.extend_from_slice(&eta);
    }
    message.extend_from_slice(&mu);
    message.extend_from_slice(&cm_note_new.to_bytes());
    message.extend_from_slice(&cm_mem_new.to_bytes());
    message.extend_from_slice(&t_new.0);
    message.extend_from_slice(&k);
    message.extend_from_slice(&kappa);
    message.extend_from_slice(&data_note);
    message.extend_from_slice(&epk_note.bytes().as_ref());
    message.extend_from_slice(&data_mem);
    message.extend_from_slice(&epk_mem.bytes().as_ref());
    data_saver.write(message.by_ref())?;
    proof.write(message.by_ref())?;
    let signature = sign(message.as_slice(), &signature_keypair)
        .expect("Signing should not fail.")
        .as_ref()
        .to_vec();

    stream_writer.write_all(&u64_array_to_u8_vector(&[pk_sig.len() as u64]))?;
    stream_writer.write_all(pk_sig.as_slice())?;
    stream_writer.write_all(&u64_array_to_u8_vector(&[signature.len() as u64]))?;
    stream_writer.write_all(&signature)?;

    stream_writer.flush()?;
    let mut result = [0; 1];
    stream_reader.read_exact(&mut result)?;
    match result[0] {
        1 => {
            println!("Transaction sent:");
            println!(
                "{}",
                TransferTransaction {
                    rt_cred,
                    rt_note,
                    rt_mem,
                    eta,
                    mu,
                    cm_note_new,
                    cm_mem_new,
                    t_new,
                    k,
                    kappa,
                    data_note,
                    epk_note,
                    data_mem,
                    epk_mem,
                    data_saver,
                    proof,
                    pk_sig,
                    signature,
                }
            );
            if let Some(note_index) = note_index {
                data.notes.remove(note_index);
                data.note_witnesses.remove(note_index);
            }
            if let Some(mem_old) = replace(&mut data.memory, Some(mem_new)) {
                data.ceil_memories.push(mem_old);
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Request any blocks from the blockchain, to update the local blockchain state.
/// Scans the blockchain for transactions that are sent to this user, accordingly updating `data`.
pub fn update(data: &mut UserData) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(format!("{}:{}", constants::HOST, constants::PORT))?;
    send(&mut stream, Command::Update)?;
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let chain_size = data.blockchain.blocks.len();
    stream_writer.write_all(&u64_array_to_u8_vector(&[chain_size as u64]))?;
    stream_writer.flush()?;
    let mut block_amount = [0; 8];
    stream_reader.read_exact(&mut block_amount)?;
    let block_amount = u8_array_to_u64(&block_amount);
    for _ in 0..block_amount {
        let new_block = Block::read(stream_reader.by_ref())?;
        scan(&new_block, data);
        data.blockchain.blocks.push(new_block)
    }
    Ok(())
}

/// Scan a newly received block on transactions for this user. Updates `data` accordingly.
fn scan(block: &Block, data: &mut UserData) {
    for transaction in &block.transactions {
        transaction.update_trees(&mut data.blockchain).unwrap();
        transaction.update_witnesses(data).unwrap();
        transaction.scan(data);
        //remove unnecessary ceiling memory cells (and corresponding witnesses)
        let t_cur = u8_array_to_u64(&TransactionTime::current().0);
        for (i, ceil_memory) in data.ceil_memories.iter().enumerate() {
            if u8_array_to_u64(&ceil_memory.t_mem.0) > t_cur - TIME_LIMIT {
                data.ceil_memories.drain(0..(i - 1));
                data.ceil_memory_witnesses.drain(0..(i - 1));
                break;
            }
        }
    }
}
