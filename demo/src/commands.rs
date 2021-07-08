use std::fmt::Formatter;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use bellman::groth16::Proof;
use bls12_381::Bls12;
use rand::rngs::OsRng;
use ring::agreement::{EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::signature::Ed25519KeyPair;
use ring::test::rand::FixedSliceRandom;

use primitives::definitions::{
    AddressPublicKey, MemoryNullifier, Note, NoteNullifier, SignatureKeyHash, SignatureKeyLink,
    TransactionTime,
};
use primitives::encryption::encrypt;
use primitives::saver::SaverCiphertext;
use primitives::serialise::{fr_from_repr, u64_array_to_u8_vector, u8_array_to_u64};
use primitives::signature::sign;
use proofs::{convert_from, convert_to};
use proofs::{credential, transfer};

use crate::blockchain::{
    BlockChain, CFromTransaction, CToTransaction, CredTransaction, TransferTransaction,
};
use crate::constants;

#[repr(u8)]
/// Types of commands that can be expected in client-server communication.
pub enum Command {
    Cred = 0,
    CTo = 1,
    CFrom = 2,
    Transfer = 3,
    Update = 4,
}

/// Store the relevant data of the demo server.
pub struct ServerData<'a> {
    pub name: &'a str,
    pub address_private_key: [u8; 32],
    pub address_public_key: AddressPublicKey,
    pub private_key_input: [u8; 32],
    pub private_key: EphemeralPrivateKey,
    pub public_key: PublicKey,
    pub signature_keypair: Ed25519KeyPair,
}

/// Get a copy of the server's `private_key`.
impl<'a> ServerData<'a> {
    pub fn private_key(&self) -> EphemeralPrivateKey {
        let rng = FixedSliceRandom {
            bytes: &self.private_key_input,
        };
        EphemeralPrivateKey::generate(&X25519, &rng).unwrap()
    }
}

impl<'a> std::fmt::Display for ServerData<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Name:                     {}", self.name)?;
        writeln!(
            f,
            "Address secret key:       0x{}",
            hex::encode(self.address_private_key)
        )?;
        writeln!(
            f,
            "Address public key:       0x{}",
            hex::encode(self.address_public_key)
        )?;
        writeln!(
            f,
            "Encryption private key:   0x{}",
            hex::encode(self.private_key_input)
        )?;
        writeln!(
            f,
            "Encryption public key:    0x{}",
            hex::encode(self.public_key.as_ref())
        )?;
        Ok(())
    }
}

/// This function handles the server side of a `ProofCred` command.
/// It returns the result of the proof verification.
pub fn cred(
    stream: TcpStream,
    blockchain: Arc<RwLock<BlockChain>>,
    server_data: Arc<ServerData>,
) -> std::io::Result<bool> {
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let mut message = vec![];
    let mut pk_addr: AddressPublicKey = [0; 32];
    let mut cm_cred = [0; 32];
    stream_reader.read_exact(&mut pk_addr)?;
    println!(
        "Performing KYC for new client with public address key 0x{}...",
        hex::encode(pk_addr)
    );
    stream_reader.read_exact(&mut cm_cred)?;
    let cm_cred = fr_from_repr(cm_cred)?;
    let proof = Proof::<Bls12>::read(stream_reader.by_ref())?;
    let time_start = Instant::now();
    let result =
        credential::verifier::verify_proof(&proof, &pk_addr, &cm_cred, &constants::CRED_PVK);
    let duration = time_start.elapsed();
    println!("Proof validation took {} seconds.", duration.as_secs_f64());
    stream_writer.write_all(&[result as u8])?;
    stream_writer.flush()?;
    match result {
        true => {
            let t_new = TransactionTime::current();
            message.extend_from_slice(&cm_cred.to_bytes());
            message.extend_from_slice(&pk_addr);
            message.extend_from_slice(&t_new.0);
            proof.write(message.by_ref())?;
            let signature = sign(message.as_slice(), &server_data.signature_keypair)
                .expect("Signing should not fail.")
                .as_ref()
                .to_vec();
            stream_writer.write_all(&t_new.0)?;
            stream_writer.write_all(&u64_array_to_u8_vector(&[signature.len() as u64]))?;
            stream_writer.write_all(&signature)?;
            stream_writer.flush()?;

            let mut blockchain = blockchain.write().unwrap();
            blockchain
                .new_block
                .as_mut()
                .expect("A new block should be ready.")
                .add_transaction(Box::new(CredTransaction {
                    cm_cred,
                    pk_addr,
                    t_new,
                    proof,
                    signature,
                }));
            println!(
                "KYC completed successful for client with public address key 0x{}.",
                hex::encode(pk_addr)
            );
            Ok(true)
        }
        false => Ok(false),
    }
}

/// This function handles the server side of a `ConvertTo` command.
/// It returns the result of the proof verification.
pub fn c_to(
    stream: TcpStream,
    blockchain: Arc<RwLock<BlockChain>>,
    server_data: Arc<ServerData>,
) -> std::io::Result<bool> {
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let mut rng = OsRng;
    let mut pk_addr: AddressPublicKey = [0; 32];
    let mut pk_enc = [0; 32];
    let mut v_note = [0; 8];
    let mut message = vec![];
    stream_reader.read_exact(&mut pk_addr)?;
    stream_reader.read_exact(&mut pk_enc)?;
    let pk_enc = UnparsedPublicKey::new(&X25519, pk_enc);
    stream_reader.read_exact(&mut v_note)?;
    let note_new = Note::generate_random_from_pk_and_v(pk_addr, v_note, &mut rng);
    let time_start = Instant::now();
    let proof = convert_to::prover::create_proof(&note_new, &constants::C_TO_PARAMS);
    let duration = time_start.elapsed();
    println!("Proof generation took {} seconds.", duration.as_secs_f64());
    let cm_note_new = note_new.comm_note();
    stream_writer.write_all(&cm_note_new.to_bytes())?;
    proof.write(stream_writer.by_ref())?;
    stream_writer.flush()?;
    let mut result = [0; 1];
    stream_reader.read_exact(&mut result)?;
    match result[0] {
        1 => {
            let mut data = vec![];
            data.extend(&note_new.s_note.to_bytes());
            data.extend(&note_new.v_note);
            let mut context = vec![];
            proof.write(context.by_ref())?;
            let epk = encrypt(&mut data, &context, &pk_enc).unwrap();

            message.extend_from_slice(&cm_note_new.to_bytes());
            message.extend_from_slice(data.as_slice());
            message.extend_from_slice(epk.bytes().as_ref());
            proof.write(message.by_ref())?;
            let signature = sign(message.as_slice(), &server_data.signature_keypair)
                .expect("Signing should not fail.")
                .as_ref()
                .to_vec();
            stream_writer.write_all(&u64_array_to_u8_vector(&[signature.len() as u64]))?;
            stream_writer.write_all(&signature)?;
            stream_writer.flush()?;

            let mut blockchain = blockchain.write().unwrap();
            blockchain
                .new_block
                .as_mut()
                .expect("A new block should be ready.")
                .add_transaction(Box::new(CToTransaction {
                    cm_note_new,
                    t_new: TransactionTime::current(),
                    data,
                    epk,
                    proof,
                    signature,
                }));
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// This function handles the server side of a `ConvertFrom` command.
/// It returns the result of the proof verification.
pub fn c_from(
    stream: TcpStream,
    blockchain: Arc<RwLock<BlockChain>>,
    server_data: Arc<ServerData>,
) -> std::io::Result<bool> {
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let mut rt_note = [0; 32];
    let mut eta = [0; 32];
    let mut pk_addr: AddressPublicKey = [0; 32];
    let mut t_new = [0; 8];
    let mut message = vec![];
    stream_reader.read_exact(&mut rt_note)?;
    let rt_note = fr_from_repr(rt_note)?;
    stream_reader.read_exact(&mut eta)?;
    stream_reader.read_exact(&mut pk_addr)?;
    stream_reader.read_exact(&mut t_new)?;
    let t_new = TransactionTime(t_new);
    let proof = Proof::<Bls12>::read(stream_reader.by_ref())?;
    let time_start = Instant::now();
    let result = convert_from::verifier::verify_proof(
        &proof,
        &rt_note,
        &eta,
        &pk_addr,
        &constants::C_FROM_PVK,
    );
    let duration = time_start.elapsed();
    println!("Proof validation took {} seconds.", duration.as_secs_f64());
    stream_writer.write_all(&[result as u8])?;
    stream_writer.flush()?;
    match result {
        true => {
            message.extend_from_slice(&rt_note.to_bytes());
            message.extend_from_slice(&eta);
            message.extend_from_slice(&pk_addr);
            proof.write(message.by_ref())?;
            let signature = sign(message.as_slice(), &server_data.signature_keypair)
                .expect("Signing should not fail.")
                .as_ref()
                .to_vec();
            stream_writer.write_all(&u64_array_to_u8_vector(&[signature.len() as u64]))?;
            stream_writer.write_all(&signature)?;
            stream_writer.flush()?;

            let mut blockchain = blockchain.write().unwrap();
            blockchain
                .new_block
                .as_mut()
                .expect("A new block should be ready.")
                .add_transaction(Box::new(CFromTransaction {
                    rt_note,
                    eta,
                    pk_addr,
                    t_new,
                    proof,
                    signature,
                }));
            Ok(true)
        }
        false => Ok(false),
    }
}

/// This function handles the server side of a `Transfer` command.
/// It returns the result of the proof verification.
pub fn transfer(
    stream: TcpStream,
    blockchain: Arc<RwLock<BlockChain>>,
    server_data: Arc<ServerData>,
) -> std::io::Result<bool> {
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let mut option = [0; 1];
    let mut data_len = [0; 8];
    let mut rt_cred = [0; 32];
    let mut rt_note = [0; 32];
    let mut rt_mem = [0; 32];
    let mut eta: NoteNullifier = [0; 32];
    let mut mu: MemoryNullifier = [0; 32];
    let mut cm_note_new = [0; 32];
    let mut cm_mem_new = [0; 32];
    let mut t_new = [0; 8];
    let mut k: SignatureKeyHash = [0; 32];
    let mut kappa: SignatureKeyLink = [0; 32];
    let mut data_note = vec![];
    let mut epk_note = [0; 32];
    let mut data_mem = vec![];
    let mut epk_mem = [0; 32];
    stream_reader.read_exact(&mut option)?;
    match option[0] {
        1 => {
            stream_writer.write_all(&server_data.address_public_key)?;
            stream_writer.write_all(server_data.public_key.as_ref())?;
            stream_writer.flush()?;
        }
        0 => {}
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Cannot read withdraw option.",
            ))
        }
    };
    stream_reader.read_exact(&mut rt_cred)?;
    let rt_cred = fr_from_repr(rt_cred)?;
    stream_reader.read_exact(&mut option)?;
    let rt_note = match option[0] {
        0 => None,
        1 => {
            stream_reader.read_exact(&mut rt_note)?;
            Some(fr_from_repr(rt_note)?)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Cannot read option.",
            ))
        }
    };
    stream_reader.read_exact(&mut rt_mem)?;
    let rt_mem = fr_from_repr(rt_mem)?;
    stream_reader.read_exact(&mut option)?;
    let eta = match option[0] {
        0 => None,
        1 => {
            stream_reader.read_exact(&mut eta)?;
            Some(eta)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Cannot read option.",
            ))
        }
    };
    stream_reader.read_exact(&mut mu)?;
    stream_reader.read_exact(&mut cm_note_new)?;
    let cm_note_new = fr_from_repr(cm_note_new)?;
    stream_reader.read_exact(&mut cm_mem_new)?;
    let cm_mem_new = fr_from_repr(cm_mem_new)?;
    stream_reader.read_exact(&mut t_new)?;
    let t_new = TransactionTime(t_new);
    stream_reader.read_exact(&mut k)?;
    stream_reader.read_exact(&mut kappa)?;
    let proof = Proof::<Bls12>::read(stream_reader.by_ref())?;
    stream_reader.read_exact(&mut data_len)?;
    let data_note_len = u8_array_to_u64(&data_len);
    for _ in 0..data_note_len {
        let mut byte = [0; 1];
        stream_reader.read_exact(&mut byte)?;
        data_note.push(byte[0])
    }
    stream_reader.read_exact(&mut epk_note)?;
    let epk_note = UnparsedPublicKey::new(&X25519, epk_note);
    stream_reader.read_exact(&mut data_len)?;
    let data_mem_len = u8_array_to_u64(&data_len);
    for _ in 0..data_mem_len {
        let mut byte = [0; 1];
        stream_reader.read_exact(&mut byte)?;
        data_mem.push(byte[0])
    }
    stream_reader.read_exact(&mut epk_mem)?;
    let epk_mem = UnparsedPublicKey::new(&X25519, epk_mem);
    let data_saver = SaverCiphertext::<Bls12>::read(stream_reader.by_ref())?;
    let mut vec_len = [0; 8];
    stream_reader.read_exact(&mut vec_len)?;
    let mut pk_sig = vec![0; u8_array_to_u64(&vec_len) as usize];
    stream_reader.read_exact(&mut pk_sig)?;
    stream_reader.read_exact(&mut vec_len)?;
    let mut signature = vec![0; u8_array_to_u64(&vec_len) as usize];
    stream_reader.read_exact(&mut signature)?;
    let time_start = Instant::now();
    let result = transfer::verifier::verify_proof(
        &proof,
        &data_saver,
        &rt_cred,
        rt_note.as_ref(),
        &rt_mem,
        eta.as_ref(),
        &mu,
        &cm_note_new,
        &cm_mem_new,
        &k,
        &kappa,
        &t_new,
        &constants::TRANSFER_PVK,
        &constants::SAVER_KEYS.pk,
    );
    let duration = time_start.elapsed();
    println!("Proof validation took {} seconds.", duration.as_secs_f64());
    stream_writer.write_all(&[result as u8])?;
    stream_writer.flush()?;
    match result {
        true => {
            let mut blockchain = blockchain.write().unwrap();
            blockchain
                .new_block
                .as_mut()
                .expect("A new block should be ready.")
                .add_transaction(Box::new(TransferTransaction {
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
                }));
            Ok(true)
        }
        false => Ok(false),
    }
}

/// This function handles the server side of an `Update` command.
pub fn update(stream: TcpStream, blockchain: Arc<RwLock<BlockChain>>) -> std::io::Result<()> {
    let mut stream_reader = BufReader::new(&stream);
    let mut stream_writer = BufWriter::new(&stream);
    let mut client_chain_size = [0; 8];
    stream_reader.read_exact(&mut client_chain_size)?;
    let mut index = u8_array_to_u64(&client_chain_size) as usize;
    let blockchain = blockchain.read().unwrap();
    let block_amount = blockchain.blocks.len() - index;
    stream_writer.write_all(&u64_array_to_u8_vector(&[block_amount as u64]))?;
    while index < blockchain.blocks.len() {
        blockchain.blocks[index].write(stream_writer.by_ref())?;
        index += 1
    }
    stream_writer.flush()?;
    Ok(())
}
