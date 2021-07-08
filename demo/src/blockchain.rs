use std::convert::TryInto;
use std::fmt::Formatter;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::mem::replace;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use bellman::groth16::Proof;
use bls12_381::{Bls12, Scalar};
use ff::PrimeField;
use ring::agreement::{UnparsedPublicKey, X25519};

use primitives::constants::{CREDENTIAL_MT_DEPTH, MEMORY_MT_DEPTH, NOTE_MT_DEPTH};
use primitives::definitions::{
    AddressPublicKey, CredentialCommitment, MemoryCommitment, MemoryNullifier, MerkleRoot, Note,
    NoteCommitment, NoteNullifier, SignatureKeyHash, SignatureKeyLink, TransactionTime,
};
use primitives::merkle_trees::{IncrementalMerkleWitness, MerkleNode, MerkleTree, TreeType};
use primitives::saver::{verify_decryption, SaverCiphertext};
use primitives::serialise::{fr_from_repr, u64_array_to_u8_vector, u8_array_to_u64};
use primitives::{encryption, saver};

use crate::commands::{Command, ServerData};
use crate::constants;
use crate::user_input::{send_c_from, UserData};

/// Object storing the current state of the blockchain: all blocks, Merkle Trees, and the
/// `new_block` that is still under construction.
pub struct BlockChain {
    pub blocks: Vec<Block>,
    pub tree_cred: MerkleTree,
    pub tree_note: MerkleTree,
    pub tree_mem: MerkleTree,
    pub new_block: Option<Block>,
}

/// Object storing all block details, and transactions on this block.
pub struct Block {
    hash: [u8; 32],
    prev_hash: [u8; 32],
    index: usize,
    rt_cred: MerkleRoot,
    rt_note: MerkleRoot,
    rt_mem: MerkleRoot,
    pub transactions: Vec<Box<dyn Transaction + Send + Sync>>,
}

/// Generic transaction object that belongs to a block.
pub trait Transaction: std::fmt::Display {
    /// Update the Merkle Trees in `chain` with the commitments in this transaction.
    fn update_trees(&self, chain: &mut BlockChain) -> Result<(), ()>;
    /// Update the `IncrementalMerkleWitness` objects of a user with data `user_data` with the
    /// commitments in this transaction.
    fn update_witnesses(&self, user_data: &mut UserData) -> Result<(), ()>;
    /// Convert this `Transaction` to a byte vector.
    fn as_u8(&self) -> std::io::Result<Vec<u8>>;
    /// Scan if this transaction was sent to the user owning `user_data`, if so update `user_data`
    /// accordingly and display the results.
    fn scan(&self, user_data: &mut UserData);
    /// Scan if this transaction was sent the the server/admin with `server_data`. If so only for
    /// a transfer transaction call a thread that creates a convert_from transaction. Other types do nothing.
    fn scan_server(
        &self,
        server_data: &Arc<ServerData>,
        blockchain: &BlockChain,
        remaining_transactions: &[Box<dyn Transaction + Send + Sync>],
    );
    /// A requirement for the scan_server functionality.
    fn update_witness_server(&self, witness: &mut IncrementalMerkleWitness);
}

pub struct CredTransaction {
    pub cm_cred: CredentialCommitment,
    pub pk_addr: AddressPublicKey,
    pub t_new: TransactionTime,
    pub proof: Proof<Bls12>,
    pub signature: Vec<u8>,
}

pub struct CToTransaction<B: AsRef<[u8]>> {
    pub cm_note_new: NoteCommitment,
    pub t_new: TransactionTime,
    pub data: Vec<u8>,
    pub epk: UnparsedPublicKey<B>,
    pub proof: Proof<Bls12>,
    pub signature: Vec<u8>,
}

pub struct CFromTransaction {
    pub rt_note: MerkleRoot,
    pub eta: NoteNullifier,
    pub pk_addr: AddressPublicKey,
    pub t_new: TransactionTime,
    pub proof: Proof<Bls12>,
    pub signature: Vec<u8>,
}

pub struct TransferTransaction<B: AsRef<[u8]>> {
    pub rt_cred: MerkleRoot,
    pub rt_note: Option<MerkleRoot>,
    pub rt_mem: MerkleRoot,
    pub eta: Option<NoteNullifier>,
    pub mu: MemoryNullifier,
    pub cm_note_new: NoteCommitment,
    pub cm_mem_new: MemoryCommitment,
    pub t_new: TransactionTime,
    pub k: SignatureKeyHash,
    pub kappa: SignatureKeyLink,
    pub data_note: Vec<u8>,
    pub epk_note: UnparsedPublicKey<B>,
    pub data_mem: Vec<u8>,
    pub epk_mem: UnparsedPublicKey<B>,
    pub data_saver: SaverCiphertext<Bls12>,
    pub proof: Proof<Bls12>,
    pub pk_sig: Vec<u8>,
    pub signature: Vec<u8>,
}

impl BlockChain {
    /// Construct a fresh `Blockchain`.
    pub fn new() -> Result<BlockChain, ()> {
        let mut chain = BlockChain {
            blocks: vec![],
            tree_cred: MerkleTree::new_cred(),
            tree_note: MerkleTree::new_note(),
            tree_mem: MerkleTree::new_mem(),
            new_block: None,
        };
        chain.add_block(Block::genesis(), None)?;
        Ok(chain)
    }

    /// Add `block` to this `Blockchain` and update the Merkle Trees accordingly.
    pub fn add_block(
        &mut self,
        mut block: Block,
        server_data: Option<Arc<ServerData>>,
    ) -> Result<(), ()> {
        let mut transaction_hashes = vec![];
        for (i, transaction) in block.transactions.iter().enumerate() {
            transaction_hashes.extend(transaction.as_u8().unwrap());
            transaction.update_trees(self)?;
            if let Some(server_data) = server_data.as_ref() {
                transaction.scan_server(server_data, self, &block.transactions[i..]);
            }
        }
        block.hash = *blake2s_simd::Params::new()
            .hash_length(32)
            .personal(constants::PERSONALISATION_BLOCK_HASH)
            .to_state()
            .update(&block.prev_hash)
            .update(&[block.index as u8])
            .update(&block.rt_cred.to_repr())
            .update(&block.rt_note.to_repr())
            .update(&block.rt_mem.to_repr())
            .update(&transaction_hashes)
            .finalize()
            .as_array();
        block.rt_cred = self.tree_cred.root_value();
        block.rt_mem = self.tree_mem.root_value();
        block.rt_note = self.tree_mem.root_value();
        self.new_block = Some(Block::new(&block));
        self.blocks.push(block);
        Ok(())
    }

    /// Add the block that is currently under construction to the `Blockchain`.
    pub fn refresh(&mut self, server_data: Arc<ServerData>) -> Result<(), ()> {
        let block = self.new_block.take().expect("A new block should be ready.");
        self.add_block(block, Some(server_data))
    }

    /// Write this `Blockchain` to a .blockchain with `name`.
    pub fn write(&self, name: &str) -> std::io::Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .open(format!("{}.blockchain", name));

        let mut old_blocks_amount = [0; 8];
        let mut position = [0, 0, 0, 0, 0, 0, 0, 16];
        match file {
            Ok(mut file) => {
                file.read_exact(&mut position)?;
                file.read_exact(&mut old_blocks_amount)?;
            }
            Err(_) => {
                File::create(format!("{}.blockchain", name))?;
            }
        }

        let position = u8_array_to_u64(&position);
        let mut old_blocks_amount = u8_array_to_u64(&old_blocks_amount) as usize;

        let mut file = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .open(format!("{}.blockchain", name))?,
        );
        file.write_all(&[0; 8])?;
        let block_amount = self.blocks.len();
        file.write_all(&u64_array_to_u8_vector(&[block_amount as u64]))?;
        file.seek(SeekFrom::Start(position))?;
        while old_blocks_amount < self.blocks.len() {
            self.blocks[old_blocks_amount].write(file.by_ref())?;
            old_blocks_amount += 1;
        }
        let position = file.seek(SeekFrom::Current(0))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&u64_array_to_u8_vector(&[position]))?;
        file.seek(SeekFrom::Start(position))?;

        self.tree_cred.write(file.by_ref())?;
        self.tree_note.write(file.by_ref())?;
        self.tree_mem.write(file.by_ref())?;
        file.flush()?;
        Ok(())
    }

    /// Read a `Blockchain` file from a `reader` and return the created object.
    pub fn read<R: Read + Seek>(mut reader: R) -> std::io::Result<BlockChain> {
        reader.seek(SeekFrom::Start(8))?;
        let mut blocks = vec![];
        let mut block_amount = [0; 8];
        reader.read_exact(&mut block_amount)?;
        let block_amount = u8_array_to_u64(&block_amount);
        for _ in 0..block_amount {
            blocks.push(Block::read(reader.by_ref())?);
        }
        let tree_cred =
            MerkleTree::read(reader.by_ref(), TreeType::Credential, CREDENTIAL_MT_DEPTH)?;
        let tree_note = MerkleTree::read(reader.by_ref(), TreeType::Note, NOTE_MT_DEPTH)?;
        let tree_mem = MerkleTree::read(reader.by_ref(), TreeType::Memory, MEMORY_MT_DEPTH)?;
        let new_block = Some(Block::new(blocks.last().unwrap()));
        Ok(BlockChain {
            blocks,
            tree_cred,
            tree_note,
            tree_mem,
            new_block,
        })
    }
}

impl std::fmt::Display for BlockChain {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        println!("Latest block no:   {}", self.blocks.len() - 1);
        println!(
            "Credential root:   0x{}",
            hex::encode(self.tree_cred.root_value().to_repr())
        );
        println!(
            "Note root:         0x{}",
            hex::encode(self.tree_note.root_value().to_repr())
        );
        println!(
            "Memory root:       0x{}\n",
            hex::encode(self.tree_mem.root_value().to_repr())
        );
        loop {
            print!("Which block do you want to view? [<index>/close]?   ");
            std::io::stdout().flush().unwrap();
            let mut index = String::new();
            std::io::stdin().read_line(&mut index).unwrap();
            match index.trim() {
                "close" | "c" | "quit" | "q" | "exit" | "e" => break,
                index => match index.parse::<usize>() {
                    Ok(index) => {
                        if index < self.blocks.len() {
                            println!("{}", self.blocks[index]);
                        } else {
                            println!("Please choose an index in [0;{}]\n", self.blocks.len() - 1);
                        }
                    }
                    Err(_) => println!("Invalid input.\n"),
                },
            }
        }
        Ok(())
    }
}

impl Block {
    /// Create the genesis block, i.e. first block of the blockchain.
    pub fn genesis() -> Block {
        Block {
            hash: [0; 32],
            prev_hash: [0; 32],
            index: 0,
            rt_cred: Scalar::one(),
            rt_note: Scalar::one(),
            rt_mem: Scalar::one(),
            transactions: vec![],
        }
    }

    /// Create an emtpy new `Block` (not the genesis block).
    pub fn new(prev_block: &Block) -> Block {
        Block {
            hash: [0; 32],
            prev_hash: prev_block.hash,
            index: prev_block.index + 1,
            rt_cred: Scalar::one(),
            rt_note: Scalar::one(),
            rt_mem: Scalar::one(),
            transactions: vec![],
        }
    }

    /// Add the `transaction` to this block.
    pub fn add_transaction(&mut self, transaction: Box<dyn Transaction + Send + Sync>) {
        self.transactions.push(transaction)
    }

    /// Write this `Block` to a `writer`.
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.hash)?;
        writer.write_all(&self.prev_hash)?;
        writer.write_all(&u64_array_to_u8_vector(&[self.index as u64]))?;
        writer.write_all(&self.rt_cred.to_bytes())?;
        writer.write_all(&self.rt_note.to_bytes())?;
        writer.write_all(&self.rt_mem.to_bytes())?;
        let transaction_amount = self.transactions.len();
        writer.write_all(&u64_array_to_u8_vector(&[transaction_amount as u64]))?;
        for transaction in &self.transactions {
            writer.write_all(&transaction.as_u8()?)?;
        }
        Ok(())
    }

    /// Read this `Block` from a `reader` and return the created object.
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Block> {
        let mut hash = [0; 32];
        let mut prev_hash = [0; 32];
        let mut index = [0; 8];
        let mut rt_cred = [0; 32];
        let mut rt_note = [0; 32];
        let mut rt_mem = [0; 32];
        let mut transaction_amount = [0; 8];
        reader.read_exact(&mut hash)?;
        reader.read_exact(&mut prev_hash)?;
        reader.read_exact(&mut index)?;
        let index = u8_array_to_u64(&index) as usize;
        reader.read_exact(&mut rt_cred)?;
        let rt_cred = fr_from_repr(rt_cred)?;
        reader.read_exact(&mut rt_note)?;
        let rt_note = fr_from_repr(rt_note)?;
        reader.read_exact(&mut rt_mem)?;
        let rt_mem = fr_from_repr(rt_mem)?;
        reader.read_exact(&mut transaction_amount)?;
        let mut block = Block {
            hash,
            prev_hash,
            index,
            rt_cred,
            rt_note,
            rt_mem,
            transactions: vec![],
        };
        let transaction_amount = u8_array_to_u64(&transaction_amount);
        for _ in 0..transaction_amount {
            let mut transaction_type = [0; 1];
            reader.read_exact(&mut transaction_type)?;
            match transaction_type[0] {
                t if t == Command::Cred as u8 => {
                    block.add_transaction(Box::new(CredTransaction::from_u8(reader.by_ref())?));
                }
                t if t == Command::CTo as u8 => {
                    block.add_transaction(Box::new(CToTransaction::<[u8; 32]>::from_u8(
                        reader.by_ref(),
                    )?));
                }
                t if t == Command::CFrom as u8 => {
                    block.add_transaction(Box::new(CFromTransaction::from_u8(reader.by_ref())?));
                }
                t if t == Command::Transfer as u8 => {
                    block.add_transaction(Box::new(TransferTransaction::<[u8; 32]>::from_u8(
                        reader.by_ref(),
                    )?));
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Unknown transaction type.",
                    ));
                }
            }
        }
        Ok(block)
    }
}

impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Block index:           {}", self.index)?;
        writeln!(f, "Block hash:            0x{}", hex::encode(self.hash))?;
        writeln!(
            f,
            "Previous block hash:   0x{}",
            hex::encode(self.prev_hash)
        )?;
        writeln!(
            f,
            "Credential root:       0x{}",
            hex::encode(self.rt_cred.to_repr())
        )?;
        writeln!(
            f,
            "Note root:             0x{}",
            hex::encode(self.rt_note.to_repr())
        )?;
        writeln!(
            f,
            "Memory root:           0x{}",
            hex::encode(self.rt_mem.to_repr())
        )?;
        for (i, transaction) in self.transactions.iter().enumerate() {
            writeln!(f, "Transaction {}", i)?;
            writeln!(f, "{}", transaction)?;
        }
        Ok(())
    }
}

impl Transaction for CredTransaction {
    fn update_trees(&self, chain: &mut BlockChain) -> Result<(), ()> {
        chain.tree_cred.append_credential_commitment(self.cm_cred)?;
        Ok(())
    }

    fn update_witnesses(&self, user_data: &mut UserData) -> Result<(), ()> {
        if let Some(witness) = &mut user_data.cred_witness {
            witness.append(MerkleNode {
                value: self.cm_cred.to_repr(),
            })?;
        }
        Ok(())
    }

    fn as_u8(&self) -> std::io::Result<Vec<u8>> {
        let mut u8_vector = vec![Command::Cred as u8];
        u8_vector.extend(&self.cm_cred.to_bytes());
        u8_vector.extend(&self.pk_addr);
        u8_vector.extend(&self.t_new.0);
        self.proof.write(u8_vector.by_ref())?;
        u8_vector.extend_from_slice(&u64_array_to_u8_vector(&[self.signature.len() as u64]));
        u8_vector.extend_from_slice(&self.signature);
        Ok(u8_vector)
    }

    fn scan(&self, user_data: &mut UserData) {
        if self.pk_addr == user_data.cred.pk_addr && self.cm_cred == user_data.cred.comm_cred() {
            user_data.cred_witness = Some(IncrementalMerkleWitness::from_tree(
                &user_data.blockchain.tree_cred,
            ));
            println!("Transaction found:");
            println!("{}", self);
        }
    }

    fn scan_server(
        &self,
        _server_data: &Arc<ServerData>,
        _blockchain: &BlockChain,
        _remaining_transactions: &[Box<dyn Transaction + Send + Sync>],
    ) {
    }

    fn update_witness_server(&self, _witness: &mut IncrementalMerkleWitness) {}
}

impl CredTransaction {
    /// Read a `CredTransaction` from a `reader` of bytes and return it.
    fn from_u8<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut cm_cred = [0; 32];
        let mut pk_addr: AddressPublicKey = [0; 32];
        let mut t_new = [0; 8];
        reader.read_exact(&mut cm_cred)?;
        let cm_cred = fr_from_repr(cm_cred)?;
        reader.read_exact(&mut pk_addr)?;
        reader.read_exact(&mut t_new)?;
        let t_new = TransactionTime(t_new);
        let proof = Proof::<Bls12>::read(reader.by_ref())?;
        let mut vec_len = [0; 8];
        reader.read_exact(&mut vec_len)?;
        let mut signature = vec![0; u8_array_to_u64(&vec_len) as usize];
        reader.read_exact(&mut signature)?;
        Ok(CredTransaction {
            cm_cred,
            pk_addr,
            t_new,
            proof,
            signature,
        })
    }
}

impl std::fmt::Display for CredTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   Transaction type:           Credential")?;
        writeln!(
            f,
            "   Credential commitment:      0x{}",
            hex::encode(self.cm_cred.to_repr())
        )?;
        writeln!(
            f,
            "   Public address key:         0x{}",
            hex::encode(self.pk_addr)
        )?;
        writeln!(f, "   Transaction time:           {}", self.t_new)?;
        let mut proof = vec![];
        self.proof.write(proof.by_ref()).unwrap();
        writeln!(f, "   Proof:                      0x{}", hex::encode(proof))?;
        writeln!(
            f,
            "   Signature:                  0x{}",
            hex::encode(&self.signature)
        )?;
        Ok(())
    }
}

impl<B: AsRef<[u8]>> Transaction for CToTransaction<B> {
    fn update_trees(&self, chain: &mut BlockChain) -> Result<(), ()> {
        chain
            .tree_note
            .append_note_commitment(self.cm_note_new, &self.t_new)?;
        Ok(())
    }

    fn update_witnesses(&self, user_data: &mut UserData) -> Result<(), ()> {
        for witness in &mut user_data.note_witnesses {
            witness.append(MerkleNode {
                value: self.cm_note_new.to_repr(),
            })?;
        }
        Ok(())
    }

    fn as_u8(&self) -> std::io::Result<Vec<u8>> {
        let mut u8_vector = vec![Command::CTo as u8];
        u8_vector.extend(&self.cm_note_new.to_bytes());
        u8_vector.extend(&self.t_new.0);
        let data_len = u64_array_to_u8_vector(&[self.data.len() as u64]);
        u8_vector.extend(data_len);
        u8_vector.extend(&self.data);
        u8_vector.extend(self.epk.bytes().as_ref());
        self.proof.write(u8_vector.by_ref())?;
        u8_vector.extend_from_slice(&u64_array_to_u8_vector(&[self.signature.len() as u64]));
        u8_vector.extend_from_slice(&self.signature);
        Ok(u8_vector)
    }

    fn scan(&self, user_data: &mut UserData) {
        let mut data = self.data.clone();
        let mut context = vec![];
        self.proof.write(context.by_ref()).unwrap();
        if let Ok(data) =
            encryption::decrypt(&mut data, &context, user_data.private_key(), &self.epk)
        {
            if data.len() == (32 + 8) {
                let s_note = data[0..32].try_into().expect("This should fit.");
                let s_note = jubjub::Scalar::from_repr(s_note);
                if let Some(s_note) = s_note {
                    let v_note: [u8; 8] = data[32..(32 + 8)].try_into().unwrap();
                    let note = Note {
                        pk_addr: user_data.cred.pk_addr,
                        v_note,
                        s_note,
                        t_note: TransactionTime(self.t_new.0),
                        t_delta: [0; 8],
                    };
                    if note.comm_note() == self.cm_note_new {
                        //the transaction was sent to this user
                        println!("Transaction found:");
                        println!("{}", self);
                        println!("New note:");
                        println!("{}", note);
                        user_data.notes.push(note);
                        user_data
                            .note_witnesses
                            .push(IncrementalMerkleWitness::from_tree(
                                &user_data.blockchain.tree_note,
                            ));
                    }
                }
            }
        }
    }

    fn scan_server(
        &self,
        _server_data: &Arc<ServerData>,
        _blockchain: &BlockChain,
        _remaining_transactions: &[Box<dyn Transaction + Send + Sync>],
    ) {
    }

    fn update_witness_server(&self, witness: &mut IncrementalMerkleWitness) {
        witness
            .append(MerkleNode {
                value: self.cm_note_new.to_repr(),
            })
            .expect("This should not fail.");
    }
}

impl CToTransaction<[u8; 32]> {
    /// Read a `CToTransaction` from a `reader` of bytes and return it.
    fn from_u8<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut cm_note_new = [0; 32];
        let mut t_new = [0; 8];
        let mut data_len = [0; 8];
        let mut data = vec![];
        let mut epk = [0; 32];
        reader.read_exact(&mut cm_note_new)?;
        let cm_note_new = fr_from_repr(cm_note_new)?;
        reader.read_exact(&mut t_new)?;
        let t_new = TransactionTime(t_new);
        reader.read_exact(&mut data_len)?;
        let data_len = u8_array_to_u64(&data_len);
        for _ in 0..data_len {
            let mut byte = [0; 1];
            reader.read_exact(&mut byte)?;
            data.push(byte[0])
        }
        reader.read_exact(&mut epk)?;
        let epk = UnparsedPublicKey::new(&X25519, epk);
        let proof = Proof::<Bls12>::read(reader.by_ref())?;
        let mut vec_len = [0; 8];
        reader.read_exact(&mut vec_len)?;
        let mut signature = vec![0; u8_array_to_u64(&vec_len) as usize];
        reader.read_exact(&mut signature)?;
        Ok(CToTransaction {
            cm_note_new,
            t_new,
            data,
            epk,
            proof,
            signature,
        })
    }
}

impl<B: AsRef<[u8]>> std::fmt::Display for CToTransaction<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   Transaction type:       ConvertTo")?;
        writeln!(
            f,
            "   Note commitment:        0x{}",
            hex::encode(self.cm_note_new.to_repr())
        )?;
        writeln!(f, "   Transaction time:       {}", self.t_new)?;
        writeln!(
            f,
            "   Encrypted data:         0x{}",
            hex::encode(&self.data)
        )?;
        writeln!(
            f,
            "   Ephemeral public key:   0x{}",
            hex::encode(self.epk.bytes())
        )?;
        let mut proof = vec![];
        self.proof.write(proof.by_ref()).unwrap();
        writeln!(f, "   Proof:                  0x{}", hex::encode(proof))?;
        writeln!(
            f,
            "   Signature:              0x{}",
            hex::encode(&self.signature)
        )?;
        Ok(())
    }
}

impl Transaction for CFromTransaction {
    fn update_trees(&self, _chain: &mut BlockChain) -> Result<(), ()> {
        Ok(())
    }

    fn update_witnesses(&self, _user_data: &mut UserData) -> Result<(), ()> {
        Ok(())
    }

    fn as_u8(&self) -> std::io::Result<Vec<u8>> {
        let mut u8_vector = vec![Command::CFrom as u8];
        u8_vector.extend(&self.rt_note.to_bytes());
        u8_vector.extend(&self.eta);
        u8_vector.extend(&self.pk_addr);
        u8_vector.extend(&self.t_new.0);
        self.proof.write(u8_vector.by_ref())?;
        u8_vector.extend_from_slice(&u64_array_to_u8_vector(&[self.signature.len() as u64]));
        u8_vector.extend_from_slice(&self.signature);
        Ok(u8_vector)
    }

    fn scan(&self, _user_data: &mut UserData) {}

    fn scan_server(
        &self,
        _server_data: &Arc<ServerData>,
        _blockchain: &BlockChain,
        _remaining_transactions: &[Box<dyn Transaction + Send + Sync>],
    ) {
    }

    fn update_witness_server(&self, _witness: &mut IncrementalMerkleWitness) {}
}

impl CFromTransaction {
    /// Read a `CFromTransaction` from a `reader` of bytes and return it.
    fn from_u8<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut rt_note = [0; 32];
        let mut eta: NoteNullifier = [0; 32];
        let mut pk_addr: AddressPublicKey = [0; 32];
        let mut t_new = [0; 8];
        reader.read_exact(&mut rt_note)?;
        let rt_note = fr_from_repr(rt_note)?;
        reader.read_exact(&mut eta)?;
        reader.read_exact(&mut pk_addr)?;
        reader.read_exact(&mut t_new)?;
        let t_new = TransactionTime(t_new);
        let proof = Proof::<Bls12>::read(reader.by_ref())?;
        let mut vec_len = [0; 8];
        reader.read_exact(&mut vec_len)?;
        let mut signature = vec![0; u8_array_to_u64(&vec_len) as usize];
        reader.read_exact(&mut signature)?;
        Ok(CFromTransaction {
            rt_note,
            eta,
            pk_addr,
            t_new,
            proof,
            signature,
        })
    }
}

impl std::fmt::Display for CFromTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   Transaction type:     ConvertFrom")?;
        writeln!(
            f,
            "   Note root:            0x{}",
            hex::encode(self.rt_note.to_repr())
        )?;
        writeln!(f, "   Note nullifier:       0x{}", hex::encode(self.eta))?;
        writeln!(
            f,
            "   Public address key:   0x{}",
            hex::encode(self.pk_addr)
        )?;
        writeln!(f, "   Transaction time:     {}", self.t_new)?;
        let mut proof = vec![];
        self.proof.write(proof.by_ref()).unwrap();
        writeln!(f, "   Proof:                0x{}", hex::encode(proof))?;
        writeln!(
            f,
            "   Signature:            0x{}",
            hex::encode(&self.signature)
        )?;
        Ok(())
    }
}

impl<B: AsRef<[u8]>> Transaction for TransferTransaction<B> {
    fn update_trees(&self, chain: &mut BlockChain) -> Result<(), ()> {
        chain
            .tree_note
            .append_note_commitment(self.cm_note_new, &self.t_new)?;
        chain
            .tree_mem
            .append_memory_commitment(self.cm_mem_new, &self.t_new)?;
        Ok(())
    }

    fn update_witnesses(&self, user_data: &mut UserData) -> Result<(), ()> {
        for witness in &mut user_data.note_witnesses {
            witness.append(MerkleNode {
                value: self.cm_note_new.to_repr(),
            })?;
        }
        if let Some(witness) = user_data.memory_witness.as_mut() {
            witness.append(MerkleNode {
                value: self.cm_mem_new.to_repr(),
            })?;
        }
        for witness in &mut user_data.ceil_memory_witnesses {
            witness.append(MerkleNode {
                value: self.cm_mem_new.to_repr(),
            })?;
        }
        Ok(())
    }

    fn as_u8(&self) -> std::io::Result<Vec<u8>> {
        let mut u8_vector = vec![Command::Transfer as u8];
        u8_vector.extend(&self.rt_cred.to_bytes());
        match &self.rt_note {
            None => u8_vector.push(0),
            Some(rt_note) => {
                u8_vector.push(1);
                u8_vector.extend(&rt_note.to_bytes());
            }
        }
        u8_vector.extend(&self.rt_mem.to_bytes());
        match &self.eta {
            None => u8_vector.push(0),
            Some(eta) => {
                u8_vector.push(1);
                u8_vector.extend(eta);
            }
        }
        u8_vector.extend(&self.mu);
        u8_vector.extend(&self.cm_note_new.to_bytes());
        u8_vector.extend(&self.cm_mem_new.to_bytes());
        u8_vector.extend(&self.t_new.0);
        u8_vector.extend(&self.k);
        u8_vector.extend(&self.kappa);
        let data_note_len = u64_array_to_u8_vector(&[self.data_note.len() as u64]);
        u8_vector.extend(data_note_len);
        u8_vector.extend(&self.data_note);
        u8_vector.extend(self.epk_note.bytes().as_ref());
        let data_mem_len = u64_array_to_u8_vector(&[self.data_mem.len() as u64]);
        u8_vector.extend(data_mem_len);
        u8_vector.extend(&self.data_mem);
        u8_vector.extend(self.epk_mem.bytes().as_ref());
        self.data_saver.write(u8_vector.by_ref())?;
        self.proof.write(u8_vector.by_ref())?;
        u8_vector.extend_from_slice(&u64_array_to_u8_vector(&[self.pk_sig.len() as u64]));
        u8_vector.extend_from_slice(&self.pk_sig);
        u8_vector.extend_from_slice(&u64_array_to_u8_vector(&[self.signature.len() as u64]));
        u8_vector.extend_from_slice(&self.signature);
        Ok(u8_vector)
    }

    fn scan(&self, user_data: &mut UserData) {
        let mut data = self.data_note.clone();
        let mut context = vec![];
        self.proof.write(context.by_ref()).unwrap();
        if let Ok(data) =
            encryption::decrypt(&mut data, &context, user_data.private_key(), &self.epk_note)
        {
            if data.len() == (32 + 8 + 32 + 8) {
                let s_note = data[0..32].try_into().expect("This should fit.");
                let s_note = jubjub::Scalar::from_repr(s_note);
                if let Some(s_note) = s_note {
                    let v_note: [u8; 8] = data[32..(32 + 8)].try_into().unwrap();
                    if data[(32 + 8)..(32 + 8 + 32)] == [0; 32] {
                        let t_delta: [u8; 8] =
                            data[(32 + 8 + 32)..(32 + 8 + 32 + 8)].try_into().unwrap();
                        let note = Note {
                            pk_addr: user_data.cred.pk_addr,
                            v_note,
                            s_note,
                            t_note: TransactionTime(self.t_new.0),
                            t_delta,
                        };
                        if note.comm_note() == self.cm_note_new {
                            // the transaction was sent to this user
                            println!("Transaction found:");
                            println!("{}", self);
                            println!("New note:");
                            println!("{}", note);
                            user_data.notes.push(note);
                            user_data
                                .note_witnesses
                                .push(IncrementalMerkleWitness::from_tree(
                                    &user_data.blockchain.tree_note,
                                ));
                        }
                    }
                }
            }
        }
        if let Some(memory) = &user_data.memory {
            let mut data = self.data_mem.clone();
            if let Ok(data) =
                encryption::decrypt(&mut data, &context, user_data.private_key(), &self.epk_mem)
            {
                if data.len() == 32 {
                    let s_mem = data[0..32].try_into().expect("This should fit.");
                    let s_mem = jubjub::Scalar::from_repr(s_mem);
                    if let Some(s_mem) = s_mem {
                        if s_mem == memory.s_mem {
                            // the transaction was sent by this user
                            println!("Transaction found:");
                            println!("{}", self);
                            println!("New memory:");
                            println!("{}", memory);
                            let witness = replace(
                                &mut user_data.memory_witness,
                                Some(IncrementalMerkleWitness::from_tree(
                                    &user_data.blockchain.tree_mem,
                                )),
                            );
                            if let Some(witness) = witness {
                                user_data.ceil_memory_witnesses.push(witness);
                            }
                        }
                    }
                }
            }
        }
    }

    fn scan_server(
        &self,
        server_data: &Arc<ServerData>,
        blockchain: &BlockChain,
        remaining_transactions: &[Box<dyn Transaction + Send + Sync>],
    ) {
        let mut data = self.data_note.clone();
        let mut context = vec![];
        self.proof.write(context.by_ref()).unwrap();
        if let Ok(data) = encryption::decrypt(
            &mut data,
            &context,
            server_data.private_key(),
            &self.epk_note,
        ) {
            if data.len() == (32 + 8 + 32 + 8) {
                let s_note = data[0..32].try_into().expect("This should fit.");
                let s_note = jubjub::Scalar::from_repr(s_note);
                if let Some(s_note) = s_note {
                    let v_note: [u8; 8] = data[32..(32 + 8)].try_into().unwrap();
                    let pk_addr_sndr: AddressPublicKey =
                        data[(32 + 8)..(32 + 8 + 32)].try_into().unwrap();
                    let t_delta: [u8; 8] =
                        data[(32 + 8 + 32)..(32 + 8 + 32 + 8)].try_into().unwrap();
                    let note = Note {
                        pk_addr: server_data.address_public_key,
                        v_note,
                        s_note,
                        t_note: TransactionTime(self.t_new.0),
                        t_delta,
                    };
                    if note.comm_note() == self.cm_note_new {
                        println!("yes");
                        // the self was sent to this user
                        println!("Transaction found:");
                        println!("{}", self);
                        println!("New note:");
                        println!("{}", note);
                        let mut note_witness =
                            IncrementalMerkleWitness::from_tree(&blockchain.tree_note);
                        for transaction in remaining_transactions {
                            transaction.update_witness_server(&mut note_witness);
                        }
                        let witness = note_witness.witness();
                        let rt_note = note_witness.root_value();
                        let sk_addr = server_data.address_private_key;
                        let pk_addr = server_data.address_public_key;
                        thread::spawn(move || {
                            send_c_from(sk_addr, pk_addr, &note, witness, rt_note, pk_addr_sndr)
                                .expect("Conversion from anonymous note should not fail.");
                        });
                    }
                }
            }
        }
    }

    fn update_witness_server(&self, witness: &mut IncrementalMerkleWitness) {
        witness
            .append(MerkleNode {
                value: self.cm_note_new.to_repr(),
            })
            .expect("This should not fail.");
    }
}

impl TransferTransaction<[u8; 32]> {
    /// Read a `TransferTransaction` from a `reader` of bytes and return it.
    fn from_u8<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut option = [0; 1];
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
        let mut data_note_len = [0; 8];
        let mut data_note = vec![];
        let mut epk_note = [0; 32];
        let mut data_mem_len = [0; 8];
        let mut data_mem = vec![];
        let mut epk_mem = [0; 32];
        reader.read_exact(&mut rt_cred)?;
        let rt_cred = fr_from_repr(rt_cred)?;
        reader.read_exact(&mut option)?;
        let rt_note = match option[0] {
            0 => None,
            1 => {
                reader.read_exact(&mut rt_note)?;
                Some(fr_from_repr(rt_note)?)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid rt_note option.",
                ))
            }
        };
        reader.read_exact(&mut rt_mem)?;
        let rt_mem = fr_from_repr(rt_mem)?;
        reader.read_exact(&mut option)?;
        let eta = match option[0] {
            0 => None,
            1 => {
                reader.read_exact(&mut eta)?;
                Some(eta)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid eta option.",
                ))
            }
        };
        reader.read_exact(&mut mu)?;
        reader.read_exact(&mut cm_note_new)?;
        let cm_note_new = fr_from_repr(cm_note_new)?;
        reader.read_exact(&mut cm_mem_new)?;
        let cm_mem_new = fr_from_repr(cm_mem_new)?;
        reader.read_exact(&mut t_new)?;
        let t_new = TransactionTime(t_new);
        reader.read_exact(&mut k)?;
        reader.read_exact(&mut kappa)?;
        reader.read_exact(&mut data_note_len)?;
        let data_note_len = u8_array_to_u64(&data_note_len);
        for _ in 0..data_note_len {
            let mut byte = [0; 1];
            reader.read_exact(&mut byte)?;
            data_note.push(byte[0])
        }
        reader.read_exact(&mut epk_note)?;
        let epk_note = UnparsedPublicKey::new(&X25519, epk_note);
        reader.read_exact(&mut data_mem_len)?;
        let data_mem_len = u8_array_to_u64(&data_mem_len);
        for _ in 0..data_mem_len {
            let mut byte = [0; 1];
            reader.read_exact(&mut byte)?;
            data_mem.push(byte[0])
        }
        reader.read_exact(&mut epk_mem)?;
        let epk_mem = UnparsedPublicKey::new(&X25519, epk_mem);
        let data_saver = SaverCiphertext::<Bls12>::read(reader.by_ref())?;
        let proof = Proof::<Bls12>::read(reader.by_ref())?;
        let mut vec_len = [0; 8];
        reader.read_exact(&mut vec_len)?;
        let mut pk_sig = vec![0; u8_array_to_u64(&vec_len) as usize];
        reader.read_exact(&mut pk_sig)?;
        reader.read_exact(&mut vec_len)?;
        let mut signature = vec![0; u8_array_to_u64(&vec_len) as usize];
        reader.read_exact(&mut signature)?;
        Ok(TransferTransaction {
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
        })
    }
}

impl<B: AsRef<[u8]>> std::fmt::Display for TransferTransaction<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "   Transaction type:              Transfer")?;
        writeln!(
            f,
            "   Credential root:               0x{}",
            hex::encode(self.rt_cred.to_repr())
        )?;
        writeln!(
            f,
            "   Note root:                     {}",
            match self.rt_note {
                Some(rt_note) => format!("0x{}", hex::encode(rt_note.to_repr())),
                None => "-".to_string(),
            }
        )?;
        writeln!(
            f,
            "   Memory root:                   0x{}",
            hex::encode(self.rt_mem.to_repr())
        )?;
        writeln!(
            f,
            "   Note nullifier:                {}",
            match self.eta {
                Some(eta) => format!("0x{}", hex::encode(eta)),
                None => "-".to_string(),
            }
        )?;
        writeln!(
            f,
            "   Memory nullifier:              0x{}",
            hex::encode(self.mu)
        )?;
        writeln!(
            f,
            "   Note commitment:               0x{}",
            hex::encode(self.cm_note_new.to_repr())
        )?;
        writeln!(
            f,
            "   Memory commitment:             0x{}",
            hex::encode(self.cm_mem_new.to_repr())
        )?;
        writeln!(f, "   Transaction time:              {}", self.t_new)?;
        writeln!(
            f,
            "   Signature key hash:            0x{}",
            hex::encode(self.k)
        )?;
        writeln!(
            f,
            "   Signature key link:            0x{}",
            hex::encode(self.kappa)
        )?;
        writeln!(
            f,
            "   Encrypted note data:           0x{}",
            hex::encode(&self.data_note)
        )?;
        writeln!(
            f,
            "   Ephemeral note public key:     0x{}",
            hex::encode(self.epk_note.bytes())
        )?;
        writeln!(
            f,
            "   Encrypted memory data:         0x{}",
            hex::encode(&self.data_mem)
        )?;
        writeln!(
            f,
            "   Ephemeral memory public key:   0x{}",
            hex::encode(self.epk_mem.bytes())
        )?;
        write!(f, "   Encrypted transaction data:    {}", self.data_saver)?;
        let mut proof = vec![];
        self.proof.write(proof.by_ref()).unwrap();
        writeln!(
            f,
            "   Proof:                         0x{}",
            hex::encode(proof)
        )?;
        writeln!(
            f,
            "   Signature public key:          0x{}",
            hex::encode(&self.pk_sig)
        )?;
        writeln!(
            f,
            "   Signature:                     0x{}",
            hex::encode(&self.signature)
        )?;
        print!("Decrypt transaction details? [Y/n]   ");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        match input.to_ascii_lowercase().trim() {
            "y" | "yes" | "" => {
                let time_start = Instant::now();
                let plaintext = saver::decrypt(
                    &self.data_saver,
                    &constants::TRANSFER_PARAMS,
                    &constants::SAVER_KEYS.sk,
                    &constants::SAVER_KEYS.vk,
                )
                .expect("Decryption should not fail.");
                let duration = time_start.elapsed();
                println!("Decryption took {} seconds.", duration.as_secs_f64());
                let time_start = Instant::now();
                let result = verify_decryption(
                    &plaintext,
                    &self.data_saver,
                    &constants::TRANSFER_PARAMS,
                    &constants::SAVER_KEYS.pk,
                    &constants::SAVER_KEYS.vk,
                );
                let duration = time_start.elapsed();
                println!(
                    "Decryption verification took {} seconds.",
                    duration.as_secs_f64()
                );
                match result {
                    true => {
                        println!("Decryption was successful:");
                        let plaintext = plaintext.as_u8();
                        println!(
                            "   Sender public address key:     0x{}",
                            hex::encode(&plaintext.0[0..32])
                        );
                        println!(
                            "   Receiver public address key:   0x{}",
                            hex::encode(&plaintext.0[32..(32 + 32)])
                        );
                        println!(
                            "   Transferred value:             €{}",
                            u8_array_to_u64(&plaintext.0[(32 + 32)..(32 + 32 + 8)])
                        );
                        println!(
                            "   Decryption proof:              0x{}",
                            hex::encode(&plaintext.1)
                        );
                    }
                    false => println!("Decryption was unsuccessful."),
                };
            }
            _ => {}
        };
        Ok(())
    }
}
