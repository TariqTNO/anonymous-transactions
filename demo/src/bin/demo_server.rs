use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;

use lazy_static::initialize;
use rand::rngs::OsRng;
use rand::Rng;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use ring::test::rand::FixedSliceRandom;

use demo::blockchain::BlockChain;
use demo::commands::{c_from, c_to, cred, transfer, update, Command, ServerData};
use demo::constants;
use primitives::definitions::Credentials;
use primitives::encryption::generate_keypair;
use primitives::serialise::{u64_array_to_u8_vector, u8_array_to_u64};
use primitives::{encryption, signature};

/// Handle the input from the terminal on a separate thread, using the shared `blockchain` and
/// server `data`.
fn handle_input(blockchain: Arc<RwLock<BlockChain>>, data: Arc<ServerData>) {
    println!("Available commands:");
    println!("   update:   Add a new block to the blockchain.");
    println!("   show:     Show the blockchain.");
    println!("   quit:     Quit program.\n");
    loop {
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Reading from stdin should always work.");
        match input.to_ascii_lowercase().trim() {
            "update" | "u" => {
                let mut blockchain = blockchain.write().unwrap();
                blockchain
                    .refresh(data.clone())
                    .expect("Trees should not be full.");
                println!("New block successfully created.\n");
            }
            "show" | "s" => {
                let blockchain = blockchain.read().unwrap();
                println!("{}", blockchain);
            }
            "quit" | "q" | "exit" | "e" => {
                let blockchain = blockchain.write().unwrap();
                blockchain
                    .write(data.name)
                    .expect("Writing the blockchain on quit should succeed.");
                println!("Bye!");
                break;
            }
            _ => println!("Unknown command."),
        }
    }
}

/// Handle the input that comes from the `stream`, `index` is used as an id for this stream, using
/// the shared `blockchain` and server `data.
/// Receives a command and calls the appropriate function for further processing.
fn handle_client(
    mut stream: TcpStream,
    index: usize,
    blockchain: Arc<RwLock<BlockChain>>,
    data: Arc<ServerData>,
) {
    let mut command = [0; 1];
    match stream.read_exact(&mut command) {
        Ok(_) => match stream.write_all(&command) {
            Ok(_) => match command[0] {
                c if c == Command::Cred as u8 => {
                    println!("[Connection {}] Command: {} = Credential", index, c);
                    match cred(stream, blockchain, data) {
                        Ok(result) => println!("[Connection {}] Result: {}", index, result),
                        Err(e) => println!("[Connection {}] Error: {}", index, e),
                    }
                }
                c if c == Command::CTo as u8 => {
                    println!("[Connection {}] Command: {} = Deposit", index, c);
                    match c_to(stream, blockchain, data) {
                        Ok(result) => println!("[Connection {}] Result: {}", index, result),
                        Err(e) => println!("[Connection {}] Error: {}", index, e),
                    }
                }
                c if c == Command::CFrom as u8 => {
                    println!("[Connection {}] Command: {} = Withdraw", index, c);
                    match c_from(stream, blockchain, data) {
                        Ok(result) => println!("[Connection {}] Result: {}", index, result),
                        Err(e) => println!("[Connection {}] Error: {}", index, e),
                    }
                }
                c if c == Command::Transfer as u8 => {
                    println!("[Connection {}] Command: {} = Transfer", index, c);
                    match transfer(stream, blockchain, data) {
                        Ok(result) => println!("[Connection {}] Result: {}", index, result),
                        Err(e) => println!("[Connection {}] Error: {}", index, e),
                    }
                }
                c if c == Command::Update as u8 => {
                    println!("[Connection {}] Command: {} = Update", index, c);
                    match update(stream, blockchain) {
                        Ok(()) => {}
                        Err(e) => println!("[Connection {}] Error: {}", index, e),
                    }
                }
                e => println!("[Connection {}] Error: Unknown command \"{}\"", index, e),
            },
            Err(e) => println!("[Connection {}] Error: {}", index, e),
        },
        Err(e) => println!("[Connection {}] Error: {}", index, e),
    }
    println!("Closed connection: {}\n", index);
}

//todo: nullifier lists
//todo: verify all signatures
//todo: basically a full verify transaction
fn main() {
    println!("Launching...\n");
    constants::initialise_jubjub_constants();
    initialize(&constants::CRED_PVK);
    initialize(&constants::C_TO_PARAMS);
    initialize(&constants::C_FROM_PVK);
    initialize(&constants::TRANSFER_PVK);
    initialize(&constants::SAVER_KEYS);
    let data;
    let blockchain = Arc::new(RwLock::new(match File::open("server.blockchain") {
        Ok(file) => {
            let mut data_file =
                BufReader::new(File::open("server.data").expect("Cannot open file."));
            let mut private_key_input = [0; 32];
            let mut address_private_key = [0; 32];
            let mut address_public_key = [0; 32];
            data_file
                .read_exact(&mut address_private_key)
                .expect("Cannot read from file.");
            data_file
                .read_exact(&mut address_public_key)
                .expect("Cannot read from file.");
            data_file
                .read_exact(&mut private_key_input)
                .expect("Cannot read from file.");
            let mut vec_len = [0; 8];
            data_file
                .read_exact(&mut vec_len)
                .expect("Cannot read from file.");
            let mut signature_document = vec![0; u8_array_to_u64(&vec_len) as usize];
            data_file
                .read_exact(&mut signature_document)
                .expect("Cannot read from file.");
            let rng = FixedSliceRandom {
                bytes: &private_key_input,
            };
            let (private_key, public_key) =
                generate_keypair(&rng).expect("Keypair generation should not fail.");
            let signature_keypair = Ed25519KeyPair::from_pkcs8(signature_document.as_slice())
                .expect("Keypair generation should not fail.");
            data = Arc::new(ServerData {
                name: "server",
                address_private_key,
                address_public_key,
                private_key_input,
                private_key,
                public_key,
                signature_keypair,
            });
            BlockChain::read(BufReader::new(file)).expect("Loading the blockchain should succeed.")
        }
        Err(_) => {
            let mut file =
                BufWriter::new(File::create("server.data").expect("Cannot create file."));
            let mut rng = OsRng;
            let address_private_key: [u8; 32] = rng.gen();
            file.write_all(&address_private_key)
                .expect("Cannot write to file.");
            let address_public_key = Credentials::prf_addr(&address_private_key);
            file.write_all(&address_public_key)
                .expect("Cannot write to file.");
            let private_key_input: [u8; 32] = rng.gen();
            file.write_all(&private_key_input)
                .expect("Cannot write to file.");
            let signature_document = signature::generate_keypair(&SystemRandom::new())
                .expect("Keypair generation should not fail.")
                .as_ref()
                .to_vec();
            file.write_all(&u64_array_to_u8_vector(&[signature_document.len() as u64]))
                .expect("Cannot write to file.");
            file.write_all(signature_document.as_slice())
                .expect("Cannot write to file.");
            file.flush().unwrap();
            let rng = FixedSliceRandom {
                bytes: &private_key_input,
            };
            let (private_key, public_key) =
                encryption::generate_keypair(&rng).expect("Keypair generation should not fail.");
            let signature_keypair = Ed25519KeyPair::from_pkcs8(signature_document.as_ref())
                .expect("Keypair generation should not fail.");
            data = Arc::new(ServerData {
                name: "server",
                address_private_key,
                address_public_key,
                private_key_input,
                private_key,
                public_key,
                signature_keypair,
            });
            BlockChain::new().expect("Creating an empty blockchain should succeed.")
        }
    }));

    println!("Server data:");
    println! {"{}", data};

    let input_thread;
    {
        let blockchain = blockchain.clone();
        let data = data.clone();
        input_thread = thread::spawn(move || handle_input(blockchain, data));
    }
    let socket_thread = thread::spawn(move || {
        match TcpListener::bind(format!("{}:{}", constants::HOST, constants::PORT)) {
            Ok(listener) => {
                let mut index = 0;
                println!(
                    "Server listening on {}:{}",
                    constants::HOST,
                    constants::PORT
                );
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            index += 1;
                            let blockchain = blockchain.clone();
                            let data = data.clone();
                            println!("New connection: {}", index);
                            thread::spawn(move || {
                                handle_client(stream, index, blockchain, data);
                            });
                        }
                        Err(e) => {
                            println!("Error: {}", e);
                        }
                    }
                }
            }
            Err(e) => println!("Error: {}", e),
        };
    });
    input_thread.join().unwrap();
    drop(socket_thread)
}
