use std::fs::File;
use std::io::{BufReader, Write};

use lazy_static::initialize;
use rand::rngs::OsRng;
use rand::Rng;
use ring::test::rand::FixedSliceRandom;

use demo::blockchain::BlockChain;
use demo::constants;
use demo::user_input::{send_c_to, send_cred, send_transfer, update, UserData};
use primitives::encryption::generate_keypair;

/// Handle the commands that the user having `data` writes on stdin.
fn get_input(data: &mut UserData) -> std::io::Result<bool> {
    println!("Available commands:");
    println!("   update:     Update local blockchain.");
    println!("   show:       Show the local blockchain.");
    println!("   deposit:    Deposit € into this anonymous account.");
    println!("   withdraw:   Withdraw € from this anonymous account.");
    println!("   transfer:   Make a transfer to another anonymous account.");
    println!("   quit:       Quit program.\n");
    print!("What do you want to do:   ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    match input.to_ascii_lowercase().trim() {
        "update" | "u" => {
            update(data)?;
            Ok(true)
        }
        "show" | "s" => {
            println!("{}", data.blockchain);
            Ok(true)
        }
        "deposit" | "d" => {
            match send_c_to(data)? {
                true => println!("Deposit successful!\n"),
                false => println!("Deposit failed.\n"),
            }
            Ok(true)
        }
        "withdraw" | "w" => {
            match send_transfer(data, true)? {
                true => println!("Withdrawal successful!\n"),
                false => println!("Withdrawal failed.\n"),
            }
            Ok(true)
        }
        "transfer" | "t" => {
            match send_transfer(data, false)? {
                true => println!("Transfer successful!\n"),
                false => println!("Transfer failed.\n"),
            }
            Ok(true)
        }
        "quit" | "q" | "exit" | "e" => {
            data.blockchain.write(data.name)?;
            data.write()?;
            Ok(false)
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Unknown command.",
        )),
    }
}

/// Load the data of the user with the input `name`.
fn get_data(name: &str) -> std::io::Result<Option<UserData>> {
    let data_file = File::open(format!("{}.data", name));
    let mut data = None;
    match data_file {
        Ok(file) => {
            let file = BufReader::new(file);
            println!("Loading credentials...\n");
            data = Some(UserData::read(file, name)?)
        }
        Err(_) => loop {
            print!("Do you want to request an anonymous account? [Y/n]   ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            match input.to_ascii_lowercase().trim() {
                "n" | "no" => break,
                "" | "y" | "yes" => {
                    println!("Creating new credentials...");
                    match send_cred()? {
                        Some(cred) => {
                            println!("Account creation successful!\n");
                            let private_key_input: [u8; 32] = OsRng.gen();
                            let rng = FixedSliceRandom {
                                bytes: &private_key_input,
                            };
                            let (private_key, public_key) = generate_keypair(&rng)
                                .expect("Keypair generation should not fail.");
                            let blockchain = match BlockChain::new() {
                                Ok(chain) => chain,
                                Err(_) => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        "Could not construct new blockchain.",
                                    ));
                                }
                            };
                            data = Some(UserData {
                                name,
                                cred,
                                private_key_input,
                                private_key,
                                public_key,
                                blockchain,
                                cred_witness: None,
                                notes: vec![],
                                note_witnesses: vec![],
                                memory: None,
                                memory_witness: None,
                                ceil_memories: vec![],
                                ceil_memory_witnesses: vec![],
                            });
                            break;
                        }
                        None => println!("Account creation failed.\n"),
                    }
                }
                _ => println!("Error: Unknown command.\n"),
            }
        },
    };
    if let Some(data) = &data {
        println!("Your data:");
        println!("{}", data);
    }

    Ok(data)
}

fn main() {
    println!("Launching...");
    constants::initialise_jubjub_constants();
    initialize(&constants::CRED_PARAMS);
    initialize(&constants::C_TO_PVK);
    initialize(&constants::C_FROM_PARAMS);
    initialize(&constants::TRANSFER_PARAMS);
    initialize(&constants::SAVER_KEYS);
    print!("Hello! What's your name?   ");
    match std::io::stdout().flush() {
        Ok(_) => {
            let mut name = String::new();
            match std::io::stdin().read_line(&mut name) {
                Ok(_) => {
                    name.make_ascii_lowercase();
                    let name = name.trim();
                    println!("Hello, {}!\n", name);
                    match get_data(name) {
                        Ok(Some(mut data)) => loop {
                            match get_input(&mut data) {
                                Ok(true) => {}
                                Ok(false) => {
                                    println!("Bye, {}!", name);
                                    break;
                                }
                                Err(e) => println!("Error: {}\n", e),
                            }
                        },
                        Ok(None) => println!("Bye, {}!", name),
                        Err(e) => println!("Error: {}", e),
                    }
                }
                Err(e) => println!("Error: {}", e),
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}
