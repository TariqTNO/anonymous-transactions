use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::time::Instant;

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey};
use bls12_381::Bls12;
use lazy_static::lazy_static;

use primitives::saver::{prepare_verifying_key_saver, PreparedVerifyingKeySaver, SaverKeys};
use proofs::{convert_from, convert_to, credential, transfer};

// connection
pub const PORT: u16 = 3333;
pub const HOST: &str = "localhost";

// blockchain
pub const PERSONALISATION_BLOCK_HASH: &[u8; 8] = b"BLOCKHSH";

// proofs
lazy_static! {
    pub static ref CRED_PARAMS: Parameters<Bls12> = load_params("cred");
    pub static ref C_TO_PARAMS: Parameters<Bls12> = load_params("c_to");
    pub static ref C_FROM_PARAMS: Parameters<Bls12> = load_params("c_from");
    pub static ref TRANSFER_PARAMS: Parameters<Bls12> = load_params("transfer");
    pub static ref CRED_PVK: PreparedVerifyingKey<Bls12> = prepare_verifying_key(&CRED_PARAMS.vk);
    pub static ref C_TO_PVK: PreparedVerifyingKey<Bls12> = prepare_verifying_key(&C_TO_PARAMS.vk);
    pub static ref C_FROM_PVK: PreparedVerifyingKey<Bls12> =
        prepare_verifying_key(&C_FROM_PARAMS.vk);
    pub static ref TRANSFER_PVK: PreparedVerifyingKeySaver<Bls12> =
        prepare_verifying_key_saver(&TRANSFER_PARAMS.vk);
    pub static ref SAVER_KEYS: SaverKeys<Bls12> = load_saver_keys("transfer");
}

/// Initialise all static references for the Jubjub curve.
pub fn initialise_jubjub_constants() {
    primitives::constants::initialise_jubjub_constants();
    proofs::constants::initialise_jubjub_constants();
}

/// Function to load the saver keys of type `file_name` from the corresponding file. If the file
/// does not exist, the parameters are generated and written to a new file with name `file_name`.
fn load_saver_keys(file_name: &str) -> SaverKeys<Bls12> {
    let file = match File::open(format!("{}.saver", file_name)) {
        Ok(file) => file,
        Err(_) => {
            load_params(file_name);
            File::open(format!("{}.saver", file_name)).expect("The file should exist now.")
        }
    };
    SaverKeys::read(BufReader::new(file)).expect("Cannot read from file.")
}

/// Function to load the parameters of type `file_name` from the corresponding file. If the file
/// does not exist, the parameters are generated and written to a new file with name `file_name`.
fn load_params(file_name: &str) -> Parameters<Bls12> {
    match File::open(format!("{}.params", file_name)) {
        Ok(file) => Parameters::read(BufReader::new(file), false).expect("Cannot read from file."),
        Err(_) => {
            let params = match file_name {
                "cred" => {
                    let time_start = Instant::now();
                    let params = credential::generator::generate_random_parameters()
                        .expect("Parameter generation should not fail.");
                    let duration = time_start.elapsed();
                    println!(
                        "CREDENTIAL parameter generation took {} seconds",
                        duration.as_secs_f64()
                    );
                    params
                }
                "c_to" => {
                    let time_start = Instant::now();
                    let params = convert_to::generator::generate_random_parameters()
                        .expect("Parameter generation should not fail.");
                    let duration = time_start.elapsed();
                    println!(
                        "CONVERT_TO parameter generation took {} seconds",
                        duration.as_secs_f64()
                    );
                    params
                }
                "c_from" => {
                    let time_start = Instant::now();
                    let params = convert_from::generator::generate_random_parameters()
                        .expect("Parameter generation should not fail.");
                    let duration = time_start.elapsed();
                    println!(
                        "CONVERT_FROM parameter generation took {} seconds",
                        duration.as_secs_f64()
                    );
                    params
                }
                "transfer" => {
                    let time_start = Instant::now();
                    let (params, saver_keys) = transfer::generator::generate_random_parameters()
                        .expect("Parameter generation should not fail.");
                    let duration = time_start.elapsed();
                    println!(
                        "TRANSFER parameter generation (incl. SAVER) took {} seconds",
                        duration.as_secs_f64()
                    );
                    let mut file = BufWriter::new(
                        File::create(format!("{}.saver", file_name)).expect("Cannot create file."),
                    );
                    saver_keys
                        .write(file.by_ref())
                        .expect("Cannot write to file.");
                    file.flush().expect("Cannot flush buffer to file.");
                    params
                }
                _ => panic!("Unknown parameter type."),
            };
            let mut file = BufWriter::new(
                File::create(format!("{}.params", file_name)).expect("Cannot create file."),
            );
            params.write(file.by_ref()).expect("Cannot write to file.");
            file.flush().expect("Cannot flush buffer to file.");
            params
        }
    }
}
