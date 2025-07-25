//! This module contains utility to load or create verifier scripts for the groth16 verifier
//! program.
use std::{fs, sync::LazyLock, time};

use ark_serialize::CanonicalSerialize;
use bitcoin::{hex::DisplayHex, ScriptBuf};
use bitvm::chunk::api::{api_generate_partial_script, NUM_TAPS};
use strata_bridge_proof_snark::bridge_vk::{self, fetch_groth16_vk};
use tracing::{info, warn};

const VK_PATH: &str = "strata-bridge-groth16-vk.hex";
const PARTIAL_VERIFIER_SCRIPTS_PATH: &str = "strata-bridge-vk.scripts";

/// The verifier scripts for the groth16 verifier program.
pub static PARTIAL_VERIFIER_SCRIPTS: LazyLock<[ScriptBuf; NUM_TAPS]> =
    LazyLock::new(load_or_create_verifier_scripts);

/// Loads tapscripts for the groth16 verifier program.
///
/// NOTE: these scripts must be regenerated whenever the following change:
///
/// * The verification key for the groth16 verifier program.
/// * The number and nature of tapscripts generated by bitvm.
/// * The structure of the verifier program (i.e., the proof statements/guest build).
pub fn load_or_create_verifier_scripts() -> [ScriptBuf; NUM_TAPS] {
    if std::env::var("ZKVM_MOCK")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        warn!("Detected mock feature, returning empty verifier scripts");

        return vec![ScriptBuf::new(); NUM_TAPS]
            .try_into()
            .expect("there must be NUM_TAPS scripts");
    }

    if fs::exists(PARTIAL_VERIFIER_SCRIPTS_PATH)
        .expect("should be able to check for existence of verifier scripts file")
    {
        warn!(
            action = "loading verifier script from file cache...this will take some time",
            estimated_time = "1 min"
        );

        let loading_time = time::Instant::now();

        let contents: Vec<u8> = fs::read(PARTIAL_VERIFIER_SCRIPTS_PATH)
            .expect("should be able to read verifier scripts from file");
        let deserialized: Vec<Vec<u8>> = bincode::deserialize(&contents)
            .expect("should be able to deserialize verifier scripts from file");

        let verifier_scripts = deserialized
            .iter()
            .map(|de| ScriptBuf::from_bytes(de.to_vec()))
            .collect::<Vec<ScriptBuf>>();

        let num_scripts = verifier_scripts.len();
        warn!(event = "loaded verifier scripts", %num_scripts, time_taken = ?loading_time.elapsed());

        verifier_scripts.try_into().unwrap_or_else(|_| {
            panic!("number of scripts should be: {NUM_TAPS} not {num_scripts}",)
        })
    } else {
        warn!(
            action = "compiling verifier scripts, this will take time...",
            estimated_time = "3 mins"
        );

        let compilation_start_time = time::Instant::now();

        info!(vk_path=%VK_PATH, "trying to fetch verification key from file");
        let bridge_g16_vk = fetch_groth16_vk(VK_PATH).unwrap_or_else(|| {
            warn!(vk_path=%VK_PATH, "could not find verification key, generating a new one");
            let vk = bridge_vk::GROTH16_VERIFICATION_KEY.clone();

            info!(vk_path=%VK_PATH, "dumping verification key to file");

            let mut vk_serialized = Vec::new();
            vk.serialize_compressed(&mut vk_serialized)
                .expect("should be able to serialize verification key");

            let vk_hex = vk_serialized.to_lower_hex_string();

            fs::write(VK_PATH, vk_hex).expect("should be able to write verification key to file");
            vk
        });

        let verifier_scripts = api_generate_partial_script(&bridge_g16_vk);

        warn!(action = "caching verifier scripts for later", cache_file=%PARTIAL_VERIFIER_SCRIPTS_PATH);
        let serialized: Vec<Vec<u8>> = verifier_scripts
            .clone()
            .into_iter()
            .map(|s| s.to_bytes())
            .collect();

        let serialized: Vec<u8> =
            bincode::serialize(&serialized).expect("should be able to serialize verifier scripts");

        fs::write(PARTIAL_VERIFIER_SCRIPTS_PATH, serialized)
            .expect("should be able to write verifier scripts to file");

        warn!(action = "finished compiling verifier scripts", time_taken = ?compilation_start_time.elapsed());

        verifier_scripts
    }
}

/// Get the verifier scripts for the groth16 verifier program.
///
/// This returns a memoized version of the verifier scripts.
pub fn get_verifier_scripts() -> &'static [ScriptBuf; NUM_TAPS] {
    &PARTIAL_VERIFIER_SCRIPTS
}
