use anyhow::Result;
use tracing::info;

use super::wallet;
use crate::cli::GeneratePrivateKeyArgs;

pub(crate) fn handle_keygen(args: GeneratePrivateKeyArgs) -> Result<()> {
    info!(
        command = "keygen",
        output = %args.output.display(),
        network = %args.network,
        force = args.force,
        "generating WIF private key"
    );

    wallet::generate_private_key_file(&args.output, args.network, args.force)?;

    info!(
        command = "keygen",
        output = %args.output.display(),
        network = %args.network,
        "WIF private key written"
    );
    println!("wrote WIF private key to {}", args.output.display());

    Ok(())
}
