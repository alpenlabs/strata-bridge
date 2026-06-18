use anyhow::Result;
use tracing::info;

use super::wallet;
use crate::cli::GenerateAddressArgs;

pub(crate) fn handle_addr(args: GenerateAddressArgs) -> Result<()> {
    info!(
        command = "addr",
        key_file = %args.private_key_file.display(),
        network = %args.network,
        "deriving P2TR address from WIF private key"
    );

    let private_key = wallet::read_private_key_file(&args.private_key_file, args.network)?;
    let address = wallet::p2tr_address_from_private_key(&private_key, args.network);

    info!(
        command = "addr",
        %address,
        network = %args.network,
        "derived P2TR address"
    );
    println!("{address}");

    Ok(())
}
