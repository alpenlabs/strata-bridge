use bitcoincore_rpc::{Auth, Client};

pub(crate) fn get_btc_client(
    url: &str,
    user: String,
    pass: String,
) -> Result<Client, anyhow::Error> {
    let btc_auth = Auth::UserPass(user, pass);
    let btc_client = Client::new(url, btc_auth)
        .map_err(|e| anyhow::anyhow!("Failed to create RPC client: {}", e))?;

    Ok(btc_client)
}
