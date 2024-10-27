use alloy::{
    primitives::U256,
    providers::{Provider, WalletProvider},
};
use argh::FromArgs;
use console::Term;

use crate::{
    constants::NETWORK,
    net_type::{net_type_or_exit, NetworkType},
    seed::Seed,
    settings::Settings,
    signet::{EsploraClient, SignetWallet},
    strata::StrataWallet,
};

/// Prints the wallet's current balance(s)
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "balance")]
pub struct BalanceArgs {
    /// either "signet" or "strata"
    #[argh(positional)]
    network_type: String,
}

pub async fn balance(args: BalanceArgs, seed: Seed, settings: Settings, esplora: EsploraClient) {
    let term = Term::stdout();
    let network_type = net_type_or_exit(&args.network_type, &term);

    if let NetworkType::Signet = network_type {
        let mut l1w = SignetWallet::new(&seed, NETWORK).unwrap();
        l1w.sync(&esplora).await.unwrap();
        let balance = l1w.balance();
        let _ = term.write_line(&format!("Total: {}", balance.total()));
        let _ = term.write_line(&format!("  Confirmed: {}", balance.confirmed));
        let _ = term.write_line(&format!("  Trusted pending: {}", balance.trusted_pending));
        let _ = term.write_line(&format!(
            "  Untrusted pending: {}",
            balance.untrusted_pending
        ));
        let _ = term.write_line(&format!("  Immature: {}", balance.immature));
    }

    if let NetworkType::Strata = network_type {
        let l2w = StrataWallet::new(&seed, &settings.l2_http_endpoint).unwrap();
        let _ = term.write_line("Getting balance...");
        let balance = l2w.get_balance(l2w.default_signer_address()).await.unwrap();
        // 1 BTC = 1 ETH
        let balance_in_btc = balance / U256::from(10u64.pow(18));
        let _ = term.write_line(&format!("\nTotal: {} BTC", balance_in_btc));
    }
}
