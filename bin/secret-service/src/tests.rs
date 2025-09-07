use std::{
    borrow::Borrow,
    cell::RefCell,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Deref,
    sync::Arc,
    time::Duration,
};

use bitcoin::{
    hashes::Hash,
    key::{Parity, Secp256k1, TapTweak},
    Network, OutPoint, Txid, XOnlyPublicKey,
};
use musig2::{
    secp256k1::{Message, SecretKey, SECP256K1},
    AggNonce, FirstRound, KeyAggContext, LiftedSignature, PartialSignature, SecNonceSpices,
};
use rand::{thread_rng, Rng};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::*;
use secret_service_server::{
    run_server,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        ClientConfig, ServerConfig,
    },
};
use strata_bridge_primitives::{scripts::taproot::TaprootWitness, secp::EvenSecretKey};

use crate::seeded_impl::Service;

async fn setup() -> SecretServiceClient {
    // Initialize default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    let port = thread_rng().gen_range(20_000..30_000);
    let server_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port).into();
    let server_host = "localhost".to_string();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = cert.cert.into();
    let server_tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("valid config");
    let config = secret_service_server::Config {
        addr: server_addr,
        tls_config: server_tls_config,
        connection_limit: None,
    };
    let service = Service::new_with_seed([0u8; 32], Network::Signet);

    tokio::spawn(async move {
        run_server(config, service.into()).await.unwrap();
    });

    let client_tls = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    let client_config = secret_service_client::Config {
        server_addr,
        server_hostname: server_host,
        local_addr: None,
        tls_config: client_tls,
        timeout: Duration::from_secs(1),
    };

    let client = SecretServiceClient::new(client_config)
        .await
        .expect("good conn");
    client
}

#[tokio::test]
async fn wots() {
    let client = setup().await;
    let wots = client.wots_signer();
    let txid = Txid::all_zeros();
    wots.get_128_secret_key(txid, 0, 0)
        .await
        .expect("good response");
    wots.get_128_public_key(txid, 0, 0)
        .await
        .expect("good response");
    wots.get_256_secret_key(txid, 0, 0)
        .await
        .expect("good response");
    wots.get_256_public_key(txid, 0, 0)
        .await
        .expect("good response");
}

#[tokio::test]
async fn p2p() {
    let client = setup().await;
    let p2p_signer = client.p2p_signer();
    p2p_signer.secret_key().await.expect("good response");
}

#[tokio::test]
async fn stakechain_preimg() {
    let client = setup().await;

    let sc_preimg = client.stake_chain_preimages();
    sc_preimg
        .get_preimg(Txid::all_zeros(), 0, 0)
        .await
        .expect("good response");
}

#[tokio::test]
async fn schnorr_signers() {
    let client = setup().await;

    let general_wallet_signer = client.general_wallet_signer();
    let stakechain_wallet_signer = client.stakechain_wallet_signer();
    let musig2_signer = client.musig2_signer();
    let general_pubkey = general_wallet_signer.pubkey().await.expect("good response");
    let (general_tweaked_pubkey, _) = general_pubkey.tap_tweak(SECP256K1, None);
    let stakechain_pubkey = stakechain_wallet_signer
        .pubkey()
        .await
        .expect("good response");
    let (stakechain_tweaked_pubkey, _) = stakechain_pubkey.tap_tweak(SECP256K1, None);
    let musig2_pubkey = musig2_signer.pubkey().await.expect("good response");
    let (musig2_tweaked_pubkey, _) = musig2_pubkey.tap_tweak(SECP256K1, None);

    let secp_ctx = Arc::new(Secp256k1::verification_only());
    let handles = (0..100)
        .map(|_| {
            let general_wallet_signer = general_wallet_signer.clone();
            let stakechain_wallet_signer = stakechain_wallet_signer.clone();
            let musig2_signer = musig2_signer.clone();
            let secp_ctx = secp_ctx.clone();
            tokio::spawn(async move {
                let to_sign = thread_rng().gen();
                let msg = Message::from_digest(to_sign);

                // sign general wallet
                let sig = general_wallet_signer
                    .sign(&to_sign, None)
                    .await
                    .expect("good response");
                assert!(secp_ctx
                    .verify_schnorr(&sig, &msg, &general_tweaked_pubkey.to_x_only_public_key())
                    .is_ok());

                // sign general wallet no tweak
                let sig = general_wallet_signer
                    .sign_no_tweak(&to_sign)
                    .await
                    .expect("good response");
                assert!(secp_ctx.verify_schnorr(&sig, &msg, &general_pubkey).is_ok());

                // sign stakechain wallet
                let sig = stakechain_wallet_signer
                    .sign(&to_sign, None)
                    .await
                    .expect("good response");
                assert!(secp_ctx
                    .verify_schnorr(
                        &sig,
                        &msg,
                        &stakechain_tweaked_pubkey.to_x_only_public_key()
                    )
                    .is_ok());

                // sign stakechain wallet no tweak
                let sig = stakechain_wallet_signer
                    .sign_no_tweak(&to_sign)
                    .await
                    .expect("good response");
                assert!(secp_ctx
                    .verify_schnorr(&sig, &msg, &stakechain_pubkey)
                    .is_ok());

                // sign musig2
                let sig = musig2_signer
                    .sign(&to_sign, None)
                    .await
                    .expect("good response");
                assert!(secp_ctx
                    .verify_schnorr(&sig, &msg, &musig2_tweaked_pubkey.to_x_only_public_key())
                    .is_ok());

                // sign musig2 no tweak
                let sig = musig2_signer
                    .sign_no_tweak(&to_sign)
                    .await
                    .expect("good response");
                assert!(secp_ctx.verify_schnorr(&sig, &msg, &musig2_pubkey).is_ok());
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn musig2() {
    let client = setup().await;

    const TOTAL_SIGNERS: usize = 3;
    const LOCAL_SIGNERS: usize = TOTAL_SIGNERS - 1;

    let ms2_signer = client.musig2_signer();

    let local_signers = (0..LOCAL_SIGNERS)
        .map(|_| {
            EvenSecretKey::from(SecretKey::new(&mut thread_rng()))
                .deref()
                .keypair(SECP256K1)
        })
        .collect::<Vec<_>>();
    let witness = TaprootWitness::Key;

    let remote_public_key = ms2_signer.pubkey().await.expect("good response");
    let params = Musig2Params {
        ordered_pubkeys: {
            let mut pubkeys = local_signers
                .iter()
                .map(|kp| kp.x_only_public_key().0)
                .collect::<Vec<_>>();
            pubkeys.push(remote_public_key);
            pubkeys.sort();
            pubkeys
        },
        witness,
        input: OutPoint::new(Txid::all_zeros(), 0),
    };

    println!("remote pubkey: {remote_public_key:?}");

    let mut ctx = KeyAggContext::new(
        params
            .ordered_pubkeys
            .iter()
            .map(|pk| pk.public_key(Parity::Even)),
    )
    .unwrap();
    match params.witness {
        TaprootWitness::Key => {
            ctx = ctx
                .with_unspendable_taproot_tweak()
                .expect("must be able to tweak the key agg context")
        }
        TaprootWitness::Tweaked { tweak } => {
            ctx = ctx
                .with_taproot_tweak(tweak.as_ref())
                .expect("must be able to tweak the key agg context")
        }
        _ => {}
    }
    let agg_pubkey: XOnlyPublicKey = ctx.aggregated_pubkey();

    let local_first_rounds = local_signers
        .iter()
        .enumerate()
        .map(|(i, kp)| {
            let signer_index = ctx
                .pubkey_index(kp.public_key())
                .expect("must be able to find the signer index");
            println!("local signer {i} has signer idx {signer_index}");
            let spices = SecNonceSpices::new().with_seckey(kp.secret_key());
            println!("local signer {i} has seckey {:?}", kp.secret_key());
            FirstRound::new(ctx.clone(), &mut thread_rng(), signer_index, spices)
                .unwrap()
                .into()
        })
        .collect::<Vec<RefCell<_>>>();

    let remote_pub_nonce = ms2_signer
        .get_pub_nonce(params.clone())
        .await
        .expect("good response")
        .expect("our pubkey is in params");
    let remote_signer_index = ctx
        .pubkey_index(remote_public_key.public_key(Parity::Even))
        .unwrap();

    let mut pubnonces = Vec::with_capacity(TOTAL_SIGNERS);

    #[allow(
        clippy::uninit_vec,
        reason = "each of 3 indices is manually set so none will be left uninitialized"
    )]
    unsafe {
        pubnonces.set_len(TOTAL_SIGNERS);
    }

    for (i, local_fr) in local_first_rounds.iter().enumerate() {
        let idx = ctx.pubkey_index(local_signers[i].public_key()).unwrap();
        pubnonces[idx] = local_fr.borrow().our_public_nonce();
    }
    pubnonces[ctx
        .pubkey_index(remote_public_key.borrow().public_key(Parity::Even))
        .unwrap()] = remote_pub_nonce.clone();

    let aggnonce = AggNonce::sum(&pubnonces);

    let digest_to_sign = thread_rng().gen();

    // send this signer's public nonce to secret service
    let remote_partial_sig = ms2_signer
        .get_our_partial_sig(params.clone(), aggnonce.clone(), digest_to_sign)
        .await
        .expect("good response")
        .expect("partial sig");

    for i in 0..LOCAL_SIGNERS {
        let local_fr = &local_first_rounds[i];
        // send secret service's pub nonce to this local signer
        local_fr
            .borrow_mut()
            .receive_nonce(remote_signer_index, remote_pub_nonce.clone())
            .expect("our nonce to be good");
        // receive the other local pubnonces
        for j in 0..LOCAL_SIGNERS {
            if i == j {
                continue;
            }
            println!("sharing pubnonce {j} -> {i}");
            let other = &local_first_rounds[j].borrow();
            let other_index = ctx
                .pubkey_index(local_signers[j].public_key())
                .expect("must be able to find the other index");
            local_fr
                .borrow_mut()
                .receive_nonce(other_index, other.our_public_nonce())
                .expect("other nonce to be good");
        }
    }

    println!("{remote_partial_sig:?}");
    assert_eq!(local_signers.len(), local_first_rounds.len());
    let local_second_rounds = local_first_rounds
        .into_iter()
        .enumerate()
        .map(|(i, fr)| {
            println!("i: {i}: {:?}", local_signers[i].secret_key());
            let fr = fr.into_inner();
            assert!(fr.is_complete());
            fr.finalize(local_signers[i].secret_key(), digest_to_sign)
                .unwrap()
                .into()
        })
        .collect::<Vec<RefCell<_>>>();
    println!("pubkeys: {:?}", ctx.pubkeys());

    let mut partial_sigs = Vec::with_capacity(TOTAL_SIGNERS);

    #[allow(
        clippy::uninit_vec,
        reason = "each of 3 indices is manually set so none will be left uninitialized"
    )]
    unsafe {
        partial_sigs.set_len(TOTAL_SIGNERS);
    }

    for (i, local_sr) in local_second_rounds.iter().enumerate() {
        let our_sig = local_sr.borrow().our_signature();
        partial_sigs[ctx
            .pubkey_index(
                local_signers[i]
                    .x_only_public_key()
                    .0
                    .public_key(Parity::Even),
            )
            .unwrap()] = our_sig;
    }
    partial_sigs[ctx
        .pubkey_index(remote_public_key.public_key(Parity::Even))
        .unwrap()] = remote_partial_sig;

    for i in 0..LOCAL_SIGNERS {
        let sr = &local_second_rounds[i];
        // give secret service's partial sig to this signer
        sr.borrow_mut()
            .receive_signature(remote_signer_index, remote_partial_sig)
            .expect("our partial sig to be good");
        // exchange partial sigs with the other local signers
        for j in 0..LOCAL_SIGNERS {
            if i == j {
                continue;
            }
            let other = &local_second_rounds[j].borrow();
            let other_index = ctx.pubkey_index(local_signers[j].public_key()).unwrap();
            sr.borrow_mut()
                .receive_signature(other_index, other.our_signature::<PartialSignature>())
                .expect("other sig to be good");
        }
    }

    let sig: LiftedSignature = local_second_rounds
        .into_iter()
        .next()
        .unwrap()
        .into_inner()
        .finalize()
        .unwrap();
    assert!(agg_pubkey
        .verify(
            SECP256K1,
            &Message::from_digest(digest_to_sign),
            &sig.into()
        )
        .is_ok());
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
