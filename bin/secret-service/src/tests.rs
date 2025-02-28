use std::{
    cell::RefCell,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Deref,
    sync::Arc,
    time::Duration,
};

use bitcoin::{
    hashes::Hash,
    key::{Parity, Secp256k1},
    Network, Txid, XOnlyPublicKey,
};
use musig2::{
    secp256k1::{Message, SecretKey, SECP256K1},
    FirstRound, KeyAggContext, PartialSignature, SecNonceSpices,
};
use rand::{thread_rng, Rng};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v1::traits::*;
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

#[tokio::test]
async fn e2e() {
    let server_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 20_000).into();
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

    // operator signer
    let op_signer = client.operator_signer();
    let pubkey = op_signer.pubkey().await.expect("good response");

    let handles = (0..100)
        .map(|_| {
            let secp_ctx = Secp256k1::verification_only();
            let op_signer = op_signer.clone();
            tokio::spawn(async move {
                let to_sign = thread_rng().gen();
                let sig = op_signer.sign(&to_sign).await.expect("good response");
                assert!(secp_ctx
                    .verify_schnorr(&sig, &Message::from_digest(to_sign), &pubkey)
                    .is_ok());
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.await.unwrap();
    }

    // p2p signer
    let p2p_signer = client.p2p_signer();
    p2p_signer.secret_key().await.expect("good response");

    let txid = Txid::from_slice(&[0; 32]).unwrap();

    // Stakechain preimages
    let sc_preimg = client.stake_chain_preimages();
    sc_preimg
        .get_preimg(txid, 0, 0)
        .await
        .expect("good response");

    // WOTS
    let wots = client.wots_signer();
    wots.get_160_key(txid, 0, 0).await.expect("good response");
    wots.get_256_key(txid, 0, 0).await.expect("good response");

    // Musig2
    let ms2_signer = client.musig2_signer();

    let local_signers = (0..2)
        .map(|_| {
            EvenSecretKey::from(SecretKey::new(&mut thread_rng()))
                .deref()
                .keypair(SECP256K1)
        })
        .collect::<Vec<_>>();
    let witness = TaprootWitness::Key;
    let mut pubkeys = local_signers
        .iter()
        .map(|kp| kp.x_only_public_key().0)
        .collect::<Vec<_>>();
    let remote_public_key = ms2_signer.pubkey().await.expect("good response");
    pubkeys.push(remote_public_key);
    pubkeys.sort();
    let mut remote_first_round = ms2_signer
        .new_session(pubkeys.clone(), witness.clone(), txid, 0)
        .await
        .expect("good response")
        .expect("valid keys");
    println!("remote pubkey: {remote_public_key:?}");

    let mut ctx = KeyAggContext::new(pubkeys.iter().map(|pk| pk.public_key(Parity::Even))).unwrap();
    match witness {
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
            let signer_index = pubkeys.binary_search(&kp.x_only_public_key().0).unwrap();
            println!("local signer {i} has signer idx {signer_index}");
            let spices = SecNonceSpices::new().with_seckey(kp.secret_key());
            println!("local signer {i} has seckey {:?}", kp.secret_key());
            FirstRound::new(ctx.clone(), &mut thread_rng(), signer_index, spices)
                .unwrap()
                .into()
        })
        .collect::<Vec<RefCell<_>>>();

    let remote_pub_nonce = remote_first_round.our_nonce().await.expect("good response");
    let remote_signer_index = pubkeys.binary_search(&remote_public_key).unwrap();
    let total_local_signers = local_first_rounds.len();
    for i in 0..total_local_signers {
        let local_fr = &local_first_rounds[i];
        let our_pub_nonce = local_fr.borrow().our_public_nonce();
        // send this signer's public nonce to secret service
        remote_first_round
            .receive_pub_nonce(local_signers[i].x_only_public_key().0, our_pub_nonce)
            .await
            .expect("good response")
            .expect("good nonce");
        // send secret service's pub nonce to this local signer
        local_fr
            .borrow_mut()
            .receive_nonce(remote_signer_index, remote_pub_nonce.clone())
            .expect("our nonce to be good");
        // receive the other local pubnonces
        for j in 0..total_local_signers {
            if i == j {
                continue;
            }
            println!("sharing pubnonce {j} -> {i}");
            let other = &local_first_rounds[j].borrow();
            local_fr
                .borrow_mut()
                .receive_nonce(
                    pubkeys
                        .binary_search(&local_signers[j].x_only_public_key().0)
                        .unwrap(),
                    other.our_public_nonce(),
                )
                .expect("other nonce to be good");
        }
    }
    assert!(remote_first_round
        .is_complete()
        .await
        .expect("good response"));
    let digest = thread_rng().gen();
    let mut remote_second_round = remote_first_round
        .finalize(digest)
        .await
        .expect("good response")
        .expect("good finalize");
    let remote_partial_sig = remote_second_round
        .our_signature()
        .await
        .expect("good response");
    println!("{remote_partial_sig:?}");
    assert_eq!(local_signers.len(), local_first_rounds.len());
    let local_second_rounds = local_first_rounds
        .into_iter()
        .enumerate()
        .map(|(i, fr)| {
            println!("i: {i}: {:?}", local_signers[i].secret_key());
            let fr = fr.into_inner();
            assert!(fr.is_complete());
            fr.finalize(local_signers[i].secret_key(), digest)
                .unwrap()
                .into()
        })
        .collect::<Vec<RefCell<_>>>();
    println!("pubkeys: {pubkeys:?}");
    for i in 0..total_local_signers {
        let sr = &local_second_rounds[i];
        let our_sig = sr.borrow().our_signature();
        // send secret service this signer's partial sig
        remote_second_round
            .receive_signature(local_signers[i].x_only_public_key().0, our_sig)
            .await
            .expect("good response")
            .expect("good sig");
        // give secret service's partial sig to this signer
        sr.borrow_mut()
            .receive_signature(remote_signer_index, remote_partial_sig)
            .expect("our partial sig to be good");
        // exchange partial sigs with the other local signers
        for j in 0..total_local_signers {
            if i == j {
                continue;
            }
            let other = &local_second_rounds[j].borrow();
            sr.borrow_mut()
                .receive_signature(
                    pubkeys
                        .binary_search(&local_signers[j].x_only_public_key().0)
                        .unwrap(),
                    other.our_signature::<PartialSignature>(),
                )
                .expect("other sig to be good");
        }
    }
    assert!(remote_second_round
        .is_complete()
        .await
        .expect("good response"));

    let sig = remote_second_round
        .finalize()
        .await
        .expect("good response")
        .expect("good sig");
    assert!(agg_pubkey
        .verify(SECP256K1, &Message::from_digest(digest), &sig.into())
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
