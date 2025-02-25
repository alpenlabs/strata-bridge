use std::{
    cell::RefCell,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use bitcoin::{
    hashes::Hash,
    key::{Keypair, Parity::Even, Secp256k1},
    Txid, XOnlyPublicKey,
};
use musig2::{secp256k1::Message, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
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
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

use crate::disk::Service;

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
    let service = Service::new_with_seed([0u8; 32]);

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

    let handles = (0..1000)
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

    let sc_preimg = client.stake_chain_preimages();
    sc_preimg
        .get_preimg(txid.clone(), 0, 0)
        .await
        .expect("good response");

    let wots = client.wots_signer();
    wots.get_160_key(txid.clone(), 0, 0)
        .await
        .expect("good response");
    wots.get_256_key(txid.clone(), 0, 0)
        .await
        .expect("good response");

    let ms2_signer = client.musig2_signer();

    let signers = (0..2)
        .map(|_| Keypair::new_global(&mut thread_rng()))
        .collect::<Vec<_>>();
    let mut our_first_round = ms2_signer
        .new_session(
            signers.iter().map(|kp| kp.x_only_public_key().0).collect(),
            TaprootWitness::Key,
            txid,
            0,
        )
        .await
        .expect("good response")
        .expect("valid keys");
    let our_public_key = ms2_signer.pubkey().await.expect("good response");
    let mut pubkeys = signers
        .iter()
        .map(|kp| kp.x_only_public_key().0)
        .collect::<Vec<_>>();
    pubkeys.push(our_public_key);
    pubkeys.sort();
    let ctx = KeyAggContext::new(pubkeys.iter().map(|pk| pk.public_key(Even))).unwrap();
    // let agg_pubkey: XOnlyPublicKey = ctx.aggregated_pubkey();

    let first_rounds = signers
        .iter()
        .map(|kp| {
            let signer_index = pubkeys.binary_search(&kp.x_only_public_key().0).unwrap();
            let spices = SecNonceSpices::new().with_seckey(kp.secret_key());
            FirstRound::new(ctx.clone(), &mut thread_rng(), signer_index, spices)
                .unwrap()
                .into()
        })
        .collect::<Vec<RefCell<_>>>();

    let our_pub_nonce = our_first_round.our_nonce().await.expect("good response");
    let our_signer_index = pubkeys.binary_search(&our_public_key).unwrap();
    let total_local_signers = first_rounds.len();
    for i in 0..total_local_signers {
        let mut fr = first_rounds[i].borrow_mut();
        our_first_round
            .receive_pub_nonce(signers[i].x_only_public_key().0, fr.our_public_nonce())
            .await
            .expect("good response")
            .expect("good nonce");
        fr.receive_nonce(our_signer_index, our_pub_nonce.clone())
            .expect("our nonce to be good");
        for j in 0..total_local_signers {
            if i == j || j == our_signer_index {
                continue;
            }
            let other = &first_rounds[j].borrow();
            fr.receive_nonce(
                pubkeys
                    .binary_search(&signers[j].x_only_public_key().0)
                    .unwrap(),
                other.our_public_nonce(),
            )
            .expect("other nonce to be good");
        }
    }
    assert!(our_first_round.is_complete().await.expect("good response"));
    let digest = thread_rng().gen();
    let mut our_second_round = our_first_round
        .finalize(digest)
        .await
        .expect("good response")
        .expect("good finalize");
    let our_partial_sig = our_second_round
        .our_signature()
        .await
        .expect("good response");
    let second_rounds = first_rounds
        .into_iter()
        .enumerate()
        .map(|(i, fr)| {
            fr.into_inner()
                .finalize(signers[i].secret_key(), digest)
                .unwrap()
                .into()
        })
        .collect::<Vec<RefCell<_>>>();

    for i in 0..total_local_signers {
        let mut sr = second_rounds[i].borrow_mut();
        // send secret service this signer's partial sig
        our_second_round
            .receive_signature(signers[i].x_only_public_key().0, sr.our_signature())
            .await
            .expect("good response")
            .expect("good sig");
        // give secret service's partial sig to this signer
        sr.receive_signature(our_signer_index, our_partial_sig.clone())
            .expect("our partial sig to be good");
        // exchange partial sigs with the other local signers
        for j in 0..total_local_signers {
            if i == j || j == our_signer_index {
                continue;
            }
            let other = &second_rounds[j].borrow();
            sr.receive_signature(
                pubkeys
                    .binary_search(&signers[j].x_only_public_key().0)
                    .unwrap(),
                other.our_signature::<PartialSignature>(),
            )
            .expect("other sig to be good");
        }
    }
    assert!(our_second_round.is_complete().await.expect("good response"));
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
