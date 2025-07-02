use arbitrary::{Arbitrary, Unstructured};
use secp256k1::{Message, SecretKey, SECP256K1};
use strata_primitives::{
    batch::{Checkpoint, CheckpointSidecar, SignedCheckpoint},
    buf::{Buf32, Buf64},
};
use strata_state::chain_state::Chainstate;

pub(crate) fn create_checkpoint(chainstate: Chainstate) -> Checkpoint {
    let chainstate_ser = borsh::to_vec(&chainstate).unwrap();
    let mut raw = Unstructured::new(&[1, 2, 3, 4, 5, 6]);
    let batchinfo = Arbitrary::arbitrary(&mut raw).unwrap();
    let transition = Arbitrary::arbitrary(&mut raw).unwrap();
    let sidecar = CheckpointSidecar::new(chainstate_ser);
    let proof = vec![100];
    Checkpoint::new(batchinfo, transition, proof.as_slice().into(), sidecar)
}

pub(crate) fn sign_checkpoint(checkpoint: Checkpoint, secretkey: &Buf32) -> SignedCheckpoint {
    let message = checkpoint.hash();

    let sk = SecretKey::from_slice(secretkey.as_ref()).expect("Invalid private key");
    let kp = sk.keypair(SECP256K1);
    let msg = Message::from_digest_slice(message.as_ref()).expect("Invalid message hash");
    let sig = SECP256K1.sign_schnorr(&msg, &kp);
    let sig = Buf64::from(sig.serialize());
    SignedCheckpoint::new(checkpoint, sig)
}
