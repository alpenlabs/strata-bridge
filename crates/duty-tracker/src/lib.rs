use bitcoin::{
    opcodes::all::OP_RETURN, Amount, Network, Script, ScriptBuf, Transaction, XOnlyPublicKey,
};
use btc_notify::client::BtcZmqClient;
use futures::StreamExt;
use tokio::task::JoinHandle;

const DUST_VALUE: Amount = Amount::from_sat(330);

fn op_return_data(script: &Script) -> Option<&[u8]> {
    let mut instructions = script.instructions();
    if let Some(Ok(bitcoin::script::Instruction::Op(OP_RETURN))) = instructions.next() {
        // NOOP
    } else {
        return None;
    }

    if let Some(Ok(bitcoin::script::Instruction::PushBytes(bytes))) = instructions.next() {
        Some(bytes.as_bytes())
    } else {
        None
    }
}

fn magic_tagged_data(script: &Script) -> Option<&[u8]> {
    const MAGIC_BYTES: &[u8; 6] = b"strata";
    op_return_data(script).and_then(|data| {
        if data.starts_with(MAGIC_BYTES) {
            Some(&data[MAGIC_BYTES.len()..])
        } else {
            None
        }
    })
}

const EL_ADDR_SIZE: usize = 20;

fn is_deposit_request(tx: &Transaction) -> bool {
    const MERKLE_PROOF_SIZE: usize = 32;
    tx.output.iter().any(|output| {
        if let Some(meta) = magic_tagged_data(&output.script_pubkey) {
            meta.len() == MERKLE_PROOF_SIZE + EL_ADDR_SIZE
        } else {
            false
        }
    })
}

// Duties, like transactions are ultimately events. These events are generated in reaction to other
// events.

pub enum OperatorDuty {
    CollectSignatures,  // Originates when detecting a deposit request
    PublishDeposit,     // Originates when detecting deposit request
    PublishFulfillment, // Originates when strata state on L1 is published and assignment is self.
    AdvanceStakeChain,  // Originates when Fulfillment has been completed
    VerifyStake,        /* Originates when any of other operator's Claim,
                         * PreAssert, Assert, or Post-Assert are issued. */
    PublishClaim,            // Originates when Fulfillment confirms (is buried?)
    VerifyClaim,             // Originates when *other* operator Claim transaction is issued
    PublishChallenge,        // Originates when fraudulent Claim transaction is issued
    PublishPayoutOptimistic, // Originates after reaching timelock expiry for Claim transaction
    PublishPreAssert,        // Originates once challenge transaction is issued
    PublishAssertData,       // Originates once Pre-Assert confirms
    PublishPostAssert,       // Originates once *all* Assert Data transactions confirm
    PublishPayout,           // Originates after post-assert timelock expires
    PublishDisprove,         /* Originates after Post-Assert is issued if Disprove script is
                              * satisfiable */
}

fn create_duty(duty: OperatorDuty) {
    unimplemented!()
}

struct DutyTracker {
    btc_zmq_client: BtcZmqClient,
    deposit_request_monitor: JoinHandle<()>,
}
impl DutyTracker {
    async fn new(mut btc_zmq_client: BtcZmqClient) -> Self {
        let sub = btc_zmq_client
            .subscribe_transactions(is_deposit_request)
            .await;
        let deposit_request_monitor = tokio::task::spawn(async move {});
        DutyTracker {
            btc_zmq_client,
            deposit_request_monitor,
        }
    }
}

// Manifest
