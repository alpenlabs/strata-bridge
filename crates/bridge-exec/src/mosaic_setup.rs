//! Checks that this node can answer every watchtower's counterproof before it risks funds.

use std::collections::BTreeSet;

use strata_bridge_primitives::types::OperatorIdx;
use strata_mosaic_client_api::{MosaicClientApi, types::Role};

use crate::errors::ExecutorError;

/// Fails unless this node's evaluator setup with each of `watchtowers` has completed.
///
/// A claimant answers a watchtower's counterproof through that setup. A setup that a contest has
/// since consumed also passes: the watchtower cannot post another counterproof with it.
pub(crate) async fn ensure_evaluator_setups(
    mosaic_client: &dyn MosaicClientApi,
    watchtowers: &BTreeSet<OperatorIdx>,
) -> Result<(), ExecutorError> {
    for &watchtower in watchtowers {
        let complete = mosaic_client
            .is_setup_complete(watchtower, Role::Evaluator)
            .await
            .map_err(|e| ExecutorError::MosaicErr(format!("is_setup_complete: {e:?}")))?;
        if !complete {
            return Err(ExecutorError::MosaicErr(format!(
                "evaluator setup with watchtower {watchtower} is incomplete"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use strata_bridge_primitives::{subscription::Subscription, types::GameIndex};
    use strata_mosaic_client_api::{MosaicError, MosaicEvent, MosaicSetupError, types::*};

    use super::*;

    /// Reports evaluator setup completion per watchtower; any other call is a test failure.
    struct SetupCompletion(HashMap<OperatorIdx, Result<bool, ()>>);

    #[async_trait]
    impl MosaicClientApi for SetupCompletion {
        async fn ensure_mosaic_setup(
            &self,
            _operator_idx: OperatorIdx,
            _role: Role,
        ) -> Result<(), MosaicSetupError> {
            unimplemented!("not used by the setup check")
        }

        async fn get_fault_pubkey(
            &self,
            _operator_idx: OperatorIdx,
            _role: Role,
        ) -> Result<Option<PubKey>, MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn get_adaptor_pubkey(
            &self,
            _operator_idx: OperatorIdx,
            _game_index: GameIndex,
        ) -> Result<Option<PubKey>, MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn init_evaluator_deposit(
            &self,
            _operator_idx: OperatorIdx,
            _game_index: GameIndex,
            _sighashes: DepositSighashes,
        ) -> Result<(), MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn init_garbler_deposit(
            &self,
            _operator_idx: OperatorIdx,
            _game_index: GameIndex,
            _sighashes: DepositSighashes,
            _adaptor_pubkey: PubKey,
        ) -> Result<(), MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn mark_deposit_withdrawn(
            &self,
            _operator_idx: OperatorIdx,
            _role: Role,
            _game_index: GameIndex,
        ) -> Result<(), MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn is_setup_available(
            &self,
            _operator_idx: OperatorIdx,
            _role: Role,
            _game_index: GameIndex,
        ) -> Result<bool, MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn is_setup_complete(
            &self,
            operator_idx: OperatorIdx,
            role: Role,
        ) -> Result<bool, MosaicError> {
            assert_eq!(
                role,
                Role::Evaluator,
                "the claimant's own setups are evaluator setups"
            );
            self.0
                .get(&operator_idx)
                .expect("only watchtowers are queried")
                .map_err(|()| MosaicError::SetupMissing(operator_idx, role))
        }

        async fn complete_adaptor_sigs(
            &self,
            _operator_idx: OperatorIdx,
            _game_index: GameIndex,
            _counterproof: G16ProofRaw,
        ) -> Result<CompletedSignatures, MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn get_completed_adaptor_sigs(
            &self,
            _operator_idx: OperatorIdx,
            _game_index: GameIndex,
        ) -> Result<Option<CompletedSignatures>, MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn evaluate_and_sign(
            &self,
            _operator_idx: OperatorIdx,
            _game_index: GameIndex,
            _completed_signatures: CompletedSignatures,
            _sighash: Sighash,
            _tweak: Option<Tweak>,
        ) -> Result<Option<Signature>, MosaicError> {
            unimplemented!("not used by the setup check")
        }

        async fn subscribe_events(&self) -> Subscription<MosaicEvent> {
            unimplemented!("not used by the setup check")
        }
    }

    async fn check(completion: &[(OperatorIdx, Result<bool, ()>)]) -> Result<(), ExecutorError> {
        let client = SetupCompletion(completion.iter().copied().collect());
        let watchtowers = completion.iter().map(|(idx, _)| *idx).collect();
        ensure_evaluator_setups(&client, &watchtowers).await
    }

    #[tokio::test]
    async fn passes_when_every_watchtower_setup_is_complete() {
        assert!(
            check(&[(1, Ok(true)), (2, Ok(true))]).await.is_ok(),
            "completed setups with every watchtower must let the operator proceed"
        );
        assert!(
            check(&[]).await.is_ok(),
            "an operator without watchtowers has no counterproof to answer"
        );
    }

    #[tokio::test]
    async fn fails_when_any_watchtower_setup_is_incomplete() {
        let err = check(&[(1, Ok(true)), (2, Ok(false))])
            .await
            .expect_err("an incomplete setup must stop the operator");
        assert!(
            err.to_string().contains("watchtower 2"),
            "the error must name the watchtower whose setup is incomplete: {err}"
        );
    }

    #[tokio::test]
    async fn fails_when_setup_status_cannot_be_read() {
        assert!(
            matches!(
                check(&[(1, Err(()))]).await,
                Err(ExecutorError::MosaicErr(_))
            ),
            "an unreadable setup status must stop the operator"
        );
    }
}
