use bitcoin::Txid;

use crate::contract_state_machine::{ContractCfg, MachineState};

struct PersistErr;
struct ContractPersister {}
impl ContractPersister {
    fn new() -> Self {
        ContractPersister {}
    }
    async fn init(&self, cfg: &ContractCfg, state: &MachineState) -> Result<(), PersistErr> {
        Err(PersistErr)
    }
    async fn commit(&self, state: &MachineState) -> Result<(), PersistErr> {
        Err(PersistErr)
    }
    async fn load(&self, deposit_txid: Txid) -> Result<(ContractCfg, MachineState), PersistErr> {
        Err(PersistErr)
    }
}
