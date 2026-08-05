# Legacy state machine encodings

`legacy_deposit_sm.postcard` and `legacy_graph_sm.postcard` are postcard encodings of a
`DepositSM` and a `GraphSM` produced by a binary built **before** per-SM params existed
(`f710eb40`, the commit STR-3745 branched from).

They exist so `legacy_sm_rows_still_decode` can prove that a deposit persisted by an older node
still decodes. A round-trip test through the current code cannot prove this — it would pass even
if the encoding had changed, because both sides would have changed together.

Adding a field to `DepositSM` or `GraphSM` will break this test. That is the point: doing so
breaks every deployment with in-flight deposits, since FoundationDB rows carry no version tag and
there is no migration path. If the encoding genuinely must change, the change needs a migration
story first — regenerating these files is not it.

## Regenerating

Only after an intentional, migrated encoding change. Check out the commit the new encoding was
introduced at, add a temporary test that writes the fixture below, and copy the output here.

```rust
let outpoint = OutPoint { txid: Txid::from_byte_array([0x11; 32]), vout: 7 };
let table = test_operator_table(5, TEST_POV_IDX);

let deposit = DepositSM {
    context: DepositSMCtx {
        deposit_idx: 42,
        deposit_request_outpoint: outpoint,
        deposit_outpoint: outpoint,
        operator_table: table.clone(),
    },
    state: DepositState::Deposited { last_block_height: 900_001 },
};
let graph = GraphSM {
    context: GraphSMCtx {
        graph_idx: GraphIdx { deposit: 42, operator: TEST_POV_IDX },
        deposit_outpoint: outpoint,
        stake_outpoint: OutPoint { txid: outpoint.txid, vout: 8 },
        unstaking_image: sha256::Hash::from_byte_array([0x22; 32]),
        operator_table: table,
    },
    state: GraphState::Created { last_block_height: 900_001 },
};
```
