# Transaction fees and fee bumping

This page describes how the bridge node prices and bumps its Bitcoin transactions. It is the entry point for the CPFP, fee source and wallet changes. Read it before the code.

## Glossary

- **Parent.** A transaction that the bridge publishes. It is a presigned graph transaction, or a transaction that the operator funds from its own wallet: fulfillment, stake funding, refill, burn, bridge proof.
- **Child.** A transaction that spends one output of a parent and pays a fee for both. The child confirms only with the parent, so a miner that takes the child takes the package.
- **Package.** The parent and its child, submitted together through `submitpackage`. The node judges the package fee rate, not the parent alone.
- **TRUC, v3.** BIP-431 topology rules. A v3 transaction has at most one unconfirmed parent and one unconfirmed child, and the child is at most 1,000 vB. Every bridge transaction is v3, so a package is one parent and one child (1P1C).
- **Anchor.** An output of a presigned parent that exists only for the child to spend. A *keyed anchor* is a bare Taproot key-path output at the operator's protocol key. A *multi-anchor* is a Taproot script tree with one leaf per operator, so each operator can bump the same parent.
- **Owned output.** A parent output that pays the operator's general wallet, for example the change of a funded transaction or a payout. The child spends it as a wallet input.
- **Lease.** An in-memory hold on wallet outpoints that a transaction in flight spends. A lease stops a second duty from selecting the same outpoint. A lease drops with its value, or stays committed until a sync shows a buried spend.
- **Bury depth.** The number of confirmations after which the protocol treats a transaction as final. Rows that store wallet inputs name only inputs buried that deep, and leases drop only once a spend is that deep.
- **Deadline class.** Whether a protocol timelock races the parent. Deadline parents bump first.
- **Package state.** Where the driver last saw a package: pending, in the mempool, mined, conflicted, or ended. See step 7.
- **Fee source.** Where the next-block fee estimate comes from. The options are Bitcoin Core `estimatesmartfee`, a mempool explorer with Core as the fallback, or a fixed rate for tests.

## One bump, end to end

1. A duty builds and signs a parent and calls `publish_signed_transaction` in `bridge-exec`. The call carries a `CpfpKind`. It says which output the child spends, how the parent's fee is known, and the deadline class.
2. The publish path resolves the parent fee: exact when the duty funded the parent itself, otherwise from the prevouts through the node (`txindex`). A failed read publishes without a CPFP path, and the next trigger of the duty reads again.
3. The driver in `btc-tracker` opens one package per transaction and sends the parent bare. A parent that the node rejects goes to the bumper at once, and so does a presigned parent. A parent that the duty priced at the market rate waits for the first block or tick. A child at the publish would pay the ladder's premium for nothing.
4. On each block and tick the driver bumps every pending or in-mempool package, deadline parents first, two at a time. An evicted parent goes back bare first. The attempt reads the mempool state of the parent and its child. It computes the target from the fee source with the operator's premium, floor and cap. It then decides: nothing, a new child, or a replacement child at a higher rate.
5. The wallet plans the child. The child spends the anchor or owned output, adds the smallest general-wallet input that pays the shortfall, and drains the rest to the wallet. The protocol key signs an anchor input. The general custody signs the wallet inputs.
6. The attempt submits `[parent, child]` through `submitpackage`. Acceptance, "parent already in mempool", and each rejection class map to a typed outcome. A rejection that no retry can fix ends the bumps for that parent.
7. Each package has a state machine. ZMQ events, a read on each block, ticks and the results of its sends and bumps drive it. A transition can send the parent, bump it, release the child's state with its lease, report a new status, or end the package. A mined package takes no bumps, and a reorg returns it to the earlier states. At burial the package ends and the caller that waited hears the result.
8. The driver gives up on a parent only when a conflicting transaction is buried. Until then every trigger retries.

## Who owns what

| Crate | Owns |
|---|---|
| `btc-tracker` | The driver: the package state machine and the tracker that alone changes it, the broadcaster, the bumper that owns each child's state and lease, and the `CpfpBumper` seam. No wallet dependency. |
| `bridge-exec/src/cpfp` | The bump attempt: the decision (`ladder`), the package submission wrapper, the adapters from wallet, signers and fee source to the seam, and the metrics. |
| `bridge-exec/src/fees.rs` | The fee sources, the shared quote memo with its TTL, and the pricing of transactions that duties fund. |
| `bridge-exec/src/chain.rs` | The publish path, `CpfpKind`, `ParentFee`, and the chain reads the duties share. |
| `operator-wallet` | The two watch-only wallets (general custody and reserved pool), the sync, the pure planner for funded transactions and children, and the lease set. |
| `primitives/src/cpfp.rs` | `ChildSpend`: which output a child spends and how it is signed. |

## Failure modes and what the node does

| Situation | Behaviour |
|---|---|
| The fee source is unreachable | The memo serves the last quote for 300 s and reads the source again every 25 s. Past 300 s a duty that funds a transaction refuses with `QuoteTooOld`, fails, and retries. A memo that no read has answered refuses with `NoQuote`. Only an answer with no estimate prices at the floor of 1 sat/vB. |
| The market is above `max_fee_rate` | A duty that funds a transaction refuses and retries later. The burn skips. A bump caps the target and the parent can wait below the market; this logs at warn and counts in metrics. |
| The parent fee cannot be read | The parent publishes without a CPFP path. The next trigger reads again. |
| The node rejects the package | The attempt reports the class. A fee or RBF rule rejection waits for the next trigger. A rejection that cannot change ends the bumps, and the parent continues as a bare transaction. |
| A bump sends no package (empty wallet, signer down) | The caller keeps waiting. After three such bumps in a row, the package bumps on blocks only, until a bump reaches the network. |
| A conflicting transaction confirms | The driver keeps the parent until the conflict is buried, then gives up and the duty hears `ConflictBuried`. |
| A reorg returns a spend to the mempool | The package is still there and the bumps continue. Leases hold through the reorg, because they drop only on a buried spend. |
| A reorg removes an input that a stored row names | It cannot, within the bury depth: rows name only buried inputs. Deeper reorgs are outside the model of this node and need an operator. |
| A restart while a funded parent is in the mempool | The retry of the duty finds the mempool spender of the stored inputs and drives it again, so the bump path returns. |
| A duty fails after it leased inputs | The lease drops with the value, after a sync, and the inputs return to the pool. A lease whose transaction reached the network commits and stays until the spend is buried. |

## Reading order

1. This page.
2. `operator-wallet`: `tracked.rs`, then `plan.rs` and `leases.rs`, then `wallet.rs`.
3. `bridge-exec/src/fees.rs`.
4. `btc-tracker/src/cpfp.rs`, then `tx_driver/`: `package.rs`, `tracker.rs`, `bumper.rs`.
5. `bridge-exec/src/cpfp/submitpackage.rs`, `ladder.rs`, `adapters.rs`.
6. `bridge-exec/src/chain.rs` and the publish calls in the duties.
7. `operator-wallet/src/general/fireblocks.rs` for the Fireblocks custody.
