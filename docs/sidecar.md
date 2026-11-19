# Sidecar

A bridge operator can attach a **sidecar**: a separate service that decides whether this node may take two of its own actions. The bridge defines the question, holds the action until the answer arrives, and enforces it. What the sidecar decides, and how, is up to the operator who runs it.

The sidecar is off by default. A node without a `[sidecar]` section behaves exactly as before.

## The two actions

| Action | Asked when | If the sidecar declines |
|---|---|---|
| **Take part in a deposit request** | The node registers a new deposit request, before it builds graphs or signs | This node never signs. A deposit needs every operator, so it does not complete, and the depositor takes the request back after the recovery delay. The deposit index stays allocated, so indices stay aligned across operators. |
| **Pay a withdrawal assigned to this node** | Before the payment duty is dispatched to the executor | This node does not pay. ASM reassigns the withdrawal after its deadline, and another operator pays it. |

A decision controls only this node's own action. The node keeps processing every block, assignment and peer message, and every defensive duty keeps running. A decision never revokes a transaction already signed or published.

## The rules

- **Silence is never a decision.** The node acts only on a `proceed` or `decline` that answers the exact request and is still fresh. No answer, an error, a malformed or stale answer, and `defer` all leave the action waiting, and the node asks again.
- **`defer` is not an error.** A sidecar that cannot decide yet (a lookup is slow, data has not arrived, a manual review is queued) answers `defer`.
- **A deposit decision is final.** Once applied, it is stored with the deposit. A later answer changes nothing.
- **A withdrawal approval is checked at dispatch.** Every attempt to pay is a new dispatch and needs an approval at that moment. The executor does not ask again while it pays: an approval is at most one payment attempt old when the node signs.

## Deposit requests, end to end

1. A buried block carries a deposit request. The node registers it and allocates its deposit index exactly as without a sidecar.
2. With a sidecar attached, the deposit enters `ParticipationPending`. It keeps the unsigned deposit transaction and the stake bindings of that block, so a late approval cannot bind it to a newer covenant or stake.
3. While pending, the deposit still processes new blocks, a takeback by the depositor and a safe-harbour abort. Peer messages for it are rejected and recovered through nags once the node takes part.
4. After every committed batch, the pipeline asks the sidecar about each pending deposit. The first ask starts a call in the background.
5. When the answer arrives, the client wakes the pipeline (`SidecarHookDecision`), which asks again and applies it:
   - `proceed`: the deposit returns to `Created` and its graphs are registered, in one causal group persisted before any duty runs;
   - `decline`: the deposit becomes the terminal `ParticipationDeclined`.

A pending deposit counts against `max_active_deposits`. Nothing is asked while safe harbour is active: the safe-harbour scan aborts pending deposits.

## Withdrawals, end to end

1. ASM assigns a withdrawal to this node. The deposit state machine emits the payment duty (`FulfillWithdrawalRequest`) whenever ASM re-delivers the assignment (in practice every buried block) and on every retry tick.
2. Before dispatch, the pipeline checks that the duty still matches the deposit's assignment (this node, the same deadline and destination). A duty that does not match is dropped, never paid.
3. If the sidecar approves the exact request, the duty is dispatched. Otherwise it is held in memory and dispatched once the sidecar approves it.
4. **A payment this node already funded is not held.** The executor records its funding inputs before it signs. When such a record exists, the duty passes without asking, so the executor can resume fee bumps for a payment that is already public, for example after a restart.
5. Under safe harbour nothing is asked or held; the dispatcher suppresses withdrawal duties as before.

## The wire

One JSON-RPC 2.0 method, `sidecar_assess`, over HTTP(S). The types live in `crates/sidecar-api`; both sides use them.

Request:

```json
{ "version": 1,
  "action": { "kind": "deposit_request",
              "drt_txid": "<hex>", "drt_vout": 0, "amount_sats": 200000000 } }
```

```json
{ "version": 1,
  "action": { "kind": "withdrawal_request",
              "deposit_idx": 7, "assignee": 1, "deadline": 900530,
              "amount_sats": 200000000, "operator_fee_sats": 300000,
              "destination": "<hex BOSD descriptor>" } }
```

Answer:

```json
{ "request_id": "<hex>", "decision": "proceed", "reason": "clean",
  "assessed_at_ms": 1763370000000, "expires_at_ms": 1763370060000 }
```

- `request_id` is the blake3 hash of the request's JSON, computed with `crates/sidecar-api`. Any changed field is a new request.
- An answer counts only if its `request_id` matches, it was not given in the future, it has not expired, and it lives no longer than 300 s.
- Both sides reject unknown fields. Adding or renaming a field is a protocol change: bump `version` and upgrade both sides together.
- Network, which policy the sidecar applies, and how the two are paired are deployment settings, not on the wire.

## Timing

Decisions are event-driven. A decision wakes the pipeline at once, and again once it has expired and the 2 s retry interval has passed, so an action it leaves waiting (a declined withdrawal) is asked about again. A failed call, or a `defer`, schedules its own wake-up 2 s later. The same request is never asked more than once per retry interval. Calls run in the order they were asked, eight at a time. The periodic retry tick also asks, as a fallback, but nothing depends on it.

Answers live in memory only and count for at most 300 s. After a restart every pending action is asked again.

## Configuration

```toml
[sidecar]
kind = "enabled"
endpoint = "https://sidecar.internal:8099"
token_env = "BRIDGE_SIDECAR_TOKEN"
# request_timeout = { secs = 5, nanos = 0 }   # optional, default 5 s
```

- `endpoint`: plain HTTP is accepted only on a loopback address; a remote sidecar needs HTTPS. The URL must carry no credentials, query or fragment.
- `token_env`: the environment variable holding the bearer token sent with every call. No secret goes in the TOML file. Required, except on a node running with `dev = true` off mainnet.
- `request_timeout`: whole-call timeout, between 1 ms and 300 s.

The retry interval (2 s), the longest answer lifetime (300 s) and the number of concurrent calls (8) are fixed in the client; they follow from the node's own load and are not tuning knobs.

## Failure behaviour

- **The sidecar is down or slow.** Actions wait. Observation and defensive duties continue. A stalled call is cut off at `request_timeout`. Each failure is logged by class (`timeout`, `connect`, `http_status=N`, `rpc_error=CODE "message"`, `decode`, `stale_or_unbound`, `panicked`, `other`), never with the raw error.
- **The section is removed.** A deposit already in `ParticipationPending` stays pending; removing configuration does not admit it. It ends when the depositor takes the request back.
- **A deposit registered before the sidecar was attached** is not held.

## Who owns what

- `crates/sidecar-api`: the wire types, the request ID, the freshness rule and the JSON-RPC method.
- `crates/sidecar-client`: the HTTP client, the in-memory answers, the background worker and wake-ups, and `SidecarHook` for `SidecarClient`.
- `crates/bridge-sm`: the `ParticipationPending` and `ParticipationDeclined` deposit states. No sidecar dependency.
- `crates/orchestrator`: the `SidecarHook` trait, the `SidecarHookDecision` event, applying deposit decisions, and holding withdrawal duties. No sidecar dependency.
- `bin/strata-bridge`: the `[sidecar]` configuration and its wiring.
- `crates/bridge-exec`: unchanged.

## Writing a sidecar

Depend on `strata-bridge-sidecar-api` and implement `SidecarRpcServer` (always generated; the bridge enables the `client` feature). Answer `defer` when you cannot decide yet. Refuse a request whose `version` you do not know.

## Tests

```sh
cargo test -p strata-bridge-sidecar-api --all-features
cargo nextest run -p strata-bridge-sidecar-client
cargo test -p strata-bridge-sm --lib
cargo nextest run -p strata-bridge-orchestrator -E 'test(/sidecar_hook|participation|withdrawal_funding/)'
```

The orchestrator tests need a FoundationDB cluster.
