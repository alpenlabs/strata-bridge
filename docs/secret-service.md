The Secret Service (S2) is a remote signer system used by bridge operators to
separate their secret cryptographic keys for funds and other uses from their
bridge node(s).

This enhances protections against attackers stealing funds or other important secret
data from an operator. Instead of just compromising a bridge node, an attacker must
break into secret service servers, which have much lower attack surfaces, can be
linked to HSMs or otherwise protected through separation from bridge nodes.

S2 is built and maintained by [Azz](https://github.com/zk2u). Contact me at azz@alpenlabs.io.

### Design

Secret Service is a client-server architecture, where the client is the operator's
bridge node and the server holds the secret keys (also referred to as _the secret
service_).

Communication between client and server happens over a custom QUIC-based
binary protocol. Mutual authentication is intended for production use, where the
client and server verify each other's identity to ensure connection security. S2 is
designed to work with multiple clients and multiple servers working simultaneously.
It is a stateless API with idempotent methods, so no state needs be shared among
servers when configured appropriately.

| Deployment | S2 version |
| ---------- | ---------- |
| Testnet 1  | 2          |

The implementation is broken into 3 libraries and 1 reference server implementation.
S2's reference code is in Rust. We take the approach of Bitcoin Core, where the
code serves as the canonical specification rather than a spec doc.

| Crate                   | Purpose                                                                                                                                                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `secret-service`        | Reference implementation using seeds stored on the file system. Uses `secret-service-server` for networking.                                                                                                                         |
| `secret-service-proto`  | Traits (base functionality definitions), wire protocol spec/implementation.                                                                                                                                                          |
| `secret-service-client` | Implementation of traits over the wire protocol to a remote S2 server. [`tokio`](https://tokio.rs/) + [`quinn`](https://github.com/quinn-rs/quinn) , effectively the other half to `server`                                          |
| `secret-service-server` | [`tokio`](https://tokio.rs/) + [`quinn`](https://github.com/quinn-rs/quinn) based framework for building a S2 server. You implement the traits from `proto`, this crate will handle networking, wire protocol encoding/decoding etc. |

For operators, the libraries will be what you use to develop a custom
implementation, but the reference implementation is an good starting point to work
from.

## Reference

Much of the code across the crates is heavily documented. For specific
implementation information, such as how a trait's methods should function, please
check the rust docs.

You can open the docs for each crate with `cargo doc -p {pkg} --no-deps --open`.

### Available libraries

#### `secret-service-proto`

This is the base level crate, specifying the traits, individual wire messages and
serialization. Whatever you're building, you should depend on this for the basics. It's
highly advised not to try write something custom instead of using this for message
parsing and serialization.

#### `secret-service-server`

[`tokio`](https://tokio.rs/) & [`quinn`](https://github.com/quinn-rs/quinn)-based implementation of a S2 server. You provide
implementations of the traits and this will handle all the networking parts.

Each connection is handled by a tokio task, along with each individual
request/stream.

If you wanted to rewrite the networking (QUIC parts) of S2 then this would be a
good place to start. For example, maybe switch to a different event loop like [`monoio`](https://github.com/bytedance/monoio)
or use `std` networking. You could also feasibly use a different transport protocol
than the standard QUIC one, though this can have security implications if not
implemented correctly. The QUIC implementation is fast and secure using TLS 1.3
already.

TLS configuration is handled via a `rustls` server config.

#### `secret-service-client`

[`tokio`](https://tokio.rs/) & [`quinn`](https://github.com/quinn-rs/quinn)-based implementation of an S2 client. Uses the QUIC request/response pattern that standard S2 servers expect.

If you swap your transport protocol, you'd have to create a new client too. You could
also use this as a template for swapping to another event loop like [`monoio`](https://github.com/bytedance/monoio) or
QUIC implementation.

TLS configuration is handled via a `rustls` client config.

### Available methods

S2's API is made up of several stubs of related functionality. These are implemented as traits in `secret-service-proto::v2`.

| Stub                  |                                                                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Musig2Signer`        | Operations around Musig2 signing sessions. Includes the various operations where secrets are involved. All other logic is delegated to the client. |
| `P2PSigner`           | BIP340 Schnorr signer interface for signing operator's messages for the P2P network                                                                |
| `StakeChainPreimages` | Deterministic creation of preimages for the stakechain that the operator uses to fulfil withdrawals.                                               |
| `WotsSigner`          | Winternitz One-Time Signatures are used as a hash-based primitive to transfer state across Bitcoin UTXOs without native support.                   |

The exact operations available along with usage and implementation specification
can be viewed in the Rust docs.

### Networking

Communication between client and server happens over a custom QUIC-based
binary protocol.

The client is responsible for keeping the connection open with QUIC keep-alive
messages.

#### Wire protocol

The wire protocol is a request/response pattern, somewhat RPC-like. For each
request, a client opens a new bidirectional QUIC stream. It then encodes a request,
which is a `VersionedClientMessage`. This contains any inputs/parameters to the
function.

For each connection, the server will wait for new incoming streams. It will accept
these and then attempt to read & parse the client's request. The request is then
executed, and a `VersionedServerMessage` is sent back over the stream to the client.
The stream is then closed on both sides.

Messages are encoded via [`rkyv`](https://github.com/rkyv/rkyv), which is a Rust exclusive, high performance
library for serialising data in a way that can be accessed through a single pointer
cast instead of a more expensive deserialization process. Implementations may or
may not use full deserialization, but if just accessing via a pointer, the bytes should
be checked with `rkyv`'s safe API, as bytes from a client or server should not be
trusted. Full deserialization with `rkyv` is still much faster than using JSON or
protobufs, but a bytes check and pointer cast is recommended for higher
performance.

#### Security

S2 has no built-in authentication such as API tokens or alike. Instead, as an S2
server should only be used internally of an operator, we depend on TLS for
authentication and authorisation.

Mutual authentication is intended for production use, where the client and server
verify each other's identity to ensure connection security.

This works via configuration on both the clients' and servers' sides. Each
client/server has a unique TLS keypair, whose public key is signed by a certificate
authority (CA). Two CAs should be used for S2, one that signs certificates for clients
(bridge nodes) and one that signs certificates for servers (S2 servers).

Clients are configured with their unique keypair and certificate, as well as the CA
certificate they will use to verify the server's identity.

Servers are configured with their unique keypair and certificate, as well as the CA
certificate they will use to verify the client's identity.

When a client connects to a server, the client will verify the server's identity and the
server will verify the client's identity. If it is valid, the client will have full access to
all S2 functionality.
