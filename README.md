# capability-ladder

`capability-ladder` is a small, fail-closed Rust CLI for auditing delegated
agent authority. It catches privilege amplification and context drift before a
delegation chain reaches a worker, tool runner, or CI job.

It checks every parent-to-child hop for:

- exact issuer-to-subject linkage;
- action, resource, purpose, data-class, recipient, and transmission narrowing;
- non-expanding expiry windows;
- monotonically decreasing delegation depth;
- valid, unexpired time windows and unique grant IDs;
- unknown JSON fields, which are rejected instead of ignored.

The result includes stable rule codes and the SHA-256 of the exact input bytes.
No network service, policy engine, or signing infrastructure is required.

## Install

Requires stable Rust 1.85 or newer.

```console
cargo install --git https://github.com/nicholas-ruest/capability-ladder
```

Or build from a checkout:

```console
cargo build --release
```

## Use

Audit a chain at the current time:

```console
capability-ladder examples/valid-chain.json
```

Pin the evaluation time for deterministic CI or incident replay:

```console
capability-ladder examples/valid-chain.json \
  --at 2026-10-07T21:30:00Z
```

Machine-readable output:

```console
capability-ladder examples/expanded-chain.json \
  --at 2026-10-07T21:30:00Z \
  --format json
```

Exit codes are `0` for an accepted chain, `2` for policy findings, and `1` for
input or runtime errors. Add `--deny-warnings` to make duplicate constraint
values fail the command.

## Document model

Each JSON document has one `task_id` and an ordered list of grants. A child can
only retain or remove values present in its parent. The literal `"*"` in a
parent constraint authorizes any child value for that field; a child cannot
introduce `"*"` unless the parent already has it.

See [`examples/valid-chain.json`](examples/valid-chain.json) for a three-hop
chain and [`examples/expanded-chain.json`](examples/expanded-chain.json) for a
deliberately invalid chain.

This tool verifies structural attenuation. It does **not** authenticate
identities, verify signatures, interpret resource hierarchies, contact an
authorization server, or perform an action. Treat it as one deterministic gate
inside a larger identity and policy system.

## Verify

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## License

Licensed under the MIT License.
