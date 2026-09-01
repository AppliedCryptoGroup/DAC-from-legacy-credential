# Delegatable Anonymous Credentials from Legacy Credentials using recursive zk-SNARKs

A Plonky2-based recursive zero-knowledge proof scheme for delegatable legacy JWT credentials with selective delegation and disclosure.

Credentials are ECDSA-signed JWTs. The base circuit verifies the issuer signature and parses the JWT payload in-circuit, extracting the claims into a Poseidon Merkle commitment. The holder can delegate a subset of claims to another party, who can further delegate a subset, and so on. At any level the holder can produce a *presentation proof* that discloses any chosen subset of the claims and nothing else. The proof is bound to a verifier-supplied nonce (for freshness / replay protection) and stays unlinkable across presentations.

---

## Architecture

The proof system is a four-circuit pipeline over the Goldilocks field with Poseidon hashing. Each arrow is an in-circuit recursive verification of the previous proof:

```
R_Base  ->  R_Wrap  ->  R_Del  (cyclic, level 1..N)  ->  R_Pres
```

- **R_Base** ([circuits/jwt_base.rs](src/circuits/jwt_base.rs)) verifies the issuer's ECDSA signature over the JWT, parses the payload in-circuit (base64url decode, JSON claim extraction), proves possession of the holder key, and commits to the claims as a Poseidon Merkle root.
- **R_Wrap** ([jwt_wrapper.rs](src/circuits/jwt_wrapper.rs)) re-exposes the base proof under the delegation circuit's `CommonCircuitData`, so one delegation circuit can verify wrapper proofs (level 1) and its own cyclic proofs (level > 1) with a single in-circuit verifier. This adapter is what lets one delegation circuit serve many credential types.
- **R_Del** ([delegate.rs](src/circuits/delegate.rs)) is the cyclic recursion step: it increments the delegation level, re-masks the attribute set (dropping claims), and re-commits, while forwarding the issuer key unchanged.
- **R_Pres** ([present.rs](src/circuits/present.rs)) wraps a delegation proof in zero knowledge and discloses any chosen subset of attributes, bound to a verifier-supplied nonce. The delegation level stays private and the commitment is recomputed in-circuit but never exposed, so presentations reveal neither the depth nor a linkable identifier.

The supporting code is organized as: `credential/` (credential and attribute types), `circuits/` (the four circuits above plus `layout.rs`), `circuits/gadgets/` (the reusable sub-circuits: base64, array-slice, **JSON parsing**, ECDSA, SHA-256, scalar conversion), and `utils/` (Merkle commitment and recursion config). The vendored `libs/` directory holds the Plonky2 dependencies.

The cyclic delegation circuit needs a *dummy* base proof for its level-1 step. Generating one with zero knowledge enabled required adapting Plonky2's dummy-circuit generation (the adaptation described in the paper): see [`dummy_circuit.rs:115-204`](libs/plonky2/plonky2/src/recursion/dummy_circuit.rs#L115-L204) — `num_dummy_noop_gates` and its helpers `degree_after_blinding` / `num_blinding_gates` size the dummy circuit so its degree matches the real circuit *after* ZK blinding (upstream Plonky2 sizes it pre-blinding).

---

## Example

The example runs the full pipeline end to end: it signs a credential, delegates it with selective disclosure (dropping a claim at each level), and produces a presentation at each level, then repeats for a second credential with different claims.

```bash
cargo run --release --example demo
```

> **Note:** Always use `--release`. The zk circuits are too large to run at debug speed.

The example signs two credential definitions at runtime, so it needs no stored signatures:

```
examples/
  demo.rs
  fixtures/
    work_credential.json        # credential A definition
    id_credential.json          # credential B definition
```

Each run writes the freshly-signed compact `*.jwt` next to its definition (regenerated every run).

---

## Benchmarks

Measured circuit sizes, proving/verification timings, proof sizes are reported in [`benches/README.md`](benches/README.md).

The benchmark is parameterised by the number of claims and the maximum claim value size. `--claims` must be a power of two; `--max-claim-size` is the maximum claim value length in bytes (a multiple of 4).

```bash
cargo bench --bench bench_jwt -- --claims 4 --max-claim-size 32
```

---

## Tests

```bash
cargo test --release
```

> **Note:** Always use `--release`. The zk circuits are too large to run at debug speed.
