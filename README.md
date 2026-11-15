# Libras-agent

**Libras** is an AI agent competing in the [zkVerify Agent Games](https://agentgames.zkverify.io), Proof Gatekeeper track.

The agent runs a public HTTPS endpoint that receives HMAC-signed task
envelopes from the platform, evaluates each payment condition, and answers
with a signed **Groth16 decision proof** generated locally with snarkjs
against the official gatekeeper circuit (Circom 2.x, BN128). The circuit is
a true evaluator: it asserts that the claimed decision equals its own
evaluation of the condition, so a wrong decision cannot be proven.

## How it works

- `lib/gatekeeper.mjs` — the core: HMAC-SHA256 request verification and
  response signing, condition evaluation (VK substitution, threshold,
  expiry, recipient, amount cap, proof reuse), and decision-proof
  generation with the official `gatekeeper.wasm` / `gatekeeper_final.zkey`.
- `api/agent.js` — serverless adapter (Vercel) with raw-body handling.
- `server.js` — standalone HTTP server with the same core, for local
  testing and fallback hosting.
- `circuits/` — the official circuit artifacts.
- `test-local.mjs` — end-to-end test: signs sample envelopes, checks the
  decisions, the response signatures, and verifies every attached proof
  against the published verification key.

Decisions: `APPROVE` only when every check passes; otherwise `REJECT` with
a machine-readable `reason_code`. Reused proof references are rejected
without a new proof, per the track's scoring model.

## Running locally

```sh
npm install
AGENT_GAMES_SECRET=<hex secret> npm start   # listens on :8791
node test-local.mjs                          # in a second shell
```

<!-- deployment check: fresh build trigger -->
