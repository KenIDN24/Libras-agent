// Libras — Agent Games "Proof Gatekeeper" endpoint core.
//
// Contract (from the official Builder Field Guide + event page):
//   - The platform POSTs signed JSON task envelopes to the agent endpoint.
//   - Requests carry an HMAC-SHA256 signature in the `x-agent-games-signature`
//     header, computed over the RAW request body with the agent's secret.
//   - Responses must be signed the same way over the raw response body.
//   - Gatekeeper tasks ask the agent to evaluate a payment condition and to
//     attach a Groth16 decision proof (official gatekeeper circuit) whose
//     public inputs bind the decision to the condition fields.
//
// The circuit is a true evaluator: it asserts that the claimed decision
// equals its own evaluation of the condition, so a wrong decision cannot be
// proven. Signal names / public-signal order were recovered from the
// official artifacts and verified locally against the published VK.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const WASM_PATH = path.join(ROOT, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(ROOT, "circuits", "gatekeeper_final.zkey");

// The registered condition VK hash published by /api/circuit-info.
export const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

// ---------------------------------------------------------------- HMAC ----

export function hmacHex(secretHex, raw) {
  return crypto
    .createHmac("sha256", Buffer.from(secretHex, "hex"))
    .update(raw)
    .digest("hex");
}

export function verifySignature(secretHex, raw, header) {
  if (!header) return false;
  const got = String(header).trim().replace(/^sha256=/i, "");
  const expectedHex = hmacHex(secretHex, raw);
  try {
    const a = Buffer.from(expectedHex, "utf8");
    const b = Buffer.from(got, "utf8");
    if (a.length === b.length) return crypto.timingSafeEqual(a, b);
    // Tolerate a base64-encoded digest as well.
    const decoded = Buffer.from(got, "base64");
    const expectedRaw = Buffer.from(expectedHex, "hex");
    return (
      decoded.length === expectedRaw.length &&
      crypto.timingSafeEqual(decoded, expectedRaw)
    );
  } catch {
    return false;
  }
}

// ------------------------------------------------------------- parsing ----

// Parse a field that may arrive as a decimal string, a 0x-hex string
// (addresses, hashes) or a JSON number into a BigInt.
export function toBig(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  if (typeof value === "string") {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^-?\d+$/.test(s)) return BigInt(s);
  }
  throw new Error("not an integer field: " + String(value).slice(0, 40));
}

function pick(obj, keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

// Extract the Gatekeeper condition from a task envelope, tolerating the
// documented key spellings (snake_case on the event page).
export function extractCondition(envelope) {
  const input = envelope.input ?? envelope.data ?? envelope;
  const get = (...keys) => pick(input, keys) ?? pick(envelope, keys);
  return {
    taskIdRaw: get("task_id", "taskId", "id"),
    registeredVk: get("registered_vk", "registeredVk", "registered_vk_hash", "registeredVkHash"),
    proofVk: get("proof_vk", "proofVk", "proof_vk_hash", "proofVkHash"),
    minimum: get("minimum", "min", "threshold"),
    publicBalance: get("public_balance", "publicBalance", "balance"),
    expiryBlock: get("expiry_block", "expiryBlock", "expiry"),
    currentBlock: get("current_block", "currentBlock"),
    recipient: get("recipient", "to"),
    conditionRecipient: get("condition_recipient", "conditionRecipient"),
    amount: get("amount", "value"),
    maxTransfer: get("max_transfer", "maxTransfer", "cap"),
    proofTx: get("proof_tx", "proofTx", "proof_reference", "proofReference"),
  };
}

// The circuit takes taskId as a field element. The envelope's task_id is a
// string like "gk_24_9d1"; until practice mode pins the platform's exact
// encoding, use its digit sequence ("2491"). CALIBRATION POINT.
export function encodeTaskId(taskIdRaw) {
  if (typeof taskIdRaw === "number") return BigInt(taskIdRaw);
  const s = String(taskIdRaw ?? "");
  if (/^\d+$/.test(s)) return BigInt(s);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  const digits = s.replace(/\D/g, "");
  return digits ? BigInt(digits) : 0n;
}

// Deterministic per-task salt (private circuit input), derived from the
// secret so retries of the same task reproduce the same proof.
export function deriveSalt(secretHex, taskIdRaw) {
  const mac = crypto
    .createHmac("sha256", Buffer.from(secretHex, "hex"))
    .update("gatekeeper-salt:" + String(taskIdRaw))
    .digest();
  return BigInt("0x" + mac.toString("hex"));
}

// ---------------------------------------------------------- evaluation ----

// Seen proof references, for the PROOF_REUSED trap. In-memory (warm
// instance) with optional file persistence for the standalone server.
const seenProofTx = new Set();
let seenFile = null;
export function initSeenStore(file) {
  seenFile = file || null;
  if (seenFile && fs.existsSync(seenFile)) {
    for (const line of fs.readFileSync(seenFile, "utf8").split("\n")) {
      const v = line.trim();
      if (v) seenProofTx.add(v);
    }
  }
}
function markSeen(ref) {
  if (!ref) return false;
  const key = String(ref);
  if (seenProofTx.has(key)) return true;
  seenProofTx.add(key);
  if (seenFile) fs.appendFileSync(seenFile, key + "\n");
  return false;
}

// Evaluate a condition. Returns { decision, reason_code, needsProof }.
// The checks mirror the circuit's own evaluation for the provable cases;
// proof reuse is handled outside the circuit (it has no proof_tx input),
// and the scoring model excludes reused tasks from the proof requirement.
export function evaluate(cond) {
  const reused = markSeen(cond.proofTx);
  if (reused) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", needsProof: false };
  }
  const registeredVkHash = toBig(cond.registeredVk);
  const proofVkHash = toBig(cond.proofVk);
  if (proofVkHash !== registeredVkHash) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", needsProof: true };
  }
  if (toBig(cond.publicBalance) < toBig(cond.minimum)) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", needsProof: true };
  }
  if (toBig(cond.currentBlock) > toBig(cond.expiryBlock)) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", needsProof: true };
  }
  if (toBig(cond.recipient) !== toBig(cond.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", needsProof: true };
  }
  if (toBig(cond.amount) > toBig(cond.maxTransfer)) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", needsProof: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", needsProof: true };
}

// --------------------------------------------------------------- proof ----

export async function generateDecisionProof(cond, verdict, secretHex) {
  const input = {
    minimum: toBig(cond.minimum).toString(),
    publicBalance: toBig(cond.publicBalance).toString(),
    expiryBlock: toBig(cond.expiryBlock).toString(),
    currentBlock: toBig(cond.currentBlock).toString(),
    recipient: toBig(cond.recipient).toString(),
    conditionRecipient: toBig(cond.conditionRecipient).toString(),
    amount: toBig(cond.amount).toString(),
    maxTransfer: toBig(cond.maxTransfer).toString(),
    registeredVkHash: toBig(cond.registeredVk).toString(),
    proofVkHash: toBig(cond.proofVk).toString(),
    decision: verdict.decision === "APPROVE" ? "1" : "0",
    taskId: encodeTaskId(cond.taskIdRaw).toString(),
    salt: deriveSalt(secretHex, cond.taskIdRaw).toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    WASM_PATH,
    ZKEY_PATH
  );
  return { proof, publicSignals };
}

// ------------------------------------------------------------- handler ----

// Core request handler shared by the serverless adapter and the standalone
// server. Returns { status, body } where body is the exact string to send;
// the caller signs `body` and sets the signature header.
export async function handleAgentRequest({ method, rawBody, signatureHeader, secret }) {
  if (method === "GET") {
    return {
      status: 200,
      body: JSON.stringify({
        ok: true,
        agent: "libras",
        service: "agent-games-endpoint",
        tracks: ["proof-gatekeeper"],
      }),
    };
  }
  if (method !== "POST") {
    return { status: 405, body: JSON.stringify({ error: "method_not_allowed" }) };
  }
  if (!verifySignature(secret, rawBody, signatureHeader)) {
    return { status: 401, body: JSON.stringify({ error: "bad_signature" }) };
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody);
  } catch {
    return { status: 400, body: JSON.stringify({ error: "bad_json" }) };
  }

  const type = String(envelope.type ?? envelope.kind ?? "");
  const isGatekeeper =
    type.includes("proof-gatekeeper") ||
    type.includes("gatekeeper") ||
    envelope.input !== undefined;

  if (!isGatekeeper) {
    // Health-check / preflight style envelopes: echo any challenge back so
    // the platform can verify the signed round-trip.
    const ack = {
      ok: true,
      agent: "libras",
      received_type: type || null,
      task_id: envelope.task_id ?? envelope.taskId ?? null,
    };
    if (envelope.nonce !== undefined) ack.nonce = envelope.nonce;
    if (envelope.challenge !== undefined) ack.challenge = envelope.challenge;
    return { status: 200, body: JSON.stringify(ack) };
  }

  const cond = extractCondition(envelope);
  const verdict = evaluate(cond);
  const response = {
    task_id: envelope.task_id ?? envelope.taskId ?? cond.taskIdRaw ?? null,
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: cond.proofTx ?? null,
  };
  if (verdict.needsProof) {
    const { proof, publicSignals } = await generateDecisionProof(cond, verdict, secret);
    response.proof = proof;
    response.public_signals = publicSignals;
    response.publicSignals = publicSignals;
  }
  return { status: 200, body: JSON.stringify(response) };
}
