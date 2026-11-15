// Local end-to-end test: sign sample envelopes with the agent secret,
// POST them to the standalone server, verify the response signature,
// the decision, and the attached Groth16 proof against the official VK.
import crypto from "node:crypto";
import fs from "node:fs";
import * as snarkjs from "snarkjs";

const SECRET = fs.readFileSync(process.env.HOME + "/.config/agentgames/hmac-secret", "utf8").trim();
const BASE = "http://127.0.0.1:8791/agent";
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const vkey = JSON.parse(fs.readFileSync("./circuits/gatekeeper-vk.json", "utf8"));

const sign = (raw) =>
  crypto.createHmac("sha256", Buffer.from(SECRET, "hex")).update(raw).digest("hex");

function envelope(overrides = {}, taskId = "gk_24_9d1") {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "live",
    issued_at: "2026-11-15T10:00:00.000Z",
    deadline_at: "2026-11-15T10:01:00.000Z",
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: "0xDe42f9c86D07d3b21f1Aa86d04fC24E9d8eA9f01",
      condition_recipient: "0xDe42f9c86D07d3b21f1Aa86d04fC24E9d8eA9f01",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xabc" + taskId,
      ...overrides,
    },
  };
}

async function run(label, env, expectDecision, expectReason) {
  const raw = JSON.stringify(env);
  const t0 = Date.now();
  const res = await fetch(BASE, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(raw) },
    body: raw,
  });
  const text = await res.text();
  const ms = Date.now() - t0;
  const sigOk = res.headers.get("x-agent-games-signature") === sign(text);
  const body = JSON.parse(text);
  let proofOk = "n/a";
  if (body.proof) {
    proofOk = await snarkjs.groth16.verify(vkey, body.public_signals, body.proof);
  }
  const pass =
    res.status === 200 && sigOk && body.decision === expectDecision &&
    body.reason_code === expectReason && (proofOk === true || proofOk === "n/a");
  console.log(
    `${pass ? "PASS" : "FAIL"} ${label}: ${res.status} in ${ms}ms sig=${sigOk} decision=${body.decision} reason=${body.reason_code} proofVerify=${proofOk}`
  );
  return pass;
}

let all = true;
all &= await run("valid condition", envelope(), "APPROVE", "VALID_CONDITION");
all &= await run("threshold trap", envelope({ public_balance: "900" }, "gk_24_low"), "REJECT", "THRESHOLD_MISMATCH");
all &= await run("vk substitution", envelope({ proof_vk: "0x0000000000000000000000000000000000000000000000000000000000000777" }, "gk_24_vk"), "REJECT", "VK_SUBSTITUTION");
all &= await run("amount overflow", envelope({ amount: "1500" }, "gk_24_amt"), "REJECT", "AMOUNT_OVERFLOW");
// reuse: same proof_tx as the first task, different task id
all &= await run("proof reused", envelope({ proof_tx: "0xabcgk_24_9d1" }, "gk_24_again"), "REJECT", "PROOF_REUSED");

// bad signature must be rejected
{
  const raw = JSON.stringify(envelope({}, "gk_24_bad"));
  const res = await fetch(BASE, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": "00".repeat(32) },
    body: raw,
  });
  console.log(`${res.status === 401 ? "PASS" : "FAIL"} bad signature rejected: ${res.status}`);
  all &= res.status === 401;
}

// health check
{
  const res = await fetch(BASE);
  const body = await res.json();
  console.log(`${res.status === 200 && body.ok ? "PASS" : "FAIL"} health check: ${res.status} ok=${body.ok}`);
  all &= res.status === 200 && body.ok === true;
}

console.log(all ? "\nALL TESTS PASSED" : "\nSOME TESTS FAILED");
process.exit(all ? 0 : 1);
