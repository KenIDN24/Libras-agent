// Vercel serverless adapter for the Libras Agent Games endpoint.
// The raw request body is required for HMAC verification, so the built-in
// body parser is disabled and the stream is read manually.
import { handleAgentRequest, hmacHex } from "../lib/gatekeeper.mjs";

export const config = { api: { bodyParser: false } };

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  const secret = process.env.AGENT_GAMES_SECRET || "";
  if (!secret) {
    res.status(500).json({ error: "secret_not_configured" });
    return;
  }
  try {
    const rawBody = req.method === "POST" ? await readRawBody(req) : "";
    const { status, body } = await handleAgentRequest({
      method: req.method,
      rawBody,
      signatureHeader: req.headers["x-agent-games-signature"],
      secret,
    });
    res
      .status(status)
      .setHeader("content-type", "application/json")
      .setHeader("x-agent-games-signature", hmacHex(secret, body))
      .send(body);
  } catch (err) {
    res.status(500).json({ error: "internal", detail: String(err).slice(0, 120) });
  }
}
