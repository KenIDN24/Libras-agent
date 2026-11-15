// Standalone HTTP server for the Libras Agent Games endpoint.
// Used for local testing and as a fallback host. The Vercel deployment
// uses api/agent.js instead; both share lib/gatekeeper.mjs.
//
// Env: AGENT_GAMES_SECRET (hex, required), PORT (default 8791),
//      SEEN_FILE (optional path persisting seen proof references).
import http from "node:http";
import { handleAgentRequest, hmacHex, initSeenStore } from "./lib/gatekeeper.mjs";

const secret = process.env.AGENT_GAMES_SECRET || "";
if (!secret) {
  console.error("AGENT_GAMES_SECRET is not set");
  process.exit(1);
}
initSeenStore(process.env.SEEN_FILE || null);

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks).toString("utf8");
    try {
      const { status, body } = await handleAgentRequest({
        method: req.method,
        rawBody,
        signatureHeader: req.headers["x-agent-games-signature"],
        secret,
      });
      res.writeHead(status, {
        "content-type": "application/json",
        "x-agent-games-signature": hmacHex(secret, body),
      });
      res.end(body);
    } catch (err) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal", detail: String(err).slice(0, 120) }));
    }
  });
});

const port = Number(process.env.PORT || 8791);
server.listen(port, () => console.log("libras agent endpoint listening on :" + port));
