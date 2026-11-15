// Minimal diagnostic endpoint: no imports, no dependencies.
// Used to isolate deployment-level failures from module-load failures.
export default function handler(req, res) {
  res.status(200).json({ pong: true, ts: new Date().toISOString() });
}
