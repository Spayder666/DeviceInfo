import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { collectDeviceInfo } from "./deviceInfo.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";

export function createApp() {
  const app = express();

  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
  });

  app.get("/api/deviceinfo", (_req, res) => {
    res.json(collectDeviceInfo());
  });

  app.use(express.static(path.join(__dirname, "..", "public")));

  return app;
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  const app = createApp();
  app.listen(PORT, HOST, () => {
    console.log(`DeviceInfo server listening on http://${HOST}:${PORT}`);
  });
}
