import test from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/server.js";
import { collectDeviceInfo } from "../src/deviceInfo.js";

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

test("collectDeviceInfo returns a populated snapshot", () => {
  const info = collectDeviceInfo();
  assert.ok(info.host.hostname, "hostname present");
  assert.ok(info.cpu.cores > 0, "at least one CPU core");
  assert.ok(info.memory.totalBytes > 0, "total memory > 0");
  assert.match(info.runtime.node, /^v\d+/, "node version format");
});

test("GET /api/health responds ok", async () => {
  const { server, base } = await listen(createApp());
  try {
    const res = await fetch(`${base}/api/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, "ok");
  } finally {
    server.close();
  }
});

test("GET /api/deviceinfo returns device data", async () => {
  const { server, base } = await listen(createApp());
  try {
    const res = await fetch(`${base}/api/deviceinfo`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.host.platform, "platform present");
    assert.ok(body.memory.total, "memory total present");
    assert.ok(Array.isArray(body.cpu.loadAverage), "load average is an array");
  } finally {
    server.close();
  }
});

test("static index page is served", async () => {
  const { server, base } = await listen(createApp());
  try {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /DeviceInfo/);
  } finally {
    server.close();
  }
});
