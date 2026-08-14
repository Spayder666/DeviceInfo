import os from "node:os";
import process from "node:process";

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "n/a";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  parts.push(`${secs}s`);
  return parts.join(" ");
}

function nonInternalInterfaces() {
  const interfaces = os.networkInterfaces();
  const result = [];
  for (const [name, addresses] of Object.entries(interfaces)) {
    for (const addr of addresses ?? []) {
      if (addr.internal) continue;
      result.push({
        name,
        address: addr.address,
        family: addr.family,
        mac: addr.mac,
      });
    }
  }
  return result;
}

/**
 * Collect a snapshot of live device / system information.
 * All values come from Node's built-in `os` and `process` modules, so this
 * reflects the actual machine the server runs on.
 */
export function collectDeviceInfo() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const cpus = os.cpus();

  return {
    generatedAt: new Date().toISOString(),
    host: {
      hostname: os.hostname(),
      platform: os.platform(),
      type: os.type(),
      release: os.release(),
      arch: os.arch(),
      uptime: formatDuration(os.uptime()),
      uptimeSeconds: Math.floor(os.uptime()),
    },
    cpu: {
      model: cpus[0]?.model?.trim() ?? "unknown",
      cores: cpus.length,
      speedMHz: cpus[0]?.speed ?? null,
      loadAverage: os.loadavg().map((n) => Number(n.toFixed(2))),
    },
    memory: {
      total: formatBytes(totalMem),
      used: formatBytes(usedMem),
      free: formatBytes(freeMem),
      totalBytes: totalMem,
      usedBytes: usedMem,
      freeBytes: freeMem,
      usedPercent: Number(((usedMem / totalMem) * 100).toFixed(1)),
    },
    runtime: {
      node: process.version,
      pid: process.pid,
      cwd: process.cwd(),
      processUptime: formatDuration(process.uptime()),
    },
    network: {
      interfaces: nonInternalInterfaces(),
    },
    user: {
      username: os.userInfo().username,
      homedir: os.homedir(),
      shell: os.userInfo().shell ?? null,
    },
  };
}
