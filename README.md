# DeviceInfo

A small web app that reports live system and device information for the machine it runs on. It uses a Node.js/Express backend that reads real data from Node's built-in `os` and `process` modules, and a lightweight vanilla-JS frontend that displays it with auto-refresh.

## Features

- System card: hostname, platform, OS release, architecture, uptime
- CPU card: model, core count, speed, load average
- Memory card: total / used / free with a usage meter
- Runtime card: Node version, PID, process uptime, working directory
- User and network cards
- Auto-refresh every 5 seconds (toggleable) plus manual refresh

## Requirements

- Node.js >= 20 (developed against Node 22)

## Getting started

```bash
npm ci        # install exact dependencies from the lockfile
npm run dev   # start the server with file watching on http://localhost:3000
```

Then open http://localhost:3000.

For a plain (non-watch) start, use `npm start`.

## API

- `GET /api/health` — liveness probe, returns `{ "status": "ok" }`
- `GET /api/deviceinfo` — full device/system snapshot as JSON

Example:

```bash
curl http://localhost:3000/api/deviceinfo
```

## Testing

```bash
npm test
```

Tests use the built-in Node test runner (`node --test`) and cover the device-info
collector and the HTTP endpoints.

## Configuration

- `PORT` (default `3000`) — port the server listens on
- `HOST` (default `0.0.0.0`) — bind address

## Project layout

```
src/
  server.js       Express app + server bootstrap
  deviceInfo.js   Collects system info from os/process
public/
  index.html      UI
  styles.css      Styling
  app.js          Frontend logic (fetch + render)
test/
  api.test.js     Automated tests
```
