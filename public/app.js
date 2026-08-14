const grid = document.getElementById("grid");
const statusEl = document.getElementById("status");
const updatedEl = document.getElementById("updated");
const refreshBtn = document.getElementById("refresh");
const autoToggle = document.getElementById("auto");

let timer = null;

function row(key, val) {
  return `<div class="row"><span class="row__key">${key}</span><span class="row__val">${val ?? "—"}</span></div>`;
}

function card(icon, title, rowsHtml, extra = "") {
  return `
    <section class="card">
      <h2 class="card__title"><span class="card__icon">${icon}</span>${title}</h2>
      ${rowsHtml}
      ${extra}
    </section>`;
}

function render(data) {
  const host = data.host;
  const cpu = data.cpu;
  const mem = data.memory;
  const rt = data.runtime;
  const user = data.user;
  const ifaces = data.network.interfaces;

  const cards = [];

  cards.push(
    card(
      "🧭",
      "System",
      row("Hostname", host.hostname) +
        row("Platform", `${host.type} (${host.platform})`) +
        row("Release", host.release) +
        row("Architecture", host.arch) +
        row("Uptime", host.uptime)
    )
  );

  cards.push(
    card(
      "⚙️",
      "CPU",
      row("Model", cpu.model) +
        row("Cores", cpu.cores) +
        row("Speed", cpu.speedMHz ? `${cpu.speedMHz} MHz` : "—") +
        row("Load avg", cpu.loadAverage.join(", "))
    )
  );

  cards.push(
    card(
      "🧠",
      "Memory",
      row("Total", mem.total) +
        row("Used", `${mem.used} (${mem.usedPercent}%)`) +
        row("Free", mem.free),
      `<div class="meter"><div class="meter__fill" style="width:${mem.usedPercent}%"></div></div>`
    )
  );

  cards.push(
    card(
      "🟢",
      "Runtime",
      row("Node", rt.node) +
        row("PID", rt.pid) +
        row("Process uptime", rt.processUptime) +
        row("CWD", rt.cwd)
    )
  );

  cards.push(
    card(
      "👤",
      "User",
      row("Username", user.username) +
        row("Home", user.homedir) +
        row("Shell", user.shell)
    )
  );

  const netRows = ifaces.length
    ? ifaces
        .map((i) => row(`${i.name} (${i.family})`, i.address))
        .join("")
    : row("Interfaces", "none (internal only)");
  cards.push(card("🌐", "Network", netRows));

  grid.innerHTML = cards.join("");
}

async function load() {
  try {
    const res = await fetch("/api/deviceinfo", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    render(data);
    statusEl.textContent = "Connected";
    statusEl.className = "status status--ok";
    updatedEl.textContent = `Updated ${new Date(data.generatedAt).toLocaleTimeString()}`;
  } catch (err) {
    statusEl.textContent = "Error";
    statusEl.className = "status status--error";
    updatedEl.textContent = String(err);
  }
}

function startAuto() {
  stopAuto();
  timer = setInterval(load, 5000);
}

function stopAuto() {
  if (timer) clearInterval(timer);
  timer = null;
}

refreshBtn.addEventListener("click", load);
autoToggle.addEventListener("change", () => {
  if (autoToggle.checked) startAuto();
  else stopAuto();
});

load();
startAuto();
