const rows = document.getElementById("rows");
const statusLine = document.getElementById("status-line");
const viewTitle = document.getElementById("view-title");
const navItems = Array.from(document.querySelectorAll(".nav-item"));
const panelLogs = document.getElementById("panel-logs");
const panelHoney = document.getElementById("panel-honey");
const honeyMeta = document.getElementById("honey-meta");
const honeyTraps = document.getElementById("honey-traps");
const honeyFillers = document.getElementById("honey-fillers");
const honeyAlerts = document.getElementById("honey-alerts");
const panelPersist = document.getElementById("panel-persistence")
const persistmeta = document.getElementById("persist-meta")
const persistAlerts = document.getElementById("persist-alerts")
let view = "logs"; 
let events = [];
let honey = null;
let persist = null;

function msg(event) {
  return event.message || event.massage || "";
}

function detail(event) {
  const skip = new Set(["time", "kind", "message", "massage"]);
  const parts = [];
  for (const [k, v] of Object.entries(event)) {
    if (skip.has(k)) continue;
    parts.push(k + "=" + v);
  }
  return parts.join(" | ");
}

function fmtTime(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function esc(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function visibleEvents() {
  if (view === "heartbeats") {
    return events.filter((e) => e.kind === "heartbeat");
  }
  return events.filter((e) => e.kind !== "heartbeat");
}

function renderFileRows(target, list) {
  if (!list || !list.length) {
    target.innerHTML =
      '<tr><td colspan="3" class="empty">None configured.</td></tr>';
    return;
  }
  target.innerHTML = list
    .map((item) => {
      const flag = item.exists
        ? '<span class="flag-yes">yes</span>'
        : '<span class="flag-no">missing</span>';
      return (
        "<tr>" +
        "<td>" +
        esc(item.name) +
        "</td>" +
        "<td>" +
        flag +
        "</td>" +
        "<td>" +
        esc(item.path) +
        "</td>" +
        "</tr>"
      );
    })
    .join("");
}

function whoWhat(event) {
  const bits = [];
  if (event.user) bits.push("user=" + event.user);
  if (event.process) bits.push("process=" + event.process);
  if (event.access_mask) bits.push("access=" + event.access_mask);
  if (event.source) bits.push("source=" + event.source);
  if (event.path) bits.push("path=" + event.path);
  if (event.dest) bits.push("dest=" + event.dest);
  return bits.join(" | ") || detail(event);
}

function renderHoney() {
  if (!honey || !honey.ok) {
    honeyMeta.textContent =
      honey && honey.error ? honey.error : "honey data unavailable";
    honeyTraps.innerHTML =
      '<tr><td colspan="3" class="empty">:</td></tr>';
    honeyFillers.innerHTML =
      '<tr><td colspan="3" class="empty">:</td></tr>';
    honeyAlerts.innerHTML =
      '<tr><td colspan="3" class="empty">:</td></tr>';
    return;
  }
  const trapOk = (honey.traps || []).filter((t) => t.exists).length;
  const fillOk = (honey.fillers || []).filter((f) => f.exists).length;
  honeyMeta.textContent =
    "decoy: " +
    honey.decoy_root +
    "\n" +
    "folder: " +
    (honey.decoy_exists ? "present" : "missing") +
    " | traps on disk: " +
    trapOk +
    "/" +
    (honey.traps || []).length +
    " | fillers on disk: " +
    fillOk +
    "/" +
    (honey.fillers || []).length;
  renderFileRows(honeyTraps, honey.traps);
  renderFileRows(honeyFillers, honey.fillers);
  const alerts = honey.alerts || [];
  if (!alerts.length) {
    honeyAlerts.innerHTML =
      '<tr><td colspan="3" class="empty">No honey alerts yet.</td></tr>';
    return;
  }
  honeyAlerts.innerHTML = alerts
    .map((event) => {
      return (
        '<tr class="row-alert">' +
        "<td>" +
        esc(fmtTime(event.time)) +
        "</td>" +
        "<td>" +
        esc(msg(event)) +
        "</td>" +
        "<td>" +
        esc(whoWhat(event)) +
        "</td>" +
        "</tr>"
      );
    })
    .join("");
}

function persistDetail(event){
  const bits = [];
  if (event.value) bits.push("value=" + event.old);
  if (event.old) bits.push("new=" + event.new);
  return bits.join(" | ") || detail(event);
}

function renderPersist() {
  if (!persist || !persist.ok) {
    persistMeta.textContent = "persistence data unavailable";
    persistAlerts.innerHTML = 
      '<tr><td colspan="4" class="empty">:</td><tr>';
    return;
  }
  const c = persist.alert_counts || {};
  persistMeta.textContent = 
    "watch: " +
    (persist.watch_seen ? "seen in logs" : "not seen yet") +
    "\n" +
    "baseline entries: " +
    (persist.baseline_entries == null ? "?": "persist.baseline_entries") +
    "\n" +
    "alert mix (last page): run=" +
    (c.run || 0) +
    "startup=" +
    (c.startup || 0) +
    "task = " +
    (c.task || 0) +
    "other = " +
    (c.other || 0)
  const alerts = persist.alerts || [];
  if (!alerts.length) {
    persistAlerts.innerHTML = 
      '<tr><td colspan="4" class = "empty">No persistence alerts yet.</td></tr>';
    return;
  }
  persistAlerts.innerHTML = alerts
    .map((event) => {
      return(
        '<tr class="row-alert">' +
        "<td>" +
        esc(fmtTime(event.time)) +
        "</td>" +
        "<td>" +
        esc(massage(event)) +
        "</td>" +
        "<td>" +
        esc(event.entry || "") +
        "</td>" +
        "<td>" +
        esc(persistDetail(event)) +
        "</td>" +
        "</tr>"
      );
    })
    .join("");
  }


function renderLogs() {
  const list = visibleEvents();
  if (!list.length) {
    const empty =
      view === "heartbeats"
        ? "No heartbeat rows."
        : "No log rows yet. Start the agent.";
    rows.innerHTML =
      '<tr><td colspan="4" class="empty">' + empty + "</td></tr>";
    return;
  }
  rows.innerHTML = list
    .map((event) => {
      const kind = event.kind || "other";
      const cls = kind === "alert" ? ' class="row-alert"' : "";
      return (
        "<tr" +
        cls +
        ">" +
        "<td>" +
        esc(fmtTime(event.time)) +
        "</td>" +
        "<td>" +
        esc(kind) +
        "</td>" +
        "<td>" +
        esc(msg(event)) +
        "</td>" +
        "<td>" +
        esc(detail(event)) +
        "</td>" +
        "</tr>"
      );
    })
    .join("");
}

function render() {
  const titles = {
    logs: "Logs",
    heartbeats: "Heartbeats",
    honey: "Honeyfiles",
    persistence: "Persistence",
  };
  viewTitle.textContent = titles[view] || "Logs";
  const showHoney = view === "honey";
  const showPersist = view === "persistence";
  panelLogs.classList.toggle("hidden", showHoney);
  panelHoney.classList.toggle("hidden", !showHoney);
  panelPersist.classList.toggle("hidden", !showPersist);
  if (showHoney) {
    renderHoney();
  } else if(showPersist){
    renderPersist();
  }
  else {
    renderLogs();
  }
}

function setView(next) {
  view = next;
  navItems.forEach((btn) => {
    btn.classList.toggle("is-on", btn.getAttribute("data-view") === next);
  });
  render();
}

async function refresh() {
  try {
    const [evRes, honeyRes] = await Promise.all([
      fetch("/api/events?limit=500", { cache: "no-store" }),
      fetch("/api/honey", { cache: "no-store" }),
      fetch("/api/persistence", { cache: "no-store"}),
    ]);
    const data = await evRes.json();
    events = data.events || [];
    honey = await honeyRes.json();
    persist = await persistRes.json();
    if (view === "honey") {
      const n = (honey && honey.alerts && honey.alerts.length) || 0;
      statusLine.textContent = n + " honey alerts";
    }  else if(view === "persistence"){
      const n = (persist && persist.alerts && persist.length) || 0;
      statusLine.textContent = n + " persistence alerts";
    } else {
      const logsCount = events.filter((e) => e.kind !== "heartbeat").length;
      const hbCount = events.filter((e) => e.kind === "heartbeat").length;
      statusLine.textContent =
        logsCount + " logs, " + hbCount + " heartbeats";
    }
    render();
  } catch (err) {
    statusLine.textContent = "cannot reach server";
  }
}
navItems.forEach((btn) => {
  btn.addEventListener("click", () => setView(btn.getAttribute("data-view")));
});
refresh();
setInterval(refresh, 2000);