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
const persistMeta = document.getElementById("persist-meta")
const persistAlerts = document.getElementById("persist-alerts")
const panelProcess = document.getElementById("panel-process")
const processMeta = document.getElementById("process-meta")
const processAlerts = document.getElementById("process-alerts")
const processCorr = document.getElementById("process-corr")
const panelNetwork = document.getElementById("panel-network")
const networkMeta = document.getElementById("network-meta")
const networkAlerts = document.getElementById("network-alerts")
const networkLinked = document.getElementById("network-linked")
const panelControl = document.getElementById("panel-control")
const controlMeta = document.getElementById("control-meta")
const controlAlerts = document.getElementById("control-alerts")
const controlRows = document.getElementById("control-rows");
const controlMutes = document.getElementById("control-mutes")
const controlLog = document.getElementById("control-log");
let view = "logs"; 
let events = [];
let honey = null;
let persist = null;
let processData = null;
let networkData = null;
let controlData = null;

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
  if (event.value) bits.push("value=" + event.value);
  if (event.old) bits.push("old=" + event.old);
  if (event.new) bits.push("new=" + event.new)
  return bits.join(" | ") || detail(event);
}

function renderPersist() {
  if (!persist || !persist.ok) {
    persistMeta.textContent = "persistence data unavailable";
    persistAlerts.innerHTML = 
      '<tr><td colspan="4" class="empty">—</td></tr>';
    return;
  }
  const c = persist.alert_counts || {};
  persistMeta.textContent = 
    "watch: " +
    (persist.watch_seen ? "seen in logs" : "not seen yet") +
    "\n" +
    "baseline entries: " +
    (persist.baseline_entries == null ? "?": persist.baseline_entries) +
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
        esc(msg(event)) +
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

function processDetail(event){
  const bits = [];
  if (event.parent) bits.push("parent=" +event.parent);
  if (event.reasons) bits.push("reasons=" +event.reasons);
  if (event.process_reasons) bits.push("process_reasons=" +event.process_reasons);
  if (event.related) bits.push("related=" +event.related);
  if (event.pid) bits.push("pid=" +event.pid);
  if (event.ppid) bits.push("ppid=" +event.ppid);
  return bits.join(" | ") || detail(event);
}

function renderProcess(){
  if (!processData || !processData.ok) {
    processMeta.textContent = "process data unavailable";
    processAlerts.innerHTML = 
      '<tr><td colspan="4" class="empty">—</td></tr>';
    processCorr.innerHTML = 
      '<tr><td colspan="4" class="empty">—</td></tr>';
    return;
  }
  processMeta.textContent = 
    "mode:" +
    (processData.mode || "?")+
    "\n" +
    "baseline images: " +
    (processData.baseline_images || 0) +
    " | pairs: " +
    (processData.baseline_pairs || 0) +
    "\n" +
    "baseline started: " +
    (processData.started_at || "?");
  const alerts = processData.alerts || [];
  if (!alerts.length) {
    processAlerts.innerHTML = 
      '<tr><td colspan="4" class="empty">No process alerts yet.</td></tr>';
  } else {
    processAlerts.innerHTML = alerts
      .map((event) => {
        return(
          '<tr class="row-alert">' +
          "<td>" +
          esc(fmtTime(event.time)) +
          "</td>" +
          "<td>" +
          esc(msg(event)) +
          "</td>" +
          "<td>" +
          esc(event.image || "") +
          "</td>" +
          "<td>" +
          esc(processDetail(event)) +
          "</td>" +
          "</tr>"
        );
      })
      .join("");
  }
  const corr = processData.correlated || [];
  if (!corr.length) {
    processCorr.innerHTML = 
      `<tr><td colspan="4" class="empty">No correlated alerts yet.</td></tr>`;
  } else {
    processCorr.innerHTML = corr
    .map((event) =>{
      return (
        `<tr class="row-alert">` +
        "<td>" +
        esc(fmtTime(event.time)) +
        "</td>" +
        "<td>" +
        esc(msg(event)) +
        "</td>" +
        "<td>" +
        esc(event.related || "") +
        "</td>" +
        "<td>" +
        esc(processDetail(event)) +
        "</td>" +
        "</tr>"
      );
    })
    .join("");
  }
}

function networkDetail(event){
  const bits = [];
  if (event.image) bits.push("image=" + event.image);
  if (event.pid) bits.push("pid=" + event.pid);
  if (event.reasons) bits.push("reasons=" + event.reasons);
  if (event.related) bits.push("related=" + event.related);
  if (event.links) bits.push("links=" + event.links);
  return bits.join(" | ") || detail(event);
}

function renderNetwork(){
  if (!networkData || !networkData.ok) {
    networkMeta.textContent = "no network data";
    networkAlerts.innerHTML = 
      '<tr><td colspan="4" class="empty">—</td></tr>';
    networkLinked.innerHTML = 
      '<tr><td colspan="4" class="empty">—</td></tr>';
    return;
  }
  networkMeta.textContent =
    "mode:" +
    (networkData.mode || "?") +
    "\n" +
    "baseline flows: " +
    (networkData.flows || 0) +
    "\n" +
    "baseline started: " +
    (networkData.started_at || "?");
  const alerts = networkData.alerts || [];
  if (!alerts.length) {
    networkAlerts.innerHTML = 
      '<tr><td colspan="4" class="empty">No network alerts yet.</td></tr>';
  } else {
    networkAlerts.innerHTML = alerts
      .map((event) => {
        const remote =
          (event.remote_ip || "") +
          (event.remote_port ? ":" + event.remote_port : "");
        return (
          '<tr class="row-alert">' +
          "<td>" +
          esc(fmtTime(event.time)) +
          "</td>" +
          "<td>" +
          esc(msg(event)) +
          "</td>" +
          "<td>" +
          esc(remote) +
          "</td>" +
          "<td>" +
          esc(networkDetail(event)) +
          "</td>" +
          "</tr>"
        );
      })
      .join("");
  }
  const linked = networkData.linked || [];
  if (!linked.length) {
    networkLinked.innerHTML = 
      '<tr><td colspan="4" class="empty">Nothing linked yet.</td></tr>';
  } else {
    networkLinked.innerHTML = linked
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
          esc(event.related || "") +
          "</td>" +
          "<td>" +
          esc(networkDetail(event)) +
          "</td>" +
          "</tr>" 
        );
      })
      .join("");
  };
}

async function setSwitch(name, value) {
  const body = {};
  body[name] = value;
  try{
    await fetch("/api/control", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
  } catch(err) {
    statusLine.textContent = "control post failed";
  }
  refresh();
}

async function muteFor(name, minutes) {
  const body = { mute_minutes: {} };
  body.mute_minutes[names] = minutes;
  try {
    await fetch("/api/control", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
  } catch (err) {
    statusLine.textContent = "control post failed";
  }
  refresh();
}
function renderControl(){
  if (!controlData || !controlData.ok) {
    controlMeta.textContent = "no control data";
    controlRows.innerHTML = "";
    if (controlMutes) controlMutes.innerHTML = "";
    controlLog.innerHTML =
      '<tr><td colspan="3" class="empty">—</td></tr>';
    return;
  }
  controlMeta.textContent =
    "agent: " +
    (controlData.alive ? "up" : "not seen yet");
  const sw = controlData.switches || {};
  const running = controlData.running || {};
  const mutedUntil = controlData.muted_until || {};
  const names = ["honey", "persistence", "process", "network"];
  controlRows.innerHTML = names
    .map((name) => {
      const on  = !!sw[name];
      const run = !!running[name];
      return (
        '<div style="margin:6px 0;">' +
        "<div>running:" +
        (run
          ? '<span class="flag-yes">yes</span>'
          : '<span class="flag-no">no</span>' ) +
        "</div>" +
        "<label>" +
        '<input type="checkbox" data-switch="' +
        name +
        '"' +
        (on ? " checked" : "") +
        ">" +
        " " +
        name +
        "</label>" +
        "</div>"
      );
    })
    .join("");
  controlRows.querySelectorAll("input[data-switch]").forEach((el) => {
    el.addEventListener("change", ()=> {
      setSwitch(el.getAttribute("data-switch"), el.checked);
    });
  });
  if (controlMutes) {
    controlMutes.innerHTML = names
      .map((name) => {
        let muteLine = "";
        if (mutedUntil[name]) {
          muteLine = 
            "<div>until " + esc(fmtTime(mutedUntil[name])) + "</div>";
        }
        return (
        '<div class="control-row">' +
        "<div>" +
        name +
        "</div>" +
        muteLine +
        '<div class="control-mute-btns">' +
        '<button type="button" data-mute="' +
        name +
        '" data-mins="15">15m</button>' +
        '<button type="button" data-mute="' +
        name +
        '" data-mins="60">1h</button>' +
        "</div>" +
        "</div>"
        );
      })
      .join("");
    controlMutes.querySelectorAll("button[data-mute]").forEach((el) => {
      el.addEventListener("click", () => {
        muteFor(
          el.getAttribute("data-mute"),
          parseInt(el.getAttribute("data-mins"), 10)
        );
      });
    });
  }
  const recent = controlData.recent || [];
  if (!recent.length) {
    controlLog.innerHTML =
      '<tr><td colspan="3" class="empty">Nothing yet.</td></tr>';
  } else {
    controlLog.innerHTML = recent
      .map((event) => {
        return (
          "<tr>" +
          "<td>" +
          esc(fmtTime(event.time)) +
          "</td>" +
          "<td>" +
          esc(event.kind || "") +
          "</td>" +
          "<td>" +
          esc(msg(event)) +
          "</td>" +
          "</tr>"
        );
      })
      .join("");
  }
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
    process: "Process",
    network: "Network",
    control: "Control",
  };
  viewTitle.textContent = titles[view] || "Logs";
  const showHoney = view === "honey";
  const showPersist = view === "persistence";
  const showProcess = view === "process";
  const showNetwork = view === "network";
  const showControl = view === "control";
  panelLogs.classList.toggle(
    "hidden",
    showHoney || showPersist || showProcess || showNetwork || showControl
  );
  panelHoney.classList.toggle("hidden", !showHoney);
  panelPersist.classList.toggle("hidden", !showPersist);
  panelProcess.classList.toggle("hidden", !showProcess);
  panelNetwork.classList.toggle("hidden", !showNetwork);
  panelControl.classList.toggle("hidden", !showControl);
  if (showHoney) {
    renderHoney();
  } else if(showPersist){
    renderPersist();
  } else if(showProcess){
    renderProcess();
  } else if(showNetwork){
    renderNetwork();
  } else if(showControl){
    renderControl();
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
    const [evRes, honeyRes, persistRes, processRes, networkRES, controlRES] = await Promise.all([
      fetch("/api/events?limit=500", { cache: "no-store" }),
      fetch("/api/honey", { cache: "no-store" }),
      fetch("/api/persistence", { cache: "no-store"}),
      fetch("/api/process", { cache: "no-store"}),
      fetch("/api/network", { cache: "no-store"}),
      fetch("/api/control", { cache: "no-store"}),
    ]);
    const data = await evRes.json();
    events = data.events || [];
    honey = await honeyRes.json();
    persist = await persistRes.json();
    processData = await processRes.json();
    networkData = await networkRES.json();
    controlData = await controlRES.json();
    if (view === "honey") {
      const n = (honey && honey.alerts && honey.alerts.length) || 0;
      statusLine.textContent = n + " honey alerts";
    } else if(view === "persistence"){
      const n = (persist && persist.alerts && persist.alerts.length) || 0;
      statusLine.textContent = n + " persistence alerts";
    } else if(view === "process"){
      const a = (processData && processData.alerts && processData.alerts.length) || 0;
      const c = (processData && processData.correlated && processData.correlated.length) || 0;
      statusLine.textContent = a +"process, " + c + "correlated";
    } else if(view === "network"){
      const a = (networkData && networkData.alerts && networkData.alerts.length) || 0;
      const c = (networkData && networkData.linked && networkData.linked.length) || 0;
      statusLine.textContent = a+"network, " + c + "linked";
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