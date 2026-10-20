const rows = document.getElementById("rows");
const statusLine = document.getElementById("status-line");
const viewTitle = document.getElementById("view-title");
const navItems = Array.from(document.querySelectorAll(".nav-item"));

let view = "logs"; // logs | heartbeats
let events = [];

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

function render() {
  const list = visibleEvents();
  viewTitle.textContent = view === "heartbeats" ? "Heartbeats" : "Logs";

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
        '<td>' +
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

function setView(next) {
  view = next;
  navItems.forEach((btn) => {
    btn.classList.toggle("is-on", btn.getAttribute("data-view") === next);
  });
  render();
}

async function refresh() {
  try {
    const res = await fetch("/api/events?limit=500", { cache: "no-store" });
    const data = await res.json();
    events = data.events || [];
    const logsCount = events.filter((e) => e.kind !== "heartbeat").length;
    const hbCount = events.filter((e) => e.kind === "heartbeat").length;
    statusLine.textContent =
      logsCount + " logs, " + hbCount + " heartbeats";
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