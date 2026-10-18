const body = document.getElementById("events-body")
const meta = document.getElementById("meta")
const filterKind = document.getElementById("filter-kind")
const countAlert = document.getElementById("count-alert")
const countSystem = document.getElementById("count-system")
const countTotal = document.getElementById("count-total");
let allEvents = [];

function messageOf(event) {
  return event.message || event.massage || "";
}

function detailOf(event) {
  const skip = new Set(["time", "kind", "message", "massage"]);
  const parts = [];
  for (const [key, value] of Object.entries(event)) {
    if (skip.has(key)) continue;
    parts.push(`${key}=${value}`);
  }
  return parts.join(" · ");
}

function formatTime(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function render() {
  const kind = filterKind.value;
  const events = allEvents.filter((e) => kind === "all" || e.kind === kind);
  if (!events.length) {
    body.innerHTML = `<tr class="empty"><td colspan="4">No events for this filter.</td></tr>`;
    return;
  }

  body.innerHTML = events
    .map((event) => {
      const kindClass = `kind-${event.kind || "other"}`;
      return `
        <tr class="${kindClass}">
          <td class="time">${formatTime(event.time)}</td>
          <td class="kind">${event.kind || "other"}</td>
          <td>${escapeHtml(messageOf(event))}</td>
          <td class="detail">${escapeHtml(detailOf(event))}</td>
        </tr>
      `;
    })
    .join("");
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function refresh() {
  try {
    const [eventsRes, statusRes] = await Promise.all([
      fetch("/api/events?limit=200", { cache: "no-store" }),
      fetch("/api/status", { cache: "no-store" }),
    ]);
    const eventsData = await eventsRes.json();
    const statusData = await statusRes.json();
    allEvents = eventsData.events || [];
    countAlert.textContent = statusData.counts?.alert ?? 0;
    countSystem.textContent = statusData.counts?.system ?? 0;
    countTotal.textContent = statusData.total ?? allEvents.length;
    meta.textContent = `local · ${statusData.total ?? 0} events · refresh 2s`;
    render();
  } catch (err) {
    meta.textContent = "dashboard offline or agent log missing";
  }
}
filterKind.addEventListener("change", render);
refresh();
setInterval(refresh, 2000);