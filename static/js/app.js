/**
 * SentinelFlow NIDS — Frontend
 */

// ---------- View switching ----------
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("view-" + btn.dataset.view).classList.add("active");
    document.getElementById("view-title").textContent = btn.textContent.trim();
  });
});

// ---------- Overview ----------
async function loadOverview() {
  try {
    const res = await fetch("/api/overview");
    const d = await res.json();
    document.getElementById("ov-total").textContent = d.total_records.toLocaleString();
    document.getElementById("ov-attacks").textContent = d.attacks.toLocaleString();
    document.getElementById("ov-normal").textContent = d.normal.toLocaleString();
    document.getElementById("ov-precision").textContent = Math.round(d.attack_precision * 100) + "%";
    document.getElementById("ov-recall").textContent = Math.round(d.attack_recall * 100) + "%";
    document.getElementById("ov-fnr").textContent = Math.round(d.false_negative_rate * 100) + "%";

    const statusLabel = document.getElementById("model-status-label");
    if (statusLabel) {
      statusLabel.textContent = d.model_status === "loaded" ? "Model loaded" : "Demo mode";
    }
  } catch (err) {
    console.error("Overview load failed:", err);
  }
}

async function loadModelInfo() {
  try {
    const res = await fetch("/api/model-info");
    const d = await res.json();
    document.getElementById("mi-type").textContent = d.model_type || "—";
    document.getElementById("mi-dataset").textContent = d.dataset || "—";
    document.getElementById("mi-trees").textContent = d.n_estimators ?? "—";
    document.getElementById("mi-precision").textContent = Math.round((d.attack_precision || 0) * 100) + "%";
    document.getElementById("mi-recall").textContent = Math.round((d.attack_recall || 0) * 100) + "%";
    document.getElementById("mi-status").textContent = d.status || "—";
  } catch (err) {
    console.error("Model info load failed:", err);
  }
}

// ---------- Charts ----------
async function loadCharts() {
  try {
    const res = await fetch("/api/distribution");
    const data = await res.json();
    const textColor = "#94A3B8";
    const gridColor = "rgba(255,255,255,0.06)";

    new Chart(document.getElementById("chart-categories"), {
      type: "bar",
      data: {
        labels: data.categories.labels,
        datasets: [{
          data: data.categories.values,
          backgroundColor: "#38BDF8",
          borderRadius: 4,
          maxBarThickness: 42,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: textColor, font: { family: "IBM Plex Mono", size: 11 } } },
          y: { grid: { color: gridColor }, ticks: { color: textColor, font: { family: "IBM Plex Mono", size: 11 } } },
        },
      },
    });

    new Chart(document.getElementById("chart-split"), {
      type: "doughnut",
      data: {
        labels: data.split.labels,
        datasets: [{
          data: data.split.values,
          backgroundColor: data.split.labels.map((l) => l === "Attack" ? "#EF4444" : "#22C55E"),
          borderWidth: 0,
        }],
      },
      options: {
        cutout: "68%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: textColor, font: { family: "Inter", size: 12 }, padding: 16 },
          },
        },
      },
    });
  } catch (err) {
    console.error("Charts load failed:", err);
  }
}

// ---------- Notifications ----------
const notifyBtn = document.getElementById("notify-btn");

function updateNotifyBtn() {
  if (!("Notification" in window)) {
    notifyBtn.textContent = "Alerts unsupported";
    notifyBtn.disabled = true;
    return;
  }
  notifyBtn.textContent = Notification.permission === "granted"
    ? "Desktop Alerts Enabled"
    : "Enable Desktop Alerts";
}

if (notifyBtn) {
  notifyBtn.addEventListener("click", async () => {
    if (!("Notification" in window)) return;
    await Notification.requestPermission();
    updateNotifyBtn();
  });
}

function browserNotify(alert) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  new Notification("SentinelFlow — Attack Detected", {
    body: `${alert.type} from ${alert.source_ip} — ${alert.confidence}% confidence`,
    tag: "sentinelflow-alert",
  });
}

// ---------- Alert Modal ----------
const modal = document.getElementById("alert-modal");
const modalClose = document.getElementById("modal-close");

if (modalClose) {
  modalClose.addEventListener("click", () => modal.classList.remove("show"));
}
if (modal) {
  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.remove("show");
  });
}

function showAlertModal(alert) {
  document.getElementById("m-source").textContent = alert.source_ip;
  document.getElementById("m-dest").textContent = alert.dest_ip;
  document.getElementById("m-protocol").textContent = alert.protocol;
  document.getElementById("m-port").textContent = alert.dest_port;
  document.getElementById("m-class").textContent = alert.type;
  document.getElementById("m-confidence").textContent = alert.confidence + "%";
  document.getElementById("m-severity").textContent = alert.severity;
  document.getElementById("m-time").textContent = `${alert.date} ${alert.time}`;
  modal.classList.add("show");
  browserNotify(alert);
}

// ---------- Live Monitor ----------
const simBtn = document.getElementById("sim-btn");
const packetSlider = document.getElementById("packet-count");
const packetVal = document.getElementById("packet-count-val");
const terminal = document.getElementById("terminal");
const progressFill = document.getElementById("progress-fill");

let eventSource = null;

if (packetSlider && packetVal) {
  packetSlider.addEventListener("input", () => {
    packetVal.textContent = packetSlider.value;
  });
}

if (simBtn) {
  simBtn.addEventListener("click", () => {
    if (!eventSource) runSimulation(parseInt(packetSlider.value, 10));
  });
}

function runSimulation(n) {
  terminal.innerHTML = "";
  progressFill.style.width = "0%";
  document.getElementById("c-inspected").textContent = "0";
  document.getElementById("c-alerts").textContent = "0";
  document.getElementById("c-rate").textContent = "0%";
  simBtn.disabled = true;
  simBtn.textContent = "Monitoring…";

  eventSource = new EventSource(`/api/simulate?n=${n}`);

  eventSource.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    if (payload.done) {
      stopSimulation();
      return;
    }

    const line = document.createElement("div");
    line.className = "log-line " + (payload.is_attack ? "attack" : "normal");
    line.textContent = `#${String(payload.packet).padStart(3, "0")}  ${
      payload.is_attack ? "ATTACK " : "normal "
    } conf=${(payload.probability * 100).toFixed(1)}%  true=${payload.true_label}`;
    terminal.prepend(line);

    document.getElementById("c-inspected").textContent = payload.packet;
    document.getElementById("c-alerts").textContent = payload.alert_count;
    document.getElementById("c-rate").textContent =
      Math.round((payload.alert_count / payload.packet) * 100) + "%";
    progressFill.style.width = (payload.packet / payload.total) * 100 + "%";

    if (payload.alert) showAlertModal(payload.alert);
  };

  eventSource.onerror = () => stopSimulation();
}

function stopSimulation() {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  simBtn.disabled = false;
  simBtn.textContent = "Start Monitoring";
  loadAlerts();
}

// ---------- CSV Analysis ----------
const csvAnalyzeBtn = document.getElementById("csv-analyze-btn");
const csvDownloadBtn = document.getElementById("csv-download-btn");

if (csvAnalyzeBtn) {
  csvAnalyzeBtn.addEventListener("click", async () => {
    const fileInput = document.getElementById("csv-file");
    const errorBox = document.getElementById("csv-error");
    const summaryBox = document.getElementById("csv-summary");
    const tbody = document.querySelector("#csv-table tbody");

    errorBox.textContent = "";
    summaryBox.innerHTML = "";
    tbody.innerHTML = "";

    if (!fileInput.files.length) {
      errorBox.textContent = "Choose a CSV / TXT file first.";
      return;
    }

    csvAnalyzeBtn.disabled = true;
    csvAnalyzeBtn.textContent = "Analyzing…";

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
      const res = await fetch("/api/analyze-csv", { method: "POST", body: formData });
      const data = await res.json();

      if (!res.ok) {
        errorBox.textContent = data.error || "Analysis failed.";
        return;
      }

      summaryBox.innerHTML = `
        <span><strong>${data.summary.total_rows}</strong> rows analyzed</span>
        <span><strong>${data.summary.attacks}</strong> attacks</span>
        <span><strong>${data.summary.normal}</strong> normal</span>
      `;

      data.rows.forEach((r) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${r.row}</td>
          <td class="${r.is_attack ? "sev-high" : "sev-low"}">${r.is_attack ? "Attack" : "Normal"}</td>
          <td>${r.probability}%</td>
        `;
        tbody.appendChild(tr);
      });

      if (csvDownloadBtn) csvDownloadBtn.disabled = false;
      loadAlerts();
    } catch (err) {
      errorBox.textContent = "Network error while uploading file.";
      console.error(err);
    } finally {
      csvAnalyzeBtn.disabled = false;
      csvAnalyzeBtn.textContent = "Analyze";
    }
  });
}

if (csvDownloadBtn) {
  csvDownloadBtn.addEventListener("click", () => {
    window.location.href = "/api/download-results";
  });
}

// ---------- Alerts table ----------
async function loadAlerts() {
  try {
    const res = await fetch("/api/alerts");
    const alerts = await res.json();
    const tbody = document.querySelector("#alerts-table tbody");
    if (!tbody) return;

    tbody.innerHTML = "";
    alerts.forEach((a) => {
      const sevClass =
        a.severity === "High" ? "sev-high" :
        a.severity === "Medium" ? "sev-medium" : "sev-low";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${a.time}</td>
        <td>${a.source_ip}</td>
        <td>${a.dest_ip}</td>
        <td>${a.protocol}</td>
        <td>${a.type}</td>
        <td>${a.confidence}%</td>
        <td class="${sevClass}">${a.severity}</td>
        <td>${a.origin}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Alerts load failed:", err);
  }
}

// ---------- Init ----------
updateNotifyBtn();
loadOverview();
loadModelInfo();
loadCharts();
loadAlerts();