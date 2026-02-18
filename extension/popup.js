const API_BASE = "http://127.0.0.1:8000";

const scanBtn = document.getElementById("scan-btn");
const btnText = document.getElementById("btn-text");
const btnLoading = document.getElementById("btn-loading");
const currentUrlEl = document.getElementById("current-url");
const scanSection = document.getElementById("scan-section");
const resultSection = document.getElementById("result-section");
const errorSection = document.getElementById("error-section");
const errorMessage = document.getElementById("error-message");
const retryBtn = document.getElementById("retry-btn");
const scoreValue = document.getElementById("score-value");
const scoreLabel = document.getElementById("score-label");
const indicatorsList = document.getElementById("indicators-list");

let pageUrl = "";

// Get current tab URL
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0] && tabs[0].url) {
    pageUrl = tabs[0].url;
    currentUrlEl.textContent = pageUrl.length > 60 ? pageUrl.slice(0, 57) + "..." : pageUrl;
    scanBtn.disabled = false;
  } else {
    currentUrlEl.textContent = "Unable to detect URL";
  }
});

async function scanPage() {
  scanBtn.disabled = true;
  btnText.classList.add("hidden");
  btnLoading.classList.remove("hidden");
  errorSection.classList.add("hidden");
  resultSection.classList.add("hidden");

  try {
    const response = await fetch(`${API_BASE}/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: pageUrl }),
    });

    if (!response.ok) {
      throw new Error("Server returned an error");
    }

    const data = await response.json();
    showResults(data);
  } catch (err) {
    showError(err.message || "Failed to connect to the analysis server.");
  } finally {
    btnText.classList.remove("hidden");
    btnLoading.classList.add("hidden");
    scanBtn.disabled = false;
  }
}

function showResults(data) {
  scanSection.classList.add("hidden");
  resultSection.classList.remove("hidden");

  // Score
  const color = data.label === "safe" ? "#22c55e" : data.label === "suspicious" ? "#f59e0b" : "#ef4444";
  scoreValue.textContent = data.overall_score;
  scoreValue.style.color = color;
  scoreLabel.textContent = data.label.charAt(0).toUpperCase() + data.label.slice(1);
  scoreLabel.className = `score-label label-${data.label}`;

  // Top 3 indicators
  indicatorsList.innerHTML = "";
  const top3 = (data.indicators || []).slice(0, 3);
  top3.forEach((ind) => {
    const div = document.createElement("div");
    div.className = "indicator-item";
    div.innerHTML = `
      <span class="severity-dot severity-${ind.severity}"></span>
      <span>${ind.name}</span>
    `;
    indicatorsList.appendChild(div);
  });

  if (top3.length === 0) {
    const div = document.createElement("div");
    div.className = "indicator-item";
    div.textContent = "No threat indicators detected.";
    indicatorsList.appendChild(div);
  }
}

function showError(msg) {
  errorSection.classList.remove("hidden");
  errorMessage.textContent = msg;
}

scanBtn.addEventListener("click", scanPage);
retryBtn.addEventListener("click", () => {
  errorSection.classList.add("hidden");
  resultSection.classList.add("hidden");
  scanSection.classList.remove("hidden");
  scanPage();
});
