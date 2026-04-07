/* dep-vuln-triage UI — script.js */

const SESSION_ID = "ui_session";
let currentObs = null;
let cumulativeScore = 0;
let stepsHistory = [];

// ── Health check on load ─────────────────────────────────────────────────────

async function checkHealth() {
  try {
    const res = await fetch("/health");
    const data = await res.json();
    const badge = document.getElementById("health-badge");
    if (data.status === "healthy") {
      badge.textContent = "Live";
      badge.className = "badge ok";
    } else {
      badge.textContent = "Degraded";
      badge.className = "badge";
    }
  } catch {
    document.getElementById("health-badge").textContent = "Unreachable";
  }
}

// ── Utilities ────────────────────────────────────────────────────────────────

function showError(msg) {
  const el = document.getElementById("error-banner");
  el.textContent = msg;
  el.classList.add("visible");
}

function clearError() {
  const el = document.getElementById("error-banner");
  el.textContent = "";
  el.classList.remove("visible");
}

function setButtonLoading(id, loading, label) {
  const btn = document.getElementById(id);
  btn.disabled = loading;
  btn.textContent = loading ? "Loading..." : label;
}

function rewardClass(val) {
  if (val >= 0.6) return "reward-high";
  if (val >= 0.25) return "reward-mid";
  return "reward-low";
}

function scoreBarClass(pct) {
  if (pct >= 60) return "good";
  if (pct >= 30) return "mid";
  return "low";
}

// ── Action type toggle ───────────────────────────────────────────────────────

function onActionTypeChange() {
  const type = document.getElementById("action-type").value;
  const rowVer = document.getElementById("row-version");
  if (type === "propose_upgrade") {
    rowVer.classList.remove("hidden");
  } else {
    rowVer.classList.add("hidden");
  }
}

// ── Reset Environment ────────────────────────────────────────────────────────

async function resetEnv() {
  clearError();
  setButtonLoading("btn-reset", true, "Reset Environment");
  cumulativeScore = 0;
  stepsHistory = [];

  const task = document.getElementById("task-select").value;
  try {
    const res = await fetch(`/reset?session_id=${SESSION_ID}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ task_name: task, session_id: SESSION_ID })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const obs = await res.json();
    currentObs = obs;

    // Enable step button
    document.getElementById("btn-step").disabled = false;
    document.getElementById("episode-done-banner").classList.remove("visible");

    renderObservation(obs);
    resetStatsUI(obs);
    updateFeedback(null, null);

  } catch (e) {
    showError("Reset failed: " + e.message);
  } finally {
    setButtonLoading("btn-reset", false, "Reset Environment");
  }
}

// ── Send Action (Step) ───────────────────────────────────────────────────────

async function sendStep() {
  if (!currentObs) { showError("Reset the environment first."); return; }
  clearError();
  setButtonLoading("btn-step", true, "Send Action");

  const type = document.getElementById("action-type").value;
  const pkg = document.getElementById("action-package").value.trim();
  const version = document.getElementById("action-version").value.trim();
  const cve = document.getElementById("action-cve").value.trim();
  const reason = document.getElementById("action-reason").value.trim();

  if (!pkg && type !== "submit") {
    showError("Package name is required.");
    setButtonLoading("btn-step", false, "Send Action");
    return;
  }

  const action = {
    action_type: type,
    package: pkg || null,
    reason: reason || null,
  };
  if (type === "propose_upgrade" && version) action.proposed_version = version;
  if (cve) action.cve_id = cve;

  try {
    const res = await fetch(`/step?session_id=${SESSION_ID}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, session_id: SESSION_ID })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    const rewardVal = data.reward?.value ?? 0;
    const feedbackText = data.reward?.feedback ?? "";
    const done = data.done ?? false;
    const obs = data.observation;
    const info = data.info ?? {};

    cumulativeScore += rewardVal;
    stepsHistory.push(rewardVal);
    currentObs = obs;

    renderObservation(obs);
    updateFeedback(rewardVal, feedbackText);
    updateScoreUI(info, obs);

    if (done) {
      document.getElementById("episode-done-banner").classList.add("visible");
      document.getElementById("btn-step").disabled = true;
    }

  } catch (e) {
    showError("Step failed: " + e.message);
  } finally {
    setButtonLoading("btn-step", false, "Send Action");
  }
}

// ── Render Observation ───────────────────────────────────────────────────────

function renderObservation(obs) {
  if (!obs) return;

  // Manifest task label
  document.getElementById("manifest-task-label").textContent = obs.task_name ?? "";

  // Build manifest table
  const manifest = obs.manifest ?? {};
  const flagged = obs.flagged_packages ?? [];
  const depGraph = obs.dependency_graph ?? {};

  // Determine truly vulnerable packages from CVE db cross-reference (flag color)
  const tbody = document.getElementById("manifest-body");
  tbody.innerHTML = "";

  if (Object.keys(manifest).length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-muted" style="padding:16px;text-align:center">No manifest loaded.</td></tr>`;
  } else {
    for (const [pkg, ver] of Object.entries(manifest)) {
      const isFlagged = flagged.includes(pkg);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${escHtml(pkg)}</td>
        <td class="mono">${escHtml(ver)}</td>
        <td class="status-flag ${isFlagged ? "status-ok" : "status-neutral"}">${isFlagged ? "Flagged" : "—"}</td>
        <td>—</td>
      `;
      tbody.appendChild(tr);
    }
  }

  // Dependency tree
  const treeEl = document.getElementById("dep-tree-body");
  const treeCard = document.getElementById("dep-tree-card");
  if (Object.keys(depGraph).length > 0) {
    treeCard.style.display = "";
    let html = "";
    for (const [parent, children] of Object.entries(depGraph)) {
      html += `<div class="pkg">${escHtml(parent)}</div>`;
      if (Array.isArray(children)) {
        for (const child of children) {
          html += `<div class="child">${escHtml(child)}</div>`;
        }
      }
    }
    treeEl.innerHTML = html || '<span class="text-muted">Empty graph.</span>';
  } else {
    treeCard.style.display = "none";
  }
}

// ── Update feedback panel ────────────────────────────────────────────────────

function updateFeedback(reward, feedback) {
  const chip = document.getElementById("reward-chip");
  const box = document.getElementById("feedback-box");

  if (reward === null) {
    chip.textContent = "—";
    chip.className = "reward-chip reward-low";
    box.textContent = "Reset the environment to begin.";
    box.classList.remove("has-content");
    return;
  }

  chip.textContent = reward.toFixed(2);
  chip.className = `reward-chip ${rewardClass(reward)}`;

  if (feedback) {
    box.textContent = feedback;
    box.classList.add("has-content");
  } else {
    box.textContent = "No feedback.";
    box.classList.remove("has-content");
  }
}

// ── Update score + stats UI ──────────────────────────────────────────────────

function resetStatsUI(obs) {
  const maxSteps = obs?.max_steps ?? 0;

  document.getElementById("stat-score").textContent = "0.00";
  document.getElementById("stat-steps").textContent = "0";
  document.getElementById("stat-maxsteps").textContent = maxSteps;
  document.getElementById("score-display").textContent = "0.00";
  document.getElementById("score-label").textContent = obs?.task_name ?? "";

  const bar = document.getElementById("score-bar");
  bar.style.width = "0%";
  bar.className = "score-bar-fill low";

  document.getElementById("stat-correct").textContent = "0";
  document.getElementById("stat-fp").textContent = "0";
  document.getElementById("stat-total-flagged").textContent = "0";
  document.getElementById("stat-upgrades").textContent = "0";
}

function updateScoreUI(info, obs) {
  const steps = obs?.current_step ?? 0;
  const maxSteps = obs?.max_steps ?? 1;
  const score = cumulativeScore;

  document.getElementById("stat-score").textContent = score.toFixed(2);
  document.getElementById("stat-steps").textContent = steps;
  document.getElementById("stat-maxsteps").textContent = maxSteps;
  document.getElementById("score-display").textContent = score.toFixed(2);

  const pct = Math.min(score * 100, 100);
  const bar = document.getElementById("score-bar");
  bar.style.width = pct + "%";
  bar.className = `score-bar-fill ${scoreBarClass(pct)}`;

  document.getElementById("stat-correct").textContent = info.flags_correct ?? 0;
  document.getElementById("stat-fp").textContent = info.false_positives ?? 0;
  document.getElementById("stat-total-flagged").textContent = (obs?.flagged_packages ?? []).length;
  document.getElementById("stat-upgrades").textContent = (obs?.proposed_upgrades ?? []).length;
}

// ── Escape HTML ──────────────────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  checkHealth();
  onActionTypeChange();
});
