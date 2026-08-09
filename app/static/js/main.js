const state = {
    token: localStorage.getItem("sentinel_token") || "",
    stats: null
};

const $ = (id) => document.getElementById(id);

function showToast(message) {
    const toast = $("toast");
    toast.textContent = message;
    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
    }, 2500);
}

function setSection(section) {
    document.querySelectorAll(".content-section").forEach((element) => {
        element.classList.add("hidden");
    });

    $("loginSection").classList.add("hidden");

    const target = $(`${section}Section`);

    if (target) {
        target.classList.remove("hidden");
    }

    document.querySelectorAll(".nav-item").forEach((button) => {
        button.classList.toggle(
            "active",
            button.dataset.section === section
        );
    });
}

function showLogin() {
    $("loginSection").classList.remove("hidden");
    $("dashboardSection").classList.add("hidden");
    $("detectionSection").classList.add("hidden");
    $("eventsSection").classList.add("hidden");
    $("gatewaySection").classList.add("hidden");
}

function showDashboard() {
    $("loginSection").classList.add("hidden");
    setSection("dashboard");
}

async function apiRequest(path, options = {}) {
    const headers = {
        ...(options.headers || {})
    };

    if (state.token) {
        headers.Authorization = `Bearer ${state.token}`;
    }

    const response = await fetch(path, {
        ...options,
        headers
    });

    let data = null;

    try {
        data = await response.json();
    } catch {
        data = null;
    }

    if (!response.ok) {
        const message =
            data?.detail ||
            `Request failed with HTTP ${response.status}`;

        throw new Error(message);
    }

    return data;
}

async function checkHealth() {
    try {
        const data = await apiRequest("/health");

        const dot = document.querySelector(".status-dot");
        const text = document.querySelector(".connection span:last-child");

        dot.classList.add("online");
        text.textContent =
            `API online · Redis ${data.redis} · DB ${data.database}`;
    } catch {
        const text = document.querySelector(".connection span:last-child");
        text.textContent = "API unavailable";
    }
}

async function login(email, password) {
    const body = new URLSearchParams();

    body.append("username", email);
    body.append("password", password);

    const response = await fetch("/auth/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.detail || "Authentication failed");
    }

    state.token = data.access_token;

    localStorage.setItem("sentinel_token", state.token);

    showToast("Authentication successful");

    showDashboard();

    await loadDashboard();
}

async function logout() {
    const token = state.token;

    try {
        if (token) {
            await fetch("/auth/logout", {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                },
                cache: "no-store",
            });
        }
    } catch {
        // Continue local cleanup even if the server is unavailable.
    }

    state.token = "";
    localStorage.removeItem("sentinel_token");

    showLogin();

    $("loginMessage").textContent = "";

    showToast("Logged out");
}

function renderBarChart(elementId, data) {
    const container = $(elementId);

    container.innerHTML = "";

    const entries = Object.entries(data || {});

    if (!entries.length) {
        container.innerHTML =
            '<div class="empty">No data available.</div>';
        return;
    }

    const max = Math.max(
        ...entries.map(([, value]) => Number(value) || 0),
        1
    );

    entries
        .sort((a, b) => Number(b[1]) - Number(a[1]))
        .forEach(([label, value]) => {
            const row = document.createElement("div");
            row.className = "bar-row";

            const percentage =
                ((Number(value) || 0) / max) * 100;

            row.innerHTML = `
                <div class="bar-label">${escapeHtml(label)}</div>
                <div class="bar-track">
                    <div
                        class="bar-fill"
                        style="width:${percentage}%"
                    ></div>
                </div>
                <div class="bar-value">${value}</div>
            `;

            container.appendChild(row);
        });
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function levelClass(level) {
    const normalized = String(level || "NONE").toLowerCase();

    if (normalized === "critical") {
        return "badge-critical";
    }

    if (normalized === "high") {
        return "badge-high";
    }

    if (normalized === "medium") {
        return "badge-medium";
    }

    if (normalized === "low") {
        return "badge-low";
    }

    return "badge-none";
}

function renderEvents(events, targetId) {
    const table = $(targetId);

    table.innerHTML = "";

    if (!events || !events.length) {
        table.innerHTML = `
            <tr>
                <td colspan="7" class="empty">
                    No security events found.
                </td>
            </tr>
        `;
        return;
    }

    events.forEach((event) => {
        const row = document.createElement("tr");

        row.innerHTML = `
            <td>${escapeHtml(event.id ?? "-")}</td>
            <td>${escapeHtml(event.ip_address ?? "-")}</td>
            <td>${escapeHtml(event.method ?? "-")}</td>
            <td>${escapeHtml(event.path ?? "-")}</td>
            <td>${escapeHtml(event.attack_type ?? "-")}</td>
            <td>${escapeHtml(event.risk_score ?? "-")}</td>
            <td>
                <span class="badge ${levelClass(event.risk_level)}">
                    ${escapeHtml(event.risk_level ?? "NONE")}
                </span>
            </td>
        `;

        table.appendChild(row);
    });
}

async function loadStats() {
    const data = await apiRequest("/admin/stats");

    state.stats = data;

    $("totalEvents").textContent =
        data.total_events ?? 0;

    $("averageRisk").textContent =
        data.average_risk_score ?? 0;

    $("criticalEvents").textContent =
        data.risk_levels?.CRITICAL ?? 0;

    $("highEvents").textContent =
        data.risk_levels?.HIGH ?? 0;

$("blockedEvents").textContent =
    data.blocked_events ?? 0;

$("detectedEvents").textContent =
    data.detected_events ?? 0;

    renderBarChart(
        "riskChart",
        data.risk_levels || {}
    );

    renderBarChart(
        "attackChart",
        data.attack_types || {}
    );

    renderEvents(
        data.recent_events || [],
        "eventsTable"
    );

    $("lastUpdated").textContent =
        `Updated ${new Date().toLocaleTimeString()}`;
}

async function loadEvents(targetId = "allEventsTable") {
    const data = await apiRequest(
        "/admin/attacks?page=1&limit=50"
    );

    let events = [];

    if (Array.isArray(data)) {
        events = data;
    } else if (Array.isArray(data?.events)) {
        events = data.events;
    } else if (Array.isArray(data?.items)) {
        events = data.items;
    } else if (Array.isArray(data?.results)) {
        events = data.results;
    }

    renderEvents(events, targetId);
}

async function loadDashboard() {
    try {
        await loadStats();
    } catch (error) {
        if (
            error.message.toLowerCase().includes("authenticated") ||
            error.message.toLowerCase().includes("credentials")
        ) {
            logout();
            $("loginMessage").textContent =
                "Session expired. Please sign in again.";
            return;
        }

        showToast(error.message);
    }
}

async function runDetection(event) {
    event.preventDefault();

    const url = $("detectionUrl").value.trim();
    const body = $("detectionBody").value;

    let headers = {};

    const rawHeaders = $("detectionHeaders").value.trim();

    if (rawHeaders) {
        try {
            headers = JSON.parse(rawHeaders);
        } catch {
            $("detectionResult").classList.remove("hidden");
            $("detectionResult").innerHTML =
                `<div class="message">
                    Headers must be valid JSON.
                </div>`;
            return;
        }
    }

    try {
        const response = await fetch("/detect", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(state.token
                    ? { Authorization: `Bearer ${state.token}` }
                    : {})
            },
            body: JSON.stringify({
                url,
                body,
                headers
            })
        });

        let result = null;

        try {
            result = await response.json();
        } catch {
            result = {
                detail: await response.text()
            };
        }

        const detected =
            result.detected ??
            (response.status >= 400);

        const blocked =
            result.blocked ??
            (response.status === 403);

        const score =
            result.score ??
            result.risk_score ??
            0;

        const level =
            result.level ??
            result.risk_level ??
            "NONE";

        const attacks =
            result.attacks ??
            result.detected_attacks ??
            [];

        const reason =
            result.reason ??
            result.detail ??
            "No attack patterns detected";

        $("detectionResult").classList.remove("hidden");

        $("detectionResult").innerHTML = `
            <div class="result-header">
                <div>
                    <div class="stat-label">DETECTION RESULT</div>
                    <div class="result-score">
                        ${escapeHtml(score)}
                    </div>
                </div>

                <span class="badge ${
                    level === "CRITICAL"
                        ? "badge-critical"
                        : level === "HIGH"
                            ? "badge-high"
                            : level === "MEDIUM"
                                ? "badge-medium"
                                : "badge-low"
                }">
                    ${escapeHtml(level)}
                </span>
            </div>

            <p>
                <strong>Detected:</strong>
                ${detected ? "YES" : "NO"}
            </p>

            <p>
                <strong>Blocked:</strong>
                ${blocked ? "YES" : "NO"}
            </p>

            <p>
                <strong>HTTP Status:</strong>
                ${escapeHtml(response.status)}
            </p>

            <p>
                <strong>Reason:</strong>
                ${escapeHtml(reason)}
            </p>

            <div class="result-attacks">
                ${
                    attacks.length
                        ? attacks.map(
                            (attack) =>
                                `<span class="attack-chip">
                                    ${escapeHtml(attack)}
                                </span>`
                          ).join("")
                        : '<span class="attack-chip">No attack detected</span>'
                }
            </div>
        `;

        showToast(
            blocked
                ? "Malicious request blocked"
                : detected
                    ? "Threat detected"
                    : "Request analyzed"
        );

    } catch (error) {
        $("detectionResult").classList.remove("hidden");

        $("detectionResult").innerHTML =
            `<div class="message">
                ${escapeHtml(error.message)}
            </div>`;
    }
}

async function runGateway(event) {
    event.preventDefault();

    const method = $("gatewayMethod").value;
    let path = $("gatewayPath").value.trim();

    if (!path.startsWith("/")) {
        path = "/" + path;
    }

    const body = $("gatewayBody").value;

    const headers = state.token
        ? { Authorization: `Bearer ${state.token}` }
        : {};

    try {
        const response = await fetch(`/gateway${path}`, {
            method,
            headers: body
                ? {
                      ...headers,
                      "Content-Type": "application/json",
                  }
                : headers,
            body: ["GET", "HEAD"].includes(method)
                ? undefined
                : body || undefined,
        });

        /*
         * Read the response body exactly once.
         * Trying response.json() and then response.text()
         * consumes the same browser Response stream twice.
         */
        const rawBody = await response.text();

        let payload;

        try {
            payload = JSON.parse(rawBody);
        } catch {
            payload = rawBody;
        }

        const decision =
            response.headers.get("X-Sentinel-Decision") || "UNKNOWN";

        const score =
            response.headers.get("X-Sentinel-Risk-Score") || "n/a";

        const requestId =
            response.headers.get("X-Sentinel-Request-ID") || "n/a";

        $("gatewayResult").classList.remove("hidden");

        $("gatewayResult").innerHTML = `
            <div class="result-header">
                <div>
                    <div class="stat-label">GATEWAY DECISION</div>
                    <div class="result-score">
                        ${escapeHtml(response.status)}
                    </div>
                </div>

                <span class="badge ${
                    response.ok ? "badge-low" : "badge-critical"
                }">
                    ${escapeHtml(decision)}
                </span>
            </div>

            <p>
                <strong>HTTP Status:</strong>
                ${escapeHtml(response.status)}
            </p>

            <p>
                <strong>Risk Score:</strong>
                ${escapeHtml(score)}
            </p>

            <p>
                <strong>Request ID:</strong>
                ${escapeHtml(requestId)}
            </p>

            <p><strong>Response:</strong></p>

            <pre class="gateway-response">${escapeHtml(
                typeof payload === "string"
                    ? payload
                    : JSON.stringify(payload, null, 2)
            )}</pre>
        `;

        showToast(
            response.ok
                ? "Request forwarded by gateway"
                : "Request blocked by SentinelAPI"
        );

        await loadDashboard();

    } catch (error) {
        $("gatewayResult").classList.remove("hidden");

        $("gatewayResult").innerHTML =
            `<div class="message">${escapeHtml(error.message)}</div>`;
    }
}

$("loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = $("email").value.trim();
    const password = $("password").value;

    $("loginMessage").textContent = "";

    try {
        await login(email, password);
    } catch (error) {
        $("loginMessage").textContent = error.message;
    }
});

$("logoutBtn").addEventListener("click", logout);

$("refreshBtn").addEventListener("click", async () => {
    await loadDashboard();
});

$("loadEventsBtn").addEventListener("click", async () => {
    try {
        await loadEvents("eventsTable");
        showToast("Events refreshed");
    } catch (error) {
        showToast(error.message);
    }
});

$("reloadEventsBtn").addEventListener("click", async () => {
    try {
        await loadEvents("allEventsTable");
        showToast("Events refreshed");
    } catch (error) {
        showToast(error.message);
    }
});

$("detectionForm").addEventListener(
    "submit",
    runDetection
);

$("gatewayForm").addEventListener(
    "submit",
    runGateway
);

document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", async () => {
        const section = button.dataset.section;

        if (!state.token) {
            showLogin();
            return;
        }

        setSection(section);

        if (section === "dashboard") {
            await loadDashboard();
        }

        if (section === "events") {
            try {
                await loadEvents("allEventsTable");
            } catch (error) {
                showToast(error.message);
            }
        }
    });
});

async function initialize() {
    await checkHealth();

    if (state.token) {
        try {
            await apiRequest("/auth/me");
            showDashboard();
            await loadDashboard();
        } catch {
            logout();
        }
    } else {
        showLogin();
    }
}

initialize();
