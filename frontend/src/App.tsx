/**
 * Application shell for the ThreatLens ChatKit client.
 *
 * ChatKit owns conversation rendering and protocol state; this component adds
 * assessment branding, backend health visibility, and a stable rate-limit ID.
 */
import { useEffect, useMemo, useState } from "react";
import { ChatKit, useChatKit } from "@openai/chatkit-react";

type RuntimeStatus = "connecting" | "ready" | "analyzing" | "issue";

type HealthPayload = {
  status?: string;
  mode?: "agents_sdk" | string;
  model?: string;
  intelligence?: string;
};

const DEFAULT_API = "http://localhost:8000/chatkit";

function getClientId() {
  // Stable anonymous ID lets the backend rate limiter group repeated requests
  // from one browser without adding login state to the assessment demo.
  const key = "threatlens-client-id";
  const existing = localStorage.getItem(key);
  if (existing) return existing;
  const value = `analyst-${crypto.randomUUID()}`;
  localStorage.setItem(key, value);
  return value;
}

function ShieldMark() {
  return (
    <svg viewBox="0 0 48 48" role="img" aria-label="ThreatLens shield">
      <path
        d="M24 3.7 41 10v12.5c0 10.3-6.4 18.4-17 22.2C13.4 40.9 7 32.8 7 22.5V10l17-6.3Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.4"
      />
      <path d="m15 26 5-5 4 4 9-9" fill="none" stroke="currentColor" strokeWidth="2.8" />
      <circle cx="15" cy="26" r="2" fill="currentColor" />
      <circle cx="20" cy="21" r="2" fill="currentColor" />
      <circle cx="24" cy="25" r="2" fill="currentColor" />
      <circle cx="33" cy="16" r="2" fill="currentColor" />
    </svg>
  );
}

function App() {
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus>("connecting");
  const [mode, setMode] = useState("checking");
  const [activeThread, setActiveThread] = useState("New investigation");
  const [health, setHealth] = useState<HealthPayload | null>(null);

  const apiUrl = import.meta.env.VITE_CHATKIT_API_URL || DEFAULT_API;
  const domainKey = import.meta.env.VITE_CHATKIT_DOMAIN_KEY || "local-dev";
  const clientId = useMemo(getClientId, []);

  const chatkitFetch: typeof fetch = async (input, init) => {
    // ChatKit accepts a custom fetch; adding this header keeps the backend
    // rate-limit logic independent from browser IP/proxy behavior.
    const headers = new Headers(init?.headers);
    headers.set("X-Client-Id", clientId);
    return fetch(input, { ...init, headers });
  };

  const { control } = useChatKit({
    api: {
      url: apiUrl,
      domainKey,
      fetch: chatkitFetch,
    },
    theme: {
      colorScheme: "light",
      radius: "sharp",
      density: "compact",
      typography: {
        baseSize: 14,
        fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
        fontFamilyMono: "IBM Plex Mono, ui-monospace, monospace",
      },
      color: {
        accent: { primary: "#e30613", level: 2 },
        grayscale: { hue: 214, tint: 0, shade: 0 },
      },
    },
    header: {
      enabled: true,
      title: { enabled: false },
    },
    history: { enabled: true, showDelete: true, showRename: true },
    startScreen: {
      // Keep the start screen focused on standalone investigation routes.
      greeting: "What should we investigate?",
      prompts: [
        {
          label: "Live IOC reputation",
          prompt: "Is 45.83.122.10 malicious?",
          icon: "search",
        },
        {
          label: "Actor and ATT&CK profile",
          prompt: "What TTPs is APT29 known for?",
          icon: "profile-card",
        },
        {
          label: "NVD exposure check",
          prompt: "We run Confluence 7.13 - are we exposed?",
          icon: "bug",
        },
      ],
    },
    composer: {
      placeholder: "Ask about an IOC, actor, ATT&CK TTP, CVE exposure, or pivot...",
      attachments: { enabled: false },
    },
    disclaimer: {
      text: "Live provider coverage varies by API key, quota, and source freshness. Verify before action.",
      highContrast: true,
    },
    threadItemActions: { feedback: true, retry: true },
    onResponseStart: () => setRuntimeStatus("analyzing"),
    onResponseEnd: () => setRuntimeStatus("ready"),
    onThreadChange: ({ threadId }) => {
      setActiveThread(threadId ? `Thread ${threadId.slice(-8)}` : "New investigation");
    },
    onError: () => setRuntimeStatus("issue"),
  });

  useEffect(() => {
    // Surface backend readiness in the shell before the analyst sends a message;
    // this also proves the UI is connected to the Agents SDK service.
    const healthUrl = new URL(apiUrl, window.location.href);
    healthUrl.pathname = "/healthz";
    fetch(healthUrl)
      .then(async (response) => {
        if (!response.ok) throw new Error("Health check failed");
        const payload = (await response.json()) as HealthPayload;
        setHealth(payload);
        setMode("Agents SDK");
        setRuntimeStatus("ready");
      })
      .catch(() => {
        setHealth(null);
        setMode("Backend unavailable");
        setRuntimeStatus("issue");
      });
  }, [apiUrl]);

  const statusLabel = {
    connecting: "Connecting",
    ready: "Ready",
    analyzing: "Analyzing",
    issue: "Needs attention",
  }[runtimeStatus];

  const intelligenceLabel =
    health?.intelligence === "live-apis" ? "LIVE THREAT APIS" : "HEALTH PENDING";
  const modelLabel = health?.model ? health.model.toUpperCase() : "MODEL PENDING";
  const routeLabel = health?.mode === "agents_sdk" ? "AGENTS SDK" : "HEALTH PENDING";

  return (
    <main className="app-shell">
      <aside className="side-rail">
        <div className="brand-lockup">
          <span className="brand-mark"><ShieldMark /></span>
          <div>
            <p className="eyebrow">EC-COUNCIL ASSESSMENT</p>
            <h1>ThreatLens</h1>
          </div>
        </div>

        <section className="mission-copy">
          <h2>Conversational Threat Intelligence Analyst</h2>
          <p>
            Natural-language SOC investigations routed through read-only tools,
            live intelligence sources, evidence citations, and injection guardrails.
          </p>
        </section>

        <nav className="capability-list" aria-label="Assessment routes">
          <p className="section-label">CORE ROUTES</p>
          <div><span>01</span><strong>IOC reputation</strong><small>VirusTotal / AbuseIPDB / OTX</small></div>
          <div><span>02</span><strong>Actor and TTP profile</strong><small>MITRE ATT&amp;CK evidence</small></div>
          <div><span>03</span><strong>Exposure reasoning</strong><small>NVD CVE version mapping</small></div>
          <div><span>04</span><strong>Entity pivoting</strong><small>Passive DNS / related domains</small></div>
        </nav>

        <section className="trust-card">
          <div className="trust-heading">
            <span className="pulse-dot" />
            <strong>Assessment coverage</strong>
          </div>
          <ul>
            <li>Intent routing</li>
            <li>Multi-turn state</li>
            <li>Injection defense</li>
            <li>Confidence and traces</li>
          </ul>
        </section>
      </aside>

      <section className="workspace">
        <header className="topbar compact-topbar">
          <span className="sr-only">Current thread: {activeThread}</span>
          <div className="runtime-block">
            <span className={`status-pill ${runtimeStatus}`}>
              <i /> {statusLabel}
            </span>
            <span className="mode-label">{mode}</span>
          </div>
        </header>

        <div className="intel-strip">
          <div><span>DATA MODE</span><strong>{intelligenceLabel}</strong></div>
          <div><span>ROUTING</span><strong>{routeLabel} / 5 TOOLS</strong></div>
          <div><span>MODEL</span><strong>{modelLabel}</strong></div>
          <div><span>OUTPUT</span><strong>SOURCES + CONFIDENCE</strong></div>
        </div>

        <div className="chat-panel">
          <div className="chat-panel-header" aria-hidden="true">
            <span className="live-source-dot" />
            <span>Live investigation console</span>
            <i>VT / AbuseIPDB / OTX / Shodan / NVD / MITRE</i>
          </div>
          <ChatKit control={control} className="chatkit-frame" />
        </div>

        <footer className="workspace-footer">
          <span>THREATLENS / EC-COUNCIL AGENTIC AI ASSESSMENT</span>
          <span>DEFENSIVE ANALYSIS ONLY / NO CONTAINMENT ACTIONS</span>
        </footer>
      </section>
    </main>
  );
}

export default App;
