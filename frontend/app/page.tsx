"use client";
import { useState, useEffect, useRef, useCallback } from "react";

type ThemeMode = "dark" | "light";
interface Theme { bg: string; bgCard: string; bgInput: string; bgNav: string; border: string; text: string; textMuted: string; textSub: string; accent: string; accentDark: string; accentGlow: string; danger: string; safe: string; warning: string; gradientHero: string; shadow: string; shadowGlow: string; }
interface ScanEntry { id: number; url: string; is_phishing: boolean; confidence: number; timestamp: string; username: string; }
interface User { username: string; email?: string; }
interface Prediction { is_phishing: boolean; confidence: number; }

const themes: Record<ThemeMode, Theme> = {
  dark: { bg: "#0a0f0d", bgCard: "#0e1a14", bgInput: "#111f17", bgNav: "rgba(10,15,13,0.95)", border: "#1e3a2a", text: "#e2f5ec", textMuted: "#6b9e7e", textSub: "#9ec4b0", accent: "#00e676", accentDark: "#00b359", accentGlow: "rgba(0,230,118,0.15)", danger: "#ff4d6d", safe: "#00e676", warning: "#ffd166", gradientHero: "linear-gradient(135deg, #0a0f0d 0%, #071a0f 50%, #0a1a10 100%)", shadow: "0 8px 32px rgba(0,0,0,0.6)", shadowGlow: "0 0 40px rgba(0,230,118,0.1)" },
  light: { bg: "#f0faf4", bgCard: "#ffffff", bgInput: "#f5fdf8", bgNav: "rgba(240,250,244,0.95)", border: "#b8e8cc", text: "#0d2b1a", textMuted: "#4a8a63", textSub: "#2d6645", accent: "#00a854", accentDark: "#007a3d", accentGlow: "rgba(0,168,84,0.12)", danger: "#e02020", safe: "#00a854", warning: "#d97700", gradientHero: "linear-gradient(135deg, #e8f8ef 0%, #d4f0e0 50%, #e0f5ea 100%)", shadow: "0 8px 32px rgba(0,0,0,0.12)", shadowGlow: "0 0 40px rgba(0,168,84,0.08)" }
};

// ── API — all calls have AbortController + 10 s timeout ──────────────────────
const API = process.env.NEXT_PUBLIC_API_URL || "https://cybershield-ai-tnmu.onrender.com";

function fetchWithTimeout(url: string, options: RequestInit = {}, ms = 10000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...options, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

async function apiScan(url: string, username: string): Promise<Prediction> {
  const res = await fetchWithTimeout(`${API}/scan`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, username }),
  });
  if (!res.ok) throw new Error("Scan failed");
  return res.json();
}

async function apiGetPredictions(username: string): Promise<ScanEntry[]> {
  const res = await fetchWithTimeout(`${API}/api/predictions/${encodeURIComponent(username)}?limit=50`, {}, 8000);
  if (!res.ok) return [];
  return res.json();
}

async function apiChat(message: string, history: { role: string; content: string }[]): Promise<string> {
  const res = await fetchWithTimeout(`${API}/api/chat`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, history }),
  }, 12000);
  if (!res.ok) throw new Error("Chat failed");
  const data = await res.json(); return data.response;
}

async function apiLogin(username: string, password: string): Promise<{ success: boolean; username: string; email?: string }> {
  const res = await fetchWithTimeout(`${API}/api/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  }, 8000);
  if (!res.ok) throw new Error("Invalid username or password");
  return res.json();
}

async function apiSignup(username: string, password: string, email: string): Promise<{ success: boolean; username: string }> {
  const res = await fetchWithTimeout(`${API}/api/signup`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, email }),
  }, 8000);
  if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error((err as {detail?: string}).detail || "Signup failed"); }
  return res.json();
}

// ── Skeleton loader ───────────────────────────────────────────────────────────
function Skeleton({ w = "100%", h = 16, r = 6 }: { w?: string | number; h?: number; r?: number }) {
  return <div style={{ width: w, height: h, borderRadius: r, background: "linear-gradient(90deg, var(--sk1) 25%, var(--sk2) 50%, var(--sk1) 75%)", backgroundSize: "200% 100%", animation: "shimmer 1.2s infinite" }} />;
}

// ── Donut chart ───────────────────────────────────────────────────────────────
function PieChart({ phishing, safe, t }: { phishing: number; safe: number; t: Theme }) {
  const total = phishing + safe;
  if (total === 0) return <div style={{ textAlign: "center", color: t.textMuted, padding: "28px 0", fontSize: 13 }}>No scan data yet</div>;
  const r = 54, cx = 70, cy = 70, circ = 2 * Math.PI * r;
  const phishDash = (phishing / total) * circ, safeDash = (safe / total) * circ;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
      <svg width={140} height={140} viewBox="0 0 140 140">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={t.border} strokeWidth={18} />
        {safe > 0 && <circle cx={cx} cy={cy} r={r} fill="none" stroke={t.safe} strokeWidth={18} strokeDasharray={`${safeDash} ${circ}`} strokeDashoffset={-phishDash} style={{ transform: "rotate(-90deg)", transformOrigin: `${cx}px ${cy}px`, transition: "stroke-dasharray 0.6s ease" }} />}
        {phishing > 0 && <circle cx={cx} cy={cy} r={r} fill="none" stroke={t.danger} strokeWidth={18} strokeDasharray={`${phishDash} ${circ}`} strokeDashoffset={0} style={{ transform: "rotate(-90deg)", transformOrigin: `${cx}px ${cy}px`, transition: "stroke-dasharray 0.6s ease" }} />}
        <text x={cx} y={cy - 6} textAnchor="middle" fill={t.text} fontSize="19" fontWeight="900">{total}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill={t.textMuted} fontSize="10">scans</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: 1, minWidth: 130 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: t.danger }} />
          <div><div style={{ color: t.text, fontWeight: 800, fontSize: 18 }}>{phishing}</div><div style={{ color: t.textMuted, fontSize: 11 }}>Phishing — {((phishing / total) * 100).toFixed(1)}%</div></div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: t.safe }} />
          <div><div style={{ color: t.text, fontWeight: 800, fontSize: 18 }}>{safe}</div><div style={{ color: t.textMuted, fontSize: 11 }}>Safe — {((safe / total) * 100).toFixed(1)}%</div></div>
        </div>
        <div style={{ height: 5, borderRadius: 4, background: t.border, overflow: "hidden" }}>
          <div style={{ height: "100%", display: "flex" }}>
            <div style={{ width: `${(phishing / total) * 100}%`, background: t.danger, transition: "width 0.6s ease" }} />
            <div style={{ flex: 1, background: t.safe }} />
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Auth Gate Modal ───────────────────────────────────────────────────────────
function AuthGateModal({ t, onClose, onSuccess }: { t: Theme; onClose: () => void; onSuccess: (u: User) => void }) {
  const [tab, setTab] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [email, setEmail] = useState("");
  const [showPass, setShowPass] = useState(false); const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  const usernameRef = useRef<HTMLInputElement>(null);
  useEffect(() => { usernameRef.current?.focus(); }, [tab]);

  const handleSubmit = async () => {
    if (loading) return;
    setError(""); setLoading(true);
    try {
      if (tab === "login") {
        const d = await apiLogin(username.trim(), password);
        onSuccess({ username: d.username, email: d.email });
      } else {
        if (!username.trim() || !password || !email.trim()) { setError("All fields required"); setLoading(false); return; }
        const d = await apiSignup(username.trim(), password, email.trim());
        onSuccess({ username: d.username, email: email.trim() });
      }
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Failed — check backend is running"); }
    setLoading(false);
  };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(0,0,0,0.65)", backdropFilter: "blur(8px)" }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{ background: t.bgCard, border: `1px solid ${t.border}`, borderRadius: 20, padding: "36px 32px", width: "100%", maxWidth: 380, boxShadow: "0 24px 60px rgba(0,0,0,0.4)", animation: "pop 0.18s ease" }}>
        <div style={{ textAlign: "center", marginBottom: 22 }}>
          <div style={{ fontSize: 40, marginBottom: 6 }}>🔐</div>
          <h2 style={{ color: t.text, fontSize: 18, fontWeight: 800, margin: 0 }}>Login to View Dashboard</h2>
          <p style={{ color: t.textMuted, fontSize: 12, marginTop: 5 }}>Your scans are saved and tied to your account</p>
        </div>
        <div style={{ display: "flex", background: t.bg, borderRadius: 8, padding: 3, marginBottom: 18, border: `1px solid ${t.border}` }}>
          {(["login", "signup"] as const).map(tb => (
            <button key={tb} onClick={() => { setTab(tb); setError(""); }} style={{ flex: 1, padding: "7px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600, background: tab === tb ? `linear-gradient(135deg, ${t.accent}, ${t.accentDark})` : "transparent", color: tab === tb ? "#fff" : t.textMuted, transition: "all 0.15s" }}>
              {tb === "login" ? "Sign In" : "Sign Up"}
            </button>
          ))}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {tab === "signup" && (
            <div><label style={{ color: t.textMuted, fontSize: 10, fontWeight: 700, letterSpacing: "1px", display: "block", marginBottom: 4 }}>EMAIL</label>
              <input value={email} onChange={e => setEmail(e.target.value)} placeholder="your@email.com" autoComplete="email" style={{ width: "100%", background: t.bgInput, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 12px", color: t.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} /></div>
          )}
          <div><label style={{ color: t.textMuted, fontSize: 10, fontWeight: 700, letterSpacing: "1px", display: "block", marginBottom: 4 }}>USERNAME</label>
            <input ref={usernameRef} value={username} onChange={e => setUsername(e.target.value)} placeholder="Enter username" autoComplete="username" style={{ width: "100%", background: t.bgInput, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 12px", color: t.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} /></div>
          <div><label style={{ color: t.textMuted, fontSize: 10, fontWeight: 700, letterSpacing: "1px", display: "block", marginBottom: 4 }}>PASSWORD</label>
            <div style={{ position: "relative" }}>
              <input value={password} onChange={e => setPassword(e.target.value)} type={showPass ? "text" : "password"} placeholder="Enter password" autoComplete={tab === "login" ? "current-password" : "new-password"} onKeyDown={e => e.key === "Enter" && handleSubmit()} style={{ width: "100%", background: t.bgInput, border: `1px solid ${t.border}`, borderRadius: 8, padding: "9px 40px 9px 12px", color: t.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
              <button onClick={() => setShowPass(!showPass)} style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: t.textMuted, fontSize: 14 }}>{showPass ? "🙈" : "👁️"}</button>
            </div>
          </div>
        </div>
        {error && <div style={{ color: t.danger, fontSize: 12, marginTop: 8, textAlign: "center", padding: "6px 10px", background: `${t.danger}15`, borderRadius: 6 }}>{error}</div>}
        <button onClick={handleSubmit} disabled={loading} style={{ width: "100%", marginTop: 16, background: loading ? t.accentDark : `linear-gradient(135deg, ${t.accent}, ${t.accentDark})`, border: "none", color: "#fff", padding: "11px", borderRadius: 10, fontSize: 14, fontWeight: 700, cursor: loading ? "not-allowed" : "pointer", transition: "opacity 0.15s" }}>
          {loading ? "Please wait..." : tab === "login" ? "Sign In →" : "Create Account →"}
        </button>
        <button onClick={onClose} style={{ width: "100%", marginTop: 6, background: "transparent", border: `1px solid ${t.border}`, color: t.textMuted, padding: "9px", borderRadius: 10, fontSize: 12, cursor: "pointer" }}>Cancel</button>
      </div>
    </div>
  );
}

// ── NavBar ────────────────────────────────────────────────────────────────────
function NavBar({ t, page, setPage, user, setUser, themeMode, toggleTheme }: { t: Theme; page: string; setPage: (p: string) => void; user: User | null; setUser: (u: User | null) => void; themeMode: ThemeMode; toggleTheme: () => void }) {
  return (
    <nav style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, background: t.bgNav, backdropFilter: "blur(20px)", borderBottom: `1px solid ${t.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 32px", height: "62px", boxShadow: t.shadow }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }} onClick={() => setPage("home")}>
        <div style={{ width: 34, height: 34, borderRadius: 9, background: `linear-gradient(135deg, ${t.accent}, ${t.accentDark})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17 }}>🛡️</div>
        <span style={{ fontFamily: "'Courier New', monospace", fontWeight: 800, fontSize: 17, color: t.text }}>CyberShield <span style={{ color: t.accent }}>AI</span></span>
      </div>
      <div style={{ display: "flex", gap: 3 }}>
        {["home", "about", "dashboard", "history"].map(p => (
          <button key={p} onClick={() => setPage(p)} style={{ background: page === p ? t.accentGlow : "transparent", border: page === p ? `1px solid ${t.accent}40` : "1px solid transparent", color: page === p ? t.accent : t.textMuted, padding: "7px 14px", borderRadius: 7, cursor: "pointer", fontSize: 14, fontWeight: 500, textTransform: "capitalize" }}>
            {p.charAt(0).toUpperCase() + p.slice(1)}
          </button>
        ))}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button onClick={toggleTheme} style={{ background: t.bgCard, border: `1px solid ${t.border}`, borderRadius: 18, padding: "5px 12px", cursor: "pointer", color: t.text, fontSize: 12 }}>{themeMode === "dark" ? "☀️ Light" : "🌙 Dark"}</button>
        {user ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 30, height: 30, borderRadius: "50%", background: `linear-gradient(135deg, ${t.accent}, ${t.accentDark})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#fff" }}>{user.username[0].toUpperCase()}</div>
            <span style={{ color: t.textSub, fontSize: 13 }}>{user.username}</span>
            <button onClick={() => setUser(null)} style={{ background: "transparent", border: `1px solid ${t.border}`, color: t.textMuted, padding: "4px 9px", borderRadius: 6, cursor: "pointer", fontSize: 12 }}>Logout</button>
          </div>
        ) : (
          <>
            <button onClick={() => setPage("login")} style={{ background: "transparent", border: `1px solid ${t.border}`, color: t.text, padding: "7px 16px", borderRadius: 7, cursor: "pointer", fontSize: 13 }}>Login</button>
            <button onClick={() => setPage("signup")} style={{ background: `linear-gradient(135deg, ${t.accent}, ${t.accentDark})`, border: "none", color: "#fff", padding: "7px 16px", borderRadius: 7, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>Sign Up</button>
          </>
        )}
      </div>
    </nav>
  );
}

// ── HomePage ──────────────────────────────────────────────────────────────────
function HomePage({ t, user, setScanHistory }: { t: Theme; user: User | null; setPage: (p: string) => void; scanHistory: ScanEntry[]; setScanHistory: React.Dispatch<React.SetStateAction<ScanEntry[]>> }) {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<Prediction | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const handleScan = async () => {
    const trimmed = url.trim();
    if (!trimmed || scanning) return;
    setScanning(true); setResult(null); setError("");
    try {
      const username = user?.username || "guest";
      const p = await apiScan(trimmed, username);
      setScanHistory(prev => [{ id: Date.now(), url: trimmed, is_phishing: p.is_phishing, confidence: p.confidence, timestamp: new Date().toLocaleString(), username }, ...prev]);
      setResult(p);
    } catch (e: unknown) {
      setError(e instanceof Error && e.name === "AbortError" ? "⏱ Request timed out. Check your backend." : "⚠️ Backend unreachable. Is FastAPI running on port 8000?");
    }
    setScanning(false);
  };

  return (
    <div style={{ minHeight: "100vh", background: t.gradientHero, paddingTop: 62 }}>
      <div style={{ textAlign: "center", padding: "72px 20px 48px", maxWidth: 800, margin: "0 auto" }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 7, background: t.accentGlow, border: `1px solid ${t.accent}40`, borderRadius: 18, padding: "5px 14px", marginBottom: 28, color: t.accent, fontSize: 11, fontWeight: 600, letterSpacing: "2px" }}>
          <span style={{ width: 5, height: 5, borderRadius: "50%", background: t.accent, display: "inline-block" }}></span>ML-POWERED PROTECTION
        </div>
        <h1 style={{ fontSize: "clamp(38px,5.5vw,68px)", fontFamily: "'Georgia',serif", fontWeight: 900, lineHeight: 1.1, color: t.text, marginBottom: 14, letterSpacing: "-2px" }}>Detect Phishing URLs<br /><span style={{ color: t.accent, fontStyle: "italic" }}>Instantly</span></h1>
        <p style={{ color: t.textSub, fontSize: 17, lineHeight: 1.6, marginBottom: 40 }}>Analyze any URL for phishing threats using our trained ML model.<br />Real-time results powered by 30+ feature analysis.</p>

        <div style={{ background: t.bgCard, borderRadius: 14, border: `1px solid ${t.border}`, padding: 7, display: "flex", gap: 7, maxWidth: 580, margin: "0 auto", boxShadow: t.shadowGlow }}>
          <input ref={inputRef} value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && handleScan()} placeholder="https://example.com — paste URL to scan" autoFocus
            style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: t.text, fontSize: 14, padding: "11px 14px" }} />
          <button onClick={handleScan} disabled={scanning} style={{ background: scanning ? t.accentDark : `linear-gradient(135deg,${t.accent},${t.accentDark})`, border: "none", color: "#fff", padding: "11px 24px", borderRadius: 9, cursor: scanning ? "not-allowed" : "pointer", fontSize: 14, fontWeight: 700, minWidth: 110, transition: "opacity 0.15s" }}>
            {scanning ? "Scanning…" : "Scan Now"}
          </button>
        </div>

        {error && <div style={{ marginTop: 14, color: t.danger, fontSize: 13, padding: "8px 16px", background: `${t.danger}10`, borderRadius: 8, display: "inline-block" }}>{error}</div>}

        {result && (
          <div style={{ marginTop: 20, padding: "20px 28px", borderRadius: 14, background: result.is_phishing ? "rgba(255,77,109,0.1)" : "rgba(0,230,118,0.08)", border: `2px solid ${result.is_phishing ? t.danger : t.safe}40`, display: "inline-block", minWidth: 360, animation: "pop 0.2s ease" }}>
            <div style={{ fontSize: 32, marginBottom: 6 }}>{result.is_phishing ? "⚠️" : "✅"}</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: result.is_phishing ? t.danger : t.safe, marginBottom: 6 }}>{result.is_phishing ? "PHISHING DETECTED" : "SAFE URL"}</div>
            <div style={{ color: t.textSub, fontSize: 13 }}>Confidence: <strong style={{ color: t.text }}>{(result.confidence * 100).toFixed(1)}%</strong></div>
            <div style={{ color: t.textMuted, fontSize: 11, marginTop: 6, wordBreak: "break-all" }}>{url}</div>
          </div>
        )}
      </div>

      <div style={{ background: t.bgCard, padding: "60px 20px", borderTop: `1px solid ${t.border}` }}>
        <h2 style={{ textAlign: "center", color: t.text, fontSize: 32, fontWeight: 800, marginBottom: 40 }}>Why <span style={{ color: t.accent }}>CyberShield AI?</span></h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 20, maxWidth: 860, margin: "0 auto" }}>
          {[{ icon: "🤖", title: "ML-Powered", desc: "XGBoost trained on real phishing & benign URLs" }, { icon: "⚡", title: "Real-time", desc: "FastAPI returns results in milliseconds" }, { icon: "📊", title: "Confidence Score", desc: "Know how certain the model is about each prediction" }, { icon: "🔒", title: "DB-Backed", desc: "Scans saved securely to your account" }].map(f => (
            <div key={f.title} style={{ padding: "24px 20px", borderRadius: 14, background: t.bg, border: `1px solid ${t.border}`, textAlign: "center" }}>
              <div style={{ fontSize: 32, marginBottom: 10 }}>{f.icon}</div>
              <div style={{ color: t.text, fontWeight: 700, fontSize: 15, marginBottom: 6 }}>{f.title}</div>
              <div style={{ color: t.textMuted, fontSize: 13, lineHeight: 1.5 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── DashboardPage — fast with skeleton loading ────────────────────────────────
function DashboardPage({ t, user, onAuthRequired }: { t: Theme; user: User | null; scanHistory: ScanEntry[]; onAuthRequired: () => void }) {
  const [dbHistory, setDbHistory] = useState<ScanEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const fetchedRef = useRef(false);

  useEffect(() => { if (!user) { onAuthRequired(); return; } }, [user, onAuthRequired]);

  useEffect(() => {
    if (!user || fetchedRef.current) return;
    fetchedRef.current = true;
    setLoading(true);
    apiGetPredictions(user.username)
      .then(setDbHistory)
      .catch(() => setDbHistory([]))
      .finally(() => setLoading(false));
  }, [user]);

  // Reset cache on user change
  useEffect(() => { fetchedRef.current = false; }, [user?.username]);

  const total = dbHistory.length, phishing = dbHistory.filter(h => h.is_phishing).length, safe = total - phishing;
  const avgConf = total ? (dbHistory.reduce((a, b) => a + b.confidence, 0) / total * 100).toFixed(1) : 0;

  if (!user) return (
    <div style={{ minHeight: "100vh", background: t.bg, paddingTop: 62, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center" }}><div style={{ fontSize: 56, marginBottom: 14 }}>🔒</div><div style={{ fontSize: 17, fontWeight: 600, color: t.text }}>Authentication Required</div><div style={{ fontSize: 13, color: t.textMuted, marginTop: 6 }}>Please sign in to view your dashboard</div></div>
    </div>
  );

  const statColor = [t.accent, t.danger, t.safe, t.warning];
  const statItems = [{ label: "Total Scans", value: total, icon: "🔍" }, { label: "Phishing Found", value: phishing, icon: "⚠️" }, { label: "Safe URLs", value: safe, icon: "✅" }, { label: "Avg Confidence", value: `${avgConf}%`, icon: "📊" }];

  return (
    <div style={{ minHeight: "100vh", background: t.bg, paddingTop: 62 }}>
      <div style={{ maxWidth: 1080, margin: "0 auto", padding: "36px 20px" }}>
        <h1 style={{ color: t.text, fontSize: 28, fontWeight: 800, marginBottom: 6 }}>Dashboard <span style={{ color: t.accent }}>Overview</span></h1>
        <p style={{ color: t.textMuted, marginBottom: 32, fontSize: 13 }}>Welcome back, <strong style={{ color: t.accent }}>{user.username}</strong></p>

        {/* Stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 16, marginBottom: 24 }}>
          {statItems.map((s, i) => (
            <div key={s.label} style={{ background: t.bgCard, border: `1px solid ${t.border}`, borderRadius: 14, padding: 20, boxShadow: t.shadow }}>
              <div style={{ fontSize: 24, marginBottom: 6 }}>{s.icon}</div>
              {loading ? <Skeleton h={32} w="60%" /> : <div style={{ fontSize: 28, fontWeight: 900, color: statColor[i] }}>{s.value}</div>}
              <div style={{ color: t.textMuted, fontSize: 12, marginTop: 3 }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* Pie Chart */}
        <div style={{ background: t.bgCard, borderRadius: 14, border: `1px solid ${t.border}`, padding: "20px 24px", marginBottom: 24, boxShadow: t.shadow }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h3 style={{ color: t.text, fontWeight: 700, margin: 0, fontSize: 15 }}>Scan Distribution</h3>
            <span style={{ color: t.textMuted, fontSize: 11 }}>from phishing_data.db</span>
          </div>
          {loading ? (
            <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
              <Skeleton w={140} h={140} r={70} />
              <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10 }}><Skeleton h={20} w="60%" /><Skeleton h={20} w="50%" /><Skeleton h={8} /></div>
            </div>
          ) : <PieChart phishing={phishing} safe={safe} t={t} />}
        </div>

        {/* Table */}
        <div style={{ background: t.bgCard, borderRadius: 14, border: `1px solid ${t.border}`, overflow: "hidden" }}>
          <div style={{ padding: "16px 20px", borderBottom: `1px solid ${t.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ color: t.text, fontWeight: 700, margin: 0, fontSize: 15 }}>Recent Scans</h3>
            <span style={{ color: t.textMuted, fontSize: 11 }}>{loading ? "Loading…" : `${total} records`}</span>
          </div>
          {loading ? (
            <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: 12 }}>
              {[1, 2, 3, 4].map(i => <Skeleton key={i} h={18} w={`${85 - i * 8}%`} />)}
            </div>
          ) : dbHistory.length === 0 ? (
            <div style={{ padding: 48, textAlign: "center", color: t.textMuted, fontSize: 13 }}>No scan history yet. Go to Home and scan some URLs!</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr style={{ background: t.bg }}>{["#", "URL", "Status", "Confidence", "Timestamp"].map(h => <th key={h} style={{ padding: "10px 14px", textAlign: "left", color: t.textMuted, fontSize: 11, fontWeight: 600, letterSpacing: "1px", textTransform: "uppercase" }}>{h}</th>)}</tr></thead>
                <tbody>{dbHistory.map((row, i) => (
                  <tr key={row.id} style={{ borderTop: `1px solid ${t.border}` }}>
                    <td style={{ padding: "12px 14px", color: t.textMuted, fontSize: 12 }}>{i + 1}</td>
                    <td style={{ padding: "12px 14px", color: t.text, fontSize: 12, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.url}</td>
                    <td style={{ padding: "12px 14px" }}><span style={{ padding: "3px 10px", borderRadius: 18, fontSize: 11, fontWeight: 600, background: row.is_phishing ? "rgba(255,77,109,0.15)" : "rgba(0,230,118,0.12)", color: row.is_phishing ? t.danger : t.safe }}>{row.is_phishing ? "⚠️ Phishing" : "✅ Safe"}</span></td>
                    <td style={{ padding: "12px 14px", color: t.text, fontSize: 12 }}>{(row.confidence * 100).toFixed(1)}%</td>
                    <td style={{ padding: "12px 14px", color: t.textMuted, fontSize: 11 }}>{row.timestamp}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── HistoryPage ───────────────────────────────────────────────────────────────
function HistoryPage({ t, user, scanHistory }: { t: Theme; user: User | null; scanHistory: ScanEntry[] }) {
  const [filter, setFilter] = useState("all");
  const [dbHistory, setDbHistory] = useState<ScanEntry[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (user) {
      setLoading(true);
      apiGetPredictions(user.username).then(setDbHistory).catch(() => setDbHistory([])).finally(() => setLoading(false));
    } else {
      setDbHistory(scanHistory.filter(h => h.username === "guest"));
    }
  }, [user, scanHistory]);

  const base = dbHistory;
  const filtered = filter === "all" ? base : filter === "phishing" ? base.filter(h => h.is_phishing) : base.filter(h => !h.is_phishing);

  return (
    <div style={{ minHeight: "100vh", background: t.bg, paddingTop: 62 }}>
      <div style={{ maxWidth: 980, margin: "0 auto", padding: "36px 20px" }}>
        <h1 style={{ color: t.text, fontSize: 28, fontWeight: 800, marginBottom: 6 }}>Scan <span style={{ color: t.accent }}>History</span></h1>
        <p style={{ color: t.textMuted, marginBottom: 28, fontSize: 13 }}>{user ? `Records for ${user.username} from database` : "Guest session — login to see full history"}</p>
        <div style={{ display: "flex", gap: 7, marginBottom: 20 }}>
          {["all", "phishing", "safe"].map(f => <button key={f} onClick={() => setFilter(f)} style={{ padding: "7px 18px", borderRadius: 7, cursor: "pointer", fontSize: 12, fontWeight: 600, textTransform: "capitalize", background: filter === f ? t.accent : t.bgCard, color: filter === f ? "#fff" : t.textMuted, border: `1px solid ${filter === f ? t.accent : t.border}` }}>{f === "all" ? `All (${base.length})` : f === "phishing" ? `Phishing (${base.filter(h => h.is_phishing).length})` : `Safe (${base.filter(h => !h.is_phishing).length})`}</button>)}
        </div>
        {loading ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[1, 2, 3, 4, 5].map(i => <Skeleton key={i} h={60} r={10} />)}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {filtered.length === 0 ? <div style={{ textAlign: "center", padding: 48, color: t.textMuted, background: t.bgCard, borderRadius: 14, border: `1px solid ${t.border}`, fontSize: 13 }}>No records found.</div>
              : filtered.map(item => (
                <div key={item.id} style={{ background: t.bgCard, border: `1px solid ${item.is_phishing ? t.danger + "40" : t.border}`, borderRadius: 10, padding: "14px 18px", display: "flex", alignItems: "center", gap: 14 }}>
                  <span style={{ fontSize: 20 }}>{item.is_phishing ? "⚠️" : "✅"}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ color: t.text, fontSize: 13, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.url}</div>
                    <div style={{ color: t.textMuted, fontSize: 11, marginTop: 3 }}>{item.timestamp}</div>
                  </div>
                  <div style={{ textAlign: "right", flexShrink: 0 }}>
                    <div style={{ color: item.is_phishing ? t.danger : t.safe, fontWeight: 700, fontSize: 12 }}>{item.is_phishing ? "PHISHING" : "SAFE"}</div>
                    <div style={{ color: t.textMuted, fontSize: 11 }}>{(item.confidence * 100).toFixed(1)}%</div>
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── AboutPage ─────────────────────────────────────────────────────────────────
function AboutPage({ t }: { t: Theme }) {
  return (
    <div style={{ minHeight: "100vh", background: t.bg, paddingTop: 62 }}>
      <div style={{ maxWidth: 780, margin: "0 auto", padding: "52px 20px" }}>
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <div style={{ fontSize: 56, marginBottom: 14 }}>🛡️</div>
          <h1 style={{ color: t.text, fontSize: 36, fontWeight: 900, marginBottom: 14 }}>About CyberShield AI</h1>
          <p style={{ color: t.textSub, fontSize: 16, lineHeight: 1.7 }}>An intelligent phishing detection platform built with Machine Learning.</p>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {[{ title: "🤖 The ML Model", body: "XGBoost trained on 5,000+ labeled URLs with 12 handcrafted URL features + 200 TF-IDF character n-gram features. Achieves 97%+ accuracy." }, { title: "⚙️ Tech Stack", body: "Frontend: Next.js + TypeScript | Backend: FastAPI (async) + SQLite WAL | ML: XGBoost + scikit-learn | Auth: PBKDF2-SHA256" }, { title: "🗄️ Database", body: "phishing_data.db with users and predictions tables. Every scan is stored and tied to your account. Indexed for fast queries." }, { title: "🔒 Security", body: "Passwords hashed with PBKDF2-SHA256 + random salt. Login works with username or email. Users only see their own predictions." }].map(s => (
            <div key={s.title} style={{ background: t.bgCard, border: `1px solid ${t.border}`, borderRadius: 14, padding: "24px 28px" }}>
              <h3 style={{ color: t.accent, fontSize: 16, fontWeight: 700, marginBottom: 10 }}>{s.title}</h3>
              <p style={{ color: t.textSub, lineHeight: 1.7, margin: 0, fontSize: 14 }}>{s.body}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── LoginPage ─────────────────────────────────────────────────────────────────
function LoginPage({ t, setUser, setPage, isSignup }: { t: Theme; setUser: (u: User | null) => void; setPage: (p: string) => void; isSignup: boolean }) {
  const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [email, setEmail] = useState("");
  const [showPass, setShowPass] = useState(false); const [error, setError] = useState(""); const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (loading) return;
    setError(""); setLoading(true);
    try {
      if (isSignup) {
        if (!username.trim() || !password || !email.trim()) { setError("All fields required"); setLoading(false); return; }
        const d = await apiSignup(username.trim(), password, email.trim());
        setUser({ username: d.username, email: email.trim() }); setPage("home");
      } else {
        const d = await apiLogin(username.trim(), password);
        setUser({ username: d.username, email: d.email }); setPage("home");
      }
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Authentication failed"); }
    setLoading(false);
  };

  return (
    <div style={{ minHeight: "100vh", background: t.gradientHero, paddingTop: 62, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ background: t.bgCard, border: `1px solid ${t.border}`, borderRadius: 20, padding: "40px 36px", width: "100%", maxWidth: 400, boxShadow: t.shadow }}>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{ width: 54, height: 54, borderRadius: 14, background: `linear-gradient(135deg,${t.accent},${t.accentDark})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26, margin: "0 auto 14px" }}>🛡️</div>
          <h2 style={{ color: t.text, fontSize: 24, fontWeight: 800, marginBottom: 5 }}>{isSignup ? "Create Account" : "Welcome Back"}</h2>
          <p style={{ color: t.textMuted, fontSize: 12 }}>{isSignup ? "Creates your account in phishing_data.db" : "Verified against phishing_data.db users table"}</p>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          {isSignup && <div><label style={{ color: t.textMuted, fontSize: 10, fontWeight: 700, letterSpacing: "1px", display: "block", marginBottom: 5 }}>EMAIL</label><input value={email} onChange={e => setEmail(e.target.value)} placeholder="Enter your email" autoComplete="email" style={{ width: "100%", background: t.bgInput, border: `1px solid ${t.border}`, borderRadius: 9, padding: "10px 13px", color: t.text, fontSize: 13, outline: "none", boxSizing: "border-box" }} /></div>}
          <div><label style={{ color: t.textMuted, fontSize: 10, fontWeight: 700, letterSpacing: "1px", display: "block", marginBottom: 5 }}>USERNAME</label><input value={username} onChange={e => setUsername(e.target.value)} placeholder="Enter username" autoComplete="username" autoFocus style={{ width: "100%", background: t.bgInput, border: `1px solid ${t.border}`, borderRadius: 9, padding: "10px 13px", color: t.text, fontSize: 13, outline: "none", boxSizing: "border-box" }} /></div>
          <div><label style={{ color: t.textMuted, fontSize: 10, fontWeight: 700, letterSpacing: "1px", display: "block", marginBottom: 5 }}>PASSWORD</label>
            <div style={{ position: "relative" }}><input value={password} onChange={e => setPassword(e.target.value)} type={showPass ? "text" : "password"} placeholder="Enter password" autoComplete={isSignup ? "new-password" : "current-password"} onKeyDown={e => e.key === "Enter" && handleSubmit()} style={{ width: "100%", background: t.bgInput, border: `1px solid ${t.border}`, borderRadius: 9, padding: "10px 40px 10px 13px", color: t.text, fontSize: 13, outline: "none", boxSizing: "border-box" }} /><button onClick={() => setShowPass(!showPass)} style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: t.textMuted, fontSize: 14 }}>{showPass ? "🙈" : "👁️"}</button></div>
          </div>
        </div>
        {error && <div style={{ color: t.danger, fontSize: 12, marginTop: 10, textAlign: "center", padding: "6px 10px", background: `${t.danger}15`, borderRadius: 6 }}>{error}</div>}
        <button onClick={handleSubmit} disabled={loading} style={{ width: "100%", marginTop: 18, background: loading ? t.accentDark : `linear-gradient(135deg,${t.accent},${t.accentDark})`, border: "none", color: "#fff", padding: "12px", borderRadius: 10, fontSize: 14, fontWeight: 700, cursor: loading ? "not-allowed" : "pointer" }}>{loading ? "Please wait…" : isSignup ? "Create Account" : "Sign In"}</button>
        <p style={{ textAlign: "center", color: t.textMuted, fontSize: 12, marginTop: 16 }}>{isSignup ? "Already have an account? " : "Don't have an account? "}<button onClick={() => setPage(isSignup ? "login" : "signup")} style={{ background: "none", border: "none", color: t.accent, cursor: "pointer", fontWeight: 700, fontSize: 12 }}>{isSignup ? "Sign in" : "Create one"}</button></p>
      </div>
    </div>
  );
}

// ── Chatbot ───────────────────────────────────────────────────────────────────
interface ChatMsg { role: "user" | "bot"; text: string; }
function Chatbot({ t, open, setOpen }: { t: Theme; open: boolean; setOpen: (v: boolean) => void }) {
  const [messages, setMessages] = useState<ChatMsg[]>([{ role: "bot", text: "Hi! I'm CyberShield AI Assistant 🛡️ Ask me anything about phishing or URL safety!" }]);
  const [input, setInput] = useState(""); const [typing, setTyping] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const send = async () => {
    const msg = input.trim(); if (!msg || typing) return;
    setInput("");
    setMessages(prev => [...prev, { role: "user", text: msg }]); setTyping(true);
    try {
      const history = messages.slice(-6).map(m => ({ role: m.role === "user" ? "user" : "assistant", content: m.text }));
      const reply = await apiChat(msg, history);
      setMessages(prev => [...prev, { role: "bot", text: reply }]);
    } catch { setMessages(prev => [...prev, { role: "bot", text: "Sorry, couldn't reach the backend." }]); }
    setTyping(false);
  };

  return (
    <>
      <button onClick={() => setOpen(!open)} style={{ position: "fixed", bottom: 24, right: 24, zIndex: 200, width: 52, height: 52, borderRadius: "50%", background: `linear-gradient(135deg,${t.accent},${t.accentDark})`, border: "none", cursor: "pointer", fontSize: 22, boxShadow: `0 6px 20px ${t.accentGlow}`, display: "flex", alignItems: "center", justifyContent: "center" }}>{open ? "✕" : "💬"}</button>
      {open && (
        <div style={{ position: "fixed", bottom: 86, right: 24, zIndex: 200, width: 340, height: 480, borderRadius: 18, background: t.bgCard, border: `1px solid ${t.border}`, boxShadow: "0 16px 48px rgba(0,0,0,0.3)", display: "flex", flexDirection: "column", overflow: "hidden", animation: "pop 0.15s ease" }}>
          <div style={{ padding: "13px 18px", background: `linear-gradient(135deg,${t.accent}20,${t.accentDark}10)`, borderBottom: `1px solid ${t.border}`, display: "flex", alignItems: "center", gap: 9 }}>
            <span style={{ fontSize: 22 }}>🛡️</span>
            <div><div style={{ color: t.text, fontWeight: 700, fontSize: 13 }}>CyberShield Assistant</div><div style={{ color: t.safe, fontSize: 10, display: "flex", alignItems: "center", gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: "50%", background: t.safe, display: "inline-block" }}></span>Online · AI-Powered</div></div>
          </div>
          <div style={{ flex: 1, overflowY: "auto", padding: 13, display: "flex", flexDirection: "column", gap: 10 }}>
            {messages.map((m, i) => (
              <div key={i} style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start" }}>
                <div style={{ maxWidth: "82%", padding: "9px 13px", borderRadius: m.role === "user" ? "14px 14px 3px 14px" : "14px 14px 14px 3px", background: m.role === "user" ? `linear-gradient(135deg,${t.accent},${t.accentDark})` : t.bg, color: m.role === "user" ? "#fff" : t.text, fontSize: 12, lineHeight: 1.5, border: m.role === "bot" ? `1px solid ${t.border}` : "none" }}>{m.text}</div>
              </div>
            ))}
            {typing && <div style={{ display: "flex", gap: 3, padding: "9px 13px", background: t.bg, borderRadius: "14px 14px 14px 3px", border: `1px solid ${t.border}`, width: "fit-content" }}>{[0, 1, 2].map(d => <span key={d} style={{ width: 5, height: 5, borderRadius: "50%", background: t.textMuted, display: "inline-block", animation: `bounce 1s ${d * 0.2}s infinite` }}></span>)}</div>}
            <div ref={bottomRef} />
          </div>
          <div style={{ padding: 10, borderTop: `1px solid ${t.border}`, display: "flex", gap: 7 }}>
            <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && send()} placeholder="Ask about phishing…" style={{ flex: 1, background: t.bgInput, border: `1px solid ${t.border}`, borderRadius: 9, padding: "9px 12px", color: t.text, fontSize: 12, outline: "none" }} />
            <button onClick={send} disabled={typing} style={{ background: `linear-gradient(135deg,${t.accent},${t.accentDark})`, border: "none", borderRadius: 9, padding: "9px 12px", color: "#fff", cursor: typing ? "not-allowed" : "pointer", fontSize: 15 }}>➤</button>
          </div>
        </div>
      )}
    </>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [themeMode, setThemeMode] = useState<ThemeMode>("dark");
  const [page, setPage] = useState("home");
  const [user, setUser] = useState<User | null>(null);
  const [chatOpen, setChatOpen] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanEntry[]>([]);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const t: Theme = themes[themeMode];
  const toggleTheme = () => setThemeMode(m => m === "dark" ? "light" : "dark");

  const handlePageChange = useCallback((p: string) => {
    if (p === "dashboard" && !user) { setShowAuthModal(true); setPage("dashboard"); }
    else setPage(p);
  }, [user]);

  const handleAuthSuccess = (u: User) => { setUser(u); setShowAuthModal(false); setPage("dashboard"); };

  return (
    <div style={{ fontFamily: "'Segoe UI',system-ui,sans-serif", background: t.bg, minHeight: "100vh" }}>
      <style>{`
        * { box-sizing:border-box; margin:0; padding:0; }
        :root { --sk1:${themeMode === "dark" ? "#1a2e20" : "#e8f5ee"}; --sk2:${themeMode === "dark" ? "#243828" : "#d4edda"}; }
        @keyframes shimmer { to { background-position: -200% 0; } }
        @keyframes pop { from{opacity:0;transform:scale(0.96)} to{opacity:1;transform:scale(1)} }
        @keyframes bounce { 0%,60%,100%{transform:translateY(0)} 30%{transform:translateY(-5px)} }
        ::-webkit-scrollbar{width:3px} ::-webkit-scrollbar-track{background:transparent} ::-webkit-scrollbar-thumb{background:${t.border};border-radius:3px}
        input::placeholder{color:${t.textMuted}} button:hover{opacity:0.88}
      `}</style>
      <NavBar t={t} page={page} setPage={handlePageChange} user={user} setUser={setUser} themeMode={themeMode} toggleTheme={toggleTheme} />
      {page === "home"      && <HomePage      t={t} user={user} setPage={handlePageChange} scanHistory={scanHistory} setScanHistory={setScanHistory} />}
      {page === "dashboard" && <DashboardPage t={t} user={user} scanHistory={scanHistory} onAuthRequired={() => setShowAuthModal(true)} />}
      {page === "history"   && <HistoryPage   t={t} user={user} scanHistory={scanHistory} />}
      {page === "about"     && <AboutPage     t={t} />}
      {page === "login"     && <LoginPage     t={t} setUser={setUser} setPage={handlePageChange} isSignup={false} />}
      {page === "signup"    && <LoginPage     t={t} setUser={setUser} setPage={handlePageChange} isSignup={true} />}
      {showAuthModal && <AuthGateModal t={t} onClose={() => { setShowAuthModal(false); setPage("home"); }} onSuccess={handleAuthSuccess} />}
      <Chatbot t={t} open={chatOpen} setOpen={setChatOpen} />
    </div>
  );
}
