import React, { useEffect, useState, useCallback, useRef } from "react"
import {
  Shield, Activity, Bell, AlertOctagon, FileText, Brain, Zap, Cpu,
  Database, Settings, LogOut, User, RefreshCw, Play, Pause, Wifi, WifiOff,
  ChevronRight, X, ShieldOff, ShieldCheck, AlertTriangle, Lock,
  Unlock, Server, Eye, TrendingUp, CheckCircle, XCircle, BarChart3,
  Terminal, Crosshair, Radio, Layers, Flame, Search, Filter, Power
} from "lucide-react"
import {
  AreaChart, Area, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, Legend
} from "recharts"
import { useAuthStore, useAlertStore, useIncidentStore } from "../store"
import { useWebSocket } from "../hooks/useWebSocket"
import { useAttackSimulator } from "../hooks/useAttackSimulator"
import api from "../utils/api"
import { useNavigate } from "react-router-dom"

// ─── Theme Constants (UI/UX Pro Max Cyberpunk SOC HUD) ───────────────────────
const SEV_COLOR = { CRITICAL: "#ff2d55", HIGH: "#ff9500", MEDIUM: "#ffd60a", LOW: "#00ff88" }
const ATTACK_COLORS = {
  DDoS: "#f43f5e",
  Ransomware: "#a855f7",
  Phishing: "#f97316",
  "Insider Threat": "#facc15",
  "Port Scan": "#38bdf8",
  "Brute Force": "#fb923c",
  Normal: "#22c55e"
}
const LOG_COLORS = { info: "#94a3b8", success: "#00ff88", warn: "#ffd60a", danger: "#ff2d55" }

function AttackIcon({ type, size = 14 }) {
  switch (type) {
    case "DDoS":
      return <Zap size={size} className="text-rose-400 flex-shrink-0" />
    case "Ransomware":
      return <Lock size={size} className="text-purple-400 flex-shrink-0" />
    case "Phishing":
      return <AlertTriangle size={size} className="text-orange-400 flex-shrink-0" />
    case "Insider Threat":
      return <User size={size} className="text-amber-400 flex-shrink-0" />
    case "Port Scan":
      return <Crosshair size={size} className="text-sky-400 flex-shrink-0" />
    case "Brute Force":
      return <Flame size={size} className="text-orange-500 flex-shrink-0" />
    default:
      return <Shield size={size} className="text-emerald-400 flex-shrink-0" />
  }
}

const timeAgo = (dt) => {
  if (!dt) return "Just now"
  const diff = Math.floor((Date.now() - new Date(dt.endsWith('Z') ? dt : dt + "Z").getTime()) / 1000)
  if (isNaN(diff) || diff < 5) return "Just now"
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

const sevBadge = (s) => {
  const base = "px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider inline-flex items-center gap-1"
  const map = {
    CRITICAL: "bg-red-950/80 text-red-400 border border-red-500/60 shadow-[0_0_8px_rgba(255,45,85,0.2)]",
    HIGH: "bg-orange-950/80 text-orange-400 border border-orange-500/60 shadow-[0_0_8px_rgba(255,149,0,0.2)]",
    MEDIUM: "bg-yellow-950/80 text-yellow-400 border border-yellow-500/60",
    LOW: "bg-emerald-950/80 text-emerald-400 border border-emerald-500/60"
  }
  return `${base} ${map[s] || "bg-slate-900 text-slate-400 border border-slate-700"}`
}

function MiniStat({ label, value, icon: Icon, color = "cyan", sub, pulse }) {
  return (
    <div className="cyber-card p-3 flex flex-col justify-between relative group hover:border-cyan-500/40 transition-all duration-200">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">{label}</span>
        <div className="p-1 rounded bg-white/5 border border-white/10 group-hover:border-cyan-500/30 transition-colors">
          <Icon size={13} className={`text-cyber-${color}`} />
        </div>
      </div>
      <div className="text-xl font-black font-mono text-white flex items-center gap-1.5 my-1">
        {value}
        {pulse && <span className="w-2 h-2 rounded-full bg-emerald-400 pulse-dot shadow-[0_0_8px_#22c55e]" />}
      </div>
      {sub && <div className={`text-[10px] font-mono text-cyber-${color}`}>{sub}</div>}
    </div>
  )
}

function Drawer({ open, onClose, title, children }) {
  return (
    <>
      {open && <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 transition-opacity" onClick={onClose} />}
      <div className={`fixed top-0 right-0 h-full w-[500px] max-w-full bg-[#070f1f]/95 backdrop-blur-md border-l border-cyan-500/30 z-50 flex flex-col transition-transform duration-300 shadow-2xl ${open ? "translate-x-0" : "translate-x-full"}`}>
        <div className="flex items-center justify-between p-4 border-b border-cyan-500/20 bg-slate-950/60">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="font-mono font-bold text-cyber-cyan text-sm tracking-wider uppercase">{title}</span>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-white/10 transition"><X size={16} /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </div>
    </>
  )
}

function AttackDetail({ log: attackLog, onBlockIp, onAcknowledge }) {
  if (!attackLog) return <p className="text-slate-400 text-sm font-mono">Select an attack to view detailed forensic telemetry.</p>
  const raw = attackLog.raw_features || {}
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 p-3 rounded-lg bg-white/5 border border-cyan-500/20">
        <div className="w-11 h-11 rounded-lg bg-black/50 border border-cyan-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(0,229,255,0.1)]">
          <AttackIcon type={attackLog.attack_type} size={24} />
        </div>
        <div className="flex-1">
          <div className="text-base font-black text-white">{attackLog.attack_type}</div>
          <div className="flex items-center gap-2 mt-1">
            <span className={sevBadge(attackLog.severity)}>{attackLog.severity}</span>
            <span className="text-[10px] font-mono text-slate-400">ID #{attackLog.id || attackLog.attack_log_id}</span>
          </div>
        </div>
      </div>

      {/* Quick Mitigation Action Buttons */}
      <div className="grid grid-cols-2 gap-2">
        {attackLog.source_ip && attackLog.source_ip !== "N/A" && (
          <button onClick={() => onBlockIp(attackLog.source_ip, `Blocked from Attack #${attackLog.id}: ${attackLog.attack_type}`)}
            className="py-2 px-3 bg-red-950/60 hover:bg-red-900/80 border border-red-500/50 text-red-300 font-mono text-xs rounded-lg flex items-center justify-center gap-1.5 transition-all shadow-[0_0_10px_rgba(255,45,85,0.15)]">
            <ShieldOff size={13} /> Block Source IP
          </button>
        )}
        <button onClick={() => onAcknowledge(attackLog.id)}
          className="py-2 px-3 bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-500/50 text-emerald-300 font-mono text-xs rounded-lg flex items-center justify-center gap-1.5 transition-all">
          <CheckCircle size={13} /> Mark Mitigated
        </button>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {[
          ["Source IP", attackLog.source_ip],
          ["Destination IP", attackLog.dest_ip],
          ["Protocol", attackLog.protocol],
          ["Target Port", attackLog.port],
          ["SOC Status", attackLog.status],
          ["Dataset Engine", attackLog.dataset_source],
          ["Detection Time", timeAgo(attackLog.detected_at)],
          ["Model Confidence", `${attackLog.suspicious_score?.toFixed(1) ?? "96.4"}%`],
        ].map(([k, v]) => (
          <div key={k} className="cyber-card p-2.5">
            <div className="text-[10px] text-slate-400 font-mono uppercase">{k}</div>
            <div className="text-xs text-white font-mono mt-0.5 font-semibold truncate">{v || "N/A"}</div>
          </div>
        ))}
      </div>

      {attackLog.mitre_technique_id && (
        <div className="cyber-card p-3 border-cyan-500/30">
          <div className="text-[10px] text-slate-400 font-mono uppercase mb-1">MITRE ATT&CK Matrix Alignment</div>
          <div className="text-xs font-mono font-bold text-cyber-cyan">{attackLog.mitre_technique_id}</div>
          <div className="text-xs font-mono text-slate-300 mt-0.5">{attackLog.mitre_technique_name}</div>
        </div>
      )}

      {attackLog.description && (
        <div className="cyber-card p-3">
          <div className="text-[10px] text-slate-400 font-mono uppercase mb-1">AI Intelligence Briefing</div>
          <p className="text-xs text-slate-300 font-mono leading-relaxed">{attackLog.description}</p>
        </div>
      )}

      {Object.keys(raw).length > 0 && (
        <div className="cyber-card p-3">
          <div className="text-[10px] text-slate-400 font-mono uppercase mb-2">Raw Telemetry & Packet Features</div>
          <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
            {Object.entries(raw).map(([k, v]) => (
              <div key={k} className="flex justify-between text-[11px] font-mono py-0.5 border-b border-white/5">
                <span className="text-slate-400">{k}</span>
                <span className="text-slate-200 truncate ml-2 font-medium">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function FirewallPanel({ rules, onAutoBlock, onRemove, onAddOpen, loading }) {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
          <ShieldCheck size={13} className="text-emerald-400" /> Active Firewall Rules ({rules.length})
        </span>
        <div className="flex items-center gap-1.5">
          <button onClick={onAutoBlock} disabled={loading}
            className="px-2 py-1 text-[10px] font-mono bg-red-950/70 border border-red-500/50 text-red-400 rounded hover:bg-red-900/60 transition shadow-[0_0_8px_rgba(255,45,85,0.2)]">
            {loading ? "..." : "Auto-Block"}
          </button>
          <button onClick={onAddOpen}
            className="px-2 py-1 text-[10px] font-mono bg-cyan-950/70 border border-cyan-500/50 text-cyan-300 rounded hover:bg-cyan-900/60 transition shadow-[0_0_8px_rgba(0,229,255,0.15)]">
            + Rule
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
        {rules.length === 0
          ? <div className="text-xs text-slate-500 font-mono text-center py-6">No active IP blocking rules</div>
          : rules.map(rule => (
            <div key={rule.id} className="cyber-card px-2.5 py-2 flex items-center justify-between group hover:border-red-500/50 transition">
              <div className="flex items-center gap-2 min-w-0">
                <Lock size={12} className="text-rose-400 flex-shrink-0" />
                <div className="min-w-0">
                  <div className="text-xs font-mono text-white truncate font-bold">{rule.ip_address || "Any Host"}</div>
                  <div className="text-[10px] font-mono text-slate-400 truncate">{rule.attack_type || rule.reason}</div>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <span className={sevBadge(rule.severity || "HIGH")}>{rule.severity || "HIGH"}</span>
                <button onClick={() => onRemove(rule.id)}
                  className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-rose-400 transition p-0.5" title="Deactivate rule">
                  <X size={12} />
                </button>
              </div>
            </div>
          ))
        }
      </div>
    </div>
  )
}

const ATTACK_TYPES = [
  { type: "DDoS", label: "DDoS", color: "#f43f5e" },
  { type: "Ransomware", label: "Ransomware", color: "#a855f7" },
  { type: "Phishing", label: "Phishing", color: "#f97316" },
  { type: "Insider Threat", label: "Insider", color: "#facc15" },
  { type: "Port Scan", label: "Port Scan", color: "#38bdf8" },
  { type: "Brute Force", label: "Brute Force", color: "#fb923c" },
]

const SCENARIOS = [
  { key: "hospital_breach", label: "Hospital Breach", desc: "Port Scan -> Brute Force -> Ransomware" },
  { key: "phishing_campaign", label: "Phishing Campaign", desc: "Phishing URL -> Insider -> Ransomware" },
  { key: "ransomware_kill_chain", label: "Ransomware Kill Chain", desc: "Phishing -> Brute Force -> Ransomware" },
  { key: "apt_intrusion", label: "APT Intrusion", desc: "Recon -> Access -> Insider -> Zero-Day -> Ransomware" },
  { key: "data_exfiltration", label: "Data Exfiltration", desc: "Phishing -> Insider (CRIT) -> Port Scan" },
  { key: "ddos_wave", label: "DDoS Flood Wave", desc: "3x Simultaneous CRITICAL SYN Flood" },
  { key: "iot_botnet_ddos", label: "IoT Botnet DDoS", desc: "Port Scan -> DDoS -> DDoS (medical IoT)" },
  { key: "zero_day_outbreak", label: "Zero-Day Outbreak", desc: "Unknown pattern x2 -> Ransomware" },
  { key: "memory_recall", label: "Memory Recall Drill", desc: "Repeat Ransomware x4 -> DDoS (builds Threat Memory)" },
  { key: "full_spectrum", label: "Full Spectrum Siege", desc: "All 6 attack vectors sequenced" },
]

function SimulatorPanel({ sim }) {
  const { stage, log, loading, fireAttack, fireScenario, fireAnomaly, clearLog } = sim
  const [selected, setSelected] = useState("DDoS")
  const [severity, setSeverity] = useState("HIGH")
  const [activeTab, setActiveTab] = useState("attacks")

  const stageColor = {
    IDLE: "#64748b", INJECTING: "#ffd60a", DETECTED: "#ff9500",
    CLASSIFYING: "#00e5ff", QIGA: "#a855f7", FIREWALL: "#f43f5e",
    COMPLETE: "#00ff88", ERROR: "#ff2d55"
  }

  return (
    <div className="h-full flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
          <Terminal size={12} className="text-cyber-cyan" /> Attack Simulator
        </span>
        <span className="text-[9px] font-mono px-2 py-0.5 rounded font-black tracking-wider uppercase"
          style={{ background: `${stageColor[stage]}25`, color: stageColor[stage], border: `1px solid ${stageColor[stage]}50` }}>
          {stage}
        </span>
      </div>

      <div className="flex gap-1 bg-black/50 p-0.5 rounded-lg border border-cyan-500/20">
        {["attacks", "scenarios"].map(t => (
          <button key={t} onClick={() => setActiveTab(t)}
            className={`flex-1 py-1 text-[10px] font-mono uppercase rounded-md transition ${activeTab === t ? "bg-cyan-500/20 text-cyber-cyan font-bold border border-cyan-500/40 shadow-[0_0_10px_rgba(0,229,255,0.15)]" : "text-slate-400 hover:text-slate-200"}`}>
            {t}
          </button>
        ))}
      </div>

      {activeTab === "attacks" ? (
        <>
          <div className="grid grid-cols-3 gap-1.5">
            {ATTACK_TYPES.map(({ type, label, color }) => (
              <button key={type} onClick={() => setSelected(type)}
                className={`cyber-card py-2 px-1 text-center transition-all duration-150 hover:scale-[1.03] flex flex-col items-center gap-1 cursor-pointer ${selected === type ? "border-2 shadow-[0_0_12px_rgba(0,229,255,0.2)]" : "opacity-80 hover:opacity-100"}`}
                style={selected === type ? { borderColor: color, background: `${color}18` } : {}}>
                <AttackIcon type={type} size={16} />
                <div className="text-[9px] font-mono text-slate-200 font-bold truncate w-full">{label}</div>
              </button>
            ))}
          </div>

          <div className="flex gap-1">
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(sev => (
              <button key={sev} onClick={() => setSeverity(sev)}
                className={`flex-1 py-1 text-[9px] font-mono font-bold rounded transition cursor-pointer ${severity === sev ? "shadow-[0_0_8px_rgba(255,45,85,0.3)] scale-105" : "opacity-40 hover:opacity-80"}`}
                style={{ background: `${SEV_COLOR[sev]}25`, color: SEV_COLOR[sev], border: `1px solid ${SEV_COLOR[sev]}60` }}>
                {sev}
              </button>
            ))}
          </div>

          <button onClick={() => fireAttack(selected, severity)} disabled={loading}
            className="w-full py-2.5 font-mono font-bold text-xs rounded-lg flex items-center justify-center gap-2 transition-all duration-150 shadow-lg hover:brightness-125 active:scale-[0.98] cursor-pointer"
            style={{
              background: loading ? "#1e293b" : "linear-gradient(135deg,#ff2d55,#ff6b35)",
              color: loading ? "#94a3b8" : "#fff",
              border: loading ? "1px solid #334155" : "none"
            }}>
            {loading
              ? <><RefreshCw size={13} className="animate-spin text-cyan-400" /> INJECTING SIM...</>
              : <><Play size={13} /> LAUNCH {selected.toUpperCase()}</>}
          </button>

          <button onClick={() => fireAnomaly(severity)} disabled={loading}
            className="w-full py-2 font-mono font-bold text-[11px] rounded-lg flex items-center justify-center gap-2 transition-all duration-150 hover:brightness-125 active:scale-[0.98] cursor-pointer disabled:opacity-50"
            style={{
              background: "linear-gradient(135deg,#7c3aed,#0ea5e9)",
              color: "#fff",
              border: "1px solid rgba(168,85,247,0.5)"
            }}
            title="Fire a novel pattern the MLP has never seen - caught by the Isolation Forest as a zero-day">
            <Search size={12} /> LAUNCH ZERO-DAY (UNKNOWN)
          </button>
        </>
      ) : (
        <div className="space-y-1.5 overflow-y-auto pr-1" style={{ maxHeight: "230px" }}>
          {SCENARIOS.map(s => (
            <button key={s.key} onClick={() => fireScenario(s.key)} disabled={loading}
              className="w-full cyber-card p-2 text-left hover:bg-white/5 transition group flex items-center justify-between cursor-pointer">
              <div>
                <div className="text-xs font-mono text-white group-hover:text-cyber-cyan transition font-bold">{s.label}</div>
                <div className="text-[9px] font-mono text-slate-400">{s.desc}</div>
              </div>
              <Play size={11} className="text-slate-500 group-hover:text-cyber-cyan transition flex-shrink-0" />
            </button>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between mt-0.5">
        <span className="text-[10px] text-slate-400 font-mono">SIM TELEMETRY CONSOLE</span>
        <button onClick={clearLog} className="text-[10px] text-slate-500 hover:text-slate-300 font-mono transition">clear</button>
      </div>
      <div className="flex-1 overflow-y-auto space-y-0.5 bg-black/60 rounded-lg border border-slate-800 p-2 min-h-[90px] max-h-[220px]">
        {log.length === 0
          ? <div className="text-[10px] text-slate-500 font-mono">Simulator engine idle. Choose vector & click Launch...</div>
          : log.map((entry, i) => (
            <div key={i} className="text-[10px] font-mono leading-tight"
              style={{ color: LOG_COLORS[entry.type] || "#94a3b8" }}>
              <span className="text-slate-600 mr-1.5">{entry.ts}</span>{entry.msg}
            </div>
          ))
        }
      </div>
    </div>
  )
}

export default function SOCCommand() {
  const { user, logout } = useAuthStore()
  const { unreadCount, liveMetrics, liveThreats } = useAlertStore()
  const { selectedAttackLogId, setSelectedAttackLogId } = useIncidentStore()
  const navigate = useNavigate()
  useWebSocket()
  const sim = useAttackSimulator()

  const [drawer, setDrawer] = useState(false)
  const [drawerTitle, setDrawerTitle] = useState("")
  const [drawerContent, setDrawerContent] = useState(null)
  const [logs, setLogs] = useState([])
  const [alerts, setAlerts] = useState([])
  const [fwRules, setFwRules] = useState([])
  const [fwLoading, setFwLoading] = useState(false)
  const [assets, setAssets] = useState([])
  const [xaiData, setXaiData] = useState(null)
  const [qigaActions, setQigaActions] = useState([])
  const [chartHistory, setChartHistory] = useState([])
  const [attackDistrib, setAttackDistrib] = useState([])
  const [feedFilter, setFeedFilter] = useState("ALL")
  const [replayActive, setReplayActive] = useState(false)
  const [togglingReplay, setTogglingReplay] = useState(false)

  // Firewall modal
  const [fwAddOpen, setFwAddOpen] = useState(false)
  const [newIp, setNewIp] = useState("")
  const [newReason, setNewReason] = useState("")
  const [addingRule, setAddingRule] = useState(false)

  const openDrawer = (title, content) => {
    setDrawerTitle(title)
    setDrawerContent(content)
    setDrawer(true)
  }

  const fetchAll = useCallback(async () => {
    try {
      const [logsRes, alertsRes, fwRes, assetsRes, replayRes] = await Promise.all([
        api.get("/logs/?limit=40"),
        api.get("/alerts/?limit=40"),
        api.get("/firewall/rules?active_only=true"),
        api.get("/assets/"),
        api.get("/sim/replay/status").catch(() => ({ data: { enabled: false } }))
      ])
      setLogs(logsRes.data || [])
      setAlerts(alertsRes.data || [])
      setFwRules(fwRes.data || [])
      setAssets(assetsRes.data || [])
      setReplayActive(replayRes.data?.enabled ?? false)

      const dist = {}
      ;(logsRes.data || []).forEach(l => { dist[l.attack_type] = (dist[l.attack_type] || 0) + 1 })
      setAttackDistrib(Object.entries(dist).map(([name, value]) => ({ name, value })))
    } catch (err) { console.error("[SOCCommand]", err) }
  }, [])

  const toggleReplayMode = async () => {
    setTogglingReplay(true)
    try {
      const res = await api.post("/sim/replay/toggle")
      setReplayActive(res.data?.enabled)
    } catch (e) { console.error(e) } finally { setTogglingReplay(false) }
  }

  useEffect(() => {
    if (!selectedAttackLogId) { setQigaActions([]); return }
    api.get(`/xai/explain/${selectedAttackLogId}`).then(r => setXaiData(r.data)).catch(() => {})
    api.get(`/recommendations/?attack_log_id=${selectedAttackLogId}&limit=6`)
      .then(r => setQigaActions(Array.isArray(r.data) ? r.data : []))
      .catch(() => setQigaActions([]))
  }, [selectedAttackLogId])

  useEffect(() => {
    if (liveThreats[0]?.attack_log_id) setSelectedAttackLogId(liveThreats[0].attack_log_id)
  }, [liveThreats, setSelectedAttackLogId])

  useEffect(() => {
    setChartHistory(prev => {
      const entry = { time: new Date().toLocaleTimeString().slice(0, 5), risk: liveMetrics.risk_score || 0, threats: liveThreats.length }
      return [...prev.slice(-19), entry]
    })
  }, [liveMetrics, liveThreats])

  useEffect(() => { fetchAll() }, [fetchAll])

  useEffect(() => {
    if (sim.stage === "COMPLETE") setTimeout(() => fetchAll(), 1000)
  }, [sim.stage, fetchAll])

  const handleLogout = () => { logout(); navigate("/login") }

  const autoBlockCritical = async () => {
    setFwLoading(true)
    try {
      await api.post("/firewall/auto-block?minutes=60")
      const res = await api.get("/firewall/rules?active_only=true")
      setFwRules(res.data || [])
    } catch (e) { console.error(e) } finally { setFwLoading(false) }
  }

  const removeRule = async (id) => {
    try {
      await api.delete(`/firewall/rules/${id}`)
      setFwRules(prev => prev.filter(r => r.id !== id))
    } catch (e) { console.error(e) }
  }

  const blockIpDirect = async (ip, reason) => {
    if (!ip) return
    try {
      await api.post(`/firewall/block?ip_address=${encodeURIComponent(ip)}&reason=${encodeURIComponent(reason || "Direct SOC block")}&severity=CRITICAL`)
      const res = await api.get("/firewall/rules?active_only=true")
      setFwRules(res.data || [])
    } catch (e) { console.error(e) }
  }

  const addManualRule = async () => {
    if (!newIp) return
    setAddingRule(true)
    try {
      await api.post(`/firewall/block?ip_address=${encodeURIComponent(newIp)}&reason=${encodeURIComponent(newReason || "Manual block")}&severity=HIGH`)
      const res = await api.get("/firewall/rules?active_only=true")
      setFwRules(res.data || [])
      setNewIp(""); setNewReason(""); setFwAddOpen(false)
    } catch (e) { console.error(e) } finally { setAddingRule(false) }
  }

  const acknowledgeAlert = async (id) => {
    try {
      await api.patch(`/alerts/${id}/acknowledge`)
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, is_acknowledged: true } : a))
    } catch (e) { console.error(e) }
  }

  // "Mark Mitigated" from the threat drawer passes an AttackLog id; resolve the
  // matching Alert and acknowledge that (the acknowledge endpoint expects an
  // Alert id, not an AttackLog id).
  const acknowledgeByAttackLog = async (attackLogId) => {
    const match = alerts.find(a => String(a.attack_log_id) === String(attackLogId))
    if (match) {
      await acknowledgeAlert(match.id)
    } else {
      console.warn(`[SOCCommand] No alert found for attack log #${attackLogId}`)
    }
  }

  const topSev = liveThreats[0]?.severity || "LOW"
  const THREAT_LEVELS = {
    CRITICAL: { label: "CRITICAL", color: "#ff2d55", cls: "bg-red-950/80 border-red-500/60 shadow-[0_0_12px_rgba(255,45,85,0.3)]" },
    HIGH:     { label: "HIGH",     color: "#ff9500", cls: "bg-orange-950/80 border-orange-500/60 shadow-[0_0_12px_rgba(255,149,0,0.3)]" },
    MEDIUM:   { label: "MEDIUM",   color: "#ffd60a", cls: "bg-yellow-950/80 border-yellow-500/60" },
    LOW:      { label: "LOW",      color: "#00ff88", cls: "bg-emerald-950/80 border-emerald-500/60" },
  }
  const tl = THREAT_LEVELS[topSev] || THREAT_LEVELS["LOW"]

  const shap = xaiData?.top_features || xaiData?.shap_values || []
  const shapData = shap.slice(0, 8).map(s => ({
    feature: (s.feature || "").substring(0, 14),
    value: +(s.shap_value || 0).toFixed(3)
  }))

  const unacknowledgedAlerts = alerts.filter(a => !a.is_acknowledged)

  // Filtered threats feed
  const filteredThreats = liveThreats.filter(t => {
    if (feedFilter === "ALL") return true
    return t.severity === feedFilter
  })

  return (
    <div className="h-full flex flex-col overflow-hidden bg-cyber-bg grid-bg text-slate-100">
      {/* ─── HEADER ───────────────────────────────────────────────────────── */}
      <header className="flex items-center gap-3 px-4 py-2 bg-cyber-surface border-b border-cyan-500/20 flex-shrink-0 shadow-md">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center shadow-[0_0_12px_rgba(0,229,255,0.4)]">
            <Terminal size={14} className="text-slate-950 font-black" />
          </div>
          <div>
            <div className="font-mono font-black text-cyber-cyan text-xs tracking-widest leading-none">MISSION COMMAND</div>
            <div className="text-[8px] font-mono text-slate-400 uppercase tracking-wider mt-0.5">Live Threat Radar</div>
          </div>
        </div>

        {/* Global Threat Badge */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-mono font-black tracking-wider ${tl.cls}`} style={{ color: tl.color }}>
          <span className="w-2 h-2 rounded-full pulse-dot" style={{ background: tl.color }} />
          THREAT STATUS: {tl.label}
        </div>

        {/* Replay Mode Controller Switch */}
        <button onClick={toggleReplayMode} disabled={togglingReplay}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-mono font-bold transition-all cursor-pointer ${replayActive ? "bg-emerald-950/60 border-emerald-500/50 text-emerald-300 hover:bg-emerald-900/60" : "bg-amber-950/60 border-amber-500/50 text-amber-300 hover:bg-amber-900/60"}`}
          title="Toggle background dataset replay simulation">
          {replayActive ? <Radio size={12} className="text-emerald-400 pulse-dot" /> : <Pause size={12} />}
          <span>{replayActive ? "AUTO-REPLAY: LIVE" : "AUTO-REPLAY: PAUSED"}</span>
        </button>

        {/* Live Metrics Counters */}
        <div className="hidden lg:flex items-center gap-3.5 ml-2 text-[11px] font-mono text-slate-300">
          <span>SYS <span className="text-emerald-400 font-bold">{liveMetrics.sys_health?.toFixed(1) ?? "98.0"}%</span></span>
          <span>RISK <span className="text-cyber-cyan font-bold">{liveMetrics.risk_score?.toFixed(0) ?? "0"}</span></span>
          <span>THR/MIN <span className="text-amber-400 font-bold">{liveMetrics.threats_per_minute ?? "0"}</span></span>
          <span>ACTIVE CONN <span className="text-sky-400 font-bold">{liveMetrics.active_connections ?? "0"}</span></span>
        </div>

        {/* User profile & actions */}
        <div className="ml-auto flex items-center gap-3">
          <button onClick={fetchAll} className="text-slate-400 hover:text-cyber-cyan transition p-1.5 rounded-lg hover:bg-white/5 cursor-pointer" title="Refresh Telemetry">
            <RefreshCw size={14} />
          </button>
          {unreadCount > 0 && (
            <div className="flex items-center gap-1 text-xs font-mono text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded-md border border-rose-500/40 animate-pulse">
              <Bell size={12} /><span className="font-bold">{unreadCount}</span>
            </div>
          )}
          <div className="flex items-center gap-2 text-xs pl-2 border-l border-slate-700">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center shadow-inner">
              <User size={13} className="text-white" />
            </div>
            <div className="hidden sm:block text-left">
              <div className="font-mono font-bold text-slate-200 text-xs truncate">{user?.full_name}</div>
              <div className="font-mono text-slate-400 text-[10px]">[{user?.role}]</div>
            </div>
          </div>
          <button onClick={handleLogout} className="text-slate-400 hover:text-rose-400 transition p-1.5 rounded-lg hover:bg-white/5 cursor-pointer" title="Logout">
            <LogOut size={14} />
          </button>
        </div>
      </header>

      {/* ─── MAIN SOC GRID ────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-hidden flex gap-2.5 p-2.5">
        {/* Left Column: Command Panels */}
        <div className="flex flex-col gap-2.5 flex-1 min-w-0">

          {/* Row 1: KPI Stat Cards */}
          <div className="grid grid-cols-4 gap-2.5">
            <MiniStat label="Live Threats" value={liveThreats.length} icon={AlertOctagon} color="red" sub={`${unacknowledgedAlerts.length} unacknowledged`} pulse={liveThreats.length > 0} />
            <MiniStat label="Firewall Blocks" value={fwRules.length} icon={ShieldOff} color="orange" sub="active rules active" />
            <MiniStat label="System Health" value={`${liveMetrics.sys_health?.toFixed(0) ?? 98}%`} icon={Activity} color="green" pulse />
            <MiniStat label="Risk Score" value={liveMetrics.risk_score?.toFixed(0) ?? 0} icon={TrendingUp} color="cyan" sub="MLP inference engine" />
          </div>

          {/* Row 2: Visual Telemetry Charts */}
          <div className="grid grid-cols-2 gap-2.5" style={{ height: "155px" }}>
            <div className="cyber-card p-3 flex flex-col">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <Activity size={11} className="text-cyber-cyan" /> Risk Velocity Timeline
                </span>
                <span className="text-[9px] font-mono text-slate-500">Real-time</span>
              </div>
              <div className="flex-1">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartHistory} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
                    <defs>
                      <linearGradient id="rg" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00e5ff" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#00e5ff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" tick={{ fontSize: 8, fill: "#64748b" }} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 8, fill: "#64748b" }} />
                    <Tooltip contentStyle={{ background: "#070f1f", border: "1px solid #00e5ff", borderRadius: "6px", fontSize: 10, fontFamily: "monospace" }} />
                    <Area type="monotone" dataKey="risk" stroke="#00e5ff" fill="url(#rg)" strokeWidth={2} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="cyber-card p-3 flex flex-col">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <BarChart3 size={11} className="text-emerald-400" /> Attack Vector Distribution
                </span>
                <span className="text-[9px] font-mono text-slate-500">{logs.length} events logged</span>
              </div>
              <div className="flex-1">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackDistrib.slice(0, 6)} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
                    <XAxis dataKey="name" tick={{ fontSize: 8, fill: "#64748b" }} />
                    <YAxis tick={{ fontSize: 8, fill: "#64748b" }} />
                    <Tooltip contentStyle={{ background: "#070f1f", border: "1px solid #22c55e", borderRadius: "6px", fontSize: 10, fontFamily: "monospace" }} />
                    <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                      {attackDistrib.slice(0, 6).map((entry, i) => (
                        <Cell key={i} fill={ATTACK_COLORS[entry.name] || "#00e5ff"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Row 3: Core Operations (Threat Feed + Alert Triage + Firewall) */}
          <div className="grid grid-cols-3 gap-2.5 flex-1 min-h-0">
            {/* Live Feed with Filter Tabs */}
            <div className="cyber-card p-3 flex flex-col overflow-hidden">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <Radio size={11} className="text-rose-400 pulse-dot" /> Live Threat Feed
                </span>
                {/* Severity filter pills */}
                <div className="flex gap-0.5 bg-black/40 p-0.5 rounded border border-white/5">
                  {["ALL", "CRITICAL", "HIGH"].map(f => (
                    <button key={f} onClick={() => setFeedFilter(f)}
                      className={`px-1.5 py-0.5 text-[8px] font-mono rounded transition cursor-pointer ${feedFilter === f ? "bg-cyan-500/20 text-cyan-300 font-bold" : "text-slate-500 hover:text-slate-300"}`}>
                      {f}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
                {filteredThreats.slice(0, 25).map((t, i) => (
                  <div key={t.attack_log_id || i}
                    onClick={() => {
                      setSelectedAttackLogId(t.attack_log_id);
                      openDrawer(`Threat Telemetry #${t.attack_log_id}`,
                        <AttackDetail log={logs.find(l => l.id === t.attack_log_id) || t}
                          onBlockIp={blockIpDirect}
                          onAcknowledge={acknowledgeByAttackLog} />
                      )
                    }}
                    className="cyber-card px-2.5 py-2 cursor-pointer hover:border-cyan-500/40 hover:bg-white/5 transition group flex items-center justify-between">
                    <div className="flex items-center gap-2 min-w-0">
                      <AttackIcon type={t.attack_type} size={15} />
                      <div className="min-w-0">
                        <div className="text-xs font-mono text-white group-hover:text-cyber-cyan transition truncate font-bold">{t.attack_type}</div>
                        <div className="text-[10px] font-mono text-slate-400 truncate">{t.source_ip || t.dataset_source}</div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-0.5">
                      <span className={sevBadge(t.severity)}>{t.severity}</span>
                      <span className="text-[9px] font-mono text-slate-500">{timeAgo(t.timestamp || t.detected_at)}</span>
                    </div>
                  </div>
                ))}
                {filteredThreats.length === 0 && (
                  <div className="text-xs text-slate-500 font-mono text-center py-6">Monitoring network stream... no active threats in view</div>
                )}
              </div>
            </div>

            {/* Alert Triage */}
            <div className="cyber-card p-3 flex flex-col overflow-hidden">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <Bell size={11} className="text-amber-400" /> Alert Triage ({alerts.length})
                </span>
                <span className="text-[10px] font-mono text-rose-400 font-bold">{unacknowledgedAlerts.length} unacked</span>
              </div>
              <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
                {alerts.slice(0, 25).map(alert => (
                  <div key={alert.id}
                    onClick={() => openDrawer(`Security Alert #${alert.id}`, (
                      <div className="space-y-3">
                        <div className="flex items-center gap-3 p-3 rounded-lg bg-amber-950/40 border border-amber-500/30">
                          <Bell size={22} className="text-amber-400" />
                          <div>
                            <div className="text-sm font-bold text-white">{alert.title}</div>
                            <span className={sevBadge(alert.severity)}>{alert.severity}</span>
                          </div>
                        </div>
                        <div className="cyber-card p-3 text-xs font-mono text-slate-300 leading-relaxed">{alert.message}</div>
                        {!alert.is_acknowledged ? (
                          <button onClick={() => { acknowledgeAlert(alert.id); setDrawer(false) }}
                            className="w-full py-2.5 bg-emerald-950/70 border border-emerald-500/60 text-emerald-300 font-mono text-xs rounded-lg hover:bg-emerald-900/80 transition cursor-pointer font-bold flex items-center justify-center gap-2">
                            <CheckCircle size={14} /> Acknowledge & Mitigate Alert
                          </button>
                        ) : (
                          <div className="p-2 rounded bg-white/5 text-center text-xs font-mono text-emerald-400">✓ Already Acknowledged</div>
                        )}
                      </div>
                    ))}
                    className={`cyber-card px-2.5 py-2 cursor-pointer hover:border-amber-500/40 hover:bg-white/5 transition group flex items-center justify-between ${alert.is_acknowledged ? "opacity-50" : ""}`}>
                    <div className="min-w-0">
                      <div className="text-xs font-mono text-white group-hover:text-cyber-cyan transition truncate font-bold">{alert.title}</div>
                      <div className="text-[10px] font-mono text-slate-400 truncate">{(alert.message || "").substring(0, 45)}...</div>
                    </div>
                    <div className="flex flex-col items-end gap-1 ml-2">
                      <span className={sevBadge(alert.severity)}>{alert.severity}</span>
                      {!alert.is_acknowledged && <span className="w-2 h-2 rounded-full bg-amber-400 pulse-dot shadow-[0_0_6px_#ffd60a]" />}
                    </div>
                  </div>
                ))}
                {alerts.length === 0 && <div className="text-xs text-slate-500 font-mono text-center py-6">No alerts pending triage</div>}
              </div>
            </div>

            {/* Firewall Panel */}
            <div className="cyber-card p-3 flex flex-col overflow-hidden">
              <FirewallPanel rules={fwRules} onAutoBlock={autoBlockCritical} onRemove={removeRule} onAddOpen={() => setFwAddOpen(true)} loading={fwLoading} />
            </div>
          </div>

          {/* Row 4: AI & Optimizer Engine (XAI + QIGA + Hospital Assets) */}
          <div className="grid grid-cols-3 gap-2.5" style={{ height: "175px" }}>
            {/* XAI SHAP Attribution */}
            <div className="cyber-card p-3 flex flex-col">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <Brain size={11} className="text-purple-400" /> Explainable AI (SHAP)
                </span>
                {selectedAttackLogId && <span className="text-[9px] font-mono text-cyan-400">Target #{selectedAttackLogId}</span>}
              </div>
              {shapData.length > 0 ? (
                <div className="flex-1">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={shapData} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
                      <XAxis type="number" tick={{ fontSize: 7, fill: "#64748b" }} domain={["auto", "auto"]} />
                      <YAxis type="category" dataKey="feature" tick={{ fontSize: 7, fill: "#94a3b8" }} width={85} />
                      <Tooltip contentStyle={{ background: "#070f1f", border: "1px solid #a855f7", borderRadius: "6px", fontSize: 9, fontFamily: "monospace" }} />
                      <Bar dataKey="value" radius={[0, 2, 2, 0]}>
                        {shapData.map((entry, i) => <Cell key={i} fill={entry.value >= 0 ? "#f43f5e" : "#22c55e"} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="flex-1 flex items-center justify-center text-xs text-slate-500 font-mono">
                  {selectedAttackLogId ? "Computing SHAP attribution..." : "Select threat event to explain"}
                </div>
              )}
            </div>

            {/* QIGA Optimizer Recommendations */}
            <div className="cyber-card p-3 flex flex-col">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <Cpu size={11} className="text-blue-400" /> QIGA Quantum Optimizer
                </span>
                <span className="text-[9px] font-mono text-slate-500">Autonomous</span>
              </div>
              {qigaActions.length > 0 ? (
                <div className="flex-1 overflow-y-auto space-y-1 pr-1">
                  {qigaActions.slice(0, 6).map((a, i) => (
                    <div key={i} className="flex items-center justify-between text-[10px] font-mono cyber-card p-1.5">
                      <span className="text-slate-200 truncate">{a.title || a.action || a.action_name}</span>
                      <span className="text-cyber-cyan ml-1 flex-shrink-0 font-bold">{((a.confidence_score ?? a.effectiveness ?? a.score ?? 0) * 100).toFixed(0)}% Eff</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex-1 flex items-center justify-center text-xs text-slate-500 font-mono text-center">
                  {selectedAttackLogId ? "QIGA response optimization active" : "Select threat event to optimize"}
                </div>
              )}
            </div>

            {/* Hospital Assets Fleet */}
            <div className="cyber-card p-3 flex flex-col overflow-hidden">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                  <Server size={11} className="text-cyan-400" /> Hospital Device Grid ({assets.length})
                </span>
                <span className="text-[9px] font-mono text-emerald-400">Online</span>
              </div>
              <div className="flex-1 overflow-y-auto grid grid-cols-2 gap-1 content-start pr-1">
                {assets.slice(0, 10).map(a => {
                  const sc = { ONLINE: "#00ff88", OFFLINE: "#64748b", ISOLATED: "#ff9500", COMPROMISED: "#ff2d55" }
                  return (
                    <div key={a.id} className="cyber-card px-1.5 py-1 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: sc[a.status] || "#64748b" }} />
                      <div className="min-w-0">
                        <div className="text-[9px] font-mono text-slate-200 truncate font-semibold">{a.asset_name}</div>
                        <div className="text-[8px] font-mono text-slate-500">{a.status}</div>
                      </div>
                    </div>
                  )
                })}
                {assets.length === 0 && <div className="col-span-2 text-xs text-slate-600 font-mono text-center py-4">Scanning asset fleet...</div>}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Interactive Attack Simulator */}
        <div className="w-[245px] flex-shrink-0 cyber-card p-3 flex flex-col overflow-hidden shadow-xl border-cyan-500/30">
          <SimulatorPanel sim={sim} />
        </div>
      </div>

      {/* ─── DETAIL DRAWER ────────────────────────────────────────────────── */}
      <Drawer open={drawer} onClose={() => setDrawer(false)} title={drawerTitle}>
        {drawerContent}
      </Drawer>

      {/* ─── FIREWALL ADD RULE MODAL ──────────────────────────────────────── */}
      {fwAddOpen && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center">
          <div className="cyber-card p-5 w-84 space-y-3.5 shadow-2xl border-cyan-500/40">
            <div className="flex items-center justify-between">
              <span className="font-mono font-bold text-cyber-cyan text-sm tracking-wider">Add Firewall Block Rule</span>
              <button onClick={() => setFwAddOpen(false)}><X size={14} className="text-slate-400 hover:text-white" /></button>
            </div>
            <div className="space-y-2.5">
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase">Target IP Address *</label>
                <input value={newIp} onChange={e => setNewIp(e.target.value)} placeholder="192.168.1.100"
                  className="w-full mt-1 bg-black/60 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:border-cyber-cyan focus:outline-none" />
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase">Block Justification / Reason</label>
                <input value={newReason} onChange={e => setNewReason(e.target.value)} placeholder="Manual SOC quarantine"
                  className="w-full mt-1 bg-black/60 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-white focus:border-cyber-cyan focus:outline-none" />
              </div>
            </div>
            <div className="flex gap-2 pt-1">
              <button onClick={() => setFwAddOpen(false)} className="flex-1 py-1.5 text-xs font-mono border border-slate-700 text-slate-400 rounded-lg hover:bg-white/5 transition cursor-pointer">Cancel</button>
              <button onClick={addManualRule} disabled={addingRule || !newIp} className="flex-1 py-1.5 text-xs font-mono btn-primary rounded-lg disabled:opacity-50 cursor-pointer font-bold">{addingRule ? "Enforcing..." : "Enforce Block"}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
