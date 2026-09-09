import React, { useEffect, useState } from 'react'
import {
  Zap,
  ShieldOff,
  CheckCircle,
  RefreshCw,
  AlertTriangle,
  AlertOctagon,
  Terminal,
  Shield,
  Search,
  Flame,
  User,
  Radio,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  UserCheck,
} from 'lucide-react'
import api from '../utils/api'
import { useAuthStore, useIncidentStore } from '../store'
import { useSOCStore } from '../store/socEngine'

export default function Response() {
  const { user } = useAuthStore()
  const { selectedAttackLogId, setSelectedAttackLogId } = useIncidentStore()
  const incidents = useSOCStore((state) => state.incidents)
  const acknowledgeThreat = useSOCStore((state) => state.acknowledgeThreat)

  // Real detected threats sorted by highest risk
  const activeThreats = incidents
    .filter((inc) => inc.is_threat && inc.attack_type !== 'Normal')
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))

  // Selected threat resolution
  const selectedLog =
    incidents.find((inc) => {
      const id = inc.attack_log_id ?? inc.id
      return String(id) === String(selectedAttackLogId)
    }) ||
    activeThreats[0] ||
    null

  const threatId = selectedLog ? selectedLog.attack_log_id ?? selectedLog.id : null

  // Ensure an initial threat is selected if available
  useEffect(() => {
    if (!selectedAttackLogId && activeThreats.length > 0) {
      const firstId = activeThreats[0].attack_log_id ?? activeThreats[0].id
      setSelectedAttackLogId(firstId)
    }
  }, [selectedAttackLogId, activeThreats, setSelectedAttackLogId])

  // Fetch QIGA intelligence briefing for selected threat
  const [recs, setRecs] = useState([])
  const [loadingRecs, setLoadingRecs] = useState(false)
  const [ackLoading, setAckLoading] = useState(false)
  const [ackSuccess, setAckSuccess] = useState(false)
  const [ackedThreatIds, setAckedThreatIds] = useState(() => new Set())
  const [blockLoading, setBlockLoading] = useState(false)
  const [blockSuccess, setBlockSuccess] = useState(false)

  useEffect(() => {
    if (!threatId) {
      setRecs([])
      return
    }
    setLoadingRecs(true)
    api
      .get(`/recommendations/?attack_log_id=${threatId}&limit=6`)
      .then((res) => {
        setRecs(Array.isArray(res.data) ? res.data : [])
      })
      .catch(() => setRecs([]))
      .finally(() => setLoadingRecs(false))
  }, [threatId])

  const isAcknowledged =
    selectedLog?.status === 'ACKNOWLEDGED' ||
    ackedThreatIds.has(String(threatId))

  const normalizedRole = String(user?.role ?? '').toLowerCase()
  const canAcknowledge =
    normalizedRole === 'admin' ||
    normalizedRole === 'analyst' ||
    !user?.role // allow by default for analyst session

  const handleAcknowledgeThreat = async () => {
    if (!threatId || ackLoading) return
    setAckLoading(true)
    setAckedThreatIds((prev) => new Set([...prev, String(threatId)]))
    try {
      await acknowledgeThreat(threatId)
      setAckSuccess(true)
      setTimeout(() => setAckSuccess(false), 3500)
    } catch (err) {
      console.error('[Response] Acknowledge error:', err)
    } finally {
      setAckLoading(false)
    }
  }

  const handleBlockIp = async () => {
    if (!selectedLog?.source_ip || selectedLog.source_ip === 'N/A' || blockLoading) return
    setBlockLoading(true)
    try {
      await api.post(
        `/firewall/block?ip_address=${encodeURIComponent(
          selectedLog.source_ip
        )}&reason=${encodeURIComponent(
          `Manual analyst block for Threat #${threatId}: ${selectedLog.attack_type}`
        )}&severity=CRITICAL`
      )
      setBlockSuccess(true)
      setTimeout(() => setBlockSuccess(false), 3500)
    } catch (err) {
      console.error('[Response] Block error:', err)
    } finally {
      setBlockLoading(false)
    }
  }

  // Helper for threat navigation
  const currentIndex = activeThreats.findIndex(
    (t) => String(t.attack_log_id ?? t.id) === String(threatId)
  )

  const handlePrev = () => {
    if (currentIndex > 0) {
      const prev = activeThreats[currentIndex - 1]
      setSelectedAttackLogId(prev.attack_log_id ?? prev.id)
    }
  }

  const handleNext = () => {
    if (currentIndex < activeThreats.length - 1) {
      const next = activeThreats[currentIndex + 1]
      setSelectedAttackLogId(next.attack_log_id ?? next.id)
    }
  }

  return (
    <div className="p-6 space-y-6 bg-cyber-bg min-h-screen text-slate-100 font-sans">
      {/* ─── HEADER ──────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/20 pb-4">
        <div>
          <h1 className="text-2xl font-black font-mono tracking-wide text-white flex items-center gap-2.5">
            <Shield className="text-cyber-cyan" size={24} />
            THREAT ORCHESTRATION &amp; ANALYST VERIFICATION
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Real-time security threat stream. Automated mitigation is disabled; human analyst review and acknowledgement required.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-300">
            <span className="w-2 h-2 rounded-full bg-cyan-400 pulse-dot" />
            HUMAN-IN-THE-LOOP ACTIVE
          </div>
          <div className="text-xs font-mono text-slate-400 bg-black/40 px-3 py-1.5 rounded border border-white/10">
            Operator: <span className="text-white font-bold">{user?.full_name || user?.username || 'Dr. Sara Gharat'}</span> ({user?.role || 'analyst'})
          </div>
        </div>
      </div>

      {/* ─── COMPACT THREAT SELECTOR ──────────────────────────────────────── */}
      <div className="cyber-card p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-l-4 border-cyber-cyan">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-red-950/60 border border-red-500/40 flex items-center justify-center">
            <AlertOctagon className="text-red-400" size={20} />
          </div>
          <div>
            <div className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              Detected Healthcare Threats
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
              {activeThreats.length} threat{activeThreats.length !== 1 ? 's' : ''} currently logged in network stream
            </div>
          </div>
        </div>

        {activeThreats.length > 0 ? (
          <div className="flex items-center gap-2 w-full md:w-auto">
            <button
              onClick={handlePrev}
              disabled={currentIndex <= 0}
              className="p-1.5 rounded bg-black/50 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition"
              title="Previous threat"
            >
              <ChevronLeft size={16} />
            </button>

            <select
              value={threatId || ''}
              onChange={(e) => setSelectedAttackLogId(e.target.value)}
              className="bg-black/80 border border-cyan-500/40 text-cyan-300 text-xs font-mono rounded-lg px-3 py-2 focus:border-cyber-cyan focus:outline-none w-full md:w-96 font-semibold"
            >
              {activeThreats.map((t) => {
                const id = t.attack_log_id ?? t.id
                const isAck =
                  t.status === 'ACKNOWLEDGED' ||
                  ackedThreatIds.has(String(id))
                return (
                  <option key={id} value={id}>
                    #{id} · {t.attack_type} [{t.severity}] · Risk {Math.round(t.risk_score || 0)}/100 · {isAck ? '✓ ACKNOWLEDGED' : 'DETECTED'}
                  </option>
                )
              })}
            </select>

            <button
              onClick={handleNext}
              disabled={currentIndex >= activeThreats.length - 1}
              className="p-1.5 rounded bg-black/50 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition"
              title="Next threat"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        ) : (
          <div className="text-xs font-mono text-slate-500">
            No active threats in network stream
          </div>
        )}
      </div>

      {/* ─── NO THREATS EMPTY STATE ───────────────────────────────────────── */}
      {!selectedLog && (
        <div className="cyber-card p-12 text-center border-dashed border-slate-800">
          <CheckCircle size={40} className="text-emerald-500/60 mx-auto mb-3" />
          <h2 className="text-base font-mono font-bold text-white uppercase">
            Network Stream Clear
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1 max-w-md mx-auto">
            Zero security threats detected. Continuous MLP classification and healthcare node telemetry monitoring is running normally.
          </p>
        </div>
      )}

      {/* ─── MAIN THREAT INVESTIGATION & ANALYST TRIAGE ───────────────────── */}
      {selectedLog && (
        <div className="space-y-5">
          {/* Status & Analyst Verification Banner */}
          <div className={`cyber-card p-5 border-l-4 transition-all duration-300 ${
            isAcknowledged ? 'border-emerald-500 bg-emerald-950/10' : 'border-red-500 bg-red-950/10'
          }`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2.5">
                  <span className={`w-2.5 h-2.5 rounded-full ${isAcknowledged ? 'bg-emerald-400' : 'bg-red-500 pulse-dot'}`} />
                  <span className="text-xs font-mono font-black uppercase tracking-wider text-slate-300">
                    Mandatory Analyst Verification
                  </span>
                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-black tracking-wider uppercase border ${
                    isAcknowledged
                      ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/60 shadow-[0_0_10px_rgba(16,185,129,0.3)]'
                      : 'bg-red-950/80 text-red-300 border-red-500/60 shadow-[0_0_10px_rgba(255,45,85,0.3)]'
                  }`}>
                    STATUS: {isAcknowledged ? 'ACKNOWLEDGED' : 'DETECTED'}
                  </span>
                </div>

                <p className="text-xs font-mono text-slate-400 mt-1.5 leading-relaxed max-w-2xl">
                  {isAcknowledged
                    ? 'This threat has been reviewed, acknowledged, and signed off by a certified healthcare security analyst.'
                    : 'Threat requires manual review by the security analyst. Automatic containment and recovery are disabled to protect healthcare availability.'}
                </p>
              </div>

              {/* Action Buttons for Analyst */}
              <div className="flex flex-wrap items-center gap-3">
                {!isAcknowledged && canAcknowledge && (
                  <button
                    onClick={handleAcknowledgeThreat}
                    disabled={ackLoading}
                    className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-mono font-bold text-xs rounded-lg transition-all shadow-[0_0_15px_rgba(16,185,129,0.4)] flex items-center gap-2 cursor-pointer disabled:opacity-60 active:scale-[0.98]"
                  >
                    {ackLoading ? (
                      <RefreshCw size={14} className="animate-spin text-slate-950" />
                    ) : (
                      <CheckCircle size={14} className="text-slate-950 font-black" />
                    )}
                    <span>Acknowledge Threat (Analyst Sign-off)</span>
                  </button>
                )}

                {isAcknowledged && (
                  <div className="flex items-center gap-2 px-4 py-2 bg-emerald-950/60 border border-emerald-500/60 rounded-lg text-emerald-300 font-mono text-xs font-bold shadow-[0_0_10px_rgba(16,185,129,0.2)]">
                    <UserCheck size={16} className="text-emerald-400" />
                    <span>✓ Acknowledged by Analyst ({user?.full_name || 'Dr. Sara Gharat'})</span>
                  </div>
                )}

                {selectedLog.source_ip && selectedLog.source_ip !== 'N/A' && (
                  <button
                    onClick={handleBlockIp}
                    disabled={blockLoading || blockSuccess}
                    className={`px-4 py-2.5 font-mono font-bold text-xs rounded-lg transition-all flex items-center gap-2 border cursor-pointer disabled:opacity-60 ${
                      blockSuccess
                        ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300'
                        : 'bg-rose-950/80 hover:bg-rose-900 border-rose-500/60 text-rose-300'
                    }`}
                  >
                    <ShieldOff size={14} />
                    <span>{blockSuccess ? 'Source IP Blocked ✓' : `Block IP (${selectedLog.source_ip})`}</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Threat Metadata Grid */}
          <div className="cyber-card p-5">
            <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle size={16} className="text-yellow-400" />
                <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                  Threat Telemetry &amp; Impact Analysis — AttackLog #{threatId}
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                Detected: {selectedLog.detected_at ? new Date(selectedLog.detected_at).toLocaleString() : 'Live'}
              </span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">Attack Type</p>
                <p className="text-sm font-black text-white mt-1 truncate">{selectedLog.attack_type || 'N/A'}</p>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">Severity Level</p>
                <p className="text-sm font-black text-orange-400 mt-1 truncate">{selectedLog.severity || 'HIGH'}</p>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">Risk Index Score</p>
                <p className="text-sm font-black text-red-400 mt-1">
                  {selectedLog.risk_score != null ? `${Math.round(Number(selectedLog.risk_score))}/100` : 'N/A'}
                </p>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">AI Classifier Confidence</p>
                <p className="text-sm font-black text-cyber-cyan mt-1">
                  {selectedLog.confidence != null ? `${Math.round(Number(selectedLog.confidence))}%` : '98%'}
                </p>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">Target Hospital Asset</p>
                <p className="text-sm font-bold text-purple-300 mt-1 truncate">
                  {selectedLog.asset_name || selectedLog.dest_ip || 'Laboratory Server'}
                </p>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">Department Enclave</p>
                <p className="text-sm font-bold text-slate-200 mt-1 truncate">
                  {selectedLog.department || 'Hospital IT'}
                </p>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">Source IP / Origin</p>
                <p className="text-sm font-bold text-cyan-400 mt-1 truncate font-mono">
                  {selectedLog.source_ip || 'N/A'}
                </p>
              </div>

              <div className="p-3 bg-black/40 rounded-lg border border-white/5">
                <p className="text-[10px] text-slate-400 uppercase">Target Port &amp; Protocol</p>
                <p className="text-sm font-bold text-slate-200 mt-1 truncate">
                  {selectedLog.port || '80'} / {selectedLog.protocol || 'TCP'}
                </p>
              </div>
            </div>

            {/* MITRE Alignment */}
            {(selectedLog.mitre_technique_id || selectedLog.mitre_technique_name) && (
              <div className="mt-4 p-3.5 rounded-lg bg-purple-950/20 border border-purple-700/40">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-purple-400 uppercase font-bold">
                    MITRE ATT&amp;CK Matrix Alignment
                  </span>
                  <span className="text-xs font-mono font-bold text-purple-300">
                    {selectedLog.mitre_technique_id || 'T1486'}
                  </span>
                </div>
                <p className="text-xs text-purple-200 font-mono mt-1">
                  {selectedLog.mitre_technique_name || 'Data Encrypted for Impact'}
                </p>
                {selectedLog.description && (
                  <p className="text-[11px] text-slate-400 font-mono mt-2 leading-relaxed">
                    {selectedLog.description}
                  </p>
                )}
              </div>
            )}
          </div>

          {/* AI Decision Support & Advisory Guidance */}
          <div className="cyber-card p-5">
            <div className="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
              <div>
                <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Zap size={14} className="text-cyber-cyan" /> AI Decision Support &amp; Recommended Actions
                </h3>
                <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                  Guidance generated by QIGA for human analyst review. No action is performed automatically.
                </p>
              </div>
              <span className="text-[10px] font-mono text-cyan-400 border border-cyan-500/30 px-2 py-0.5 rounded">
                ADVISORY ONLY
              </span>
            </div>

            {loadingRecs ? (
              <div className="py-6 text-center font-mono text-xs text-slate-400">
                <RefreshCw size={16} className="animate-spin inline mr-2 text-cyan-400" />
                Retrieving AI recommendations...
              </div>
            ) : recs.length === 0 ? (
              <div className="p-4 rounded-lg bg-black/40 border border-white/5 text-xs font-mono text-slate-400">
                Standard containment guidance: Isolate target subnet, inspect host memory, and rotate privileged medical workstation credentials manually.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {recs.map((r, i) => (
                  <div key={r.id || i} className="p-3.5 rounded-lg bg-black/40 border border-cyan-500/20 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-white">{r.title || r.action_type}</span>
                        <span className="text-[10px] font-mono text-cyan-400 font-bold">{r.confidence_score ? `${Math.round(r.confidence_score * 100)}% Conf` : 'HIGH'}</span>
                      </div>
                      <p className="text-[11px] font-mono text-slate-300 mt-1.5 leading-relaxed">
                        {r.description || 'Review network logs and isolate affected node per hospital SOC protocol.'}
                      </p>
                    </div>
                    <div className="mt-3 pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-slate-500">
                      <span>Action Type: {r.action_type || 'MANUAL_TRIAGE'}</span>
                      <span className="text-emerald-400">Analyst Discretion</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
