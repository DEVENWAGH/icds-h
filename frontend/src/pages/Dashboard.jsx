import React, { useEffect, useState, useCallback, useMemo } from 'react'
import {
  Cpu,
  FileText,
  Database,
  AlertOctagon,
  AlertTriangle,
  RefreshCw,
  Server,
  TrendingUp,
  Activity,
  Shield,
  Network,
  Stethoscope,
  Radio,
  Layers
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from 'recharts'

import { useAlertStore, useAuthStore } from '../store'
import { useSOCStore } from '../store/socEngine'
import api from '../utils/api'

const SEV_COLOR = {
  CRITICAL: '#f87171',
  HIGH: '#fbbf24',
  MEDIUM: '#f59e0b',
  LOW: '#38bdf8',
}

/** Prefer the strongest real count so WS zeros never hide live SOC data. */
function pickCount(...values) {
  const nums = values
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value) && value >= 0)
  return nums.length ? Math.max(...nums) : 0
}

function pickRisk(...values) {
  const nums = values
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value) && value > 0)
  return nums.length ? Math.max(...nums) : 0
}

const SEVERITY_WEIGHT = {
  CRITICAL: 1,
  HIGH: 0.75,
  MEDIUM: 0.45,
  LOW: 0.2,
}

/** Same composite as backend telemetry — real active AttackLog risk, not a mock. */
function computeLocalSystemThreat(activeIncidents) {
  if (!activeIncidents.length) {
    return { score: 0, peak: 0, mean: 0, status: 'STABLE' }
  }

  const scores = activeIncidents.map((incident) => {
    const score = Number(incident.risk_score)
    return Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0
  })
  const peak = Math.max(...scores)
  const mean = scores.reduce((sum, value) => sum + value, 0) / scores.length
  const severityPressure = activeIncidents.reduce(
    (sum, incident) => sum + (SEVERITY_WEIGHT[incident.severity] || 0.2),
    0
  )
  const volumeFactor = Math.min(25, activeIncidents.length * 2.5)
  const severityFactor = Math.min(20, severityPressure * 4)
  const score = Math.min(100, (0.55 * peak) + (0.25 * mean) + (0.12 * volumeFactor) + (0.08 * severityFactor))
  const rounded = Math.round(score * 10) / 10

  return {
    score: rounded,
    peak: Math.round(peak * 10) / 10,
    mean: Math.round(mean * 10) / 10,
    status: rounded > 70 ? 'CRITICAL' : rounded > 40 ? 'WARNING' : 'STABLE',
  }
}

const StatCard = ({
  label,
  value,
  sub,
  icon: Icon,
  color = 'cyan',
  pulse,
}) => (
  <div className="card-marketing p-5 bg-[#0a0a0a] border border-[#262626]">
    <div className="flex items-start justify-between mb-3">
      <span className="text-xs font-mono text-mute uppercase tracking-wider">
        {label}
      </span>
      <Icon
        size={15}
        className="text-mute"
      />
    </div>

    <div className="text-2xl sm:text-3xl font-semibold font-mono text-white flex items-center gap-2 tracking-tight">
      {value}
      {pulse && (
        <span className="w-2 h-2 rounded-full bg-cyan pulse-dot" />
      )}
    </div>

    {sub && (
      <div className="text-[11px] font-mono text-mute mt-1">
        {sub}
      </div>
    )}
  </div>
)

export default function Dashboard() {
  const { user } = useAuthStore()
  const { liveMetrics } = useAlertStore()

  const incidents = useSOCStore((state) => state.incidents)

  const [dashboardData, setDashboardData] = useState(null)
  const [riskHistory, setRiskHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // ---------------------------------------------------------
  // Backend dashboard snapshot
  // ---------------------------------------------------------
  const refreshIncidents = useSOCStore((state) => state.refreshIncidents)

  const fetchData = useCallback(async () => {
    try {
      setRefreshing(true)
      const [dashboardResponse, riskResponse] = await Promise.all([
        api.get('/dashboard/'),
        api.get('/dashboard/risk-history'),
      ])
      await refreshIncidents()

      setDashboardData(dashboardResponse.data ?? {})
      setRiskHistory(Array.isArray(riskResponse.data) ? riskResponse.data : [])
    } catch (error) {
      console.error('[Dashboard] Failed to fetch dashboard data:', error)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [refreshIncidents])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => clearInterval(interval)
  }, [fetchData])

  // Re-sync overview when live threats arrive over WebSocket
  useEffect(() => {
    const onSocEvent = () => {
      // light refresh of backend snapshot without blocking UI
      api.get('/dashboard/').then((res) => setDashboardData(res.data ?? {})).catch(() => {})
      api.get('/dashboard/risk-history').then((res) => {
        if (Array.isArray(res.data)) setRiskHistory(res.data)
      }).catch(() => {})
    }
    window.addEventListener('mlp-prediction', onSocEvent)
    window.addEventListener('lifecycle-update', onSocEvent)
    return () => {
      window.removeEventListener('mlp-prediction', onSocEvent)
      window.removeEventListener('lifecycle-update', onSocEvent)
    }
  }, [])

  const filteredIncidents = useMemo(
    () => incidents.filter((incident) => incident.attack_type !== 'Normal'),
    [incidents]
  )

  const activeIncidents = useMemo(
    () => filteredIncidents.filter((incident) => !incident.resolved && String(incident.status || '').toUpperCase() !== 'RESOLVED'),
    [filteredIncidents]
  )

  const localCritical = activeIncidents.filter((incident) => incident.severity === 'CRITICAL').length
  const localThreat = useMemo(
    () => computeLocalSystemThreat(activeIncidents),
    [activeIncidents]
  )

  const localSeverity = useMemo(() => ({
    CRITICAL: filteredIncidents.filter((i) => i.severity === 'CRITICAL').length,
    HIGH: filteredIncidents.filter((i) => i.severity === 'HIGH').length,
    MEDIUM: filteredIncidents.filter((i) => i.severity === 'MEDIUM').length,
    LOW: filteredIncidents.filter((i) => i.severity === 'LOW').length,
  }), [filteredIncidents])

  // Local SOC stream is the same source as the incidents table — never hide it behind WS zeros.
  const activeThreats = pickCount(
    activeIncidents.length,
    liveMetrics?.active_threats,
    dashboardData?.attack_stats?.active
  )

  const totalIncidents = pickCount(
    filteredIncidents.length,
    liveMetrics?.total_incidents,
    dashboardData?.incident_stats?.total,
    dashboardData?.attack_stats?.total
  )

  const criticalAlerts = pickCount(
    localCritical,
    liveMetrics?.critical_alerts,
    dashboardData?.alert_stats?.unacknowledged
  )

  const systemsProtected = pickCount(
    liveMetrics?.systems_protected,
    dashboardData?.asset_stats?.online
  )

  // Real composite threat level from active MLP risk scores (not mock).
  const riskScore = pickRisk(
    localThreat.score,
    liveMetrics?.risk_score,
    liveMetrics?.peak_risk,
    dashboardData?.latest_risk_score?.score
  )

  const riskStatus =
    liveMetrics?.risk_status ||
    dashboardData?.latest_risk_score?.status ||
    localThreat.status ||
    (riskScore > 70 ? 'CRITICAL' : riskScore > 40 ? 'WARNING' : activeThreats > 0 ? 'WARNING' : 'STABLE')

  const peakRisk = pickRisk(
    localThreat.peak,
    liveMetrics?.peak_risk,
    dashboardData?.latest_risk_score?.peak_risk,
    riskScore
  )

  const meanRisk = pickRisk(
    localThreat.mean,
    liveMetrics?.mean_risk,
    dashboardData?.latest_risk_score?.mean_risk
  )

  const sysHealthRaw = Number(
    liveMetrics?.sys_health ?? dashboardData?.sys_health
  )
  const sysHealth = Number.isFinite(sysHealthRaw)
    ? sysHealthRaw
    : Math.max(0, 100 - Number(criticalAlerts) * 4 - Math.min(Number(activeThreats), 25) * 0.8)

  const activeConfidenceValues = activeIncidents
    .map((incident) => Number(incident.confidence))
    .filter((value) => Number.isFinite(value) && value > 0)

  const avgConf = activeConfidenceValues.length
    ? Math.round(
        activeConfidenceValues.reduce((sum, value) => sum + value, 0) / activeConfidenceValues.length
      )
    : 0

  const sevData = [
    {
      name: 'CRIT',
      val: pickCount(localSeverity.CRITICAL, dashboardData?.severity_counts?.CRITICAL),
      color: '#f87171',
    },
    {
      name: 'HIGH',
      val: pickCount(localSeverity.HIGH, dashboardData?.severity_counts?.HIGH),
      color: '#fbbf24',
    },
    {
      name: 'MED',
      val: pickCount(localSeverity.MEDIUM, dashboardData?.severity_counts?.MEDIUM),
      color: '#0070f3',
    },
    {
      name: 'LOW',
      val: pickCount(localSeverity.LOW, dashboardData?.severity_counts?.LOW),
      color: '#50e3c2',
    },
  ]

  const normalizedRiskHistory = useMemo(
    () =>
      riskHistory
        .map((item, index) => ({
          id: `${item?.t ?? 'risk'}-${index}`,
          time: item?.t ?? '',
          score: Number(item?.risk ?? 0),
          threats: Number(item?.threats ?? 0),
        }))
        .filter((item) => Number.isFinite(item.score)),
    [riskHistory]
  )

  const chartData = useMemo(() => {
    const history = normalizedRiskHistory.slice(-29)
    if (!riskScore && !activeThreats) {
      return history
    }

    // Build trend from live incidents when history is empty
    if (!history.length && activeIncidents.length) {
      return [...activeIncidents]
        .slice(0, 12)
        .reverse()
        .map((incident, index) => ({
          id: `inc-${incident.attack_log_id ?? index}`,
          time: incident.detected_at
            ? new Date(incident.detected_at).toLocaleTimeString([], { hour12: false })
            : `${index}`,
          score: Number(incident.risk_score) || 0,
          threats: 1,
        }))
    }

    return [
      ...history,
      {
        id: 'live-current-risk',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        score: riskScore,
        threats: Number(activeThreats) || 0,
      },
    ]
  }, [normalizedRiskHistory, riskScore, activeThreats, activeIncidents])

  if (loading && !dashboardData && incidents.length === 0) {
    return (
      <div className="p-10 text-center text-white font-mono">
        <RefreshCw className="animate-spin inline mr-2 text-mute" size={16} />
        Synchronizing SOC Overview Data...
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-6 max-w-7xl mx-auto font-sans bg-black">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight-md text-white">
            Security Operations Overview
          </h1>
          <p className="text-xs text-mute font-mono mt-0.5">
            Operator: <span className="text-white font-medium">{user?.full_name || 'Admin'}</span> · Role:{' '}
            <span className="text-white font-medium uppercase">{user?.role || 'SecDirector'}</span> · Clearance Level{' '}
            {user?.clearance_level ?? '5'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="badge-secondary text-[11px] font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
            <span>LIVE TELEMETRY</span>
          </div>

          <button
            onClick={fetchData}
            disabled={refreshing}
            className="btn-secondary text-xs cursor-pointer"
            title="Refresh dashboard"
          >
            <RefreshCw
              size={13}
              className={refreshing ? 'animate-spin' : ''}
            />
            <span>Sync</span>
          </button>
        </div>
      </div>

      {/* Risk Score Hero Card */}
      <div className="card-marketing-large p-8 text-center relative overflow-hidden bg-[#0a0a0a] border border-[#262626]">
        <div className="relative z-10">
          <p className="text-xs font-mono text-mute uppercase tracking-wider mb-2">
            System Threat Level
          </p>

          <div
            className="text-6xl sm:text-7xl font-semibold font-mono tracking-tight-xl text-white"
          >
            {Number(riskScore || 0).toFixed(0)}
            <span className="text-2xl sm:text-3xl text-mute font-normal font-sans ml-1">
              / 100
            </span>
          </div>

          <p className="text-[11px] font-mono text-mute mt-2">
            Live composite from active MLP risk · peak {Number(peakRisk || 0).toFixed(0)} · {activeThreats} open vector{Number(activeThreats) !== 1 ? 's' : ''}
          </p>

          <div className="flex items-center justify-center gap-2.5 mt-4 flex-wrap">
            <div
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium border ${
                riskStatus === 'CRITICAL'
                  ? 'bg-red-950/70 text-red-300 border-red-800/80'
                  : riskStatus === 'WARNING'
                  ? 'bg-yellow-950/70 text-yellow-300 border-yellow-800/80'
                  : 'bg-teal-950/70 text-teal-300 border-teal-800/80'
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  riskStatus === 'CRITICAL' ? 'bg-error' : riskStatus === 'WARNING' ? 'bg-warning' : 'bg-cyan'
                }`}
              />
              <span>{riskStatus} STATUS · {activeThreats} ACTIVE VECTOR{Number(activeThreats) !== 1 ? 'S' : ''}</span>
            </div>

            <div className="badge-secondary text-xs font-mono">
              <Cpu size={12} className="text-mute" />
              <span>AI Classifier Confidence: {avgConf}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Grid — 3×2 */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label="Peak Risk Score"
          value={Number(peakRisk || 0).toFixed(0)}
          sub="Highest active MLP risk"
          icon={AlertTriangle}
        />
        <StatCard
          label="Incidents"
          value={totalIncidents}
          icon={FileText}
        />
        <StatCard
          label="Protected Nodes"
          value={systemsProtected}
          icon={Server}
        />
        <StatCard
          label="Critical Alerts"
          value={criticalAlerts}
          icon={AlertOctagon}
          pulse={Number(criticalAlerts) > 0}
        />
        <StatCard
          label="System Health"
          value={`${Number(sysHealth || 0).toFixed(0)}%`}
          icon={Activity}
        />
        <StatCard
          label="Mean Risk"
          value={Number(meanRisk || 0).toFixed(0)}
          sub="Avg active MLP risk"
          icon={TrendingUp}
        />
      </div>

      {/* Charts Grid */}
      <div className="grid lg:grid-cols-2 gap-5">
        {/* Risk Trend Chart */}
        <div className="card-marketing p-5 bg-[#0a0a0a] border border-[#262626]">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono font-semibold text-white uppercase tracking-wider">
              Live Threat Index Trend
            </h3>
            <span className="text-[11px] font-mono text-mute">0 - 100 Score</span>
          </div>

          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="riskG" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0070f3" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#0070f3" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" hide />
              <YAxis domain={[0, 100]} hide />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0a0a0a',
                  border: '1px solid #262626',
                  borderRadius: 6,
                  fontSize: 12,
                  boxShadow: '0 8px 24px rgba(0,0,0,0.8)',
                  color: '#ffffff'
                }}
                formatter={(value) => [Number(value).toFixed(1), 'Risk Score']}
              />
              <Area
                type="monotone"
                dataKey="score"
                stroke="#0070f3"
                fill="url(#riskG)"
                strokeWidth={1.5}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Chart */}
        <div className="card-marketing p-5 bg-[#0a0a0a] border border-[#262626]">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono font-semibold text-white uppercase tracking-wider">
              Threat Severity Distribution
            </h3>
            <span className="text-[11px] font-mono text-mute">Active Incident Classes</span>
          </div>

          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={sevData} barSize={24}>
              <XAxis
                dataKey="name"
                tick={{ fill: '#737373', fontSize: 11, fontFamily: 'monospace' }}
                axisLine={{ stroke: '#262626' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#737373', fontSize: 10, fontFamily: 'monospace' }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0a0a0a',
                  border: '1px solid #262626',
                  borderRadius: 6,
                  fontSize: 12,
                  boxShadow: '0 8px 24px rgba(0,0,0,0.8)',
                  color: '#ffffff'
                }}
                formatter={(value) => [value, 'Incidents']}
              />
              <Bar dataKey="val" radius={[4, 4, 0, 0]}>
                {sevData.map((entry) => (
                  <Cell key={`severity-${entry.name}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Current Hospital Incidents Table */}
      <div className="card-marketing p-5 overflow-hidden bg-[#0a0a0a] border border-[#262626]">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs font-mono font-semibold text-white uppercase tracking-wider">
            Active Security Incidents &amp; Classifications
          </h3>
          <span className="text-[11px] font-mono text-mute">Total: {filteredIncidents.length}</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs font-sans text-left">
            <thead>
              <tr className="border-b border-[#262626] bg-[#141414] text-mute font-mono text-[11px] uppercase">
                <th className="py-2.5 px-3">Incident ID</th>
                <th className="py-2.5 px-3">Vector Type</th>
                <th className="py-2.5 px-3">Target Asset</th>
                <th className="py-2.5 px-3">Risk Level</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {filteredIncidents.slice(0, 8).map((inc) => {
                const incidentId = inc.attack_log_id ?? inc.id
                return (
                  <tr key={`incident-${incidentId}`} className="hover:bg-[#141414] transition-colors font-mono">
                    <td className="py-2.5 px-3 font-semibold text-white">
                      {inc.incidentId || `EVT-${incidentId}`}
                    </td>
                    <td className="py-2.5 px-3 font-sans text-white font-medium">
                      {inc.attack_type}
                    </td>
                    <td className="py-2.5 px-3 text-body">
                      {inc.asset_name || 'PACSServer-01'}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                        inc.severity === 'CRITICAL' ? 'severity-critical' : inc.severity === 'HIGH' ? 'severity-high' : 'severity-low'
                      }`}>
                        {inc.severity || 'LOW'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-white">
                      {inc.confidence != null ? `${Math.round(Number(inc.confidence))}%` : '99%'}
                    </td>
                    <td className="py-2.5 px-3 text-mute">
                      {inc.detected_at ? new Date(inc.detected_at).toLocaleTimeString() : 'Live'}
                    </td>
                    <td className="py-2.5 px-3 font-sans">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                        inc.status === 'ACKNOWLEDGED'
                          ? 'bg-emerald-950/60 text-emerald-400 border-emerald-500/50'
                          : 'bg-red-950/60 text-red-400 border-red-500/50'
                      }`}>
                        {inc.status === 'ACKNOWLEDGED' ? 'ACKNOWLEDGED' : 'DETECTED'}
                      </span>
                    </td>
                  </tr>
                )
              })}
              {filteredIncidents.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-mute font-mono">
                    Zero active hospital incidents recorded in this epoch.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Protected Asset Categories */}
      <div className="card-marketing p-5 bg-[#0a0a0a] border border-[#262626]">
        <h3 className="text-xs font-mono font-semibold text-white uppercase tracking-wider mb-4">
          Hospital Asset Protection Enclaves
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Patient EHR Data */}
          <div className="p-4 rounded-md border border-[#262626] bg-[#141414]">
            <div className="flex items-center gap-2 mb-2">
              <Database size={16} className="text-white" />
              <p className="text-xs font-semibold text-white">Patient EHR &amp; Clinical Data</p>
            </div>
            <div className="space-y-1 text-xs text-mute font-mono">
              <p>• Patient Records &amp; Medical History</p>
              <p>• Lab Reports &amp; Prescriptions</p>
              <p>• Billing &amp; Identity Enclave</p>
            </div>
            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-cyan">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
              <span>PROTECTED</span>
            </div>
          </div>

          {/* Hospital Network */}
          <div className="p-4 rounded-md border border-[#262626] bg-[#141414]">
            <div className="flex items-center gap-2 mb-2">
              <Network size={16} className="text-white" />
              <p className="text-xs font-semibold text-white">Hospital Subnet Infrastructure</p>
            </div>
            <div className="space-y-1 text-xs text-mute font-mono">
              <p>• EHR Core Database Cluster</p>
              <p>• Wi-Fi &amp; VLAN Microsegmentation</p>
              <p>• PAC Server Gateway</p>
            </div>
            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-cyan">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
              <span>ZERO TRUST ACTIVE</span>
            </div>
          </div>

          {/* Medical Devices */}
          <div className="p-4 rounded-md border border-[#262626] bg-[#141414]">
            <div className="flex items-center gap-2 mb-2">
              <Stethoscope size={16} className="text-white" />
              <p className="text-xs font-semibold text-white">IoMT Medical Devices</p>
            </div>
            <div className="space-y-1 text-xs text-mute font-mono">
              <p>• MRI / CT Scanners Telemetry</p>
              <p>• Ventilators &amp; Smart Infusion Pumps</p>
              <p>• ICU Bedside Vital Monitors</p>
            </div>
            <div className="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-cyan">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
              <span>CONTINUOUS TELEMETRY</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}