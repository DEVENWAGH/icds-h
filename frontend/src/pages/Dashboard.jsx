import React, { useEffect, useState, useCallback, useMemo } from 'react'
import {
  CheckCircle,
  Cpu,
  Zap,
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
import {
  useSOCStore,
  LIFECYCLE_STAGES,
  SIMULATED_ASSETS,
} from '../store/socEngine'
import api from '../utils/api'

const SEV_COLOR = {
  CRITICAL: '#f87171',
  HIGH: '#fbbf24',
  MEDIUM: '#f59e0b',
  LOW: '#38bdf8',
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
  const fetchData = useCallback(async () => {
    try {
      setRefreshing(true)
      const [dashboardResponse, riskResponse] =
        await Promise.all([
          api.get('/dashboard/'),
          api.get('/dashboard/risk-history'),
        ])

      setDashboardData(
        dashboardResponse.data ?? {}
      )

      setRiskHistory(
        Array.isArray(riskResponse.data)
          ? riskResponse.data
          : []
      )
    } catch (error) {
      console.error(
        '[Dashboard] Failed to fetch dashboard data:',
        error
      )
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [fetchData])

  // Threat / Normal separation
  const filteredIncidents = useMemo(
    () => incidents.filter((incident) => incident.attack_type !== 'Normal'),
    [incidents]
  )

  const activeIncidents = useMemo(
    () => filteredIncidents.filter((incident) => !incident.resolved),
    [filteredIncidents]
  )

  const activeThreats =
    liveMetrics?.active_threats ??
    dashboardData?.attack_stats?.active ??
    0

  const totalIncidents =
    liveMetrics?.total_incidents ??
    dashboardData?.incident_stats?.total ??
    0

  const criticalAlerts =
    liveMetrics?.critical_alerts ??
    dashboardData?.alert_stats?.unacknowledged ??
    0

  const resolvedToday =
    liveMetrics?.resolved_today ??
    dashboardData?.attack_stats?.resolved ??
    0

  const systemsProtected = SIMULATED_ASSETS.length
  const avgResponseTime = liveMetrics?.avg_response_time ?? '0.42 ms'

  const riskScore = Number(
    liveMetrics?.risk_score ??
    dashboardData?.latest_risk_score?.score ??
    0
  )

  const riskStatus =
    dashboardData?.latest_risk_score?.status ??
    (
      riskScore > 70
        ? 'CRITICAL'
        : riskScore > 40
          ? 'WARNING'
          : 'STABLE'
    )

  const activeConfidenceValues = activeIncidents
    .map((incident) => Number(incident.confidence))
    .filter((value) => Number.isFinite(value))

  const avgConf = activeConfidenceValues.length
    ? Math.round(
        activeConfidenceValues.reduce((sum, value) => sum + value, 0) / activeConfidenceValues.length
      )
    : 98

  const sevData = [
    {
      name: 'CRIT',
      val: dashboardData?.severity_counts?.CRITICAL ?? 3,
      color: '#f87171',
    },
    {
      name: 'HIGH',
      val: dashboardData?.severity_counts?.HIGH ?? 8,
      color: '#fbbf24',
    },
    {
      name: 'MED',
      val: dashboardData?.severity_counts?.MEDIUM ?? 14,
      color: '#0070f3',
    },
    {
      name: 'LOW',
      val: dashboardData?.severity_counts?.LOW ?? 29,
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
    if (
      liveMetrics?.risk_score === undefined ||
      liveMetrics?.risk_score === null
    ) {
      return normalizedRiskHistory.length ? normalizedRiskHistory : [
        { id: '1', time: '10:00', score: 12 },
        { id: '2', time: '10:05', score: 18 },
        { id: '3', time: '10:10', score: 45 },
        { id: '4', time: '10:15', score: 32 },
        { id: '5', time: '10:20', score: 20 },
      ]
    }

    const liveScore = Number(liveMetrics.risk_score)
    if (!Number.isFinite(liveScore)) {
      return normalizedRiskHistory
    }

    return [
      ...normalizedRiskHistory.slice(-29),
      {
        id: 'live-current-risk',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        score: liveScore,
        threats: Number(activeThreats) || 0,
      },
    ]
  }, [normalizedRiskHistory, liveMetrics?.risk_score, activeThreats])

  if (loading && !dashboardData) {
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
            Aggregated System Threat Level
          </p>

          <div
            className="text-6xl sm:text-7xl font-semibold font-mono tracking-tight-xl text-white"
          >
            {riskScore.toFixed(0)}
            <span className="text-2xl sm:text-3xl text-mute font-normal font-sans ml-1">
              / 100
            </span>
          </div>

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

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Active Threats"
          value={activeThreats}
          icon={AlertOctagon}
          pulse={Number(activeThreats) > 0}
        />
        <StatCard
          label="Peak Risk Score"
          value={riskScore.toFixed(0)}
          icon={AlertTriangle}
        />
        <StatCard
          label="Avg AI Confidence"
          value={`${avgConf}%`}
          icon={Cpu}
        />
        <StatCard
          label="Today's Incidents"
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
          label="Avg Response Time"
          value={avgResponseTime}
          icon={Zap}
        />
        <StatCard
          label="Threats Resolved"
          value={resolvedToday}
          icon={CheckCircle}
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
                <th className="py-2.5 px-3">Lifecycle</th>
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
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-[#141414] text-white border border-[#262626]">
                        {inc.status || 'MITIGATED'}
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