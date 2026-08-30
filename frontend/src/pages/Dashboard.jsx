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
  CRITICAL: '#ff2d55',
  HIGH: '#ff9500',
  MEDIUM: '#ffd60a',
  LOW: '#00ff88',
}

const StatCard = ({
  label,
  value,
  sub,
  icon: Icon,
  color = 'cyan',
  pulse,
}) => (
  <div className="cyber-card p-5">
    <div className="flex items-start justify-between mb-3">
      <span className="text-xs font-mono text-gray-500 uppercase tracking-widest">
        {label}
      </span>

      <Icon
        size={16}
        className={`text-cyber-${color}`}
      />
    </div>

    <div className="text-3xl font-black font-mono text-white flex items-center gap-2">
      {value}

      {pulse && (
        <span className="w-2 h-2 rounded-full bg-cyber-green pulse-dot" />
      )}
    </div>

    {sub && (
      <div className={`text-xs font-mono text-cyber-${color} mt-1`}>
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

    // Backup synchronization.
    // Live changes come primarily from WebSocket metrics/events.
    const interval = setInterval(
      fetchData,
      30000
    )

    return () => clearInterval(interval)
  }, [fetchData])

  // ---------------------------------------------------------
  // Threat / Normal separation
  // ---------------------------------------------------------
  const filteredIncidents = useMemo(
    () =>
      incidents.filter(
        (incident) =>
          incident.attack_type !== 'Normal'
      ),
    [incidents]
  )

  const activeIncidents = useMemo(
    () =>
      filteredIncidents.filter(
        (incident) => !incident.resolved
      ),
    [filteredIncidents]
  )

  // ---------------------------------------------------------
  // Live metrics from backend WebSocket
  // ---------------------------------------------------------
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

  /*
   * Backend HospitalAsset table is not the source for our simulated
   * hospital environment. These are deterministic simulated assets.
   */
  const systemsProtected =
    SIMULATED_ASSETS.length

  const avgResponseTime =
    liveMetrics?.avg_response_time ??
    'N/A'

  // ---------------------------------------------------------
  // Current risk score
  // ---------------------------------------------------------
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

  const riskColor =
    riskScore > 70
      ? '#ff2d55'
      : riskScore > 40
        ? '#ffd60a'
        : '#00ff88'

  // ---------------------------------------------------------
  // Average confidence from active backend events
  // ---------------------------------------------------------
  const activeConfidenceValues = activeIncidents
    .map((incident) =>
      Number(incident.confidence)
    )
    .filter((value) =>
      Number.isFinite(value)
    )

  const avgConf = activeConfidenceValues.length
    ? Math.round(
        activeConfidenceValues.reduce(
          (sum, value) =>
            sum + value,
          0
        ) / activeConfidenceValues.length
      )
    : null

  // ---------------------------------------------------------
  // Backend severity counts
  //
  // These values come directly from /api/dashboard/.
  // ---------------------------------------------------------
  const sevData = [
    {
      name: 'CRIT',
      val:
        dashboardData?.severity_counts?.CRITICAL ??
        0,
      color: '#ff2d55',
    },
    {
      name: 'HIGH',
      val:
        dashboardData?.severity_counts?.HIGH ??
        0,
      color: '#ff9500',
    },
    {
      name: 'MED',
      val:
        dashboardData?.severity_counts?.MEDIUM ??
        0,
      color: '#ffd60a',
    },
    {
      name: 'LOW',
      val:
        dashboardData?.severity_counts?.LOW ??
        0,
      color: '#00ff88',
    },
  ]

  // ---------------------------------------------------------
  // Backend risk-history normalization
  //
  // Backend returns:
  // { t, risk, threats }
  // ---------------------------------------------------------
  const normalizedRiskHistory = useMemo(
    () =>
      riskHistory
        .map((item, index) => ({
          id: `${item?.t ?? 'risk'}-${index}`,
          time: item?.t ?? '',
          score: Number(item?.risk ?? 0),
          threats: Number(item?.threats ?? 0),
        }))
        .filter((item) =>
          Number.isFinite(item.score)
        ),
    [riskHistory]
  )

  // ---------------------------------------------------------
  // Add the newest live WebSocket risk point
  // ---------------------------------------------------------
  const chartData = useMemo(() => {
    if (
      liveMetrics?.risk_score === undefined ||
      liveMetrics?.risk_score === null
    ) {
      return normalizedRiskHistory
    }

    const liveScore = Number(
      liveMetrics.risk_score
    )

    if (!Number.isFinite(liveScore)) {
      return normalizedRiskHistory
    }

    return [
      ...normalizedRiskHistory.slice(-29),
      {
        id: 'live-current-risk',
        time: new Date().toLocaleTimeString(
          [],
          { hour12: false }
        ),
        score: liveScore,
        threats: Number(activeThreats) || 0,
      },
    ]
  }, [
    normalizedRiskHistory,
    liveMetrics?.risk_score,
    activeThreats,
  ])

  if (loading && !dashboardData) {
    return (
      <div className="p-10 text-center text-cyber-cyan font-mono">
        <RefreshCw className="animate-spin inline mr-2" />
        Loading Dashboard Data...
      </div>
    )
  }

  return (
    <div className="p-6 space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">
            Security Operations Center
          </h1>

          <p className="text-xs text-gray-500 font-mono">
            Welcome, {user?.full_name || 'Admin'} · Role:{' '}
            <span className="text-cyber-cyan uppercase">
              {user?.role || 'Operator'}
            </span>{' '}
            · Clearance L
            {user?.clearance_level ?? 'N/A'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-mono text-cyber-green">
            <span className="w-2 h-2 rounded-full bg-cyber-green pulse-dot" />
            LIVE MONITORING
          </div>

          <button
            onClick={fetchData}
            disabled={refreshing}
            className="text-gray-500 hover:text-cyber-cyan transition-colors"
            title="Refresh dashboard"
          >
            <RefreshCw
              size={14}
              className={
                refreshing
                  ? 'animate-spin'
                  : ''
              }
            />
          </button>
        </div>
      </div>

      {/* Risk Score Hero */}
      <div className="cyber-card p-8 text-center relative overflow-hidden">
        <div
          className="absolute inset-0"
          style={{
            background:
              `radial-gradient(ellipse at center, ${riskColor}10 0%, transparent 70%)`,
          }}
        />

        <div className="relative z-10">
          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-2">
            Current System Risk Score
          </p>

          <div
            className="text-7xl font-black font-mono"
            style={{
              color: riskColor,
              textShadow:
                `0 0 30px ${riskColor}80`,
            }}
          >
            {riskScore.toFixed(0)}

            <span className="text-3xl text-gray-600">
              /100
            </span>
          </div>

          <div className="flex items-center justify-center gap-3 mt-3 flex-wrap">

            <div
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border text-sm font-mono"
              style={{
                borderColor:
                  `${riskColor}40`,
                color: riskColor,
                background:
                  `${riskColor}10`,
              }}
            >
              <span
                className="w-2 h-2 rounded-full pulse-dot"
                style={{
                  background: riskColor,
                }}
              />

              {riskStatus} · {activeThreats} Active Threat
              {Number(activeThreats) !== 1
                ? 's'
                : ''}
            </div>

            <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-mono border-cyber-cyan/30 text-cyber-cyan bg-cyber-cyan/5">
              AI Confidence:{' '}
              {avgConf !== null
                ? `${avgConf}%`
                : 'N/A'}
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
          color="red"
          pulse={
            Number(activeThreats) > 0
          }
        />

        <StatCard
          label="Peak Risk Score"
          value={riskScore.toFixed(0)}
          icon={AlertTriangle}
          color="red"
        />

        <StatCard
          label="Avg AI Confidence"
          value={
            avgConf !== null
              ? `${avgConf}%`
              : 'N/A'
          }
          icon={Cpu}
          color="cyan"
        />

        <StatCard
          label="Today's Incidents"
          value={totalIncidents}
          icon={FileText}
          color="yellow"
        />

        <StatCard
          label="Systems Protected"
          value={systemsProtected}
          icon={Server}
          color="blue"
        />

        <StatCard
          label="CRITICAL Alerts"
          value={criticalAlerts}
          icon={AlertOctagon}
          color="red"
          pulse={
            Number(criticalAlerts) > 0
          }
        />

        <StatCard
          label="Avg Response Time"
          value={avgResponseTime}
          icon={Zap}
          color="purple"
        />

        <StatCard
          label="Resolved Today"
          value={resolvedToday}
          icon={CheckCircle}
          color="green"
        />
      </div>

      {/* Charts */}
      <div className="grid lg:grid-cols-2 gap-5">

        {/* Risk Chart */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-bold text-white mb-4 font-mono">
            LIVE RISK SCORE TREND
          </h3>

          <ResponsiveContainer
            width="100%"
            height={150}
          >
            <AreaChart data={chartData}>

              <defs>
                <linearGradient
                  id="riskG"
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="5%"
                    stopColor="#00e5ff"
                    stopOpacity={0.3}
                  />

                  <stop
                    offset="95%"
                    stopColor="#00e5ff"
                    stopOpacity={0}
                  />
                </linearGradient>
              </defs>

              <XAxis
                dataKey="time"
                hide
              />

              <YAxis
                domain={[0, 100]}
                hide
              />

              <Tooltip
                contentStyle={{
                  background: '#0d1f3c',
                  border:
                    '1px solid #1a3a6e',
                  borderRadius: 8,
                  fontSize: 11,
                }}
                formatter={(value) => [
                  Number(value).toFixed(1),
                  'Risk',
                ]}
              />

              <Area
                type="monotone"
                dataKey="score"
                stroke="#00e5ff"
                fill="url(#riskG)"
                strokeWidth={2}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Chart */}
        <div className="cyber-card p-5">
          <h3 className="text-sm font-bold text-white mb-4 font-mono">
            SEVERITY DISTRIBUTION
          </h3>

          <ResponsiveContainer
            width="100%"
            height={150}
          >
            <BarChart
              data={sevData}
              barSize={28}
            >
              <XAxis
                dataKey="name"
                tick={{
                  fill: '#9ca3af',
                  fontSize: 11,
                  fontFamily:
                    'monospace',
                }}
              />

              <YAxis
                tick={{
                  fill: '#4a5568',
                  fontSize: 10,
                }}
              />

              <Tooltip
                contentStyle={{
                  background: '#0d1f3c',
                  border:
                    '1px solid #1a3a6e',
                  borderRadius: 8,
                  fontSize: 11,
                }}
                formatter={(value) => [
                  value,
                  'Incidents',
                ]}
              />

              <Bar
                dataKey="val"
                radius={[4, 4, 0, 0]}
              >
                {sevData.map((entry) => (
                  <Cell
                    key={`severity-${entry.name}`}
                    fill={entry.color}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Live Attack Feed */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">

          <h3 className="text-sm font-bold text-white font-mono">
            LIVE ATTACK FEED
          </h3>

          <div className="flex items-center gap-1.5 text-xs font-mono text-cyber-red">
            <span className="w-2 h-2 rounded-full bg-cyber-red pulse-dot" />
            REAL-TIME · MULTI-DATASET
          </div>
        </div>

        <div className="space-y-2 max-h-56 overflow-y-auto pr-1">

          {filteredIncidents
            .slice(0, 8)
            .map((inc) => {

              const sevColor =
                SEV_COLOR[
                  inc.severity
                ] || '#888'

              const incidentId =
                inc.attack_log_id ??
                inc.id

              return (
                <div
                  key={`feed-${incidentId}`}
                  className="flex items-start gap-3 p-2.5 rounded-lg bg-cyber-bg/60 border border-cyber-border/40"
                >
                  <div
                    className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0 pulse-dot"
                    style={{
                      background:
                        sevColor,
                    }}
                  />

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">

                      <span className="text-xs font-mono font-bold text-white">
                        {inc.incidentId ||
                          `EVT-${incidentId}`}
                      </span>

                      <span className="text-xs font-mono font-bold text-white">
                        {inc.attack_type}
                      </span>

                      <span
                        className="text-xs font-mono px-1.5 py-0.5 rounded"
                        style={{
                          background:
                            `${sevColor}20`,
                          color:
                            sevColor,
                          border:
                            `1px solid ${sevColor}40`,
                        }}
                      >
                        {inc.severity ||
                          'N/A'}
                      </span>
                    </div>

                    <p className="text-xs text-gray-500 font-mono mt-0.5">
                      {inc.source_ip ||
                        'N/A'}
                      {' → '}
                      {inc.dest_ip ||
                        'N/A'}
                      {' · '}
                      {inc.asset_name ||
                        'N/A'}
                    </p>

                    <p className="text-xs text-purple-400 font-mono">
                      {inc.mitre_id ||
                        inc.mitre_technique_id ||
                        'N/A'}
                      {' · '}
                      {inc.mitre_name ||
                        inc.mitre_technique_name ||
                        'N/A'}
                    </p>
                  </div>

                  <div className="text-right flex-shrink-0">

                    <p className="text-xs font-mono font-bold text-cyber-cyan">
                      {inc.confidence != null
                        ? `${Math.round(
                            Number(
                              inc.confidence
                            )
                          )}%`
                        : 'N/A'}
                    </p>

                    <p className="text-xs text-gray-600 font-mono">
                      {LIFECYCLE_STAGES[
                        inc.stage
                      ] ||
                        inc.status ||
                        'DETECTED'}
                    </p>
                  </div>
                </div>
              )
            })}

          {filteredIncidents.length === 0 && (
            <p className="text-xs text-gray-600 font-mono text-center py-8">
              Awaiting telemetry events...
            </p>
          )}
        </div>
      </div>

      {/* Current Hospital Incidents */}
      <div className="cyber-card p-5">
        <h3 className="text-sm font-bold text-white mb-4 font-mono">
          CURRENT HOSPITAL INCIDENTS
        </h3>

        <div className="overflow-x-auto max-h-[300px] overflow-y-auto">

          <table className="w-full text-xs font-mono">

            <thead>
              <tr className="border-b border-cyber-border text-gray-500 uppercase">

                <th className="pb-2 text-left pr-4">
                  Incident ID
                </th>

                <th className="pb-2 text-left pr-4">
                  Attack Type
                </th>

                <th className="pb-2 text-left pr-4">
                  Asset
                </th>

                <th className="pb-2 text-left pr-4">
                  Risk Score
                </th>

                <th className="pb-2 text-left pr-4">
                  Confidence
                </th>

                <th className="pb-2 text-left pr-4">
                  Timestamp
                </th>

                <th className="pb-2 text-left">
                  Status
                </th>

              </tr>
            </thead>

            <tbody>

              {filteredIncidents.map((inc) => {

                const incidentId =
                  inc.attack_log_id ??
                  inc.id

                return (
                  <tr
                    key={`incident-${incidentId}`}
                    className="border-b border-cyber-border/30 hover:bg-white/2 transition-colors"
                  >

                    <td className="py-2 pr-4 font-bold text-cyber-cyan">
                      {inc.incidentId ||
                        `EVT-${incidentId}`}
                    </td>

                    <td className="py-2 pr-4 font-bold text-white">
                      {inc.attack_type}
                    </td>

                    <td className="py-2 pr-4 text-gray-400">
                      {inc.asset_name ||
                        'N/A'}
                    </td>

                    <td className="py-2 pr-4">
                      <span
                        style={{
                          color:
                            Number(
                              inc.risk_score
                            ) > 75
                              ? '#ff2d55'
                              : Number(
                                    inc.risk_score
                                  ) > 45
                                ? '#ffd60a'
                                : '#00ff88',
                        }}
                      >
                        {inc.risk_score != null
                          ? Math.round(
                              Number(
                                inc.risk_score
                              )
                            )
                          : 'N/A'}
                      </span>
                    </td>

                    <td className="py-2 pr-4 text-cyan-400">
                      {inc.confidence != null
                        ? `${Math.round(
                            Number(
                              inc.confidence
                            )
                          )}%`
                        : 'N/A'}
                    </td>

                    <td className="py-2 pr-4 text-gray-500">
                      {inc.detected_at
                        ? new Date(
                            inc.detected_at
                          ).toLocaleTimeString()
                        : inc.timestamp
                          ? new Date(
                              inc.timestamp
                            ).toLocaleTimeString()
                          : 'N/A'}
                    </td>

                    <td className="py-2">
                      <span
                        className={`px-2 py-0.5 rounded text-xs ${
                          inc.status ===
                          'RESOLVED'
                            ? 'bg-green-900/30 text-green-400 border border-green-700/40'
                            : inc.status ===
                              'RECOVERY'
                              ? 'bg-blue-900/30 text-blue-400 border border-blue-700/40'
                              : inc.status ===
                                'CONTAINMENT'
                                ? 'bg-orange-900/30 text-orange-400 border border-orange-700/40'
                                : inc.status ===
                                  'ANALYZING'
                                  ? 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/40'
                                  : 'bg-red-900/30 text-red-400 border border-red-700/40'
                        }`}
                      >
                        {inc.status ||
                          'DETECTED'}
                      </span>
                    </td>

                  </tr>
                )
              })}

              {filteredIncidents.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="py-6 text-center text-gray-600"
                  >
                    No active security incidents.
                  </td>
                </tr>
              )}

            </tbody>
          </table>
        </div>
      </div>

      {/* Protected Asset Categories */}
      <div className="cyber-card p-5">

        <h3 className="text-sm font-bold text-white mb-4 font-mono">
          PROTECTED ASSET CATEGORIES
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">

          {/* Patient Data */}
          <div className="p-4 rounded-lg border border-blue-700/40 bg-blue-900/10">

            <div className="flex items-center gap-2 mb-3">
              <span className="text-xl">
                🏥
              </span>

              <p className="text-sm font-mono font-bold text-blue-300">
                Patient Data
              </p>
            </div>

            <div className="space-y-1 text-xs font-mono text-gray-500">
              <p>• Patient Records &amp; Medical History</p>
              <p>• Lab Reports &amp; Prescriptions</p>
              <p>• Billing Information</p>
            </div>

            <div className="mt-3 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-400 pulse-dot" />

              <span className="text-xs font-mono text-green-400">
                PROTECTED
              </span>
            </div>
          </div>

          {/* Hospital Network */}
          <div className="p-4 rounded-lg border border-cyan-700/40 bg-cyan-900/10">

            <div className="flex items-center gap-2 mb-3">
              <span className="text-xl">
                🌐
              </span>

              <p className="text-sm font-mono font-bold text-cyber-cyan">
                Hospital Network
              </p>
            </div>

            <div className="space-y-1 text-xs font-mono text-gray-500">
              <p>• EHR Systems &amp; Databases</p>
              <p>• Wi-Fi &amp; Cloud Storage</p>
              <p>• Hospital Servers</p>
            </div>

            <div className="mt-3 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyber-cyan pulse-dot" />

              <span className="text-xs font-mono text-cyber-cyan">
                MONITORING
              </span>
            </div>
          </div>

          {/* Medical Devices */}
          <div className="p-4 rounded-lg border border-purple-700/40 bg-purple-900/10">

            <div className="flex items-center gap-2 mb-3">
              <span className="text-xl">
                ⚕️
              </span>

              <p className="text-sm font-mono font-bold text-purple-300">
                Medical Devices
              </p>
            </div>

            <div className="space-y-1 text-xs font-mono text-gray-500">
              <p>• MRI / CT Scanners</p>
              <p>• Ventilators &amp; Infusion Pumps</p>
              <p>• ICU Patient Monitors</p>
            </div>

            <div className="mt-3 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-purple-400 pulse-dot" />

              <span className="text-xs font-mono text-purple-400">
                ACTIVE DEFENSE
              </span>
            </div>
          </div>

        </div>
      </div>

      {/* System Status */}
      <div className="flex gap-4 flex-wrap">

        <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 text-xs font-mono text-cyber-cyan">
          <Cpu size={14} />
          ICDS-H AI ENGINE: ACTIVE
        </div>

        <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-900/20 border border-purple-700/30 text-xs font-mono text-purple-400">
          <Zap size={14} />
          QIGA OPTIMIZER: ACTIVE
        </div>

        <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-900/20 border border-blue-700/30 text-xs font-mono text-blue-400">
          <TrendingUp size={14} />
          MITRE ATT&amp;CK: MAPPED
        </div>

        <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-green-900/20 border border-green-700/30 text-xs font-mono text-green-400">
          <Database size={14} />
          LIVE DATASETS: TON_IoT · PhiUSIIL · CERT
        </div>

      </div>
    </div>
  )
}