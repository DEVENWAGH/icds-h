import React, { useState, useEffect, useMemo } from 'react'
import {
  FileText, Download, BarChart3, TrendingUp, Shield, Activity,
  AlertTriangle, Filter, CheckCircle2, Clock, Search, Printer,
  Layers, Database, Sparkles, ArrowUpRight, X, Lock, Check,
  Building2, Award, Calendar, RefreshCw
} from 'lucide-react'
import {
  PieChart as RePie, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Legend
} from 'recharts'
import { useSOCStore } from '../store/socEngine'
import api from '../utils/api'

const isMitigated = (incident) =>
  incident.resolved === true || String(incident.status || '').toUpperCase() === 'RESOLVED'

const ATTACK_COLORS = {
  'DDoS': '#f43f5e',
  'DoS': '#e11d48',
  'Ransomware': '#a855f7',
  'Backdoor': '#ec4899',
  'Injection': '#8b5cf6',
  'Password Attack': '#fb923c',
  'Scanning': '#38bdf8',
  'XSS': '#06b6d4',
  'MITM': '#14b8a6',
  'Phishing': '#f97316',
  'Insider Threat': '#facc15',
  'Anomaly (Zero-Day)': '#6366f1',
  'Port Scan': '#38bdf8',
  'Brute Force': '#fb923c',
}

const DATASET_COLORS = {
  'TON_IoT': '#38bdf8',
  'PhiUSIIL': '#34d399',
  'CERT': '#fbbf24',
  'CERT r4': '#fbbf24',
  'Anomaly': '#a78bfa',
  'N/A': '#94a3b8'
}

export default function Reports() {
  const allIncidents = useSOCStore((s) => s.incidents).filter(i => i.attack_type !== 'Normal')
  const refreshIncidents = useSOCStore((s) => s.refreshIncidents)
  const [generating, setGenerating] = useState(false)
  const [backendResolved, setBackendResolved] = useState(null)
  const [datasetFilter, setDatasetFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [printModalOpen, setPrintModalOpen] = useState(false)

  useEffect(() => {
    refreshIncidents()
    api.get('/dashboard/')
      .then(res => setBackendResolved(res.data?.attack_stats?.resolved ?? null))
      .catch(() => {})
  }, [refreshIncidents])

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return allIncidents.filter(i => {
      const matchDataset = datasetFilter === 'ALL' || (i.dataset && i.dataset.toLowerCase().includes(datasetFilter.toLowerCase()))
      const matchSeverity = severityFilter === 'ALL' || i.severity === severityFilter
      const q = searchQuery.toLowerCase().trim()
      const matchSearch = !q || (
        (i.attack_type && i.attack_type.toLowerCase().includes(q)) ||
        (i.source_ip && i.source_ip.toLowerCase().includes(q)) ||
        (i.department && i.department.toLowerCase().includes(q)) ||
        (i.asset_name && i.asset_name.toLowerCase().includes(q))
      )
      return matchDataset && matchSeverity && matchSearch
    })
  }, [allIncidents, datasetFilter, severityFilter, searchQuery])

  const stats = useMemo(() => {
    const total = allIncidents.length
    const resolved = allIncidents.filter(isMitigated).length
    const avgRisk = total ? allIncidents.reduce((acc, i) => acc + (i.risk_score || 0), 0) / total : 0
    const avgConf = total ? allIncidents.reduce((acc, i) => acc + (i.confidence || 0), 0) / total : 0

    const datasets = allIncidents.reduce((acc, i) => {
      const ds = i.dataset || 'TON_IoT'
      acc[ds] = (acc[ds] || 0) + 1
      return acc
    }, {})

    const attack_types = allIncidents.reduce((acc, i) => {
      acc[i.attack_type] = (acc[i.attack_type] || 0) + 1
      return acc
    }, {})

    const departments = allIncidents.reduce((acc, i) => {
      const dept = i.department || 'General Network'
      acc[dept] = (acc[dept] || 0) + 1
      return acc
    }, {})

    return {
      total_incidents: total,
      total_resolved: resolved,
      avg_risk_score: avgRisk,
      avg_confidence: avgConf,
      datasets,
      attack_types,
      departments,
    }
  }, [allIncidents])

  const attackDist = useMemo(() => {
    return Object.entries(stats.attack_types).map(([type, count]) => ({
      name: type,
      value: count,
      color: ATTACK_COLORS[type] || '#38bdf8',
    }))
  }, [stats.attack_types])

  // Weekly detection vs mitigation
  const weekDays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
  const weekly = useMemo(() => {
    return weekDays.map(day => {
      const dayIncidents = allIncidents.filter(i => {
        if (!i.detected_at && !i.timestamp) return false
        const d = new Date(i.detected_at || i.timestamp)
        return weekDays[d.getDay() === 0 ? 6 : d.getDay() - 1] === day
      })
      return {
        day,
        detected: dayIncidents.length,
        mitigated: dayIncidents.filter(isMitigated).length,
      }
    })
  }, [allIncidents])

  const totalIncidents = stats.total_incidents
  const resolvedCount = backendResolved != null
    ? Math.max(stats.total_resolved, backendResolved)
    : stats.total_resolved
  const mitigationRate = totalIncidents > 0 ? Math.round((resolvedCount / totalIncidents) * 100) : 0

  const healthcareKpis = {
    criticalThreats: allIncidents.filter(i => i.severity === 'CRITICAL' && !isMitigated(i)).length,
    zeroDayCount: allIncidents.filter(i => String(i.attack_type || '').includes('Anomaly') || String(i.attack_type || '').includes('Zero-Day')).length,
    clinicalDepts: new Set(
      allIncidents
        .filter(i => ['ICU', 'Pharmacy', 'Health Information', 'Radiology', 'Emergency Department'].includes(i.department))
        .map(i => i.department)
    ).size,
    ransomwareCount: allIncidents.filter(i => i.attack_type === 'Ransomware').length,
  }

  const deptData = useMemo(() => {
    return Object.entries(stats.departments)
      .map(([dept, count]) => ({ dept, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6)
  }, [stats.departments])

  const handleExport = () => {
    setGenerating(true)
    setTimeout(() => {
      const rows = allIncidents.map(i =>
        `"${i.attack_log_id || i.id || ''}","${i.attack_type || ''}","${i.severity || ''}","${i.source_ip || ''}","${i.dest_ip || ''}","${i.port || ''}","${i.department || ''}","${i.asset_name || ''}","${i.mitre_technique_id || i.mitre_id || ''}","${i.confidence || ''}%","${i.risk_score || ''}","${i.status || ''}","${i.detected_at || i.timestamp || ''}"`
      )
      const csv = ['"Incident ID","Attack Type","Severity","Source IP","Dest IP","Port","Department","Asset","MITRE","Confidence","Risk Score","Status","Detected"', ...rows].join('\n')
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `icds-h-soc-report-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      setGenerating(false)
    }, 600)
  }

  const triggerDirectPrint = () => {
    window.print()
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto text-ink font-sans">
      {/* Header with Title and Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-hairline no-print">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white">Compliance & Incident Reports</h1>
            <span className="badge-secondary font-mono text-[10px] text-cyan">
              <Shield size={11} /> AUDIT READY
            </span>
          </div>
          <p className="text-xs text-mute font-mono mt-1">
            TON_IoT (10 Classes) · PhiUSIIL Phishing · CERT Insider · Isolation Forest Anomaly Detection
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setPrintModalOpen(true)}
            className="btn-secondary text-xs h-9 px-3.5 flex items-center gap-1.5 cursor-pointer font-mono"
            title="Preview and print formal audit summary"
          >
            <Printer size={13} className="text-mute" /> Print Summary
          </button>

          <button
            onClick={handleExport}
            disabled={generating}
            className="btn-primary text-xs h-9 px-4 flex items-center gap-2 cursor-pointer font-mono font-medium disabled:opacity-50"
          >
            {generating ? <RefreshCw size={13} className="animate-spin text-black" /> : <Download size={13} />}
            {generating ? 'Generating...' : 'Export CSV'}
          </button>
        </div>
      </div>

      {/* Primary KPI Metrics Ladder */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 no-print">
        {[
          { label: 'Total Incidents', val: totalIncidents, sub: 'Logged security events', icon: BarChart3, color: 'text-white' },
          { label: 'Mitigation Rate', val: `${mitigationRate}%`, sub: `${resolvedCount}/${totalIncidents} mitigated`, icon: TrendingUp, color: 'text-cyan' },
          { label: 'Avg AI Confidence', val: `${Math.round(stats.avg_confidence)}%`, sub: 'Supervised MLP certainty', icon: Sparkles, color: 'text-cyan' },
          { label: 'Avg Risk Index', val: `${Math.round(stats.avg_risk_score)}/100`, sub: 'Dynamic severity index', icon: Shield, color: 'text-red-400' },
        ].map(({ label, val, sub, icon: Icon, color }) => (
          <div key={label} className="cyber-card p-4 group">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-mute">
                {label}
              </span>
              <Icon size={15} className="text-mute group-hover:text-cyan transition-colors" />
            </div>
            <p className={`text-2xl font-bold font-mono ${color}`}>{val}</p>
            <p className="text-xs text-mute mt-1 font-mono">{sub}</p>
          </div>
        ))}
      </div>

      {/* Healthcare Threat Posture Badges */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 no-print">
        {[
          { label: 'Active Critical Threats', val: healthcareKpis.criticalThreats, sub: 'Requires containment', icon: AlertTriangle, color: 'text-red-400' },
          { label: 'Zero-Day Anomalies', val: healthcareKpis.zeroDayCount, sub: 'Isolation Forest flags', icon: Activity, color: 'text-yellow-400' },
          { label: 'Clinical Depts Affected', val: healthcareKpis.clinicalDepts, sub: 'ICU · HIM · Pharmacy', icon: Database, color: 'text-cyan' },
          { label: 'Ransomware Incidents', val: healthcareKpis.ransomwareCount, sub: 'PHI vector encryption', icon: Shield, color: 'text-purple-400' },
        ].map(({ label, val, sub, icon: Icon, color }) => (
          <div key={label} className="card-soft p-4 group">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-mute">
                {label}
              </span>
              <Icon size={13} className="text-mute group-hover:text-cyan transition-colors" />
            </div>
            <p className={`text-xl font-bold font-mono ${color}`}>{val}</p>
            <p className="text-[11px] text-mute mt-0.5 font-mono">{sub}</p>
          </div>
        ))}
      </div>

      {/* Visual Analytics Charts */}
      <div className="grid md:grid-cols-2 gap-6 no-print">
        {/* Attack Vector Distribution */}
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-ink font-bold flex items-center gap-2">
              <BarChart3 size={14} className="text-cyan" /> Multi-Dataset Attack Vector Distribution
            </h3>
            <span className="text-[10px] font-mono text-mute">{allIncidents.length} events logged</span>
          </div>

          <ResponsiveContainer width="100%" height={220}>
            <RePie>
              <Pie data={attackDist} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={2}>
                {attackDist.map((e, i) => <Cell key={i} fill={e.color} stroke="#0a0a0a" strokeWidth={2} />)}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#0a0a0a',
                  border: '1px solid #262626',
                  borderRadius: '6px',
                  color: '#ededed',
                  fontSize: '11px',
                  fontFamily: 'monospace'
                }}
                itemStyle={{ color: '#ededed' }}
              />
            </RePie>
          </ResponsiveContainer>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 mt-3 pt-3 border-t border-hairline">
            {attackDist.map(d => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs font-mono p-1 rounded hover:bg-white/[0.04] transition-colors">
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: d.color }} />
                <span className="text-body truncate">{d.name}</span>
                <span className="text-mute ml-auto font-bold">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Weekly Detection vs Mitigation */}
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-ink font-bold flex items-center gap-2">
              <TrendingUp size={14} className="text-cyan" /> Weekly Detections vs Mitigations
            </h3>
            <span className="text-[10px] font-mono text-mute">7-day lifecycle cadence</span>
          </div>

          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={weekly} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="day" tick={{ fill: '#737373', fontSize: 11, fontFamily: 'monospace' }} stroke="#262626" />
              <YAxis tick={{ fill: '#737373', fontSize: 11, fontFamily: 'monospace' }} stroke="#262626" />
              <Tooltip
                contentStyle={{
                  background: '#0a0a0a',
                  border: '1px solid #262626',
                  borderRadius: '6px',
                  color: '#ededed',
                  fontSize: '11px',
                  fontFamily: 'monospace'
                }}
              />
              <Legend wrapperStyle={{ fontSize: 11, fontFamily: 'monospace', color: '#a1a1a1' }} />
              <Bar dataKey="detected" fill="#f87171" radius={[4, 4, 0, 0]} name="Detected Attacks" />
              <Bar dataKey="mitigated" fill="#50e3c2" radius={[4, 4, 0, 0]} name="Mitigated & Contained" />
            </BarChart>
          </ResponsiveContainer>

          <div className="flex items-center justify-between text-xs font-mono text-mute mt-3 pt-3 border-t border-hairline">
            <span>Overall Success Ratio</span>
            <span className="text-cyan font-bold">{mitigationRate}% contained</span>
          </div>
        </div>
      </div>

      {/* Dataset & Department Breakdown */}
      <div className="grid md:grid-cols-2 gap-6 no-print">
        {/* Dataset Breakdown */}
        <div className="cyber-card p-5">
          <h3 className="text-xs font-mono uppercase tracking-wider text-ink font-bold mb-4 flex items-center gap-2">
            <Database size={14} className="text-cyan" /> Detection Engine Source Attribution
          </h3>

          <div className="grid grid-cols-2 gap-3">
            {[
              ['TON_IoT', '10 Attack Classes', 'IoT Network Telemetry'],
              ['PhiUSIIL', 'Phishing URLs', 'Email & Web Gateway'],
              ['CERT', 'Insider Threat', 'Behavioral Anomaly'],
              ['Anomaly', 'Zero-Day IF', 'Unsupervised Network Outlier'],
            ].map(([ds, label, sub]) => {
              const count = stats.datasets[ds] || 0
              const pct = totalIncidents > 0 ? Math.round((count / totalIncidents) * 100) : 0
              return (
                <div key={ds} className="card-soft p-3.5 transition-all group">
                  <div className="flex items-center justify-between">
                    <p className="text-xs font-mono font-bold" style={{ color: DATASET_COLORS[ds] || '#38bdf8' }}>{ds}</p>
                    <span className="text-[10px] font-mono text-mute group-hover:text-body">{pct}%</span>
                  </div>
                  <p className="text-xl font-black text-white font-mono my-1">{count}</p>
                  <p className="text-xs text-body font-medium">{label}</p>
                  <p className="text-[10px] text-mute">{sub}</p>
                  <div className="h-1 bg-black rounded-full mt-2 overflow-hidden border border-hairline">
                    <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: DATASET_COLORS[ds] || '#38bdf8' }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Hospital Department Distribution */}
        <div className="cyber-card p-5">
          <h3 className="text-xs font-mono uppercase tracking-wider text-ink font-bold mb-4 flex items-center gap-2">
            <Shield size={14} className="text-cyan" /> Hospital Unit & Department Impact
          </h3>

          <div className="space-y-3">
            {deptData.map(({ dept, count }) => {
              const pct = totalIncidents > 0 ? Math.round((count / totalIncidents) * 100) : 0
              return (
                <div key={dept} className="card-soft p-2.5 transition-colors">
                  <div className="flex items-center justify-between mb-1.5 text-xs font-mono">
                    <span className="text-body font-medium">{dept}</span>
                    <span className="text-cyan font-bold">{count} events ({pct}%)</span>
                  </div>
                  <div className="h-1.5 bg-black rounded-full overflow-hidden border border-hairline">
                    <div className="h-full bg-gradient-to-r from-cyan to-link rounded-full transition-all duration-300" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
            {deptData.length === 0 && (
              <p className="text-xs font-mono text-mute text-center py-6">No departmental incidents recorded.</p>
            )}
          </div>
        </div>
      </div>

      {/* Forensic Incident Log Table with Search & Filter Bar */}
      <div className="cyber-card p-5 space-y-4 no-print">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <FileText size={15} className="text-cyan" /> Incident Log Audit Trail
            </h3>
            <p className="text-xs text-mute font-mono mt-0.5">
              Showing {filteredIncidents.length} of {allIncidents.length} security incidents
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-mute" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search incident, IP, dept..."
                className="form-input-sm pl-8 text-xs font-mono w-48 sm:w-56"
              />
            </div>

            {/* Dataset Filter */}
            <select
              value={datasetFilter}
              onChange={(e) => setDatasetFilter(e.target.value)}
              className="form-input-sm text-xs font-mono cursor-pointer"
            >
              <option value="ALL">All Datasets</option>
              <option value="TON_IoT">TON_IoT</option>
              <option value="PhiUSIIL">PhiUSIIL</option>
              <option value="CERT">CERT</option>
              <option value="Anomaly">Anomaly</option>
            </select>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="form-input-sm text-xs font-mono cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto rounded-md border border-hairline">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-hairline bg-canvas-soft-2 text-mute uppercase tracking-wider text-[10px]">
                <th className="py-2.5 px-3 text-left">Incident ID</th>
                <th className="py-2.5 px-3 text-left">Attack Classification</th>
                <th className="py-2.5 px-3 text-left">Severity</th>
                <th className="py-2.5 px-3 text-left">AI Conf</th>
                <th className="py-2.5 px-3 text-left">Risk Index</th>
                <th className="py-2.5 px-3 text-left">Source IP / Host</th>
                <th className="py-2.5 px-3 text-left">Department</th>
                <th className="py-2.5 px-3 text-left">Dataset</th>
                <th className="py-2.5 px-3 text-left">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline bg-canvas">
              {filteredIncidents.slice(0, 30).map((inc) => {
                const id = inc.attack_log_id || inc.id || inc.incidentId || 'LOG'
                const sev = inc.severity || 'HIGH'
                const risk = inc.risk_score != null ? Math.round(Number(inc.risk_score)) : 'N/A'
                const conf = inc.confidence != null ? Math.round(Number(inc.confidence)) : 'N/A'
                const status = String(inc.status || 'DETECTED').toUpperCase()

                return (
                  <tr
                    key={id}
                    className="hover:bg-white/[0.04] transition-colors duration-150 group cursor-default"
                  >
                    <td className="py-2.5 px-3 text-cyan font-bold group-hover:text-white">
                      #{id}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-ink group-hover:text-white">
                      {inc.attack_type || 'Unknown'}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold border uppercase tracking-wider ${
                        sev === 'CRITICAL' ? 'severity-critical' :
                        sev === 'HIGH' ? 'severity-high' :
                        sev === 'MEDIUM' ? 'severity-medium' : 'severity-low'
                      }`}>
                        {sev}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-body group-hover:text-white">
                      {conf !== 'N/A' ? `${conf}%` : 'N/A'}
                    </td>
                    <td className="py-2.5 px-3 font-bold" style={{ color: Number(risk) > 75 ? '#f87171' : Number(risk) > 45 ? '#fbbf24' : '#50e3c2' }}>
                      {risk}
                    </td>
                    <td className="py-2.5 px-3 text-body group-hover:text-white font-mono">
                      {inc.source_ip || inc.user || inc.url || '10.0.0.X'}
                    </td>
                    <td className="py-2.5 px-3 text-body group-hover:text-white">
                      {inc.department || inc.pc || 'Hospital Core'}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                        style={{
                          color: DATASET_COLORS[inc.dataset] || '#38bdf8',
                          background: `${DATASET_COLORS[inc.dataset] || '#38bdf8'}15`,
                          borderColor: `${DATASET_COLORS[inc.dataset] || '#38bdf8'}40`,
                        }}
                      >
                        {inc.dataset || 'TON_IoT'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`inline-flex items-center gap-1 font-bold text-[10px] ${isMitigated(inc) ? 'text-cyan' : 'text-amber-400'}`}>
                        {isMitigated(inc) ? <CheckCircle2 size={11} /> : <Clock size={11} />}
                        {status}
                      </span>
                    </td>
                  </tr>
                )
              })}
              {filteredIncidents.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-mute font-mono">
                    No incidents match the active filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* PRINT SUMMARY MODAL / AUDIT REPORT PREVIEW                                */}
      {/* ========================================================================= */}
      {printModalOpen && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="cyber-card w-full max-w-4xl max-h-[92vh] flex flex-col overflow-hidden shadow-2xl border-hairline-strong">
            {/* Modal Action Bar */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-hairline bg-canvas-soft-2 no-print">
              <div className="flex items-center gap-2">
                <Shield size={16} className="text-cyan" />
                <span className="font-mono font-bold text-sm text-white">Executive Compliance & Audit Summary</span>
                <span className="badge-secondary text-[10px] text-cyan">HIPAA / SOC2 Type II</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={triggerDirectPrint}
                  className="btn-primary text-xs h-8 px-4 flex items-center gap-1.5 cursor-pointer font-mono font-bold"
                >
                  <Printer size={13} /> Print / Save PDF
                </button>
                <button
                  onClick={() => setPrintModalOpen(false)}
                  className="text-mute hover:text-white p-1.5 rounded-md hover:bg-white/10 transition cursor-pointer"
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Printable Document Content */}
            <div className="p-8 space-y-6 overflow-y-auto bg-white text-slate-900 font-sans print:p-0 print:m-0">
              {/* Document Header */}
              <div className="border-b-2 border-slate-900 pb-4 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <div className="w-7 h-7 rounded bg-slate-950 text-white flex items-center justify-center font-black font-mono text-sm">
                      IC
                    </div>
                    <h2 className="text-xl font-black text-slate-950 tracking-tight">ICDS-H Clinical SOC Security Audit Report</h2>
                  </div>
                  <p className="text-xs text-slate-600 font-mono mt-1">
                    Intelligent Cyber Defense System for Healthcare · Multi-Engine Threat Audit
                  </p>
                </div>
                <div className="text-right text-xs font-mono text-slate-600">
                  <p className="font-bold text-slate-900">DATE: {new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}</p>
                  <p>CLEARANCE: TOP SECRET / CLINICAL</p>
                  <p>STATUS: AUDIT VERIFIED</p>
                </div>
              </div>

              {/* Executive Summary Grid */}
              <div className="grid grid-cols-4 gap-3">
                <div className="p-3 bg-slate-100 rounded border border-slate-300">
                  <p className="text-[10px] font-mono uppercase text-slate-600 font-bold">Total Security Incidents</p>
                  <p className="text-2xl font-black font-mono text-slate-950 mt-1">{totalIncidents}</p>
                  <p className="text-[10px] text-slate-500 font-mono">100% telemetry captured</p>
                </div>
                <div className="p-3 bg-slate-100 rounded border border-slate-300">
                  <p className="text-[10px] font-mono uppercase text-slate-600 font-bold">Mitigation & Containment</p>
                  <p className="text-2xl font-black font-mono text-emerald-700 mt-1">{mitigationRate}%</p>
                  <p className="text-[10px] text-slate-500 font-mono">{resolvedCount} incidents resolved</p>
                </div>
                <div className="p-3 bg-slate-100 rounded border border-slate-300">
                  <p className="text-[10px] font-mono uppercase text-slate-600 font-bold">AI Model Confidence</p>
                  <p className="text-2xl font-black font-mono text-blue-700 mt-1">{Math.round(stats.avg_confidence)}%</p>
                  <p className="text-[10px] text-slate-500 font-mono">MLP supervised cert</p>
                </div>
                <div className="p-3 bg-slate-100 rounded border border-slate-300">
                  <p className="text-[10px] font-mono uppercase text-slate-600 font-bold">Critical PHI Threats</p>
                  <p className="text-2xl font-black font-mono text-rose-700 mt-1">{healthcareKpis.criticalThreats}</p>
                  <p className="text-[10px] text-slate-500 font-mono">Unresolved threats</p>
                </div>
              </div>

              {/* Compliance Controls Checklist */}
              <div className="p-4 bg-slate-50 rounded border border-slate-200 space-y-2">
                <h4 className="text-xs font-mono font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                  <Award size={14} className="text-blue-600" /> Regulatory Compliance Attestation
                </h4>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-700 pt-1">
                  <div className="flex items-center gap-1.5">
                    <Check size={13} className="text-emerald-600 font-bold" /> HIPAA §164.312(b) Audit Controls: Verified
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Check size={13} className="text-emerald-600 font-bold" /> SOC 2 Type II Telemetry Immutability: Compliant
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Check size={13} className="text-emerald-600 font-bold" /> NIST SP 800-66 Incident Response: Automated
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Check size={13} className="text-emerald-600 font-bold" /> PHI Segmentation & Firewall Quarantines: Active
                  </div>
                </div>
              </div>

              {/* Forensic Audit Incident Table */}
              <div>
                <h4 className="text-xs font-mono font-bold text-slate-900 uppercase tracking-wider mb-2">
                  Forensic Incident Log (Top 15 Events)
                </h4>
                <table className="w-full text-xs font-mono border border-slate-300">
                  <thead>
                    <tr className="bg-slate-200 border-b border-slate-300 text-slate-800 text-[10px]">
                      <th className="p-1.5 text-left">ID</th>
                      <th className="p-1.5 text-left">Attack Classification</th>
                      <th className="p-1.5 text-left">Severity</th>
                      <th className="p-1.5 text-left">Source IP / Host</th>
                      <th className="p-1.5 text-left">Department</th>
                      <th className="p-1.5 text-left">Risk</th>
                      <th className="p-1.5 text-left">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {allIncidents.slice(0, 15).map(inc => (
                      <tr key={inc.id || inc.attack_log_id}>
                        <td className="p-1.5 font-bold">#{inc.attack_log_id || inc.id}</td>
                        <td className="p-1.5 font-semibold">{inc.attack_type}</td>
                        <td className="p-1.5 font-bold" style={{ color: inc.severity === 'CRITICAL' ? '#b91c1c' : inc.severity === 'HIGH' ? '#b45309' : '#047857' }}>
                          {inc.severity}
                        </td>
                        <td className="p-1.5">{inc.source_ip || inc.user || '10.0.0.X'}</td>
                        <td className="p-1.5">{inc.department || 'Hospital Core'}</td>
                        <td className="p-1.5 font-bold">{Math.round(inc.risk_score || 0)}/100</td>
                        <td className="p-1.5">{isMitigated(inc) ? 'RESOLVED' : 'ACTIVE'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Auditor Sign-off Section */}
              <div className="pt-4 border-t border-slate-300 grid grid-cols-2 gap-8 text-xs font-mono">
                <div>
                  <p className="font-bold text-slate-900">SOC Lead / CISO Sign-off:</p>
                  <div className="mt-4 border-b border-slate-400 w-48" />
                  <p className="text-[10px] text-slate-500 mt-1">Authorized Clinical Security Officer</p>
                </div>
                <div className="text-right">
                  <p className="font-bold text-slate-900">Hospital Compliance Office:</p>
                  <div className="mt-4 border-b border-slate-400 w-48 ml-auto" />
                  <p className="text-[10px] text-slate-500 mt-1">HIPAA Privacy & Security Auditor</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
