import React, { useState, useEffect } from 'react'
import { FileText, Download, BarChart3, TrendingUp, Shield, Activity, AlertTriangle } from 'lucide-react'
import { PieChart as RePie, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Legend } from 'recharts'
import { useSOCStore } from '../store/socEngine'
import api from '../utils/api'

const isMitigated = (incident) =>
  incident.resolved === true || String(incident.status || '').toUpperCase() === 'RESOLVED'

const ATTACK_COLORS = {
  // TON_IoT
  'DDoS':           '#ff2d55',
  'Ransomware':     '#ff453a',
  // PhiUSIIL
  'Phishing':       '#30d158',
  // CERT r4
  'Insider Threat': '#ffd60a',
  // CICIDS-2017
  'Brute Force':    '#ff9500',
  'Port Scan':      '#0066ff',
  'Bot':            '#bf5af2',
  'Heartbleed':     '#ff6b35',
  'Web Attack':     '#00e5ff',
  'DoS':            '#ff8c00',
  'Infiltration':   '#34c759',
}

const DATASET_COLORS = { 'TON_IoT': '#ff2d55', 'PhiUSIIL': '#30d158', 'CERT r4': '#ffd60a', 'CICIDS-2017': '#00e5ff', 'CERT': '#ffd60a', 'N/A': '#4a5568' }

export default function Reports() {
  const allIncidents = useSOCStore((s) => s.incidents).filter(i => i.attack_type !== 'Normal')
  const refreshIncidents = useSOCStore((s) => s.refreshIncidents)
  const [generating, setGenerating] = useState(false)
  const [backendResolved, setBackendResolved] = useState(null)

  useEffect(() => {
    refreshIncidents()
    api.get('/dashboard/')
      .then(res => setBackendResolved(res.data?.attack_stats?.resolved ?? null))
      .catch(() => {})
  }, [refreshIncidents])

  const stats = {
    total_incidents: allIncidents.length,
    total_resolved: allIncidents.filter(isMitigated).length,
    avg_risk_score: allIncidents.length ? allIncidents.reduce((acc, i) => acc + (i.risk_score || 0), 0) / allIncidents.length : 0,
    avg_confidence: allIncidents.length ? allIncidents.reduce((acc, i) => acc + (i.confidence || 0), 0) / allIncidents.length : 0,
    datasets: allIncidents.reduce((acc, i) => {
      const ds = i.dataset || 'CICIDS-2017'
      acc[ds] = (acc[ds] || 0) + 1
      return acc
    }, {}),
    attack_types: allIncidents.reduce((acc, i) => {
      acc[i.attack_type] = (acc[i.attack_type] || 0) + 1
      return acc
    }, {}),
    departments: allIncidents.reduce((acc, i) => {
      const dept = i.department || 'Unknown'
      acc[dept] = (acc[dept] || 0) + 1
      return acc
    }, {})
  }

  const typeCounts = Object.entries(stats.attack_types).map(([type, count]) => ({
    name: type,
    value: count,
    color: ATTACK_COLORS[type] || '#888',
  }))

  const attackDist = typeCounts.length > 0 ? typeCounts : []

  // Weekly detection – derived from incident timestamps
  const weekDays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
  const weekly = weekDays.map(day => {
    const dayIncidents = allIncidents.filter(i => {
      if (!i.detected_at) return false;
      const d = new Date(i.detected_at)
      return weekDays[d.getDay() === 0 ? 6 : d.getDay() - 1] === day
    })
    return {
      day,
      detected: dayIncidents.length,
      mitigated: dayIncidents.filter(isMitigated).length,
    }
  })

  const totalIncidents = stats.total_incidents
  const resolvedCount = backendResolved != null
    ? Math.max(stats.total_resolved, backendResolved)
    : stats.total_resolved
  const mitigationRate = totalIncidents > 0 ? Math.round((resolvedCount / totalIncidents) * 100) : 0

  const healthcareKpis = {
    criticalThreats: allIncidents.filter(i => i.severity === 'CRITICAL' && !isMitigated(i)).length,
    zeroDayCount: allIncidents.filter(i => String(i.attack_type || '').includes('Anomaly')).length,
    clinicalDepts: new Set(
      allIncidents
        .filter(i => ['ICU', 'Pharmacy', 'Health Information', 'Radiology'].includes(i.department))
        .map(i => i.department)
    ).size,
    ransomwareCount: allIncidents.filter(i => i.attack_type === 'Ransomware').length,
  }

  const datasetData = Object.entries(stats.datasets).map(([ds, count]) => ({ ds, count }))
  const deptData = Object.entries(stats.departments)
    .map(([dept, count]) => ({ dept, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6)

  const handleExport = () => {
    setGenerating(true)
    setTimeout(() => {
      const rows = allIncidents.map(i =>
        `${i.incidentId},${i.attack_type},${i.severity},${i.source_ip},${i.dest_ip},${i.port},${i.department},${i.asset},${i.mitre_id},${i.cvss},${i.confidence}%,${i.risk_score},${i.status},${i.detected_at ? new Date(i.detected_at).toISOString() : ''}`
      )
      const csv = ['Incident ID,Attack Type,Severity,Source IP,Dest IP,Port,Department,Asset,MITRE,CVSS,Confidence,Risk Score,Status,Detected', ...rows].join('\n')
      const blob = new Blob([csv], { type: 'text/csv' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `icds-h-report-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      setGenerating(false)
    }, 1000)
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Reports & Analytics</h1>
          <p className="text-xs text-gray-500 font-mono mt-1">CICIDS-2017 · TON_IoT · PhiUSIIL · CERT r4 · Real-time incident reporting</p>
        </div>
        <button onClick={handleExport} disabled={generating}
          className="btn-primary flex items-center gap-2 text-xs">
          <Download size={14} /> {generating ? 'Generating...' : 'Export CSV Report'}
        </button>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total Incidents', val: totalIncidents, sub: 'All datasets', icon: BarChart3, color: 'text-white' },
          { label: 'Mitigation Rate', val: `${mitigationRate}%`, sub: `${resolvedCount}/${totalIncidents} resolved`, icon: TrendingUp, color: 'text-green-400' },
          { label: 'Avg Confidence', val: `${Math.round(stats.avg_confidence)}%`, sub: 'AI detection accuracy', icon: FileText, color: 'text-cyan-400' },
          { label: 'Avg Risk Score', val: Math.round(stats.avg_risk_score), sub: 'Across all incidents', icon: BarChart3, color: 'text-red-400' },
        ].map(({ label, val, sub, icon: Icon, color }) => (
          <div key={label} className="cyber-card p-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-gray-500 uppercase">{label}</span>
              <Icon size={14} className="text-cyber-cyan" />
            </div>
            <p className={`text-2xl font-black font-mono ${color}`}>{val}</p>
            <p className="text-xs text-gray-600 mt-1">{sub}</p>
          </div>
        ))}
      </div>

      {/* Healthcare Security Posture */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Critical Threats Active', val: healthcareKpis.criticalThreats, sub: 'Unresolved CRITICAL events', icon: AlertTriangle, color: 'text-red-400' },
          { label: 'Zero-Day Detections', val: healthcareKpis.zeroDayCount, sub: 'Isolation Forest anomalies', icon: Activity, color: 'text-yellow-400' },
          { label: 'Clinical Depts Impacted', val: healthcareKpis.clinicalDepts, sub: 'ICU · Pharmacy · HIM · Radiology', icon: Shield, color: 'text-cyan-400' },
          { label: 'Ransomware Events', val: healthcareKpis.ransomwareCount, sub: 'PHI encryption risk vector', icon: Shield, color: 'text-purple-400' },
        ].map(({ label, val, sub, icon: Icon, color }) => (
          <div key={label} className="cyber-card p-4 border border-cyber-cyan/10">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono text-gray-500 uppercase">{label}</span>
              <Icon size={14} className="text-cyber-cyan" />
            </div>
            <p className={`text-xl font-black font-mono ${color}`}>{val}</p>
            <p className="text-[10px] text-gray-600 mt-1">{sub}</p>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid md:grid-cols-2 gap-6">
        <div className="cyber-card p-5">
          <h3 className="text-xs font-mono text-gray-500 uppercase mb-4">Multi-Dataset Attack Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <RePie>
              <Pie data={attackDist} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value">
                {attackDist.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#0d1f3c', border: '1px solid #1a3a6e', fontSize: 11 }} />
            </RePie>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-1 mt-2">
            {attackDist.map(d => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs font-mono">
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: d.color }} />
                <span className="text-gray-400">{d.name}</span>
                <span className="text-gray-600 ml-auto">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="cyber-card p-5">
          <h3 className="text-xs font-mono text-gray-500 uppercase mb-4">Weekly Detection vs Mitigation</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={weekly}>
              <XAxis dataKey="day" tick={{ fill: '#4a5568', fontSize: 10 }} />
              <YAxis tick={{ fill: '#4a5568', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#0d1f3c', border: '1px solid #1a3a6e', fontSize: 11 }} />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              <Bar dataKey="detected" fill="#ff2d55" radius={[3, 3, 0, 0]} name="Detected" />
              <Bar dataKey="mitigated" fill="#00e5ff" radius={[3, 3, 0, 0]} name="Mitigated" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Dataset source breakdown */}
      {datasetData.length > 0 && (
        <div className="cyber-card p-5">
          <h3 className="text-xs font-mono text-gray-500 uppercase mb-4">Detection Source — Dataset Breakdown</h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[['TON_IoT', 'DDoS · Ransomware'], ['PhiUSIIL', 'Phishing'], ['CERT r4', 'Insider Threat'], ['CICIDS-2017', 'Network Attacks']].map(([ds, label]) => {
              const count = stats.datasets[ds] || 0
              const pct = totalIncidents > 0 ? Math.round((count / totalIncidents) * 100) : 0
              return (
                <div key={ds} className="cyber-card p-3 border" style={{ borderColor: `${DATASET_COLORS[ds]}30` }}>
                  <p className="text-xs font-mono font-bold" style={{ color: DATASET_COLORS[ds] }}>{ds}</p>
                  <p className="text-lg font-black text-white font-mono">{count}</p>
                  <p className="text-xs text-gray-600">{label}</p>
                  <div className="h-1 bg-cyber-surface rounded-full mt-2">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: DATASET_COLORS[ds] }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Department breakdown */}
      {deptData.length > 0 && (
        <div className="cyber-card p-5">
        <h3 className="text-xs font-mono text-gray-500 uppercase mb-4">Incidents by Hospital Department</h3>
          <div className="space-y-3">
            {deptData.map(({ dept, count }) => {
              const pct = totalIncidents > 0 ? Math.round((count / totalIncidents) * 100) : 0
              return (
                <div key={dept}>
                  <div className="flex items-center justify-between mb-1 text-xs font-mono">
                    <span className="text-gray-300">{dept}</span>
                    <span className="text-cyber-cyan font-bold">{count} incidents ({pct}%)</span>
                  </div>
                  <div className="h-1.5 bg-cyber-surface rounded-full">
                    <div className="h-full bg-cyber-cyan rounded-full transition-all" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Recent incidents table */}
      <div className="cyber-card p-5">
        <h3 className="text-xs font-mono text-gray-500 uppercase mb-4">Recent Incident Log</h3>
        <div className="overflow-x-auto max-h-[250px] overflow-y-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border text-gray-500 uppercase">
                <th className="pb-2 text-left pr-3">ID</th>
                <th className="pb-2 text-left pr-3">Attack</th>
                <th className="pb-2 text-left pr-3">Severity</th>
                <th className="pb-2 text-left pr-3">Confidence</th>
                <th className="pb-2 text-left pr-3">Risk</th>
                <th className="pb-2 text-left pr-3">Department</th>
                <th className="pb-2 text-left pr-3">MITRE</th>
                <th className="pb-2 text-left pr-3">Dataset</th>
                <th className="pb-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {allIncidents.slice(0, 10).map(inc => (
                <tr key={inc.id || inc.incidentId} className="border-b border-cyber-border/30 hover:bg-white/2 transition-colors">
                  <td className="py-2 pr-3 text-cyber-cyan">{inc.incidentId}</td>
                  <td className="py-2 pr-3 text-white font-bold">{inc.attack_type}</td>
                  <td className="py-2 pr-3" style={{ color: { CRITICAL: '#ff2d55', HIGH: '#ff9500', MEDIUM: '#ffd60a', LOW: '#00ff88' }[inc.severity] }}>
                    {inc.severity}
                  </td>
                  <td className="py-2 pr-3 text-cyan-400">{inc.confidence}%</td>
                  <td className="py-2 pr-3 font-bold" style={{ color: inc.risk_score > 75 ? '#ff2d55' : inc.risk_score > 45 ? '#ffd60a' : '#00ff88' }}>
                    {inc.risk_score}
                  </td>
                  <td className="py-2 pr-3 text-gray-400">{inc.department}</td>
                  <td className="py-2 pr-3 text-purple-400">{inc.mitre_id}</td>
                  <td className="py-2 pr-3">
                    <span className="text-xs font-mono px-1.5 py-0.5 rounded" style={{
                      color: DATASET_COLORS[inc.dataset] || '#888',
                      background: `${DATASET_COLORS[inc.dataset] || '#888'}20`,
                    }}>{inc.dataset || 'CICIDS-2017'}</span>
                  </td>
                  <td className="py-2" style={{ color: isMitigated(inc) ? '#00ff88' : '#ffd60a' }}>{inc.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
