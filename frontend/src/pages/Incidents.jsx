import React, { useState } from 'react'
import { AlertOctagon, RefreshCw, CheckCircle } from 'lucide-react'
import { useAuthStore, useIncidentStore } from '../store'
import { useSOCStore } from '../store/socEngine'

const STAGES = ['DETECTED', 'ANALYZING', 'CONTAINMENT', 'RECOVERY', 'RESOLVED']

const STATUS_CONFIG = {
  DETECTED:    { color: 'text-red-400',    bg: 'bg-red-900/20 border-red-700/50' },
  ANALYZING:   { color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700/50' },
  CONTAINMENT: { color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/50' },
  RECOVERY:    { color: 'text-blue-400',   bg: 'bg-blue-900/20 border-blue-700/50' },
  RESOLVED:    { color: 'text-green-400',  bg: 'bg-green-900/20 border-green-700/50' },
}

export default function Incidents() {
  const { user } = useAuthStore()
  const allIncidents = useSOCStore((s) => s.incidents).filter(i => i.attack_type !== 'Normal')
  const { selectedAttackLogId, setSelectedAttackLogId } = useIncidentStore()
  const [filter, setFilter] = useState('')

  const filtered = filter ? allIncidents.filter(i => i.status === filter) : allIncidents

  const counts = {
    DETECTED:    allIncidents.filter(i => i.status === 'DETECTED').length,
    ANALYZING:   allIncidents.filter(i => i.status === 'ANALYZING').length,
    CONTAINMENT: allIncidents.filter(i => i.status === 'CONTAINMENT').length,
    RECOVERY:    allIncidents.filter(i => i.status === 'RECOVERY').length,
    RESOLVED:    allIncidents.filter(i => i.status === 'RESOLVED').length,
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Incident Management</h1>
          <p className="text-xs text-gray-500 font-mono mt-1">MITRE ATT&CK correlated · TON_IoT · PhiUSIIL · CERT r4 · CICIDS-2017 · Auto-lifecycle progression</p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-cyber-green">
          <span className="w-2 h-2 rounded-full bg-cyber-green pulse-dot" />
          LIVE TRACKING
        </div>
      </div>

      {/* Lifecycle stage summary cards */}
      <div className="grid grid-cols-5 gap-3">
        {Object.entries(counts).map(([status, count]) => {
          const cfg = STATUS_CONFIG[status] || {}
          return (
            <div key={status}
              className={`cyber-card p-4 cursor-pointer transition-all ${filter === status ? 'border-cyber-cyan/50' : ''}`}
              onClick={() => setFilter(filter === status ? '' : status)}>
              <p className={`text-2xl font-black font-mono ${cfg.color}`}>{count}</p>
              <p className="text-xs font-mono text-gray-500 uppercase mt-1">{status}</p>
            </div>
          )
        })}
      </div>

      {/* Lifecycle pipeline visualization */}
      <div className="cyber-card p-4">
        <p className="text-xs font-mono text-gray-500 uppercase mb-3">Attack Lifecycle Pipeline</p>
        <div className="flex items-center gap-1">
          {STAGES.map((stage, i) => {
            const statusKey = stage.toUpperCase()
            const count = counts[statusKey] || 0
            const colors = ['#ff2d55', '#ffd60a', '#ff9500', '#0066ff', '#00ff88']
            return (
              <React.Fragment key={stage}>
                <div className="flex-1 text-center">
                  <div className="h-2 rounded-full mb-1.5" style={{ background: count > 0 ? colors[i] : '#1a2a4a' }} />
                  <p className="text-xs font-mono" style={{ color: count > 0 ? colors[i] : '#4a5568' }}>{stage}</p>
                  <p className="text-xs font-mono font-bold" style={{ color: count > 0 ? colors[i] : '#4a5568' }}>{count}</p>
                </div>
                {i < STAGES.length - 1 && (
                  <div className="text-gray-700 text-xs">→</div>
                )}
              </React.Fragment>
            )
          })}
        </div>
      </div>

      {/* Filter buttons */}
      <div className="flex gap-2 flex-wrap">
        {['', ...Object.keys(counts)].map(s => (
          <button key={s} onClick={() => setFilter(s)}
            className={`px-3 py-1.5 rounded text-xs font-mono border transition-all
              ${filter === s ? 'border-cyber-cyan/60 text-cyber-cyan bg-cyber-cyan/10' : 'border-cyber-border text-gray-500 hover:border-gray-500'}`}>
            {s || 'ALL'} {s ? `(${counts[s]})` : `(${allIncidents.length})`}
          </button>
        ))}
      </div>

      {/* Full incidents table */}
      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto max-h-[450px] overflow-y-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border bg-cyber-surface/50">
                {['Incident ID', 'Attack Type', 'Stage', 'Source IP', 'Dest IP', 'Port', 'Department', 'Asset', 'MITRE', 'CVSS', 'Confidence', 'Risk', 'Recommended Action', 'Detected'].map(h => (
                  <th key={h} className="px-3 py-3 text-left text-gray-500 uppercase whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(inc => {
                const cfg = STATUS_CONFIG[inc.status] || {}
                const isSelected = selectedAttackLogId === inc.attack_log_id
                return (
                  <tr 
                    key={inc.id}
                    onClick={() => setSelectedAttackLogId(inc.attack_log_id)}
                    className={`border-b border-cyber-border/30 cursor-pointer transition-colors ${isSelected ? 'bg-cyber-cyan/10 border-l-2 border-l-cyber-cyan' : 'hover:bg-white/[0.04]'}`}
                  >
                    <td className="px-3 py-3 font-bold text-cyber-cyan whitespace-nowrap">{inc.incidentId}</td>
                    <td className="px-3 py-3 font-bold text-white whitespace-nowrap">{inc.attack_type}</td>
                    <td className="px-3 py-3">
                      <span className={`px-2 py-0.5 rounded border text-xs whitespace-nowrap ${cfg.color} ${cfg.bg}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="px-3 py-3 text-red-400">{inc.source_ip || 'N/A'}</td>
                    <td className="px-3 py-3 text-green-400">{inc.dest_ip || 'N/A'}</td>
                    <td className="px-3 py-3 text-gray-400">{inc.port || 'N/A'}</td>
                    <td className="px-3 py-3 text-gray-300 whitespace-nowrap">{inc.department || 'N/A'}</td>
                    <td className="px-3 py-3 text-gray-400 whitespace-nowrap">{inc.asset_name || 'N/A'}</td>
                    <td className="px-3 py-3 text-purple-400 whitespace-nowrap">{inc.mitre_id || 'N/A'}</td>
                    <td className="px-3 py-3 text-orange-400">{inc.cvss || inc.severity || 'N/A'}</td>
                    <td className="px-3 py-3 text-cyan-400 font-bold">{Math.round(inc.confidence || 0)}%</td>
                    <td className="px-3 py-3 font-bold" style={{ color: (inc.risk_score || 0) > 75 ? '#ff2d55' : (inc.risk_score || 0) > 45 ? '#ffd60a' : '#00ff88' }}>
                      {Math.round(inc.risk_score || 0)}
                    </td>
                    <td className="px-3 py-3 text-purple-300" style={{ maxWidth: 200, whiteSpace: 'normal' }}>{inc.action || 'N/A'}</td>
                    <td className="px-3 py-3 text-gray-500 whitespace-nowrap">{inc.detected_at ? new Date(inc.detected_at).toLocaleTimeString() : 'N/A'}</td>
                  </tr>
                )
              })}
              {filtered.length === 0 && (
                <tr><td colSpan={14} className="px-4 py-12 text-center text-gray-600">No incidents found for this filter</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
