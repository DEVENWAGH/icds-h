import React, { useState } from 'react'
import { Search } from 'lucide-react'
import { useSOCStore, LIFECYCLE_STAGES } from '../store/socEngine'
import { useIncidentStore } from '../store'

const SEV_COLOR = {
  CRITICAL: 'text-red-400 bg-red-900/20 border border-red-700/50',
  HIGH: 'text-orange-400 bg-orange-900/20 border border-orange-700/50',
  MEDIUM: 'text-yellow-400 bg-yellow-900/20 border border-yellow-700/50',
  LOW: 'text-green-400 bg-green-900/20 border border-green-700/50',
  NORMAL: 'text-gray-400 bg-gray-800/50 border border-gray-600/50',
}

export default function Logs() {
  const incidents = useSOCStore((s) => s.incidents)
  const { selectedAttackLogId, setSelectedAttackLogId } = useIncidentStore()
  const [filter, setFilter] = useState('')
  const [search, setSearch] = useState('')

  const filtered = incidents
    .filter(i => {
      if (!filter) return true;
      if (filter === 'NORMAL') return i.attack_type === 'Normal';
      return i.severity === filter && i.attack_type !== 'Normal';
    })
    .filter(i => !search ||
      i.attack_type.toLowerCase().includes(search.toLowerCase()) ||
      i.source_ip.includes(search) ||
      i.dest_ip.includes(search) ||
      (i.department || '').toLowerCase().includes(search.toLowerCase()) ||
      (i.asset_name || i.asset || '').toLowerCase().includes(search.toLowerCase()) ||
      String(i.attack_log_id || i.incidentId).includes(search)
    )

  const stats = {
    total: incidents.length,
    critical: incidents.filter(i => i.severity === 'CRITICAL' && i.attack_type !== 'Normal').length,
    normal: incidents.filter(i => i.attack_type === 'Normal').length,
    active: incidents.filter(i => !i.resolved && i.attack_type !== 'Normal').length,
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Attack Logs</h1>
          <p className="text-xs text-gray-500 font-mono mt-1">TON_IoT · PhiUSIIL · CERT r4 · CICIDS-2017 · Live feed · Auto-updating every 4s</p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-cyber-green">
          <span className="w-2 h-2 rounded-full bg-cyber-green pulse-dot" />
          LIVE
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total', val: stats.total, color: 'text-white' },
          { label: 'Critical', val: stats.critical, color: 'text-red-400' },
          { label: 'Normal', val: stats.normal, color: 'text-gray-400' },
          { label: 'Active Threats', val: stats.active, color: 'text-yellow-400' },
        ].map(({ label, val, color }) => (
          <div key={label} className="cyber-card p-4 text-center">
            <p className={`text-2xl font-black font-mono ${color}`}>{val}</p>
            <p className="text-xs font-mono text-gray-500 uppercase">{label}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <div className="flex-1 relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search by attack type, IP, department, asset, or incident ID..."
            className="w-full bg-cyber-surface border border-cyber-border rounded pl-9 pr-4 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyber-cyan/60" />
        </div>
        <div className="flex gap-2">
          {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'NORMAL'].map(sev => (
            <button key={sev} onClick={() => setFilter(sev)}
              className={`px-3 py-2 rounded text-xs font-mono transition-all border
                ${filter === sev ? 'border-cyber-cyan/50 text-cyber-cyan bg-cyber-cyan/10' :
                'border-cyber-border text-gray-500 hover:border-gray-500'}`}>
              {sev || 'ALL'}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="cyber-card overflow-hidden">
        <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border bg-cyber-surface/50">
                {['Incident ID', 'Attack Type', 'Source IP', 'Dest IP', 'Protocol', 'Port', 'Department', 'Asset', 'MITRE', 'CVSS', 'Confidence', 'Risk', 'Stage', 'Severity', 'Detected'].map(h => (
                  <th key={h} className="px-3 py-3 text-left text-gray-500 uppercase whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(log => {
                const isSelected = selectedAttackLogId === log.attack_log_id
                const isNormal = log.attack_type === 'Normal'
                const sevKey = isNormal ? 'NORMAL' : log.severity
                const sevClass = SEV_COLOR[sevKey] || SEV_COLOR.LOW

                return (
                <tr key={log.id} 
                    onClick={() => setSelectedAttackLogId(log.attack_log_id)}
                    className={`border-b border-cyber-border/30 cursor-pointer transition-colors ${
                      isSelected ? 'bg-cyber-cyan/10 border-l-2 border-l-cyber-cyan' : 'hover:bg-white/[0.04]'
                    }`}>
                  <td className="px-3 py-3 text-cyber-cyan font-bold">{log.attack_log_id || log.incidentId}</td>
                  <td className={`px-3 py-3 font-bold whitespace-nowrap ${isNormal ? 'text-gray-400' : 'text-white'}`}>{log.attack_type}</td>
                  <td className="px-3 py-3 text-red-400">{log.source_ip}</td>
                  <td className="px-3 py-3 text-green-400">{log.dest_ip}</td>
                  <td className="px-3 py-3 text-gray-400">{log.protocol || '--'}</td>
                  <td className="px-3 py-3 text-gray-400">{log.port || '--'}</td>
                  <td className="px-3 py-3 text-gray-300 whitespace-nowrap">{log.department || '--'}</td>
                  <td className="px-3 py-3 text-gray-400 whitespace-nowrap">{log.asset_name || log.asset || 'N/A'}</td>
                  <td className="px-3 py-3 text-purple-400">{log.mitre_id || '--'}</td>
                  <td className="px-3 py-3 text-orange-400">{log.cvss || '--'}</td>
                  <td className="px-3 py-3 text-cyan-400 font-bold">{log.confidence ? `${log.confidence}%` : '--'}</td>
                  <td className="px-3 py-3 font-bold" style={{ color: isNormal ? '#6b7280' : log.risk_score > 75 ? '#ff2d55' : log.risk_score > 45 ? '#ffd60a' : '#00ff88' }}>
                    {isNormal ? '--' : Math.round(log.risk_score || 0)}
                  </td>
                  <td className="px-3 py-3 text-yellow-400">{LIFECYCLE_STAGES?.[log.stage] || log.stage || '--'}</td>
                  <td className="px-3 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${sevClass}`}>
                      {isNormal ? 'NORMAL' : log.severity}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-gray-600 whitespace-nowrap">
                    {log.detected_at ? new Date(log.detected_at).toLocaleString() : '--'}
                  </td>
                </tr>
              )})}
              {filtered.length === 0 && (
                <tr><td colSpan={15} className="px-4 py-12 text-center text-gray-600">No logs found</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
