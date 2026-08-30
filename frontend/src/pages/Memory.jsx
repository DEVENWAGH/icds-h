import React, { useState, useEffect, useCallback } from 'react'
import { Database, RefreshCw, Clock, Shield, CheckCircle, XCircle, Search } from 'lucide-react'
import api from '../utils/api'
import { useIncidentStore } from '../store'

const TYPE_COLORS = {
  Ransomware: '#ff2d55', DDoS: '#ff9500', 'Brute Force': '#ffd60a',
  Phishing: '#bf5af2', 'Insider Threat': '#00e5ff', 'SQL Injection': '#ff6b6b',
  Botnet: '#ff4500', BENIGN: '#00ff88',
}

const OutcomeBadge = ({ outcome }) => {
  if (!outcome) return null
  const success = outcome === 'SUCCESS' || outcome === 'SUCCESS_WITH_IMPACT'
  const color = success ? '#00ff88' : outcome === 'MITIGATED' ? '#00e5ff' : '#ff2d55'
  return (
    <span className="text-xs font-mono px-2 py-0.5 rounded inline-flex items-center gap-1"
      style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}>
      {success ? <CheckCircle size={10} /> : <Clock size={10} />}
      {outcome}
    </span>
  )
}

export default function MemoryPage() {
  const { selectedAttackLogId } = useIncidentStore()
  const [stats, setStats] = useState(null)
  const [entries, setEntries] = useState([])
  const [similar, setSimilar] = useState([])
  const [bestActions, setBestActions] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const fetchStats = useCallback(async () => {
    try {
      const { data } = await api.get('/memory/stats')
      setStats(data)
    } catch (err) {
      console.error(err)
    }
  }, [])

  const fetchHistory = useCallback(async () => {
    try {
      const { data } = await api.get('/memory/history')
      setEntries(data)
    } catch (err) {
      console.error(err)
    }
  }, [])

  const fetchSimilar = useCallback(async () => {
    if (!selectedAttackLogId) return
    setLoading(true)
    setError(null)
    try {
      const { data } = await api.get(`/memory/similar?attack_log_id=${selectedAttackLogId}&k=5`)
      setSimilar(data.similar_attacks || [])
      setBestActions(data.recommended_actions || [])
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to find similar attacks.")
      setSimilar([])
      setBestActions([])
    } finally {
      setLoading(false)
    }
  }, [selectedAttackLogId])

  useEffect(() => {
    fetchStats()
    fetchHistory()
  }, [fetchStats, fetchHistory])

  useEffect(() => {
    if (selectedAttackLogId) {
      fetchSimilar()
    } else {
      setSimilar([])
      setBestActions([])
    }
  }, [selectedAttackLogId, fetchSimilar])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-mono text-gray-500 mb-1">KNOWLEDGE BASE v2.0</p>
          <h1 className="text-2xl font-black text-white">Attack Knowledge Memory</h1>
          <p className="text-xs text-gray-500 mt-1">Historical pattern matching · Neural Network retrieval · Success-weighted recommendations</p>
        </div>
        <button onClick={() => { fetchStats(); fetchHistory(); fetchSimilar() }}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-mono border border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/10 transition-all">
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cyber-card p-5 text-center">
          <p className="text-xs font-mono text-gray-500 mb-1">Total Entries</p>
          <p className="text-3xl font-black font-mono text-cyber-cyan">{stats?.total_entries ?? 'N/A'}</p>
          <p className="text-xs font-mono text-gray-600">Recorded</p>
        </div>
        <div className="cyber-card p-5 text-center">
          <p className="text-xs font-mono text-gray-500 mb-1">Success Rate</p>
          <p className="text-3xl font-black font-mono text-green-400">
            {stats?.overall_success_rate !== undefined ? `${(stats.overall_success_rate * 100).toFixed(0)}%` : 'N/A'}
          </p>
          <p className="text-xs font-mono text-gray-600">Mitigated / Resolved</p>
        </div>
        <div className="cyber-card p-5 text-center">
          <p className="text-xs font-mono text-gray-500 mb-1">Unique Actions</p>
          <p className="text-3xl font-black font-mono text-purple-400">
            {stats?.unique_actions ?? 'N/A'}
          </p>
          <p className="text-xs font-mono text-gray-600">Successfully deployed</p>
        </div>
        <div className="cyber-card p-5 text-center">
          <p className="text-xs font-mono text-gray-500 mb-1">Top Attack Type</p>
          <p className="text-lg font-black font-mono text-yellow-400 truncate mt-2">
            {stats?.most_frequent_attack_type ?? 'N/A'}
          </p>
          <p className="text-xs font-mono text-gray-600">Most frequent pattern</p>
        </div>
      </div>

      {/* Similar Attack Lookup */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">Find Similar Historical Attacks</p>
          <div className="flex items-center gap-3">
            <span className="text-sm font-mono text-white">
              Selected Log: <span className="text-cyber-cyan font-bold">{selectedAttackLogId || 'None'}</span>
            </span>
            <button onClick={fetchSimilar} disabled={loading || !selectedAttackLogId}
              className="flex items-center gap-1 px-3 py-1.5 rounded text-xs font-mono border border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/10 disabled:opacity-50">
              <Search size={12} /> Query
            </button>
          </div>
        </div>

        {error && (
          <div className="text-xs text-red-400 bg-red-900/20 border border-red-500/30 p-3 rounded mb-4 font-mono">
            Error: {error}
          </div>
        )}

        {!selectedAttackLogId ? (
          <div className="p-8 text-center text-gray-500 font-mono text-sm border border-dashed border-gray-700 rounded">
            Select an AttackLog from the Incidents or Attack Logs page to query memory.
          </div>
        ) : (
          <div className="grid lg:grid-cols-2 gap-5">
            {/* Similar attacks */}
            <div>
              <p className="text-xs font-mono text-gray-600 mb-3">Top {similar.length} Similar Attacks</p>
              <div className="space-y-2">
                {similar.map((entry, i) => {
                  const color = TYPE_COLORS[entry.attack_type] || '#888'
                  const simPct = Math.round((entry.similarity ?? 0) * 100)
                  return (
                    <div key={i} className="p-3 rounded-lg border border-cyber-border/40 bg-cyber-bg/60">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full" style={{ background: color }} />
                          <span className="text-xs font-mono font-bold text-white">{entry.attack_type}</span>
                          <span className="text-xs font-mono px-1.5 py-0.5 rounded"
                            style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}>
                            {entry.severity}
                          </span>
                        </div>
                        <OutcomeBadge outcome={entry.outcome} />
                      </div>
                      <div className="flex items-center gap-3 text-xs font-mono text-gray-500">
                        <span>Risk: <span className="text-white">{entry.risk_score?.toFixed(1)}</span></span>
                        <span>Actions: <span className="text-cyber-cyan">{(entry.actions || []).join(', ')}</span></span>
                      </div>
                      {/* Similarity bar */}
                      <div className="mt-2">
                        <div className="flex justify-between text-xs font-mono mb-1">
                          <span className="text-gray-600">Similarity</span>
                          <span className="text-cyber-cyan">{simPct}%</span>
                        </div>
                        <div className="h-1 bg-gray-800 rounded-full">
                          <div className="h-1 rounded-full bg-cyber-cyan transition-all"
                            style={{ width: `${simPct}%` }} />
                        </div>
                      </div>
                    </div>
                  )
                })}
                {similar.length === 0 && !loading && (
                  <p className="text-xs text-gray-600 font-mono text-center py-6 border border-dashed border-gray-700 rounded">No similar attacks found in memory</p>
                )}
              </div>
            </div>

            {/* Recommended actions from memory */}
            <div>
              <p className="text-xs font-mono text-gray-600 mb-3">Historically Successful Actions</p>
              <div className="space-y-3">
                {bestActions.map((action, i) => {
                  const confPct = Math.round((action.historical_confidence ?? 0) * 100)
                  const actionColor = confPct > 50 ? '#00ff88' : confPct > 30 ? '#ffd60a' : '#ff9500'
                  return (
                    <div key={i} className="p-3 rounded-lg border border-cyber-border/40">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-mono font-bold text-white">{action.action}</span>
                        <span className="text-xs font-mono font-bold" style={{ color: actionColor }}>{confPct}%</span>
                      </div>
                      <p className="text-xs font-mono text-gray-500 mb-2">
                        Used {action.occurrence_count} times · success-weighted confidence
                      </p>
                      <div className="h-1.5 bg-gray-800 rounded-full">
                        <div className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${confPct}%`, background: actionColor }} />
                      </div>
                    </div>
                  )
                })}
                {bestActions.length === 0 && !loading && (
                  <p className="text-xs text-gray-600 font-mono text-center py-6 border border-dashed border-gray-700 rounded">No action history available</p>
                )}
              </div>

              {/* How it works */}
              <div className="mt-4 bg-cyber-bg/60 rounded-lg p-3 border border-cyber-border/40">
                <p className="text-xs font-mono text-gray-500 mb-2">How Memory Works</p>
                <div className="space-y-1 text-xs font-mono text-gray-600">
                  <p>1. Extract sequence feature embeddings</p>
                  <p>2. Apply multi-head attention</p>
                  <p>3. Retrieve semantically similar patterns</p>
                  <p>4. Weight actions by: semantic match × success_rate</p>
                  <p>5. Return context-aware recommendations</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* History table */}
      <div className="cyber-card p-5">
        <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">Persisted Memory Entries (Database)</p>
        <div className="overflow-x-auto max-h-[300px] overflow-y-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border text-gray-500 uppercase">
                <th className="pb-2 text-left pr-3">Attack Log ID</th>
                <th className="pb-2 text-left pr-3">Type</th>
                <th className="pb-2 text-left pr-3">Severity</th>
                <th className="pb-2 text-left pr-3">Risk</th>
                <th className="pb-2 text-left pr-3">Actions</th>
                <th className="pb-2 text-left pr-3">Outcome</th>
                <th className="pb-2 text-left">Recorded</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id} className="border-b border-cyber-border/30 hover:bg-white/2">
                  <td className="py-2 pr-3 text-cyber-cyan">{e.attack_log_id}</td>
                  <td className="py-2 pr-3 font-bold" style={{ color: TYPE_COLORS[e.attack_type] || '#888' }}>{e.attack_type}</td>
                  <td className="py-2 pr-3 text-gray-400">{e.severity}</td>
                  <td className="py-2 pr-3 text-white">{e.risk_score?.toFixed(1)}</td>
                  <td className="py-2 pr-3 text-cyber-cyan">{(e.actions ?? []).join(', ')}</td>
                  <td className="py-2 pr-3"><OutcomeBadge outcome={e.outcome} /></td>
                  <td className="py-2 text-gray-600">{new Date(e.recorded_at).toLocaleTimeString()}</td>
                </tr>
              ))}
              {entries.length === 0 && (
                <tr>
                  <td colSpan="7" className="text-center py-4 text-gray-500 italic">No history available</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
