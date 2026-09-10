import React, { useCallback, useEffect, useState } from 'react'
import { Users, Shield, Database, Activity, RefreshCw } from 'lucide-react'
import api from '../utils/api'
import { useAuthStore } from '../store'

const ROLE_OPTIONS = ['admin', 'analyst', 'clinical']

export default function Admin() {
  const { user } = useAuthStore()
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [savingId, setSavingId] = useState(null)

  const load = useCallback(async () => {
    if (user?.role !== 'admin') return
    setLoading(true)
    setError('')
    try {
      const [statsRes, usersRes] = await Promise.all([
        api.get('/admin/stats'),
        api.get('/admin/users'),
      ])
      setStats(statsRes.data)
      setUsers(Array.isArray(usersRes.data) ? usersRes.data : [])
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load admin data.')
    } finally {
      setLoading(false)
    }
  }, [user?.role])

  useEffect(() => {
    load()
  }, [load])

  const updateUser = async (userId, payload) => {
    setSavingId(userId)
    setError('')
    try {
      const { data } = await api.patch(`/admin/users/${userId}`, payload)
      setUsers((prev) => prev.map((row) => (row.id === data.id ? { ...row, ...data } : row)))
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update user.')
    } finally {
      setSavingId(null)
    }
  }

  if (user?.role !== 'admin') {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <p className="text-red-400 font-mono text-sm">Admin access required</p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Access &amp; Configuration</h1>
          <p className="text-xs text-mute font-mono mt-1">User directory, live counters, and runtime identity</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-1 text-xs font-mono text-gray-500 hover:text-cyber-cyan"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {error && (
        <div className="text-xs font-mono text-red-300 bg-red-950/70 border border-red-800/80 rounded-md px-3 py-2">
          {error}
        </div>
      )}

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Users', val: stats.total_users, icon: Users, color: 'cyan' },
            { label: 'Total Attacks', val: stats.total_attacks, icon: Shield, color: 'red' },
            { label: 'Active Threats', val: stats.active_threats, icon: Activity, color: 'yellow' },
            { label: 'Process Uptime', val: stats.system_uptime, icon: Database, color: 'green' },
          ].map(({ label, val, icon: Icon, color }) => (
            <div key={label} className="cyber-card p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-gray-500 uppercase">{label}</span>
                <Icon size={14} className={`text-cyber-${color}`} />
              </div>
              <p className={`text-2xl font-black font-mono text-cyber-${color}`}>{val ?? '—'}</p>
            </div>
          ))}
        </div>
      )}

      <div className="cyber-card p-5">
        <h3 className="text-sm font-bold text-white font-mono mb-4">RUNTIME CONFIGURATION</h3>
        <div className="grid md:grid-cols-2 gap-4 text-xs font-mono">
          {[
            ['AI Engine', stats?.model_version || 'MULTI_MLP_v1'],
            ['Database', stats?.database_engine || '—'],
            ['QIGA Runs', stats?.qiga_runs ?? '—'],
            ['Threat Memory', stats?.memory_entries ?? '—'],
            ['Total Alerts', stats?.total_alerts ?? '—'],
            ['Total Incidents', stats?.total_incidents ?? '—'],
            ['Auth', 'JWT HS256'],
          ].map(([k, v]) => (
            <div key={k} className="flex justify-between py-2 border-b border-cyber-border/30">
              <span className="text-gray-500">{k}</span>
              <span className="text-cyber-cyan">{v}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="cyber-card overflow-hidden">
        <div className="p-4 border-b border-cyber-border flex items-center gap-2">
          <Users size={14} className="text-gray-500" />
          <h3 className="text-sm font-bold text-white font-mono">USER MANAGEMENT</h3>
        </div>
        <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border bg-cyber-surface/50">
                {['ID', 'Name', 'Email', 'Role', 'Clearance', 'Status', 'Actions'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-gray-500 uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map((row) => (
                <tr key={row.id} className="border-b border-cyber-border/30 hover:bg-white/[0.04] transition-colors">
                  <td className="px-4 py-3 text-gray-500">#{row.id}</td>
                  <td className="px-4 py-3 text-white font-bold">{row.full_name}</td>
                  <td className="px-4 py-3 text-cyber-cyan">{row.email}</td>
                  <td className="px-4 py-3">
                    <select
                      disabled={savingId === row.id || row.id === user?.id}
                      value={row.role}
                      onChange={(e) => updateUser(row.id, { role: e.target.value })}
                      className="bg-black border border-[#262626] rounded px-2 py-1 text-white"
                    >
                      {ROLE_OPTIONS.map((role) => (
                        <option key={role} value={role}>{role}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3 text-yellow-400">L{row.clearance_level}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded ${row.is_active ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
                      {row.is_active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      disabled={savingId === row.id || row.id === user?.id}
                      onClick={() => updateUser(row.id, { is_active: !row.is_active })}
                      className="text-[11px] uppercase tracking-wide border border-[#333] rounded px-2 py-1 hover:border-white disabled:opacity-40"
                    >
                      {row.is_active ? 'Disable' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-gray-600">
                    {loading ? 'Loading...' : 'No users'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
