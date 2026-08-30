import React, { useEffect, useState } from 'react'
import { Settings, Users, Shield, Database, Activity, RefreshCw } from 'lucide-react'
import api from '../utils/api'
import { useAuthStore } from '../store'

export default function Admin() {
  const { user } = useAuthStore()
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (user?.role !== 'admin') return
    setLoading(true)
    Promise.all([api.get('/admin/stats'), api.get('/admin/users')])
      .then(([s, u]) => { setStats(s.data); setUsers(u.data) })
      .finally(() => setLoading(false))
  }, [])

  if (user?.role !== 'admin') return (
    <div className="p-6 flex items-center justify-center h-64">
      <p className="text-red-400 font-mono text-sm">⛔ Admin access required</p>
    </div>
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-black text-white">Admin Panel</h1>
        <button onClick={() => window.location.reload()} className="flex items-center gap-1 text-xs font-mono text-gray-500 hover:text-cyber-cyan">
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Users', val: stats.total_users, icon: Users, color: 'cyan' },
            { label: 'Total Attacks', val: stats.total_attacks, icon: Shield, color: 'red' },
            { label: 'Active Threats', val: stats.active_threats, icon: Activity, color: 'yellow' },
            { label: 'System Uptime', val: stats.system_uptime, icon: Database, color: 'green' },
          ].map(({ label, val, icon: Icon, color }) => (
            <div key={label} className="cyber-card p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-gray-500 uppercase">{label}</span>
                <Icon size={14} className={`text-cyber-${color}`} />
              </div>
              <p className={`text-2xl font-black font-mono text-cyber-${color}`}>{val}</p>
            </div>
          ))}
        </div>
      )}

      {/* System info */}
      <div className="cyber-card p-5">
        <h3 className="text-sm font-bold text-white font-mono mb-4">SYSTEM CONFIGURATION</h3>
        <div className="grid md:grid-cols-2 gap-4 text-xs font-mono">
          {[
            ['AI Engine', 'ICDS-H Core v2.1'],
            ['Data Processed', 'Real-Time Telemetry'],
            ['Algorithm', 'Behavioral Anomaly Detection'],
            ['Analysis Depth', 'Deep Packet Inspection'],
            ['Dataset', 'Live Hospital Network Data'],
            ['JWT Algorithm', 'HS256'],
            ['DB Engine', 'MySQL 8.0'],
          ].map(([k, v]) => (
            <div key={k} className="flex justify-between py-2 border-b border-cyber-border/30">
              <span className="text-gray-500">{k}</span>
              <span className="text-cyber-cyan">{v}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Users table */}
      <div className="cyber-card overflow-hidden">
        <div className="p-4 border-b border-cyber-border flex items-center gap-2">
          <Users size={14} className="text-gray-500" />
          <h3 className="text-sm font-bold text-white font-mono">USER MANAGEMENT</h3>
        </div>
        <div className="overflow-x-auto max-h-[300px] overflow-y-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-cyber-border bg-cyber-surface/50">
                {['ID', 'Name', 'Email', 'Role', 'Clearance', 'Status'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-gray-500 uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} className="border-b border-cyber-border/30 hover:bg-white/2">
                  <td className="px-4 py-3 text-gray-500">#{u.id}</td>
                  <td className="px-4 py-3 text-white font-bold">{u.full_name}</td>
                  <td className="px-4 py-3 text-cyber-cyan">{u.email}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded ${u.role === 'admin' ? 'bg-cyber-cyan/20 text-cyber-cyan' : 'bg-gray-800 text-gray-400'}`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-yellow-400">L{u.clearance_level}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded ${u.is_active ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
                      {u.is_active ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-600">{loading ? 'Loading...' : 'No users'}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
