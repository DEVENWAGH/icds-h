import { useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import api from '../utils/api'

export default function AccessLogs() {
  const [rows, setRows] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await api.get('/hospital/access-logs?limit=150')
      setRows(Array.isArray(data) ? data : [])
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not load access logs.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">Access Logs</h1>
          <p className="text-xs text-mute font-mono mt-1">
            Who signed in, when, from where, which system they opened, and whether it succeeded
          </p>
        </div>
        <button onClick={load} className="flex items-center gap-1 text-xs font-mono text-gray-400 hover:text-white">
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {error && <div className="text-xs text-red-300 font-mono">{error}</div>}

      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-gray-500 font-mono uppercase border-b border-white/10">
              {['Who', 'Time', 'IP / device', 'System', 'Action', 'Result', 'ICDS-H'].map((heading) => (
                <th key={heading} className="px-3 py-2">{heading}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-b border-white/5 align-top">
                <td className="px-3 py-2">
                  <p className="text-white">{row.who}</p>
                  <p className="text-gray-500 font-mono">{row.role}</p>
                </td>
                <td className="px-3 py-2 text-gray-300 whitespace-nowrap">
                  {row.created_at ? new Date(row.created_at).toLocaleString() : '—'}
                </td>
                <td className="px-3 py-2">
                  <p className="font-mono text-cyan-200">{row.ip_address || '—'}</p>
                  <p className="text-gray-500 max-w-[220px] truncate" title={row.device}>{row.device}</p>
                </td>
                <td className="px-3 py-2 text-gray-200">
                  {row.system || 'Sign-in'}
                  {row.asset_code ? ` · ${row.asset_name} (${row.asset_code})` : ''}
                  {row.patient_code ? ` · ${row.patient_code}` : ''}
                </td>
                <td className="px-3 py-2 font-mono text-gray-300">{row.action}</td>
                <td className="px-3 py-2">
                  <span className={row.success ? 'text-emerald-300' : 'text-red-300'}>
                    {row.success ? 'Success' : 'Failed'}
                  </span>
                  {row.suspicious && (
                    <p className="text-amber-300 mt-1">{row.suspicion_reason}</p>
                  )}
                </td>
                <td className="px-3 py-2 text-cyan-200 max-w-[280px]">
                  {row.impact_line || (row.suspicious ? 'Flagged' : '—')}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-gray-500">
                  {loading ? 'Loading...' : 'No access activity yet. Sign in or open a patient record.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
