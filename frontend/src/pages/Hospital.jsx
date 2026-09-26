import { useEffect, useState } from 'react'
import { Building2, Server, Network } from 'lucide-react'
import api from '../utils/api'

export default function Hospital() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/hospital/overview')
      .then((res) => setData(res.data))
      .catch((err) => setError(err.response?.data?.detail || 'Could not load the hospital.'))
  }, [])

  if (error) {
    return <div className="p-6 text-sm text-red-300 font-mono">{error}</div>
  }
  if (!data) {
    return <div className="p-6 text-sm text-mute font-mono">Loading hospital...</div>
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-black text-white">Hospital</h1>
        <p className="text-xs text-mute font-mono mt-1">
          Departments, clinical systems, and the assets ICDS-H protects
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          ['Departments', data.counts.departments],
          ['Systems', data.counts.systems],
          ['Assets', data.counts.assets],
          ['Patients', data.counts.patients],
          ['Accounts', data.counts.staff],
        ].map(([label, value]) => (
          <div key={label} className="cyber-card p-4">
            <p className="text-[10px] font-mono uppercase text-gray-500">{label}</p>
            <p className="text-2xl font-black text-white mt-1">{value}</p>
          </div>
        ))}
      </div>

      <div className="cyber-card p-5">
        <h2 className="text-sm font-bold text-white mb-3">Your permissions · {data.role}</h2>
        <ul className="space-y-1 text-sm text-gray-300">
          {(data.permissions || []).map((item) => (
            <li key={item}>• {item}</li>
          ))}
        </ul>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <section className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Building2 size={14} className="text-cyan-300" />
            <h2 className="text-sm font-bold text-white">Departments</h2>
          </div>
          <ul className="space-y-2">
            {data.departments.map((row) => (
              <li key={row.code} className="text-xs">
                <span className="font-mono text-cyan-300">{row.code}</span>
                <span className="text-white ml-2">{row.name}</span>
                <p className="text-gray-500">{row.description}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Network size={14} className="text-cyan-300" />
            <h2 className="text-sm font-bold text-white">Hospital systems</h2>
          </div>
          <ul className="space-y-2">
            {data.systems.map((row) => (
              <li key={row.code} className="text-xs border-b border-white/5 pb-2">
                <p className="text-white font-semibold">{row.name}</p>
                <p className="font-mono text-cyan-300">
                  {row.code} → {row.asset_name} ({row.asset_code})
                </p>
                <p className="text-gray-500">{row.description}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Server size={14} className="text-cyan-300" />
            <h2 className="text-sm font-bold text-white">Assets</h2>
          </div>
          <ul className="space-y-2">
            {data.assets.map((row) => (
              <li key={row.asset_code} className="text-xs">
                <p className="text-white">
                  {row.asset_name} <span className="font-mono text-cyan-300">({row.asset_code})</span>
                </p>
                <p className="text-gray-500">
                  {row.ip_address} · {row.criticality} · {row.status}
                  {row.department ? ` · ${row.department}` : ''}
                </p>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  )
}
