import { useEffect, useState } from 'react'
import api from '../utils/api'
import { useAuthStore } from '../store'

const ACTION_FOR_ROLE = {
  doctor: { system: 'EMR', action: 'view_record', label: 'Open medical record' },
  nurse: { system: 'EMR', action: 'view_record', label: 'Open vital signs' },
  lab_technician: { system: 'LIS', action: 'view_lab', label: 'Open lab result' },
  receptionist: { system: 'REG', action: 'check_in', label: 'Check in patient' },
  hospital_admin: { system: 'EMR', action: 'view_record', label: 'Open medical record' },
  admin: { system: 'EMR', action: 'view_record', label: 'Open medical record' },
  clinical: { system: 'EMR', action: 'view_record', label: 'Open medical record' },
}

export default function Patients() {
  const role = useAuthStore((s) => s.user?.role)
  const [patients, setPatients] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const action = ACTION_FOR_ROLE[role] || ACTION_FOR_ROLE.doctor

  useEffect(() => {
    api.get('/hospital/patients')
      .then((res) => {
        setPatients(res.data)
        if (res.data[0]) setSelectedId(res.data[0].id)
      })
      .catch((err) => setError(err.response?.data?.detail || 'Could not load patients.'))
  }, [])

  const openRecord = async () => {
    if (!selectedId) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const { data } = await api.post('/hospital/access', {
        system_code: action.system,
        action: action.action,
        patient_id: selectedId,
      })
      setResult(data)
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Access was denied and logged.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-black text-white">Patients</h1>
        <p className="text-xs text-mute font-mono mt-1">
          Doctor → Login → EMR System → Access Patient Record → Activity Logged
        </p>
      </div>

      {error && (
        <div className="text-xs font-mono text-red-300 bg-red-950/70 border border-red-800/80 rounded-md px-3 py-2">
          {error} This attempt is in Access Logs.
        </div>
      )}

      <div className="grid lg:grid-cols-[1.2fr_0.8fr] gap-4">
        <div className="cyber-card overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-gray-500 font-mono uppercase border-b border-white/10">
                {['Patient ID', 'Name', 'Age', 'Department', 'Doctor'].map((heading) => (
                  <th key={heading} className="px-3 py-2">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {patients.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => { setSelectedId(row.id); setResult(null); setError('') }}
                  className={`border-b border-white/5 cursor-pointer ${selectedId === row.id ? 'bg-white/10' : 'hover:bg-white/5'}`}
                >
                  <td className="px-3 py-2 font-mono text-cyan-300">{row.patient_code}</td>
                  <td className="px-3 py-2 text-white">{row.full_name}</td>
                  <td className="px-3 py-2 text-gray-300">{row.age}</td>
                  <td className="px-3 py-2 text-gray-300">{row.department}</td>
                  <td className="px-3 py-2 text-gray-300">{row.doctor}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="cyber-card p-4 space-y-3">
          <h2 className="text-sm font-bold text-white">Open through {action.system}</h2>
          <p className="text-xs text-gray-400">
            Your role is {role}. This action is {action.label.toLowerCase()}, and ICDS-H records who did it.
          </p>
          <button
            onClick={openRecord}
            disabled={loading || !selectedId}
            className="px-3 py-2 text-xs font-mono rounded border border-cyan-700 text-cyan-200 hover:bg-cyan-950 disabled:opacity-40"
          >
            {loading ? 'Opening...' : action.label}
          </button>
          {result?.patient && (
            <div className="text-xs space-y-2 border-t border-white/10 pt-3">
              <p className="text-cyan-200 font-mono">{result.chain?.join(' → ')}</p>
              {result.suspicious && (
                <p className="text-amber-300">Flagged for ICDS-H: {result.message}</p>
              )}
              <p className="text-white font-semibold">
                {result.patient.patient_code} · {result.patient.full_name} · {result.patient.age}
              </p>
              <p className="text-gray-400">{result.patient.department} · {result.patient.doctor}</p>
              {result.patient.medical_record ? (
                <pre className="whitespace-pre-wrap text-gray-200 font-mono text-[11px] bg-black/40 p-3 rounded">
                  {result.patient.medical_record}
                </pre>
              ) : (
                <p className="text-gray-500">No clinical record is visible for this role.</p>
              )}
              {result.system?.asset_code && (
                <p className="font-mono text-gray-400">
                  System asset: {result.system.asset_name} ({result.system.asset_code})
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
