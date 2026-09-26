import { useCallback, useEffect, useState } from 'react'
import api from '../utils/api'
import { useAuthStore } from '../store'

const HOSPITAL_ASSIGNABLE = ['doctor', 'nurse', 'lab_technician', 'receptionist']
const ADMIN_ASSIGNABLE = ['admin', 'analyst', 'clinical', 'hospital_admin', ...HOSPITAL_ASSIGNABLE]

const EMPTY = {
  full_name: '',
  email: '',
  password: '',
  role: 'doctor',
  department_code: 'CARD',
}

export default function Staff() {
  const actor = useAuthStore((s) => s.user)
  const [users, setUsers] = useState([])
  const [departments, setDepartments] = useState([])
  const [form, setForm] = useState(EMPTY)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)
  const roles = actor?.role === 'admin' ? ADMIN_ASSIGNABLE : HOSPITAL_ASSIGNABLE

  const load = useCallback(async () => {
    const [userRes, overviewRes] = await Promise.all([
      api.get('/hospital/users'),
      api.get('/hospital/overview'),
    ])
    setUsers(userRes.data)
    setDepartments(overviewRes.data.departments || [])
  }, [])

  useEffect(() => {
    load().catch((err) => setError(err.response?.data?.detail || 'Could not load staff.'))
  }, [load])

  const createUser = async (event) => {
    event.preventDefault()
    setSaving(true)
    setError('')
    setNotice('')
    try {
      await api.post('/hospital/users', form)
      setForm(EMPTY)
      setNotice('Account created. The employee can sign in with that email and password.')
      await load()
    } catch (err) {
      const detail = err.response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'Could not create the account.')
    } finally {
      setSaving(false)
    }
  }

  const setActive = async (row, isActive) => {
    setError('')
    try {
      await api.patch(`/hospital/users/${row.id}`, { is_active: isActive })
      await load()
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not update the account.')
    }
  }

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-black text-white">Staff Access</h1>
        <p className="text-xs text-mute font-mono mt-1">
          ICDS admin and hospital admin create each employee login and assign a role
        </p>
      </div>

      {error && <div className="text-xs font-mono text-red-300">{error}</div>}
      {notice && <div className="text-xs font-mono text-emerald-300">{notice}</div>}

      <form onSubmit={createUser} className="cyber-card p-4 grid md:grid-cols-6 gap-3 items-end">
        <label className="text-xs text-gray-400 md:col-span-1">
          Name
          <input
            required
            value={form.full_name}
            onChange={(e) => setForm({ ...form, full_name: e.target.value })}
            className="mt-1 w-full bg-black border border-[#333] rounded px-2 py-1.5 text-white"
          />
        </label>
        <label className="text-xs text-gray-400 md:col-span-1">
          Email
          <input
            required
            type="email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            className="mt-1 w-full bg-black border border-[#333] rounded px-2 py-1.5 text-white"
          />
        </label>
        <label className="text-xs text-gray-400">
          Password
          <input
            required
            minLength={8}
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            className="mt-1 w-full bg-black border border-[#333] rounded px-2 py-1.5 text-white"
          />
        </label>
        <label className="text-xs text-gray-400">
          Role
          <select
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
            className="mt-1 w-full bg-black border border-[#333] rounded px-2 py-1.5 text-white"
          >
            {roles.map((role) => <option key={role} value={role}>{role}</option>)}
          </select>
        </label>
        <label className="text-xs text-gray-400">
          Department
          <select
            value={form.department_code}
            onChange={(e) => setForm({ ...form, department_code: e.target.value })}
            className="mt-1 w-full bg-black border border-[#333] rounded px-2 py-1.5 text-white"
          >
            {departments.map((row) => (
              <option key={row.code} value={row.code}>{row.name}</option>
            ))}
          </select>
        </label>
        <button
          disabled={saving}
          className="h-9 text-xs font-mono rounded bg-white text-black disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Create login'}
        </button>
      </form>

      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-gray-500 font-mono uppercase border-b border-white/10">
              {['Name', 'Email', 'Role', 'Department', 'Status', ''].map((heading) => (
                <th key={heading || 'action'} className="px-3 py-2">{heading}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {users.map((row) => (
              <tr key={row.id} className="border-b border-white/5">
                <td className="px-3 py-2 text-white">{row.full_name}</td>
                <td className="px-3 py-2 font-mono text-cyan-200">{row.email}</td>
                <td className="px-3 py-2 text-gray-300">{row.role}</td>
                <td className="px-3 py-2 text-gray-300">{row.department || '—'}</td>
                <td className="px-3 py-2">{row.is_active ? 'Active' : 'Disabled'}</td>
                <td className="px-3 py-2">
                  {row.id !== actor?.id && (
                    <button
                      onClick={() => setActive(row, !row.is_active)}
                      className="border border-[#333] rounded px-2 py-1 text-[11px] uppercase"
                    >
                      {row.is_active ? 'Disable' : 'Enable'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
