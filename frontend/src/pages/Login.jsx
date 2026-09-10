import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Fingerprint, Key, AlertCircle, Eye, EyeOff,
  ArrowLeft, Lock, RefreshCw
} from 'lucide-react'
import { useAuthStore } from '../store'
import api from '../utils/api'

function homeForRole(role) {
  return role === 'clinical' ? '/app/dashboard' : '/app/command'
}

export default function Login() {
  const [form, setForm] = useState({ email: '', password: '' })
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [backendStatus, setBackendStatus] = useState('checking')
  const { setAuth, token, user } = useAuthStore()
  const navigate = useNavigate()
  const statusRef = useRef(backendStatus)
  statusRef.current = backendStatus

  useEffect(() => {
    if (token && user) {
      navigate(homeForRole(user.role), { replace: true })
    }
  }, [token, user, navigate])

  const checkBackendHealth = async () => {
    setBackendStatus('checking')
    try {
      const response = await api.get('/health', { timeout: 5000 })
      const status = response.data?.status
      if (status === 'healthy' || status === 'degraded') {
        setBackendStatus('online')
        setError('')
        return true
      }
      setBackendStatus('offline')
      return false
    } catch {
      setBackendStatus('offline')
      return false
    }
  }

  useEffect(() => {
    checkBackendHealth()
    const interval = setInterval(async () => {
      if (statusRef.current === 'offline') {
        await checkBackendHealth()
      }
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    if (backendStatus === 'offline') {
      const isOnline = await checkBackendHealth()
      if (!isOnline) {
        setError('Cannot reach the ICDS-H API. Start the backend and try again.')
        setLoading(false)
        return
      }
    }

    try {
      const { data } = await api.post('/auth/login', form)
      setAuth(data.user, data.access_token)
      navigate(homeForRole(data.user?.role))
    } catch (err) {
      if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
        setError('Connection timed out. The API may still be starting.')
        setBackendStatus('offline')
      } else if (err.code === 'ERR_NETWORK' || !err.response) {
        setError('Cannot reach the ICDS-H API. Verify the server is running.')
        setBackendStatus('offline')
      } else if (err.response?.status === 401) {
        setError('Invalid credentials. Check your email and password.')
      } else if (err.response?.status === 403) {
        setError('This account is disabled. Contact a security administrator.')
      } else if (err.response?.status === 429) {
        setError(err.response?.data?.detail || 'Too many failed attempts. Try again shortly.')
      } else {
        const detail = err.response?.data?.detail
        setError(typeof detail === 'string' ? detail : 'Authentication failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-black flex flex-col items-center justify-center p-4 selection:bg-white selection:text-black relative overflow-hidden font-sans">
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[650px] h-[400px] mesh-gradient-hero pointer-events-none -z-10" />

      <button
        onClick={() => navigate('/')}
        className="absolute top-6 left-6 text-xs font-mono text-mute hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer py-1.5 px-3 rounded-md hover:bg-[#0a0a0a] border border-transparent hover:border-[#262626]"
      >
        <ArrowLeft size={14} /> Back to Overview
      </button>

      <div className="relative w-full max-w-md my-8">
        <div className="card-marketing-large p-7 sm:p-8 shadow-2xl bg-[#0a0a0a] border border-[#262626]">
          <div className="flex justify-center mb-4">
            <div className="w-12 h-12 rounded-lg bg-white flex items-center justify-center shadow-sm">
              <Shield size={22} className="text-black font-black" />
            </div>
          </div>

          <h1 className="text-xl font-semibold text-center text-white mb-1 tracking-tight">SOC Authentication</h1>
          <p className="text-xs text-mute text-center font-mono mb-6">Zero-Trust Clinical Defense Console</p>

          <div className={`mb-6 flex items-center justify-center gap-2 py-1.5 px-3 rounded-md border text-[11px] font-mono uppercase tracking-wide transition-all ${
            backendStatus === 'online'
              ? 'bg-teal-950/70 border-teal-800/80 text-teal-300'
              : backendStatus === 'offline'
              ? 'bg-red-950/70 border-red-800/80 text-red-300'
              : 'bg-yellow-950/70 border-yellow-800/80 text-yellow-300'
          }`}>
            <span className={`w-2 h-2 rounded-full ${backendStatus === 'online' ? 'bg-cyan pulse-dot' : backendStatus === 'offline' ? 'bg-error' : 'bg-warning'}`} />
            <span>{backendStatus === 'online' ? 'API ONLINE' : backendStatus === 'offline' ? 'API OFFLINE' : 'CHECKING...'}</span>
            {backendStatus === 'offline' && (
              <button
                type="button"
                onClick={checkBackendHealth}
                className="ml-2 text-red-400 hover:text-white transition-colors cursor-pointer"
                title="Retry connection"
              >
                <RefreshCw size={12} />
              </button>
            )}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-[11px] font-mono text-body uppercase tracking-wide mb-1.5 block">
                Email
              </label>
              <div className="relative">
                <Fingerprint size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" />
                <input
                  type="email"
                  required
                  autoComplete="username"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="you@hospital.org"
                  className="w-full form-input pl-9 text-xs"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] font-mono text-body uppercase tracking-wide mb-1.5 block">
                Password
              </label>
              <div className="relative">
                <Key size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  autoComplete="current-password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="••••••••••••"
                  className="w-full form-input pl-9 pr-9 text-xs"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-mute hover:text-white transition-colors p-1 cursor-pointer"
                  aria-label="Toggle password visibility"
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 text-red-300 text-xs font-mono bg-red-950/70 border border-red-800/80 rounded-md px-3 py-2">
                <AlertCircle size={14} className="text-red-400 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-md font-sans font-medium text-black text-xs flex items-center justify-center gap-2 transition-all cursor-pointer bg-white hover:bg-gray-200 shadow-sm disabled:opacity-50"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
              ) : (
                <><Lock size={14} /> Sign in</>
              )}
            </button>
          </form>

          <div className="mt-6 border-t border-[#262626] pt-4 flex items-center justify-between text-[11px] font-mono text-mute">
            <span className="flex items-center gap-1.5 text-body">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
              <span>JWT session · role-scoped access</span>
            </span>
            <span>All logins audited</span>
          </div>
        </div>

        <p className="text-center text-[11px] text-mute font-mono mt-4">
          AUTHORIZED CLINICAL &amp; SECURITY PERSONNEL ONLY
        </p>
      </div>
    </div>
  )
}
