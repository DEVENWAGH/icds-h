import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Fingerprint, Key, Zap, AlertCircle, Eye, EyeOff, CheckCircle2, ArrowLeft, Lock, Wifi, WifiOff, RefreshCw } from 'lucide-react'
import { useAuthStore } from '../store'
import api from '../utils/api'

export default function Login() {
  const [form, setForm] = useState({ email: 'admin@icds-h.com', password: 'Admin@1234' })
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [backendStatus, setBackendStatus] = useState('checking') // 'checking' | 'online' | 'offline'
  const { setAuth } = useAuthStore()
  const navigate = useNavigate()

  const quickRoles = [
    { label: 'Admin (L5)', email: 'admin@icds-h.com', pass: 'Admin@1234', role: 'SecDirector' },
    { label: 'Analyst (L3)', email: 'analyst@icds-h.com', pass: 'Analyst@1234', role: 'SOC Lead' },
    { label: 'Clinical (L4)', email: 'clinical@icds-h.com', pass: 'Clinical@1234', role: 'MedDirector' },
  ]

  const checkBackendHealth = async () => {
    setBackendStatus('checking')
    try {
      const response = await api.get('/health', { timeout: 5000 })
      if (response.data?.status === 'healthy') {
        setBackendStatus('online')
        setError('')
        return true
      }
      setBackendStatus('offline')
      return false
    } catch (err) {
      try {
        const rootResponse = await api.get('/', { timeout: 5000 })
        if (rootResponse.data?.message) {
          setBackendStatus('online')
          setError('')
          return true
        }
      } catch {
        // Fallback check
      }
      setBackendStatus('offline')
      return false
    }
  }

  useEffect(() => {
    checkBackendHealth()
    const interval = setInterval(async () => {
      if (backendStatus === 'offline') {
        await checkBackendHealth()
      }
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  const selectRole = (email, pass) => {
    setForm({ email, password: pass })
    setError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true); setError('')

    if (backendStatus === 'offline') {
      const isOnline = await checkBackendHealth()
      if (!isOnline) {
        setError('Backend server is unreachable on port 8000. Please start uvicorn main:app')
        setLoading(false)
        return
      }
    }

    try {
      const { data } = await api.post('/auth/login', form)
      setAuth(data.user, data.access_token)
      navigate('/app/command')
    } catch (err) {
      if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
        setError('Connection timeout. Backend server may still be initializing.')
        setBackendStatus('offline')
      } else if (err.code === 'ERR_NETWORK' || !err.response) {
        setError('Cannot reach backend on port 8000. Please verify the server is running.')
        setBackendStatus('offline')
      } else if (err.response?.status === 401) {
        setError('Invalid credentials. Please verify your email and password.')
      } else if (err.response?.status === 403) {
        setError('Clearance profile disabled. Contact security officer.')
      } else {
        setError(err.response?.data?.detail || 'Authentication failed. Please try again.')
      }
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen bg-black flex flex-col items-center justify-center p-4 selection:bg-white selection:text-black relative overflow-hidden font-sans">
      {/* Subtle Mesh Background Glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[650px] h-[400px] mesh-gradient-hero pointer-events-none -z-10" />

      {/* Back to Home Navigation */}
      <button 
        onClick={() => navigate('/')} 
        className="absolute top-6 left-6 text-xs font-mono text-mute hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer py-1.5 px-3 rounded-md hover:bg-[#0a0a0a] border border-transparent hover:border-[#262626]"
      >
        <ArrowLeft size={14} /> Back to Overview
      </button>

      <div className="relative w-full max-w-md my-8">
        <div className="card-marketing-large p-7 sm:p-8 shadow-2xl bg-[#0a0a0a] border border-[#262626]">
          {/* Brand Mark */}
          <div className="flex justify-center mb-4">
            <div className="w-12 h-12 rounded-lg bg-white flex items-center justify-center shadow-sm">
              <Shield size={22} className="text-black font-black" />
            </div>
          </div>

          <h1 className="text-xl font-semibold text-center text-white mb-1 tracking-tight">SOC Authentication</h1>
          <p className="text-xs text-mute text-center font-mono mb-6">Zero-Trust Clinical Defense Console</p>

          {/* Backend Status Indicator */}
          <div className={`mb-4 flex items-center justify-center gap-2 py-1.5 px-3 rounded-md border text-[11px] font-mono uppercase tracking-wide transition-all ${
            backendStatus === 'online' 
              ? 'bg-teal-950/70 border-teal-800/80 text-teal-300'
              : backendStatus === 'offline'
              ? 'bg-red-950/70 border-red-800/80 text-red-300'
              : 'bg-yellow-950/70 border-yellow-800/80 text-yellow-300'
          }`}>
            <span className={`w-2 h-2 rounded-full ${backendStatus === 'online' ? 'bg-cyan pulse-dot' : backendStatus === 'offline' ? 'bg-error' : 'bg-warning'}`} />
            <span>{backendStatus === 'online' ? 'BACKEND ONLINE' : backendStatus === 'offline' ? 'BACKEND OFFLINE' : 'CHECKING...'}</span>
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

          {/* Quick Demo Credentials Picker */}
          <div className="mb-6 bg-[#141414] p-2.5 rounded-lg border border-[#262626]">
            <div className="text-[10px] font-mono uppercase tracking-wider text-mute mb-2 flex items-center gap-1.5">
              <Zap size={11} className="text-white" /> Select Role Clearance:
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              {quickRoles.map((r) => (
                <button
                  key={r.label}
                  type="button"
                  onClick={() => selectRole(r.email, r.pass)}
                  className={`py-1.5 px-2 rounded-md text-left text-[11px] font-mono transition-all cursor-pointer border ${
                    form.email === r.email
                      ? 'bg-black border-white text-white font-semibold shadow-sm'
                      : 'bg-black border-[#262626] text-mute hover:text-white hover:border-[#404040]'
                  }`}
                >
                  <div className="truncate">{r.label}</div>
                  <div className="text-[9px] text-mute truncate">{r.role}</div>
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-[11px] font-mono text-body uppercase tracking-wide mb-1.5 block">
                Healthcare Identifier / Email
              </label>
              <div className="relative">
                <Fingerprint size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" />
                <input
                  type="email"
                  required
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="admin@icds-h.com"
                  className="w-full form-input pl-9 text-xs"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] font-mono text-body uppercase tracking-wide mb-1.5 block">
                Security Passcode
              </label>
              <div className="relative">
                <Key size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" />
                <input
                  type={showPassword ? "text" : "password"}
                  required
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
                <><Lock size={14} /> Authenticate &amp; Enter SOC</>
              )}
            </button>
          </form>

          {/* Security Status Box */}
          <div className="mt-6 border-t border-[#262626] pt-4 flex items-center justify-between text-[11px] font-mono text-mute">
            <span className="flex items-center gap-1.5 text-body">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
              <span>TLS 1.3 · AES-256</span>
            </span>
            <span>HIPAA §164.312 Compliant</span>
          </div>
        </div>

        <p className="text-center text-[11px] text-mute font-mono mt-4">
          AUTHORIZED CLINICAL &amp; SECURITY PERSONNEL ONLY · ALL LOGINS AUDITED
        </p>
      </div>
    </div>
  )
}
