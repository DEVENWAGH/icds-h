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

  // ── Backend Health Check ─────────────────────────────────────────────────
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
      // Try the root endpoint as fallback
      try {
        const rootResponse = await api.get('/', { timeout: 5000 })
        if (rootResponse.data?.message) {
          setBackendStatus('online')
          setError('')
          return true
        }
      } catch {
        // Both failed
      }
      setBackendStatus('offline')
      return false
    }
  }

  useEffect(() => {
    checkBackendHealth()
    // Periodically check if backend comes online
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

    // Pre-check backend availability
    if (backendStatus === 'offline') {
      const isOnline = await checkBackendHealth()
      if (!isOnline) {
        setError('Backend server is not running. Please start it with: uvicorn main:app --reload')
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
        setError('Connection timeout. Backend server may be starting up. Please retry.')
        setBackendStatus('offline')
      } else if (err.code === 'ERR_NETWORK' || !err.response) {
        setError('Cannot connect to backend server. Please ensure it is running on port 8000.')
        setBackendStatus('offline')
      } else if (err.response?.status === 401) {
        setError('Invalid credentials. Please check your email and password.')
      } else if (err.response?.status === 403) {
        setError('Account is disabled. Contact your administrator.')
      } else if (err.response?.status >= 500) {
        setError('Server error. The backend encountered an internal issue.')
      } else {
        setError(err.response?.data?.detail || 'Authentication failed. Please try again.')
      }
    } finally { setLoading(false) }
  }

  const statusColor = backendStatus === 'online' ? 'emerald' : backendStatus === 'offline' ? 'rose' : 'amber'
  const statusText = backendStatus === 'online' ? 'BACKEND ONLINE' : backendStatus === 'offline' ? 'BACKEND OFFLINE' : 'CHECKING...'
  const StatusIcon = backendStatus === 'online' ? Wifi : backendStatus === 'offline' ? WifiOff : RefreshCw

  return (
    <div className="min-h-screen bg-cyber-bg grid-bg flex flex-col items-center justify-center p-4 selection:bg-cyan-500/30 selection:text-cyan-200 relative overflow-hidden">
      {/* Background Ambience */}
      <div className="fixed top-1/4 left-1/2 -translate-x-1/2 w-[550px] h-[550px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="fixed bottom-10 -right-20 w-[400px] h-[400px] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none" />

      {/* Back to Home link */}
      <button 
        onClick={() => navigate('/')} 
        className="absolute top-6 left-6 text-xs font-mono text-slate-400 hover:text-cyber-cyan flex items-center gap-1.5 transition-colors cursor-pointer py-1.5 px-3 rounded-lg hover:bg-white/5 border border-transparent hover:border-cyan-500/20"
      >
        <ArrowLeft size={14} /> Back to Homepage
      </button>

      <div className="relative w-full max-w-md my-8">
        <div className="relative cyber-card p-7 sm:p-8 border-cyan-500/30 shadow-2xl">
          {/* Top Shield Emblem */}
          <div className="flex justify-center mb-5">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-400 via-sky-500 to-blue-600 flex items-center justify-center shadow-[0_0_25px_rgba(0,229,255,0.45)] border border-cyan-300/40">
              <Shield size={32} className="text-slate-950 font-black" />
            </div>
          </div>

          <h1 className="text-xl sm:text-2xl font-black text-center text-white mb-1 tracking-tight">SOC Clearance Authentication</h1>
          <p className="text-xs text-slate-400 text-center font-mono mb-6">Encrypted Zero-Trust Portal for Digital Health Operations</p>

          {/* Backend Status Indicator */}
          <div className={`mb-4 flex items-center justify-center gap-2 py-1.5 px-3 rounded-lg border text-[10px] font-mono uppercase tracking-widest transition-all ${
            backendStatus === 'online' 
              ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400'
              : backendStatus === 'offline'
              ? 'bg-rose-950/40 border-rose-500/30 text-rose-400'
              : 'bg-amber-950/40 border-amber-500/30 text-amber-400'
          }`}>
            <StatusIcon size={12} className={backendStatus === 'checking' ? 'animate-spin' : ''} />
            <span>{statusText}</span>
            {backendStatus === 'offline' && (
              <button
                type="button"
                onClick={checkBackendHealth}
                className="ml-2 text-rose-300 hover:text-cyan-400 transition-colors cursor-pointer"
                title="Retry connection"
              >
                <RefreshCw size={11} />
              </button>
            )}
          </div>

          {/* Quick Demo Credentials Picker */}
          <div className="mb-6 bg-black/40 p-2.5 rounded-xl border border-cyan-500/20">
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-1.5">
              <Zap size={11} className="text-cyber-cyan" /> Select Quick Clearance Profile:
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              {quickRoles.map((r) => (
                <button
                  key={r.label}
                  type="button"
                  onClick={() => selectRole(r.email, r.pass)}
                  className={`py-1.5 px-2 rounded-lg text-left text-[10px] font-mono transition-all cursor-pointer border ${
                    form.email === r.email
                      ? 'bg-cyan-500/20 border-cyan-400 text-cyber-cyan font-bold shadow-[0_0_8px_rgba(0,229,255,0.2)]'
                      : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                  }`}
                >
                  <div className="truncate font-semibold">{r.label}</div>
                  <div className="text-[9px] text-slate-500 truncate">{r.role}</div>
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-[11px] font-mono text-slate-300 uppercase tracking-wider mb-1.5 block">
                Research Identifier / Email
              </label>
              <div className="relative">
                <Fingerprint size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400" />
                <input
                  type="email"
                  required
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="admin@icds-h.com"
                  className="w-full bg-slate-950/80 border border-cyan-500/25 rounded-xl pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-600 font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/50 transition-all"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] font-mono text-slate-300 uppercase tracking-wider mb-1.5 block">
                Security Passcode / Biometric Key
              </label>
              <div className="relative">
                <Key size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400" />
                <input
                  type={showPassword ? "text" : "password"}
                  required
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="••••••••••••"
                  className="w-full bg-slate-950/80 border border-cyan-500/25 rounded-xl pl-10 pr-10 py-2.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/50 transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-cyan-400 transition-colors p-1 cursor-pointer"
                  aria-label="Toggle password visibility"
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 text-rose-300 text-xs font-mono bg-rose-950/60 border border-rose-500/50 rounded-xl px-3 py-2.5 shadow-[0_0_10px_rgba(255,45,85,0.2)]">
                <AlertCircle size={15} className="text-rose-400 flex-shrink-0 mt-0.5" /> 
                <span>{error}</span>
              </div>
            )}

            <button 
              type="submit" 
              disabled={loading}
              className="w-full py-3 rounded-xl font-mono font-bold text-slate-950 text-xs flex items-center justify-center gap-2 transition-all cursor-pointer shadow-lg hover:brightness-110 active:scale-[0.99]"
              style={{ background: 'linear-gradient(135deg, #00e5ff, #0284c7)' }}
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-slate-950/30 border-t-slate-950 rounded-full animate-spin" />
              ) : (
                <><Lock size={15} /> Authenticate & Access SOC</>
              )}
            </button>
          </form>

          {/* Security Status Box */}
          <div className="mt-6 border-t border-cyan-500/20 pt-4">
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className={`flex items-center gap-1.5 text-${statusColor}-400`}>
                <span className={`w-2 h-2 rounded-full bg-${statusColor}-400 pulse-dot shadow-[0_0_8px_${statusColor === 'emerald' ? '#10b981' : statusColor === 'rose' ? '#f43f5e' : '#f59e0b'}]`} />
                <span className="font-bold">SYSTEM INTEGRITY: {backendStatus === 'online' ? '100%' : 'DEGRADED'}</span>
              </span>
              <span className="text-slate-400">TLS 1.3 / AES-256</span>
            </div>
          </div>
        </div>

        <p className="text-center text-[10px] text-slate-500 font-mono mt-4">
          AUTHORIZED CLINICAL & SECURITY PERSONNEL ONLY · ACTIVITY AUDITED UNDER HIPAA §164.312
        </p>
      </div>
    </div>
  )
}

