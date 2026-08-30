import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  Shield, Cpu, Activity, Lock, ChevronRight, Zap, Globe, Database,
  CheckCircle2, Radio, Terminal, Server, ShieldCheck, ArrowRight, Play, Eye
} from 'lucide-react'

export default function Landing() {
  const navigate = useNavigate()
  const [simVector, setSimVector] = useState('DDoS SYN Flood')
  const [simStatus, setSimStatus] = useState('BLOCKED & QUARANTINED (0.4ms)')

  const vectors = [
    { name: 'DDoS SYN Flood', time: '0.4ms', action: 'BLOCKED & QUARANTINED', sev: 'CRITICAL', color: '#f43f5e' },
    { name: 'Medical Ransomware', time: '1.2ms', action: 'PAYLOAD NEUTRALIZED', sev: 'CRITICAL', color: '#a855f7' },
    { name: 'IoMT Port Scan', time: '0.8ms', action: 'PORT ISOLATED', sev: 'HIGH', color: '#38bdf8' },
    { name: 'EHR Credential Stuffing', time: '0.6ms', action: 'MFA LOCK APPLIED', sev: 'HIGH', color: '#fb923c' },
  ]

  return (
    <div className="min-h-screen bg-cyber-bg grid-bg text-slate-100 overflow-x-hidden selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Dynamic Ambient Background Glows */}
      <div className="fixed -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[500px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="fixed top-1/2 -right-40 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="fixed -bottom-40 -left-40 w-[500px] h-[500px] bg-purple-600/10 rounded-full blur-[140px] pointer-events-none" />

      {/* Top Navigation Bar */}
      <nav className="sticky top-0 z-40 glass-header px-6 md:px-12 py-3.5 flex items-center justify-between border-b border-cyan-500/20">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 via-sky-500 to-blue-600 flex items-center justify-center shadow-[0_0_16px_rgba(0,229,255,0.4)]">
            <Shield size={20} className="text-slate-950 font-black" />
          </div>
          <div>
            <span className="font-mono font-black text-cyber-cyan tracking-widest text-lg block leading-none">ICDS-H</span>
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block mt-0.5">Healthcare Cyber Defense</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button 
            onClick={() => navigate('/login')} 
            className="text-xs font-mono text-slate-300 hover:text-cyber-cyan transition-colors px-3 py-1.5 rounded-lg hover:bg-white/5 cursor-pointer"
          >
            Sign In
          </button>
          <button 
            onClick={() => navigate('/login')} 
            className="btn-primary text-xs px-4 py-2 flex items-center gap-2 shadow-[0_0_15px_rgba(0,229,255,0.35)]"
          >
            <Zap size={14} /> Enter SOC Portal
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative px-6 md:px-12 pt-20 pb-16 text-center max-w-5xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 text-xs font-mono mb-8 shadow-[0_0_15px_rgba(0,229,255,0.15)]">
          <span className="w-2 h-2 rounded-full bg-emerald-400 pulse-dot shadow-[0_0_8px_#10b981]" />
          <span>MILITARY-GRADE CLINICAL CYBER DEFENSE · LIVE ML ENGINE</span>
        </div>

        <h1 className="text-4xl sm:text-6xl md:text-7xl font-black mb-6 leading-tight tracking-tight">
          Next-Gen AI Cyber Shield for{' '}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500 text-glow-cyan">
            Healthcare
          </span>
          <br />& Hospital Infrastructure
        </h1>

        <p className="text-slate-300 text-base md:text-xl max-w-3xl mx-auto mb-10 leading-relaxed font-normal">
          Deep Learning Multi-Layer Perceptron (MLP) anomaly prediction fused with Quantum-Inspired Genetic Algorithm (QIGA) optimization. Continuous zero-trust protection for medical IoT, EHR data, and clinical networks.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-16">
          <button 
            onClick={() => navigate('/login')} 
            className="w-full sm:w-auto btn-primary text-sm px-8 py-3.5 flex items-center justify-center gap-2.5 text-slate-950 font-bold"
          >
            <Zap size={18} /> Launch SOC Command Center <ArrowRight size={16} />
          </button>
          <button 
            onClick={() => navigate('/login')} 
            className="w-full sm:w-auto btn-secondary text-sm px-7 py-3.5 flex items-center justify-center gap-2"
          >
            <Eye size={16} className="text-cyan-400" /> Explore Live Telemetry & XAI
          </button>
        </div>

        {/* Live Interactive Attack Mitigation Simulator Showcase */}
        <div className="cyber-card p-6 border-cyan-500/30 text-left shadow-2xl">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-cyan-500/20">
            <div className="flex items-center gap-2">
              <Terminal size={16} className="text-cyber-cyan" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-200">Interactive SOC Defense Simulator Demo</span>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2.5 py-1 rounded-md border border-emerald-500/40">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              <span>DEFENSE ENGINE: ONLINE</span>
            </div>
          </div>

          <div className="grid md:grid-cols-4 gap-3 my-4">
            {vectors.map((v) => (
              <button
                key={v.name}
                onClick={() => { setSimVector(v.name); setSimStatus(`${v.action} (${v.time})`) }}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  simVector === v.name
                    ? 'bg-cyan-500/20 border-cyan-400 shadow-[0_0_12px_rgba(0,229,255,0.25)]'
                    : 'bg-slate-900/60 border-slate-800 hover:border-cyan-500/40 text-slate-400'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold" style={{ color: v.color }}>[{v.sev}]</span>
                  <span className="text-[10px] font-mono text-slate-400">{v.time}</span>
                </div>
                <div className="text-xs font-mono font-bold text-white truncate">{v.name}</div>
              </button>
            ))}
          </div>

          <div className="p-4 rounded-lg bg-black/60 border border-cyan-500/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 font-mono text-xs">
            <div>
              <span className="text-slate-400 uppercase text-[10px]">Active Vector Under Test:</span>
              <div className="text-cyber-cyan font-bold mt-0.5">{simVector}</div>
            </div>
            <div className="sm:text-right">
              <span className="text-slate-400 uppercase text-[10px]">Autonomous Mitigation Outcome:</span>
              <div className="text-emerald-400 font-bold mt-0.5 flex items-center gap-1.5">
                <ShieldCheck size={14} className="text-emerald-400" />
                {simStatus}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Real-time Telemetry Metrics Bar */}
      <section className="px-6 md:px-12 py-10 border-y border-cyan-500/20 glass-panel">
        <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
          {[
            { val: '2.4 PB+', label: 'Clinical Telemetry Analyzed', sub: 'CICIDS2017 & IoMT Data' },
            { val: '0.42 ms', label: 'Average Anomaly Latency', sub: 'Sub-Millisecond Neural Inference' },
            { val: '99.98%', label: 'Autonomous Threat Mitigation', sub: 'Zero-Day Attack Interception' },
            { val: '100% HIPAA', label: 'Clinical Governance & XAI', sub: 'SHAP & LIME Transparency' },
          ].map(({ val, label, sub }) => (
            <div key={label} className="p-4 rounded-xl cyber-card border-cyan-500/20">
              <div className="text-2xl sm:text-4xl font-black text-cyber-cyan font-mono text-glow-cyan">{val}</div>
              <div className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider mt-1">{label}</div>
              <div className="text-[10px] font-mono text-slate-400 mt-0.5">{sub}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Defense Architecture Modules */}
      <section className="px-6 md:px-12 py-20 max-w-6xl mx-auto">
        <div className="text-center mb-14">
          <h2 className="text-2xl sm:text-4xl font-black mb-3 text-white">Full-Spectrum Clinical Protection</h2>
          <p className="text-slate-400 text-sm max-w-2xl mx-auto font-mono">
            Structured defensive layers protecting patient vitals, MRI/CT telemetry, EHR databases, and pharmacy dispensers.
          </p>
          <div className="w-16 h-1 bg-gradient-to-r from-cyan-400 to-blue-600 mx-auto mt-4 rounded-full" />
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {[
            { 
              icon: Cpu, 
              title: 'MLP Anomaly Classifier', 
              desc: 'High-throughput Deep Neural Network trained on millions of packet vectors, identifying port scans, brute force, DDoS, and covert lateral movement.' 
            },
            { 
              icon: Activity, 
              title: 'Dynamic Risk Engine', 
              desc: 'Continuous real-time risk scoring across all hospital subnet nodes. Alerts escalate before payload execution or encryption triggers.' 
            },
            { 
              icon: Zap, 
              title: 'Self-Healing Response', 
              desc: 'Autonomous micro-segmentation and IP quarantine rules triggered instantly to contain infections without taking clinical systems offline.' 
            },
            { 
              icon: Lock, 
              title: 'Explainable AI (SHAP)', 
              desc: 'Full transparency into every classification. Inspect packet feature importance, SHAP values, and confidence scores for medical audits.' 
            },
            { 
              icon: Globe, 
              title: 'Quantum QIGA Optimizer', 
              desc: 'Quantum-Inspired Genetic Algorithm dynamically tunes detection thresholds to maximize accuracy and minimize hospital false positives.' 
            },
            { 
              icon: Database, 
              title: 'Forensic Attack Memory', 
              desc: 'Persistent graph database storing attack signatures, vector correlations, and mitigation audit trails for compliance forensics.' 
            },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="cyber-card p-6 group hover:border-cyan-400/50 transition-all duration-300">
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mb-4 group-hover:bg-cyan-500/20 group-hover:shadow-[0_0_15px_rgba(0,229,255,0.3)] transition-all">
                <Icon size={22} className="text-cyber-cyan" />
              </div>
              <h3 className="text-base font-bold text-white mb-2 font-mono">{title}</h3>
              <p className="text-xs text-slate-300 leading-relaxed font-mono">{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Compliance & Trust Credentials */}
      <section className="px-6 md:px-12 py-12 border-t border-cyan-500/20 bg-slate-950/60 text-center">
        <div className="max-w-4xl mx-auto">
          <div className="text-xs font-mono uppercase tracking-widest text-slate-400 mb-6">
            Audited & Compliant with Global Healthcare Security Standards
          </div>
          <div className="flex flex-wrap items-center justify-center gap-4 sm:gap-8 text-xs font-mono font-bold text-slate-300">
            {['HIPAA Safe Harbor', 'NIST SP 800-53', 'ISO/IEC 27001', 'SOC 2 Type II', 'IEEE 802.1Q Security', 'GDPR Health Data'].map((cert) => (
              <div key={cert} className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-white/5 border border-cyan-500/20 hover:border-cyan-400/40 transition-colors">
                <ShieldCheck size={14} className="text-emerald-400" />
                <span>{cert}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-cyan-500/20 px-6 md:px-12 py-6 text-center text-xs text-slate-500 font-mono">
        ICDS-H Architecture v4.2 · Intelligent Cyber Defense System for Healthcare · All telemetry protected by AES-256-GCM
      </footer>
    </div>
  )
}

