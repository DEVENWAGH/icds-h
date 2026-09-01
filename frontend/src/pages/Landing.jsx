import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  Shield, Cpu, Activity, Lock, ChevronRight, Zap, Globe, Database,
  CheckCircle2, Radio, Terminal, Server, ShieldCheck, ArrowRight, Eye, Sparkles, Layers, FileCode
} from 'lucide-react'

export default function Landing() {
  const navigate = useNavigate()
  const [simVector, setSimVector] = useState('DDoS SYN Flood')
  const [simStatus, setSimStatus] = useState('BLOCKED & QUARANTINED (0.4ms)')

  const vectors = [
    { name: 'DDoS SYN Flood', time: '0.4ms', action: 'BLOCKED & QUARANTINED', sev: 'CRITICAL', color: '#f87171' },
    { name: 'Medical Ransomware', time: '1.2ms', action: 'PAYLOAD NEUTRALIZED', sev: 'CRITICAL', color: '#a855f7' },
    { name: 'IoMT Port Scan', time: '0.8ms', action: 'PORT ISOLATED', sev: 'HIGH', color: '#38bdf8' },
    { name: 'EHR Credential Stuffing', time: '0.6ms', action: 'MFA LOCK APPLIED', sev: 'HIGH', color: '#fbbf24' },
  ]

  return (
    <div className="min-h-screen bg-black text-ink selection:bg-white selection:text-black font-sans antialiased overflow-x-hidden">
      {/* Top Sticky Navigation Bar */}
      <nav className="sticky top-0 z-40 bg-black/80 backdrop-blur-md px-6 md:px-12 h-16 flex items-center justify-between border-b border-[#262626]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-white flex items-center justify-center shadow-sm">
            <Shield size={16} className="text-black font-black" />
          </div>
          <div>
            <span className="font-sans font-semibold text-white text-sm tracking-tight block leading-tight">ICDS-H</span>
            <span className="text-[10px] font-mono text-mute uppercase tracking-wider block">Autonomous Healthcare Defense</span>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button 
            onClick={() => navigate('/login')} 
            className="nav-cta-login cursor-pointer"
          >
            Log In
          </button>
          <button 
            onClick={() => navigate('/login')} 
            className="nav-cta-signup cursor-pointer"
          >
            Sign In to SOC
          </button>
        </div>
      </nav>

      {/* Hero Section with Signature Multi-Stop Mesh Gradient Backdrop */}
      <section className="relative px-6 md:px-12 pt-24 pb-20 max-w-5xl mx-auto text-center overflow-hidden">
        {/* Multi-Color Atmospheric Mesh Gradient Backdrop */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[850px] h-[520px] mesh-gradient-hero pointer-events-none -z-10" />

        {/* Announcement Banner */}
        <div className="inline-flex items-center gap-2 banner-marketing mb-8 cursor-pointer hover:border-hairline-strong transition-all">
          <span className="w-2 h-2 rounded-full bg-cyan pulse-dot" />
          <span className="text-xs font-medium text-white">Introducing Deep Neural Anomaly Defense 4.0</span>
          <ChevronRight size={13} className="text-mute" />
        </div>

        {/* Hero Display Headline (Sentence case, tight negative letter spacing, period-terminated) */}
        <h1 className="text-4xl sm:text-6xl md:text-7xl font-semibold tracking-tight-xl text-white mb-6 leading-[1.08]">
          Build and deploy clinical cyber defense.
        </h1>

        {/* Lead Paragraph */}
        <p className="text-body text-base md:text-xl max-w-2xl mx-auto mb-10 leading-relaxed font-normal">
          A high-throughput Multi-Layer Perceptron fused with Quantum-Inspired Genetic Algorithm (QIGA) optimization. Zero-trust protection for medical IoT, EHR registries, and hospital subnets.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-3 justify-center items-center mb-16">
          <button 
            onClick={() => navigate('/login')} 
            className="btn-primary-pill shadow-elevation-2 cursor-pointer w-full sm:w-auto"
          >
            <Zap size={16} /> Launch SOC Command <ArrowRight size={15} />
          </button>
          <button 
            onClick={() => navigate('/login')} 
            className="btn-secondary-pill shadow-elevation-2 cursor-pointer w-full sm:w-auto"
          >
            <Eye size={15} className="text-mute" /> View Live Telemetry &amp; XAI
          </button>
        </div>

        {/* Interactive SOC Defense Simulator Preview Card */}
        <div className="card-marketing-large p-6 text-left shadow-2xl">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-[#262626]">
            <div className="flex items-center gap-2">
              <Terminal size={15} className="text-white" />
              <span className="font-mono text-xs font-semibold text-white uppercase tracking-wider">Autonomous SOC Defense Engine</span>
            </div>
            <div className="badge-secondary text-[11px] font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
              <span>DEFENSE ENGINE: ACTIVE</span>
            </div>
          </div>

          <div className="grid md:grid-cols-4 gap-2.5 my-4">
            {vectors.map((v) => (
              <button
                key={v.name}
                onClick={() => { setSimVector(v.name); setSimStatus(`${v.action} (${v.time})`) }}
                className={`p-3 rounded-md border text-left transition-all cursor-pointer ${
                  simVector === v.name
                    ? 'bg-[#141414] border-white shadow-sm'
                    : 'bg-[#0a0a0a] border-[#262626] hover:border-[#404040] text-body'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-semibold" style={{ color: v.color }}>[{v.sev}]</span>
                  <span className="text-[10px] font-mono text-mute">{v.time}</span>
                </div>
                <div className="text-xs font-medium text-white truncate">{v.name}</div>
              </button>
            ))}
          </div>

          {/* Code Editor Mockup Surface */}
          <div className="code-editor-mockup p-4 font-mono text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-[#050505]">
            <div>
              <span className="text-gray-400 uppercase text-[10px] block">Active Threat Vector:</span>
              <div className="text-white font-semibold mt-0.5">{simVector}</div>
            </div>
            <div className="sm:text-right">
              <span className="text-gray-400 uppercase text-[10px] block">Mitigation Outcome:</span>
              <div className="text-cyan font-semibold mt-0.5 flex items-center gap-1.5">
                <ShieldCheck size={14} className="text-cyan" />
                {simStatus}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Customer / Compliance Logo Strip */}
      <section className="border-y border-[#262626] bg-[#0a0a0a] py-8 px-6 md:px-12 text-center">
        <div className="max-w-5xl mx-auto">
          <p className="text-xs font-mono uppercase tracking-widest text-mute mb-5">
            Trusted &amp; Audited Across Enterprise Healthcare Standards
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4 sm:gap-8 text-xs font-mono font-medium text-body">
            {['HIPAA Safe Harbor', 'NIST SP 800-53', 'ISO/IEC 27001', 'SOC 2 Type II', 'IEEE 802.1Q Security', 'GDPR Health Data'].map((cert) => (
              <div key={cert} className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#141414] border border-[#262626]">
                <ShieldCheck size={13} className="text-cyan" />
                <span>{cert}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Real-time Telemetry Metrics Bar */}
      <section className="px-6 md:px-12 py-16 max-w-6xl mx-auto">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
          {[
            { val: '2.4 PB+', label: 'Clinical Telemetry Analyzed', sub: 'CICIDS2017 & IoMT Data' },
            { val: '0.42 ms', label: 'Inference Latency', sub: 'Sub-millisecond Neural Flow' },
            { val: '99.98%', label: 'Threat Interception Rate', sub: 'Zero-day Anomaly Defense' },
            { val: '100% HIPAA', label: 'Clinical Compliance', sub: 'SHAP & LIME Transparency' },
          ].map(({ val, label, sub }) => (
            <div key={label} className="p-5 rounded-lg card-marketing text-left">
              <div className="text-2xl sm:text-3xl font-semibold font-mono text-white tracking-tight">{val}</div>
              <div className="text-xs font-medium text-white mt-1.5">{label}</div>
              <div className="text-[11px] font-mono text-mute mt-0.5">{sub}</div>
            </div>
          ))}
        </div>
      </section>

      {/* 3-Up Feature Grid Band */}
      <section className="px-6 md:px-12 py-20 max-w-6xl mx-auto">
        <div className="text-center mb-14">
          <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight-lg text-white mb-3">Full-spectrum clinical protection.</h2>
          <p className="text-body text-sm max-w-xl mx-auto font-normal">
            Structured defensive layers protecting patient vitals, telemetry streams, EHR clusters, and pharmacy dispensers.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {[
            { 
              icon: Cpu, 
              title: 'MLP Anomaly Classifier', 
              desc: 'High-throughput Deep Neural Network trained on millions of packet vectors, classifying port scans, brute force, DDoS, and lateral intrusion.' 
            },
            { 
              icon: Activity, 
              title: 'Dynamic Risk Engine', 
              desc: 'Continuous real-time risk scoring across all hospital subnet nodes. Threat rules isolate bad actors before payload encryption.' 
            },
            { 
              icon: Zap, 
              title: 'Autonomous Mitigation', 
              desc: 'Micro-segmentation and IP quarantine rules triggered instantly to contain infections without disconnecting clinical apparatus.' 
            },
            { 
              icon: Lock, 
              title: 'Explainable AI (SHAP)', 
              desc: 'Full transparency into every classification. Inspect packet feature importance, SHAP values, and confidence scores for compliance audits.' 
            },
            { 
              icon: Globe, 
              title: 'Quantum QIGA Optimizer', 
              desc: 'Quantum-Inspired Genetic Algorithm dynamically tunes detection thresholds to maximize accuracy and minimize false alarms.' 
            },
            { 
              icon: Database, 
              title: 'Forensic Attack Memory', 
              desc: 'Persistent graph database storing attack signatures, vector correlations, and mitigation audit trails for forensic accountability.' 
            },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="card-marketing p-6 group hover:border-[#404040] transition-all duration-200">
              <div className="w-10 h-10 rounded-md bg-[#141414] border border-[#262626] flex items-center justify-center mb-4 text-white">
                <Icon size={18} />
              </div>
              <h3 className="text-sm font-semibold text-white mb-2">{title}</h3>
              <p className="text-xs text-body leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Dark Showcase Band */}
      <section className="bg-[#050505] border-y border-[#262626] py-20 px-6 md:px-12">
        <div className="max-w-5xl mx-auto grid md:grid-cols-2 gap-10 items-center">
          <div>
            <span className="text-xs font-mono text-cyan uppercase tracking-wider block mb-2">Neural Telemetry Engine</span>
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight-lg text-white mb-4">
              Engineered for zero hospital downtime.
            </h2>
            <p className="text-body text-sm leading-relaxed mb-6">
              When a threat strikes an infusion pump or DICOM PACS server, ICDS-H executes targeted network micro-isolation in sub-milliseconds without dropping live vital sign telemetry.
            </p>
            <button 
              onClick={() => navigate('/login')} 
              className="btn-primary-pill cursor-pointer"
            >
              Explore SOC Portal <ArrowRight size={14} />
            </button>
          </div>

          <div className="bg-black rounded-lg p-5 border border-[#262626] font-mono text-xs text-gray-300 shadow-2xl">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#262626] text-[11px] text-gray-500">
              <span>soc-mitigation-stream.log</span>
              <span className="text-cyan">LIVE</span>
            </div>
            <div className="space-y-1.5 font-mono text-[11px]">
              <p><span className="text-cyan">[00:00:00.120]</span> INGRESS: 192.168.4.120 -&gt; Port 443 (EHR Database)</p>
              <p><span className="text-amber-400">[00:00:00.240]</span> MLP CLASSIFIER: SYN_Flood detected (Confidence: 99.8%)</p>
              <p><span className="text-green-400">[00:00:00.380]</span> ORCHESTRATION: Subnet isolation rule generated</p>
              <p><span className="text-white font-semibold">[00:00:00.420]</span> STATUS: THREAT NEUTRALIZED · PATIENT MONITORS ONLINE</p>
            </div>
          </div>
        </div>
      </section>

      {/* 4-Column Vercel-Style Footer */}
      <footer className="border-t border-[#262626] bg-[#0a0a0a] px-6 md:px-12 py-16 text-xs text-body font-sans">
        <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
          <div>
            <div className="font-mono text-xs font-semibold text-white uppercase tracking-wider mb-3">Platform</div>
            <ul className="space-y-2 text-mute">
              <li><button onClick={() => navigate('/login')} className="hover:text-white transition-colors cursor-pointer">SOC Command</button></li>
              <li><button onClick={() => navigate('/login')} className="hover:text-white transition-colors cursor-pointer">MLP Engine</button></li>
              <li><button onClick={() => navigate('/login')} className="hover:text-white transition-colors cursor-pointer">QIGA Optimizer</button></li>
              <li><button onClick={() => navigate('/login')} className="hover:text-white transition-colors cursor-pointer">Forensic Memory</button></li>
            </ul>
          </div>

          <div>
            <div className="font-mono text-xs font-semibold text-white uppercase tracking-wider mb-3">Compliance</div>
            <ul className="space-y-2 text-mute">
              <li>HIPAA §164.312</li>
              <li>NIST SP 800-53</li>
              <li>ISO/IEC 27001</li>
              <li>Explainable AI (SHAP)</li>
            </ul>
          </div>

          <div>
            <div className="font-mono text-xs font-semibold text-white uppercase tracking-wider mb-3">Telemetry</div>
            <ul className="space-y-2 text-mute">
              <li>CICIDS2017 Dataset</li>
              <li>IoMT Infusion Pumps</li>
              <li>PACS / DICOM Streams</li>
              <li>Bedside Vital Monitors</li>
            </ul>
          </div>

          <div>
            <div className="font-mono text-xs font-semibold text-white uppercase tracking-wider mb-3">Defense Node</div>
            <p className="text-mute leading-relaxed">
              ICDS-H Architecture v4.2 · Intelligent Cyber Defense System for Healthcare.
            </p>
          </div>
        </div>

        <div className="max-w-6xl mx-auto pt-6 border-t border-[#262626] flex flex-col sm:flex-row items-center justify-between text-mute text-[11px] font-mono">
          <span>© 2026 ICDS-H Cyber Defense Inc. All rights reserved.</span>
          <span>AES-256-GCM Encrypted · Zero-Trust Architecture</span>
        </div>
      </footer>
    </div>
  )
}
