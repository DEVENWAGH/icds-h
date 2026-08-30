import React, { useState } from 'react'
import { Outlet, NavLink, useNavigate, Navigate } from 'react-router-dom'
import { useAuthStore, useAlertStore } from '../store'
import { useWebSocket } from '../hooks/useWebSocket'
import {
  Shield, Activity, BarChart3, Bell, FileText,
  Eye, Brain, Zap, Settings, LogOut, Menu, ChevronRight, User, AlertOctagon, Cpu, Database,
  Radio, Terminal, ShieldAlert
} from 'lucide-react'

// Role-based nav definitions with Command Center priority
const ALL_NAV = [
  { to: '/app/command',    icon: Terminal,      label: 'SOC Command HUD', roles: ['admin','analyst'] },
  { to: '/app/dashboard',  icon: Shield,        label: 'SOC Overview',    roles: ['admin','analyst'] },
  { to: '/app/monitoring', icon: Activity,      label: 'Node Telemetry',  roles: ['admin','analyst'] },
  { to: '/app/analytics',  icon: BarChart3,     label: 'Deep Analytics',  roles: ['admin','analyst'] },
  { to: '/app/alerts',     icon: Bell,          label: 'Threat Alerts',   roles: ['admin','analyst'] },
  { to: '/app/incidents',  icon: AlertOctagon,  label: 'Incidents & Mit', roles: ['admin','analyst'] },
  { to: '/app/logs',       icon: FileText,      label: 'Forensic Logs',   roles: ['admin','analyst'] },
  { to: '/app/xai',        icon: Brain,         label: 'Explainable AI',  roles: ['admin','analyst'] },
  { to: '/app/optimizer',  icon: Cpu,           label: 'QIGA Optimizer',  roles: ['admin','analyst'] },
  { to: '/app/response',   icon: Zap,           label: 'Orchestration',   roles: ['admin','analyst'] },
  { to: '/app/memory',     icon: Database,      label: 'Threat Memory',   roles: ['admin','analyst'] },
  { to: '/app/reports',    icon: Eye,           label: 'Compliance Rpt',  roles: ['admin','analyst'] },
  { to: '/app/admin',      icon: Settings,      label: 'Access & Config', roles: ['admin'] },
]

const SEV_COLOR = { CRITICAL: '#ff2d55', HIGH: '#ff9500', MEDIUM: '#ffd60a', LOW: '#00ff88' }

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false)
  const { user, logout } = useAuthStore()
  const { unreadCount, liveMetrics, liveThreats } = useAlertStore()
  const navigate = useNavigate()
  useWebSocket()

  const handleLogout = () => { logout(); navigate('/login') }

  // Must have user, PrivateRoute guarantees this but just in case
  const userRole = user?.role
  if (!userRole) return <Navigate to="/login" />

  // Filter nav items by current user role
  const navItems = ALL_NAV.filter(item => item.roles.includes(userRole))

  // Latest threat for sidebar pulse indicator
  const latestThreat = liveThreats[0]

  return (
    <div className="flex h-screen bg-cyber-bg overflow-hidden grid-bg select-none">
      {/* Sidebar */}
      <aside className={`${collapsed ? 'w-16' : 'w-64'} flex-shrink-0 glass-header border-r border-cyan-500/20 flex flex-col transition-all duration-300 z-30 shadow-2xl`}>
        {/* Brand Header */}
        <div className="flex items-center gap-3 p-4 border-b border-cyan-500/20 bg-slate-950/40">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 via-sky-500 to-blue-600 flex items-center justify-center flex-shrink-0 shadow-[0_0_15px_rgba(0,229,255,0.4)]">
            <Shield size={18} className="text-slate-950 font-black" />
          </div>
          {!collapsed && (
            <div className="flex-1 min-w-0">
              <span className="font-mono font-black text-cyber-cyan text-base tracking-widest block leading-tight">ICDS-H</span>
              <span className="text-[9px] font-mono text-slate-400 uppercase tracking-wider block">Cyber Defense SOC</span>
            </div>
          )}
          <button 
            onClick={() => setCollapsed(!collapsed)} 
            className="ml-auto text-slate-400 hover:text-cyber-cyan transition-colors p-1 rounded-md hover:bg-white/5 cursor-pointer"
            aria-label="Toggle Sidebar Navigation"
          >
            {collapsed ? <ChevronRight size={16} /> : <Menu size={16} />}
          </button>
        </div>

        {/* Live Health Status Bar */}
        {!collapsed && (
          <div className="px-4 py-2.5 border-b border-cyan-500/15 bg-slate-950/20 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 pulse-dot shadow-[0_0_8px_#10b981]" />
                <span className="text-slate-400 font-mono text-[11px]">SYS HEALTH</span>
              </span>
              <span className="text-emerald-400 font-mono font-bold text-[11px]">{liveMetrics.sys_health?.toFixed(1) ?? '98.5'}%</span>
            </div>
            {latestThreat ? (
              <div className="flex items-center justify-between text-xs pt-1 border-t border-white/5">
                <span className="flex items-center gap-1.5 min-w-0">
                  <span className="w-2 h-2 rounded-full pulse-dot flex-shrink-0" style={{ background: SEV_COLOR[latestThreat.severity] || '#888' }} />
                  <span className="font-mono text-[10px] text-slate-300 truncate">{latestThreat.attack_type}</span>
                </span>
                <span className="font-mono text-[9px] px-1.5 py-0.2 rounded uppercase font-bold" style={{ color: SEV_COLOR[latestThreat.severity], background: `${SEV_COLOR[latestThreat.severity]}20`, border: `1px solid ${SEV_COLOR[latestThreat.severity]}40` }}>
                  {latestThreat.severity}
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500">
                <Radio size={10} className="text-cyan-400 animate-pulse" />
                <span>Zero Critical Breaches</span>
              </div>
            )}
          </div>
        )}

        {/* Navigation Items */}
        <nav className="flex-1 py-3 px-2 overflow-y-auto space-y-0.5">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink 
              key={to} 
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group relative cursor-pointer
                 ${isActive
                   ? 'bg-cyan-500/15 text-cyber-cyan border border-cyan-500/40 shadow-[0_0_12px_rgba(0,229,255,0.15)] font-semibold'
                   : 'text-slate-400 hover:text-slate-100 hover:bg-white/5 border border-transparent'}`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon size={17} className={isActive ? 'text-cyber-cyan flex-shrink-0' : 'group-hover:text-cyber-cyan transition-colors flex-shrink-0'} />
                  {!collapsed && (
                    <span className="text-xs font-mono tracking-wide truncate">{label}</span>
                  )}
                  {label.includes('Alerts') && unreadCount > 0 && (
                    <span className="ml-auto text-[10px] bg-red-500 text-white font-mono font-bold rounded-full px-1.5 py-0.5 shadow-[0_0_8px_rgba(239,68,68,0.5)]">
                      {unreadCount}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* User Identity & Clearance Badge */}
        <div className="border-t border-cyan-500/20 p-3 bg-slate-950/40">
          {!collapsed ? (
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center shadow-inner flex-shrink-0">
                <User size={14} className="text-white" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold text-slate-100 truncate font-mono">{user?.full_name}</p>
                <p className="text-[10px] text-cyan-400 font-mono uppercase tracking-wider">[{user?.role}] · L{user?.clearance_level}</p>
              </div>
              <button 
                onClick={handleLogout} 
                className="text-slate-500 hover:text-rose-400 transition-colors p-1.5 rounded-lg hover:bg-red-950/30 cursor-pointer" 
                title="Log Out of SOC Session"
                aria-label="Logout"
              >
                <LogOut size={15} />
              </button>
            </div>
          ) : (
            <button 
              onClick={handleLogout} 
              className="w-full flex justify-center text-slate-500 hover:text-rose-400 p-2 hover:bg-red-950/30 rounded-lg transition-colors cursor-pointer"
              title="Logout"
              aria-label="Logout"
            >
              <LogOut size={16} />
            </button>
          )}
        </div>
      </aside>

      {/* Main Workspace Area */}
      <main className="flex-1 overflow-auto relative">
        <Outlet />
      </main>
    </div>
  )
}
