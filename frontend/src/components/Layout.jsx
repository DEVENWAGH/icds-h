import React, { useState } from 'react'
import { Outlet, NavLink, useNavigate, Navigate } from 'react-router-dom'
import { useAuthStore, useAlertStore } from '../store'
import { useWebSocket } from '../hooks/useWebSocket'
import {
  Shield, Activity, BarChart3, Bell, FileText,
  Eye, Brain, Zap, Settings, LogOut, Menu, ChevronRight, User, AlertOctagon, Cpu, Database,
  Radio, Terminal, Sparkles
} from 'lucide-react'

// Role-based nav definitions with Command Center priority
const ALL_NAV = [
  { to: '/app/command',    icon: Terminal,      label: 'SOC Command HUD', roles: ['admin','analyst'] },
  { to: '/app/dashboard',  icon: Shield,        label: 'SOC Overview',    roles: ['admin','analyst','clinical'] },
  { to: '/app/monitoring', icon: Activity,      label: 'Node Telemetry',  roles: ['admin','analyst','clinical'] },
  { to: '/app/analytics',  icon: BarChart3,     label: 'Deep Analytics',  roles: ['admin','analyst','clinical'] },
  { to: '/app/alerts',     icon: Bell,          label: 'Threat Alerts',   roles: ['admin','analyst','clinical'] },
  { to: '/app/incidents',  icon: AlertOctagon,  label: 'Incidents & Mit', roles: ['admin','analyst'] },
  { to: '/app/logs',       icon: FileText,      label: 'Forensic Logs',   roles: ['admin','analyst','clinical'] },
  { to: '/app/xai',        icon: Brain,         label: 'Explainable AI',  roles: ['admin','analyst','clinical'] },
  { to: '/app/optimizer',  icon: Cpu,           label: 'QIGA Optimizer',  roles: ['admin','analyst'] },
  { to: '/app/response',   icon: Zap,           label: 'Orchestration',   roles: ['admin','analyst'] },
  { to: '/app/memory',     icon: Database,      label: 'Threat Memory',   roles: ['admin','analyst'] },
  { to: '/app/reports',    icon: Eye,           label: 'Compliance Rpt',  roles: ['admin','analyst','clinical'] },
  { to: '/app/admin',      icon: Settings,      label: 'Access & Config', roles: ['admin'] },
]

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
    <div className="flex h-screen bg-black text-ink overflow-hidden select-none font-sans">
      {/* Vercel Dark Console Sidebar */}
      <aside className={`${collapsed ? 'w-16' : 'w-64'} flex-shrink-0 bg-[#0a0a0a] border-r border-[#262626] flex flex-col transition-all duration-200 z-30 shadow-2xl`}>
        {/* Brand Header */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[#262626] bg-[#0a0a0a]">
          <div className="w-8 h-8 rounded-md bg-white flex items-center justify-center flex-shrink-0 shadow-sm">
            <Shield size={16} className="text-black font-black" />
          </div>
          {!collapsed && (
            <div className="flex-1 min-w-0">
              <span className="font-sans font-semibold text-white text-sm tracking-tight block leading-tight">ICDS-H</span>
              <span className="text-[10px] font-mono text-mute uppercase tracking-wider block">Healthcare SOC</span>
            </div>
          )}
          <button 
            onClick={() => setCollapsed(!collapsed)} 
            className="ml-auto text-mute hover:text-white transition-colors p-1 rounded-sm hover:bg-[#171717] cursor-pointer"
            aria-label="Toggle Sidebar Navigation"
          >
            {collapsed ? <ChevronRight size={15} /> : <Menu size={15} />}
          </button>
        </div>

        {/* Live System Health Meter */}
        {!collapsed && (
          <div className="px-3.5 py-2.5 border-b border-[#262626] bg-[#050505] space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan pulse-dot" />
                <span className="text-body font-mono text-[11px]">SYS HEALTH</span>
              </span>
              <span className="text-white font-mono font-semibold text-[11px]">{liveMetrics.sys_health?.toFixed(1) ?? '99.4'}%</span>
            </div>
            {latestThreat ? (
              <div className="flex items-center justify-between text-xs pt-1 border-t border-[#262626]">
                <span className="flex items-center gap-1.5 min-w-0">
                  <span className="w-1.5 h-1.5 rounded-full flex-shrink-0 bg-error" />
                  <span className="font-mono text-[10px] text-body truncate">{latestThreat.attack_type}</span>
                </span>
                <span className="font-mono text-[9px] px-1.5 py-0.5 rounded uppercase font-medium bg-red-950/80 text-red-300 border border-red-800/80">
                  {latestThreat.severity}
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-[10px] font-mono text-mute">
                <Radio size={10} className="text-cyan animate-pulse" />
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
                `flex items-center gap-2.5 px-3 py-2 rounded-md transition-all duration-150 group relative cursor-pointer text-xs
                 ${isActive
                   ? 'bg-[#171717] text-white font-medium border border-[#333333] shadow-sm'
                   : 'text-mute hover:text-white hover:bg-[#141414] border border-transparent'}`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon size={16} className={isActive ? 'text-white flex-shrink-0' : 'text-mute group-hover:text-white transition-colors flex-shrink-0'} />
                  {!collapsed && (
                    <span className="tracking-tight truncate">{label}</span>
                  )}
                  {label.includes('Alerts') && unreadCount > 0 && (
                    <span className="ml-auto text-[10px] bg-red-500 text-white font-mono font-medium rounded-full px-1.5 py-0.2">
                      {unreadCount}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* User Identity & Clearance Badge */}
        <div className="border-t border-[#262626] p-3 bg-[#0a0a0a]">
          {!collapsed ? (
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-full bg-[#171717] border border-[#333333] flex items-center justify-center flex-shrink-0">
                <User size={13} className="text-white" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-white truncate">{user?.full_name}</p>
                <p className="text-[10px] text-mute font-mono uppercase tracking-wide">[{user?.role}] · L{user?.clearance_level}</p>
              </div>
              <button 
                onClick={handleLogout} 
                className="text-mute hover:text-error transition-colors p-1.5 rounded-sm hover:bg-[#171717] cursor-pointer" 
                title="Log Out of SOC Session"
                aria-label="Logout"
              >
                <LogOut size={14} />
              </button>
            </div>
          ) : (
            <button 
              onClick={handleLogout} 
              className="w-full flex justify-center text-mute hover:text-error p-2 hover:bg-[#171717] rounded-sm transition-colors cursor-pointer"
              title="Logout"
              aria-label="Logout"
            >
              <LogOut size={15} />
            </button>
          )}
        </div>
      </aside>

      {/* Main Workspace Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-black">
        {/* Top Header Strip */}
        <header className="h-14 bg-[#0a0a0a] border-b border-[#262626] px-6 flex items-center justify-between z-20 flex-shrink-0">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-mute uppercase tracking-wider">Enterprise Healthcare Node</span>
            <span className="text-[#333333]">/</span>
            <span className="text-xs font-medium text-white">Autonomous Defense Cloud</span>
          </div>

          <div className="flex items-center gap-2.5">
            <button 
              onClick={() => navigate('/app/xai')} 
              className="nav-cta-ask-ai cursor-pointer"
            >
              <Sparkles size={12} className="text-violet" />
              <span>Ask SOC AI</span>
            </button>
            <div className="badge-secondary text-[11px] font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan pulse-dot" />
              <span>ZERO TRUST</span>
            </div>
          </div>
        </header>

        {/* Sub-view Area */}
        <main className="flex-1 overflow-auto bg-black relative">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
