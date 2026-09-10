import React, { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './store'
import { useSOCStore } from './store/socEngine'
import { useWebSocket } from './hooks/useWebSocket'
import Layout from './components/Layout'
import Landing from './pages/Landing'
import Login from './pages/Login'
import SOCCommand from './pages/SOCCommand'
import Dashboard from './pages/Dashboard'
import Monitoring from './pages/Monitoring'
import Analytics from './pages/Analytics'
import Alerts from './pages/Alerts'
import Incidents from './pages/Incidents'
import Logs from './pages/Logs'
import XAI from './pages/XAI'
import Optimizer from './pages/Optimizer'
import Response from './pages/Response'
import Memory from './pages/Memory'
import Reports from './pages/Reports'
import Admin from './pages/Admin'

const ALL_ROLES = ['admin', 'analyst', 'clinical']
const SOC_ROLES = ['admin', 'analyst']

function PrivateRoute({ children }) {
  const token = useAuthStore((s) => s.token)
  const user = useAuthStore((s) => s.user)
  if (!token || !user) {
    return <Navigate to="/login" replace />
  }
  return (
    <>
      <SOCEngineBootstrap />
      {children}
    </>
  )
}

function RoleRoute({ roles, children }) {
  const user = useAuthStore((s) => s.user)
  if (!user || !roles.includes(user.role)) {
    const fallback = user?.role === 'clinical' ? '/app/dashboard' : '/app/command'
    return <Navigate to={fallback} replace />
  }
  return children
}

function SOCEngineBootstrap() {
  const init = useSOCStore((s) => s.init)
  const refreshIncidents = useSOCStore((s) => s.refreshIncidents)

  useWebSocket()

  useEffect(() => { init() }, [init])

  useEffect(() => {
    refreshIncidents()
  }, [refreshIncidents])

  return null
}

function AppIndexRedirect() {
  const user = useAuthStore((s) => s.user)
  if (user?.role === 'clinical') {
    return <Navigate to="/app/dashboard" replace />
  }
  return <Navigate to="/app/command" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />

        <Route path="/app" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<AppIndexRedirect />} />
          <Route path="command" element={<RoleRoute roles={SOC_ROLES}><SOCCommand /></RoleRoute>} />
          <Route path="dashboard" element={<RoleRoute roles={ALL_ROLES}><Dashboard /></RoleRoute>} />
          <Route path="monitoring" element={<RoleRoute roles={ALL_ROLES}><Monitoring /></RoleRoute>} />
          <Route path="analytics" element={<RoleRoute roles={ALL_ROLES}><Analytics /></RoleRoute>} />
          <Route path="alerts" element={<RoleRoute roles={ALL_ROLES}><Alerts /></RoleRoute>} />
          <Route path="incidents" element={<RoleRoute roles={SOC_ROLES}><Incidents /></RoleRoute>} />
          <Route path="logs" element={<RoleRoute roles={ALL_ROLES}><Logs /></RoleRoute>} />
          <Route path="xai" element={<RoleRoute roles={ALL_ROLES}><XAI /></RoleRoute>} />
          <Route path="optimizer" element={<RoleRoute roles={SOC_ROLES}><Optimizer /></RoleRoute>} />
          <Route path="response" element={<RoleRoute roles={SOC_ROLES}><Response /></RoleRoute>} />
          <Route path="memory" element={<RoleRoute roles={SOC_ROLES}><Memory /></RoleRoute>} />
          <Route path="reports" element={<RoleRoute roles={ALL_ROLES}><Reports /></RoleRoute>} />
          <Route path="admin" element={<RoleRoute roles={['admin']}><Admin /></RoleRoute>} />
          <Route path="*" element={<AppIndexRedirect />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
