import React, { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './store'
import { useSOCStore } from './store/socEngine'
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

function PrivateRoute({ children }) {
  const token = useAuthStore((s) => s.token)
  return token ? (
    <>
      <SOCEngineBootstrap />
      {children}
    </>
  ) : <Navigate to="/login" replace />
}

function SOCEngineBootstrap() {
  const init = useSOCStore((s) => s.init)
  useEffect(() => { init() }, [init])
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
        
        {/* Full-featured App layout routes */}
        <Route path="/app" element={<PrivateRoute><Layout /></PrivateRoute>}>
          <Route index element={<AppIndexRedirect />} />
          <Route path="command" element={<SOCCommand />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="monitoring" element={<Monitoring />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="logs" element={<Logs />} />
          <Route path="xai" element={<XAI />} />
          <Route path="optimizer" element={<Optimizer />} />
          <Route path="response" element={<Response />} />
          <Route path="memory" element={<Memory />} />
          <Route path="reports" element={<Reports />} />
          <Route path="admin" element={<Admin />} />
          <Route path="*" element={<AppIndexRedirect />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

