import { create } from 'zustand'
import api from '../utils/api'

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export const useSimulatorStore = create((set, get) => ({
  stage: 'IDLE',
  lastResult: null,
  log: [],
  loading: false,
  autoRunning: false,
  currentScenario: null,
  autoScenarioCount: 0,

  appendLog: (msg, type = 'info') => {
    const ts = new Date().toLocaleTimeString()
    set((state) => ({
      log: [{ ts, msg, type }, ...state.log].slice(0, 80),
    }))
  },

  clearLog: () => set({ log: [] }),

  setStage: (stage) => set({ stage }),

  // Sync state received from backend WebSocket
  syncAutoStatus: (data) => {
    if (!data) return
    const current = get()
    const isRunning = Boolean(data.enabled)
    const updates = {
      autoRunning: isRunning,
      currentScenario: data.current_scenario ?? current.currentScenario,
      autoScenarioCount: data.scenario_count ?? current.autoScenarioCount,
    }
    if (data.stage) updates.stage = data.stage
    if (data.msg) {
      current.appendLog(
        data.msg,
        isRunning ? (data.stage === 'COMPLETE' ? 'success' : 'warn') : 'info'
      )
    }
    set(updates)
  },

  // Fetch running status from backend on mount or route changes
  fetchStatus: async () => {
    try {
      const res = await api.get('/sim/auto-attack/status')
      const data = res.data
      if (data) {
        set({
          autoRunning: Boolean(data.enabled),
          currentScenario: data.current_scenario,
          autoScenarioCount: Number(data.scenario_count) || 0,
        })
      }
    } catch {
      // ignore unauthenticated or network error
    }
  },

  // Start continuous server-side auto attack
  startAutoAttack: async () => {
    try {
      get().appendLog('[AUTO] >>> STARTING PERSISTENT AUTO ATTACK ENGINE...', 'warn')
      set({ autoRunning: true })
      const res = await api.post('/sim/auto-attack/start')
      const data = res.data
      set({
        autoRunning: Boolean(data.enabled),
        autoScenarioCount: Number(data.scenario_count) || get().autoScenarioCount,
        currentScenario: data.current_scenario,
      })
      get().appendLog('[AUTO] Engine active on server. Will NOT stop when switching tabs/pages.', 'success')
    } catch (err) {
      get().appendLog(`[ERR] Failed to start auto attack: ${err?.response?.data?.detail || err.message}`, 'danger')
      set({ autoRunning: false })
    }
  },

  // Stop continuous server-side auto attack
  stopAutoAttack: async () => {
    try {
      get().appendLog('[AUTO] Stopping auto attack service...', 'warn')
      const res = await api.post('/sim/auto-attack/stop')
      const data = res.data
      set({
        autoRunning: Boolean(data.enabled),
        currentScenario: null,
      })
      get().appendLog('[AUTO] STOPPED by user. Engine returned to IDLE.', 'info')
    } catch (err) {
      get().appendLog(`[ERR] Failed to stop auto attack: ${err?.response?.data?.detail || err.message}`, 'danger')
    }
  },

  toggleAutoAttack: async () => {
    if (get().autoRunning) {
      await get().stopAutoAttack()
    } else {
      await get().startAutoAttack()
    }
  },

  // Single manual attack
  fireAttack: async (attackType = 'DDoS', severity = 'HIGH') => {
    if (get().loading) return
    set({ loading: true, lastResult: null, stage: 'INJECTING' })
    const { appendLog } = get()
    appendLog(`[>>>] Injecting ${attackType} (${severity}) into pipeline...`, 'warn')
    try {
      await delay(250)
      appendLog(`[SYN] Generating synthetic ${attackType} traffic pattern...`, 'info')
      await delay(300)
      set({ stage: 'DETECTED' })
      appendLog('[DET] Attack signature matched - AttackLog created', 'success')
      const res = await api.post(`/sim/attack?attack_type=${encodeURIComponent(attackType)}&severity=${severity}`)
      const data = res.data
      set({ lastResult: data })
      await delay(200)
      set({ stage: 'CLASSIFYING' })
      appendLog(`[MLP] MLP classifier: ${data.source_ip} -> ${attackType}`, 'info')
      appendLog(`[MLP] Risk Score: ${data.risk_score}/100 | Confidence: ${data.confidence?.toFixed(1)}%`, 'info')
      appendLog(`[MTR] MITRE: ${data.mitre}`, 'info')
      await delay(350)
      set({ stage: 'QIGA' })
      appendLog('[QGA] QIGA optimizer computing response actions...', 'info')
      await delay(400)
      if (severity === 'CRITICAL' || severity === 'HIGH') {
        set({ stage: 'FIREWALL' })
        if (severity === 'CRITICAL') {
          appendLog(`[FW]  CRITICAL - Source IP ${data.source_ip} AUTO-BLOCKED`, 'danger')
        } else {
          appendLog('[FW]  HIGH severity - Firewall alert raised', 'warn')
        }
      }
      await delay(300)
      set({ stage: 'COMPLETE' })
      appendLog(`[OK]  Pipeline complete. Attack log #${data.attack_log_id} created.`, 'success')
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'attack_completed', data } }))
    } catch (err) {
      set({ stage: 'ERROR' })
      appendLog(`[ERR] Injection failed: ${err?.response?.data?.detail || err.message || 'Unknown error'}`, 'danger')
    } finally {
      set({ loading: false })
      if (!get().autoRunning) {
        setTimeout(() => set({ stage: 'IDLE' }), 3000)
      }
    }
  },

  // Single scenario run
  fireScenario: async (scenario = 'hospital_breach') => {
    if (get().loading) return
    set({ loading: true, stage: 'INJECTING' })
    const { appendLog } = get()
    appendLog(`[SCN] Starting scenario: ${scenario.replace(/_/g, ' ').toUpperCase()}`, 'warn')
    try {
      const res = await api.post(`/sim/scenario?scenario=${scenario}`)
      const data = res.data
      set({ lastResult: data })
      appendLog(`[SCN] Scenario complete: ${data.attacks_fired} attacks injected`, 'success')
      data.results?.forEach((r) => {
        if (r.error) appendLog(`[ERR] ${r.attack_type}: ${r.error}`, 'danger')
        else appendLog(`[OK]  ${r.attack_type} (${r.severity}) -> Log #${r.attack_log_id}`, 'success')
      })
      set({ stage: 'COMPLETE' })
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'scenario_completed', data } }))
    } catch (err) {
      set({ stage: 'ERROR' })
      appendLog(`[ERR] Scenario failed: ${err?.response?.data?.detail || err.message}`, 'danger')
    } finally {
      set({ loading: false })
      if (!get().autoRunning) {
        setTimeout(() => set({ stage: 'IDLE' }), 3000)
      }
    }
  },

  // Zero-day anomaly
  fireAnomaly: async (severity = 'HIGH') => {
    if (get().loading) return
    set({ loading: true, lastResult: null, stage: 'INJECTING' })
    const { appendLog } = get()
    appendLog('[>>>] Injecting NOVEL / unrecognized traffic pattern...', 'warn')
    try {
      await delay(250)
      appendLog('[SYN] Crafting out-of-distribution packet features...', 'info')
      await delay(300)
      set({ stage: 'CLASSIFYING' })
      appendLog('[MLP] Supervised MLP verdict: Normal (pattern never seen)', 'info')
      await delay(300)
      const res = await api.post(`/sim/anomaly?severity=${severity}`)
      const data = res.data
      set({ lastResult: data, stage: 'DETECTED' })
      appendLog(`[IF]  Isolation Forest FLAGGED anomaly (score: ${Number(data.anomaly_score).toFixed(4)})`, 'danger')
      appendLog(`[IF]  Reclassified -> Anomaly (Zero-Day) | Risk ${data.risk_score}/100`, 'warn')
      appendLog(`[MTR] MITRE: ${data.mitre}`, 'info')
      await delay(300)
      set({ stage: 'COMPLETE' })
      appendLog(`[OK]  Zero-day surfaced in Live Threat Feed. Log #${data.attack_log_id}.`, 'success')
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'anomaly_completed', data } }))
    } catch (err) {
      set({ stage: 'ERROR' })
      appendLog(`[ERR] Zero-day injection failed: ${err?.response?.data?.detail || err.message || 'Unknown error'}`, 'danger')
    } finally {
      set({ loading: false })
      if (!get().autoRunning) {
        setTimeout(() => set({ stage: 'IDLE' }), 3000)
      }
    }
  },

  // CSV upload
  uploadCsv: async (file) => {
    if (get().loading || !file) return
    set({ loading: true, stage: 'INJECTING' })
    const { appendLog } = get()
    appendLog(`[CSV] Uploading ${file.name} for ML pipeline inference...`, 'warn')
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await api.post('/sim/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      const data = res.data
      set({ lastResult: data, stage: 'COMPLETE' })
      appendLog(`[CSV] Processed ${data.rows_processed}/${data.total_rows} events (${data.dataset_detected})`, 'success')
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'csv_completed', data } }))
    } catch (err) {
      set({ stage: 'ERROR' })
      appendLog(`[ERR] CSV upload error: ${err?.response?.data?.detail || err.message || 'CSV upload failed'}`, 'danger')
    } finally {
      set({ loading: false })
      if (!get().autoRunning) {
        setTimeout(() => set({ stage: 'IDLE' }), 3000)
      }
    }
  },
}))
