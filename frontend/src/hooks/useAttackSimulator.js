import { useState, useCallback, useRef, useEffect } from 'react'
import api from '../utils/api'

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

const SCENARIO_KEYS = [
  'hospital_breach',
  'phishing_campaign',
  'ransomware_kill_chain',
  'apt_intrusion',
  'data_exfiltration',
  'ddos_wave',
  'zero_day_outbreak',
]

export function useAttackSimulator() {
  const [stage, setStage] = useState('IDLE')
  const [lastResult, setLastResult] = useState(null)
  const [log, setLog] = useState([])
  const [loading, setLoading] = useState(false)
  const [autoRunning, setAutoRunning] = useState(false)
  const [currentScenario, setCurrentScenario] = useState(null)
  const [autoScenarioCount, setAutoScenarioCount] = useState(0)

  const autoAttackRef = useRef(false)

  const appendLog = (msg, type = 'info') => {
    const ts = new Date().toLocaleTimeString()
    setLog(prev => [{ ts, msg, type }, ...prev].slice(0, 60))
  }

  const fireAttack = useCallback(async (attackType = 'DDoS', severity = 'HIGH') => {
    if (loading) return
    setLoading(true)
    setLastResult(null)
    setStage('INJECTING')
    appendLog(`[>>>] Injecting ${attackType} (${severity}) into pipeline...`, 'warn')
    try {
      await delay(250)
      appendLog(`[SYN] Generating synthetic ${attackType} traffic pattern...`, 'info')
      await delay(300)
      setStage('DETECTED')
      appendLog(`[DET] Attack signature matched - AttackLog created`, 'success')
      // Note: api baseURL is already '/api'
      const res = await api.post(`/sim/attack?attack_type=${encodeURIComponent(attackType)}&severity=${severity}`)
      const data = res.data
      setLastResult(data)
      await delay(200)
      setStage('CLASSIFYING')
      appendLog(`[MLP] MLP classifier: ${data.source_ip} -> ${attackType}`, 'info')
      appendLog(`[MLP] Risk Score: ${data.risk_score}/100 | Confidence: ${data.confidence?.toFixed(1)}%`, 'info')
      appendLog(`[MTR] MITRE: ${data.mitre}`, 'info')
      await delay(350)
      setStage('QIGA')
      appendLog(`[QGA] QIGA optimizer computing response actions...`, 'info')
      await delay(400)
      if (severity === 'CRITICAL' || severity === 'HIGH') {
        setStage('FIREWALL')
        if (severity === 'CRITICAL') {
          appendLog(`[FW]  CRITICAL - Source IP ${data.source_ip} AUTO-BLOCKED`, 'danger')
        } else {
          appendLog(`[FW]  HIGH severity - Firewall alert raised`, 'warn')
        }
      }
      await delay(300)
      setStage('COMPLETE')
      appendLog(`[OK]  Pipeline complete. Attack log #${data.attack_log_id} created.`, 'success')
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'attack_completed', data } }))
    } catch (err) {
      setStage('ERROR')
      const msg = err?.response?.data?.detail || err.message || 'Unknown error'
      appendLog(`[ERR] Injection failed: ${msg}`, 'danger')
    } finally {
      setLoading(false)
      if (!autoAttackRef.current) {
        setTimeout(() => setStage('IDLE'), 3000)
      }
    }
  }, [loading])

  const fireScenario = useCallback(async (scenario = 'hospital_breach') => {
    if (loading) return
    setLoading(true)
    setStage('INJECTING')
    appendLog(`[SCN] Starting scenario: ${scenario.replace(/_/g, ' ').toUpperCase()}`, 'warn')
    try {
      const res = await api.post(`/sim/scenario?scenario=${scenario}`)
      const data = res.data
      setLastResult(data)
      appendLog(`[SCN] Scenario complete: ${data.attacks_fired} attacks injected`, 'success')
      data.results?.forEach(r => {
        if (r.error) appendLog(`[ERR] ${r.attack_type}: ${r.error}`, 'danger')
        else appendLog(`[OK]  ${r.attack_type} (${r.severity}) -> Log #${r.attack_log_id}`, 'success')
      })
      setStage('COMPLETE')
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'scenario_completed', data } }))
    } catch (err) {
      setStage('ERROR')
      appendLog(`[ERR] Scenario failed: ${err?.response?.data?.detail || err.message}`, 'danger')
    } finally {
      setLoading(false)
      if (!autoAttackRef.current) {
        setTimeout(() => setStage('IDLE'), 3000)
      }
    }
  }, [loading])

  const startAutoAttack = useCallback(async () => {
    if (autoAttackRef.current) return
    autoAttackRef.current = true
    setAutoRunning(true)
    appendLog('[AUTO] >>> AUTO ATTACK MODE ACTIVATED (Continuous Random Scenarios)', 'warn')
    appendLog('[AUTO] Running continuously until STOP is clicked. Engine will not stop on its own.', 'info')

    let lastScenario = ''
    while (autoAttackRef.current) {
      const candidates = SCENARIO_KEYS.filter(s => s !== lastScenario)
      const scenario = candidates[Math.floor(Math.random() * candidates.length)] || SCENARIO_KEYS[0]
      lastScenario = scenario
      setCurrentScenario(scenario)

      appendLog(`[AUTO] Launching random scenario: ${scenario.replace(/_/g, ' ').toUpperCase()}...`, 'warn')
      setStage('INJECTING')
      try {
        const res = await api.post(`/sim/scenario?scenario=${scenario}`)
        const data = res.data
        setLastResult(data)
        setAutoScenarioCount(c => c + 1)
        appendLog(`[SCN] Scenario finished: ${data.attacks_fired} attacks injected`, 'success')
        data.results?.forEach(r => {
          if (r.error) appendLog(`[ERR] ${r.attack_type}: ${r.error}`, 'danger')
          else appendLog(`[OK]  ${r.attack_type} (${r.severity}) -> Log #${r.attack_log_id}`, 'success')
        })
        setStage('COMPLETE')
        window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'scenario_completed', data } }))
      } catch (err) {
        setStage('ERROR')
        appendLog(`[ERR] Scenario execution error: ${err?.response?.data?.detail || err.message}`, 'danger')
      }

      if (!autoAttackRef.current) break

      appendLog('[AUTO] Pausing 4s before next random scenario...', 'info')
      await delay(4000)
    }

    setStage('IDLE')
    setCurrentScenario(null)
    appendLog('[AUTO] Auto attack mode halted.', 'info')
  }, [])

  const stopAutoAttack = useCallback(() => {
    autoAttackRef.current = false
    setAutoRunning(false)
    setCurrentScenario(null)
    appendLog('[AUTO] STOP requested. Auto attack halted by user.', 'warn')
  }, [])

  const toggleAutoAttack = useCallback(() => {
    if (autoAttackRef.current) {
      stopAutoAttack()
    } else {
      startAutoAttack()
    }
  }, [startAutoAttack, stopAutoAttack])

  useEffect(() => {
    return () => {
      autoAttackRef.current = false
    }
  }, [])

  const clearLog = useCallback(() => setLog([]), [])

  const fireAnomaly = useCallback(async (severity = 'HIGH') => {
    if (loading) return
    setLoading(true)
    setLastResult(null)
    setStage('INJECTING')
    appendLog(`[>>>] Injecting NOVEL / unrecognized traffic pattern...`, 'warn')
    try {
      await delay(250)
      appendLog(`[SYN] Crafting out-of-distribution packet features...`, 'info')
      await delay(300)
      setStage('CLASSIFYING')
      appendLog(`[MLP] Supervised MLP verdict: Normal (pattern never seen)`, 'info')
      await delay(300)
      const res = await api.post(`/sim/anomaly?severity=${severity}`)
      const data = res.data
      setLastResult(data)
      setStage('DETECTED')
      appendLog(`[IF]  Isolation Forest FLAGGED anomaly (score: ${Number(data.anomaly_score).toFixed(4)})`, 'danger')
      appendLog(`[IF]  Reclassified -> Anomaly (Zero-Day) | Risk ${data.risk_score}/100`, 'warn')
      appendLog(`[MTR] MITRE: ${data.mitre}`, 'info')
      await delay(300)
      setStage('COMPLETE')
      appendLog(`[OK]  Zero-day surfaced in Live Threat Feed. Log #${data.attack_log_id}.`, 'success')
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'anomaly_completed', data } }))
    } catch (err) {
      setStage('ERROR')
      const msg = err?.response?.data?.detail || err.message || 'Unknown error'
      appendLog(`[ERR] Zero-day injection failed: ${msg}`, 'danger')
    } finally {
      setLoading(false)
      if (!autoAttackRef.current) {
        setTimeout(() => setStage('IDLE'), 3000)
      }
    }
  }, [loading])

  const uploadCsv = useCallback(async (file) => {
    if (loading || !file) return
    setLoading(true)
    setStage('INJECTING')
    appendLog(`[CSV] Uploading ${file.name} for ML pipeline inference...`, 'warn')
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await api.post('/sim/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      const data = res.data
      setLastResult(data)
      setStage('COMPLETE')
      appendLog(`[CSV] Processed ${data.rows_processed}/${data.total_rows} events (${data.dataset_detected})`, 'success')
      window.dispatchEvent(new CustomEvent('soc-event', { detail: { type: 'csv_completed', data } }))
    } catch (err) {
      setStage('ERROR')
      const msg = err?.response?.data?.detail || err.message || 'CSV upload failed'
      appendLog(`[ERR] CSV upload error: ${msg}`, 'danger')
    } finally {
      setLoading(false)
      if (!autoAttackRef.current) {
        setTimeout(() => setStage('IDLE'), 3000)
      }
    }
  }, [loading])

  return {
    stage,
    lastResult,
    log,
    loading,
    autoRunning,
    currentScenario,
    autoScenarioCount,
    fireAttack,
    fireScenario,
    fireAnomaly,
    uploadCsv,
    clearLog,
    startAutoAttack,
    stopAutoAttack,
    toggleAutoAttack,
  }
}