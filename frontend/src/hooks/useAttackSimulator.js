import { useState, useCallback } from 'react'
import api from '../utils/api'

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export function useAttackSimulator() {
  const [stage, setStage] = useState('IDLE')
  const [lastResult, setLastResult] = useState(null)
  const [log, setLog] = useState([])
  const [loading, setLoading] = useState(false)

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
    } catch (err) {
      setStage('ERROR')
      const msg = err?.response?.data?.detail || err.message || 'Unknown error'
      appendLog(`[ERR] Injection failed: ${msg}`, 'danger')
    } finally {
      setLoading(false)
      setTimeout(() => setStage('IDLE'), 3000)
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
    } catch (err) {
      setStage('ERROR')
      appendLog(`[ERR] Scenario failed: ${err?.response?.data?.detail || err.message}`, 'danger')
    } finally {
      setLoading(false)
      setTimeout(() => setStage('IDLE'), 3000)
    }
  }, [loading])

  const clearLog = useCallback(() => setLog([]), [])

  return { stage, lastResult, log, loading, fireAttack, fireScenario, clearLog }
}