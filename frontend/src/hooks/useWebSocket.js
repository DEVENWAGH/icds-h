import { useEffect, useRef } from 'react'
import { useAuthStore, useAlertStore } from '../store'
import { useSOCStore } from '../store/socEngine'
import { useSimulatorStore } from '../store/simulatorStore'

function buildWsUrl(token) {
  if (import.meta.env.VITE_WS_URL) {
    const base = import.meta.env.VITE_WS_URL
    const separator = base.includes('?') ? '&' : '?'
    return `${base}${separator}token=${encodeURIComponent(token)}`
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/ws/live?token=${encodeURIComponent(token)}`
}

export function useWebSocket() {
  const wsRef = useRef(null)
  const timeoutRef = useRef(null)
  const token = useAuthStore((s) => s.token)

  useEffect(() => {
    if (!token) return undefined

    let isMounted = true

    const connect = () => {
      if (!isMounted) return

      const wsUrl = buildWsUrl(token)
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {}

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)

          if (msg.type === 'threat') {
            const data = msg.data || {}
            const attackLogId = data.attack_log_id

            if (attackLogId === undefined || attackLogId === null) {
              return
            }

            useSOCStore.getState().upsertIncident(data)

            if (data.attack_type !== 'Normal') {
              useAlertStore.getState().addLiveThreat(data)
            }

            window.dispatchEvent(
              new CustomEvent('mlp-prediction', {
                detail: {
                  attack_log_id: attackLogId,
                  attack_type: data.attack_type,
                  prediction_label: data.mlp_prediction?.label ?? data.attack_type,
                  prediction_type: data.attack_type === 'Normal' ? 'NORMAL' : 'ATTACK',
                  confidence: data.mlp_prediction?.confidence ?? data.confidence,
                  risk_score: data.mlp_prediction?.risk_score ?? data.risk_score,
                  dataset: data.dataset,
                  model_version: data.mlp_prediction?.model_version ?? data.model_version,
                  severity: data.severity,
                  raw_features: data.raw_features,
                },
              })
            )

            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'shap_explanation') {
            const data = msg.data || {}
            window.dispatchEvent(new CustomEvent('shap-explanation', { detail: data }))
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'qiga_recommendation') {
            const data = msg.data || {}
            window.dispatchEvent(new CustomEvent('qiga-recommendation', { detail: data }))
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'anomaly_detection') {
            const data = msg.data || {}
            if (data.is_anomaly) {
              useAlertStore.getState().addLiveThreat({
                ...data,
                attack_type: data.attack_type || 'Anomaly (Zero-Day)',
              })
            }
            window.dispatchEvent(new CustomEvent('anomaly-detection', { detail: data }))
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'auto_response') {
            const data = msg.data || {}
            useSOCStore.getState().updateLifecycle(
              data.attack_log_id,
              data.status || 'CONTAINMENT'
            )
            window.dispatchEvent(new CustomEvent('auto-response', { detail: data }))
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'metrics') {
            useAlertStore.getState().setLiveMetrics(msg.data || {})
            window.dispatchEvent(new CustomEvent('live-metrics', { detail: msg.data || {} }))
            return
          }

          if (msg.type === 'lifecycle_update') {
            const data = msg.data || {}
            const status = String(data.status || '').toUpperCase()
            useSOCStore.getState().updateLifecycle(data.attack_log_id, status)
            window.dispatchEvent(new CustomEvent('lifecycle-update', { detail: data }))
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'recovery_progress') {
            const data = msg.data || {}
            window.dispatchEvent(new CustomEvent('recovery-progress', { detail: data }))
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'recommendation_rejected') {
            const data = msg.data || {}
            window.dispatchEvent(new CustomEvent('recommendation-rejected', { detail: data }))
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'auto_attack_status') {
            const data = msg.data || {}
            useSimulatorStore.getState().syncAutoStatus(data)
            window.dispatchEvent(new CustomEvent('soc-event', { detail: msg }))
            return
          }

          if (msg.type === 'clear_telemetry') {
            useSimulatorStore.setState({
              log: [],
              stage: 'IDLE',
              lastResult: null,
              autoScenarioCount: 0,
            })
            useAlertStore.getState().clearLiveThreats()
            useSOCStore.setState({
              incidents: [],
              qigaRecommendations: {},
              lastTick: Date.now(),
            })
            window.dispatchEvent(new CustomEvent('clear-telemetry', { detail: msg }))
          }
        } catch (error) {
          console.error('[WS] Message handling error:', error)
        }
      }

      ws.onerror = () => {
        ws.close()
      }

      ws.onclose = (event) => {
        if (!isMounted) return
        const delay = event.code === 4401 || event.code === 1008 ? 15000 : 3000
        timeoutRef.current = setTimeout(connect, delay)
      }
    }

    connect()

    return () => {
      isMounted = false
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
        timeoutRef.current = null
      }
      if (wsRef.current) {
        wsRef.current.onclose = null
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [token])
}
