import { useEffect, useRef } from 'react'
import { useAlertStore } from '../store'
import { useSOCStore } from '../store/socEngine'

export function useWebSocket() {
  const wsRef = useRef(null)
  const timeoutRef = useRef(null)

  useEffect(() => {
    let isMounted = true

    const connect = () => {
      if (!isMounted) return

      const protocol =
        window.location.protocol === 'https:'
          ? 'wss:'
          : 'ws:'

      const wsUrl =
        import.meta.env.VITE_WS_URL ||
        `${protocol}//127.0.0.1:8000/ws/live`

      console.log('[WS] Connecting to:', wsUrl)

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      // =========================================================
      // CONNECTION OPEN
      // =========================================================

      ws.onopen = () => {
        console.log('[WS] Connected:', wsUrl)
      }

      // =========================================================
      // MESSAGE HANDLER
      // =========================================================

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)

          console.log('[WS] Event:', msg.type)

          // =======================================================
          // 1. MLP DETECTION / THREAT EVENT
          // =======================================================

          if (msg.type === 'threat') {
            const data = msg.data || {}

            const attackLogId =
              data.attack_log_id

            if (
              attackLogId === undefined ||
              attackLogId === null
            ) {
              console.warn(
                '[WS] Threat event has no attack_log_id:',
                data
              )
              return
            }

            /*
             * This is the detection stage.
             *
             * IMPORTANT:
             * The MLP has already run in the backend.
             *
             * Backend:
             * Dataset
             *    ↓
             * MLP
             *    ↓
             * AttackLog + RiskScore
             *    ↓
             * WebSocket "threat"
             *
             * The frontend only receives the result.
             */

            console.log(
              '[WS] MLP detection received:',
              {
                attackLogId,
                attackType: data.attack_type,
                dataset: data.dataset,
                confidence: data.confidence,
                riskScore: data.risk_score,
              }
            )

            // Update central SOC store.
            useSOCStore
              .getState()
              .upsertIncident(data)

            // Add only real threats to alert store.
            if (
              data.attack_type !== 'Normal'
            ) {
              useAlertStore
                .getState()
                .addLiveThreat(data)
            }

            /*
             * Notify Analytics / Monitoring / XAI
             * that an MLP prediction has arrived.
             *
             * SAME attack_log_id is preserved.
             */
            window.dispatchEvent(
              new CustomEvent(
                'mlp-prediction',
                {
                  detail: {
                    attack_log_id:
                      attackLogId,

                    attack_type:
                      data.attack_type,

                    prediction_label:
                      data.mlp_prediction
                        ?.label ??
                      data.attack_type,

                    prediction_type:
                      data.attack_type ===
                      'Normal'
                        ? 'NORMAL'
                        : 'ATTACK',

                    confidence:
                      data.mlp_prediction
                        ?.confidence ??
                      data.confidence,

                    risk_score:
                      data.mlp_prediction
                        ?.risk_score ??
                      data.risk_score,

                    dataset:
                      data.dataset,

                    model_version:
                      data.mlp_prediction
                        ?.model_version ??
                      data.model_version,

                    severity:
                      data.severity,

                    raw_features:
                      data.raw_features,
                  },
                }
              )
            )

            /*
             * Existing application-wide SOC event.
             */
            window.dispatchEvent(
              new CustomEvent(
                'soc-event',
                {
                  detail: msg,
                }
              )
            )

            return
          }

          // =======================================================
          // 2. SHAP EXPLANATION
          // =======================================================

          if (
            msg.type ===
            'shap_explanation'
          ) {
            const data = msg.data || {}

            console.log(
              '[WS] SHAP explanation received:',
              data
            )

            /*
             * SHAP is explanation only.
             *
             * It does NOT change the MLP prediction.
             *
             * The same attack_log_id connects
             * SHAP to the original MLP event.
             */
            window.dispatchEvent(
              new CustomEvent(
                'shap-explanation',
                {
                  detail: data,
                }
              )
            )

            /*
             * Also expose through general SOC event.
             */
            window.dispatchEvent(
              new CustomEvent(
                'soc-event',
                {
                  detail: msg,
                }
              )
            )

            return
          }

          // =======================================================
          // 3. QIGA → RECOMMENDATION
          // =======================================================

          if (
            msg.type ===
            'qiga_recommendation'
          ) {
            const data = msg.data || {}

            console.log(
              '[WS] QIGA recommendation received:',
              data
            )

            window.dispatchEvent(
              new CustomEvent(
                'qiga-recommendation',
                {
                  detail: data,
                }
              )
            )

            window.dispatchEvent(
              new CustomEvent(
                'soc-event',
                {
                  detail: msg,
                }
              )
            )

            return
          }

          // =======================================================
          // 3b. ANOMALY DETECTION (ISOLATION FOREST)
          // =======================================================

          if (msg.type === 'anomaly_detection') {
            const data = msg.data || {}

            console.log(
              '[WS] Anomaly Detection:',
              {
                attackLogId: data.attack_log_id,
                anomalyScore: data.anomaly_score,
                isAnomaly: data.is_anomaly,
                detector: data.detector_type,
              }
            )

            // Add anomaly to alert store as a live threat
            if (data.is_anomaly) {
              useAlertStore
                .getState()
                .addLiveThreat({
                  ...data,
                  attack_type: data.attack_type || 'Anomaly (Zero-Day)',
                })
            }

            window.dispatchEvent(
              new CustomEvent(
                'anomaly-detection',
                { detail: data }
              )
            )

            window.dispatchEvent(
              new CustomEvent(
                'soc-event',
                { detail: msg }
              )
            )

            return
          }

          // =======================================================
          // 3c. AUTO-RESPONSE EXECUTION
          // =======================================================

          if (msg.type === 'auto_response') {
            const data = msg.data || {}

            console.log(
              '[WS] Auto-Response Executed:',
              {
                attackLogId: data.attack_log_id,
                action: data.action_type,
                status: data.status,
              }
            )

            // Update SOC store with resolved status
            useSOCStore
              .getState()
              .updateLifecycle(
                data.attack_log_id,
                'RESOLVED'
              )

            window.dispatchEvent(
              new CustomEvent(
                'auto-response',
                { detail: data }
              )
            )

            window.dispatchEvent(
              new CustomEvent(
                'soc-event',
                { detail: msg }
              )
            )

            return
          }

          // =======================================================
          // 4. LIVE METRICS
          // =======================================================

          if (
            msg.type === 'metrics'
          ) {
            useAlertStore
              .getState()
              .setLiveMetrics(
                msg.data || {}
              )

            return
          }

          // =======================================================
          // 5. LIFECYCLE UPDATE
          // =======================================================

          if (
            msg.type ===
            'lifecycle_update'
          ) {
            const data =
              msg.data || {}

            const attackLogId =
              data.attack_log_id

            const status =
              String(
                data.status || ''
              ).toUpperCase()

            console.log(
              '[WS] Lifecycle update:',
              attackLogId,
              status
            )

            useSOCStore
              .getState()
              .updateLifecycle(
                attackLogId,
                status
              )

            window.dispatchEvent(
              new CustomEvent(
                'lifecycle-update',
                {
                  detail: data,
                }
              )
            )

            window.dispatchEvent(
              new CustomEvent(
                'soc-event',
                {
                  detail: msg,
                }
              )
            )

            return
          }

          // =======================================================
          // 6. UNKNOWN EVENT
          // =======================================================

          console.log(
            '[WS] Unhandled event type:',
            msg.type
          )

        } catch (error) {
          console.error(
            '[WS] Message handling error:',
            error
          )
        }
      }

      // =========================================================
      // ERROR
      // =========================================================

      ws.onerror = (error) => {
        console.error(
          '[WS] WebSocket error:',
          error
        )

        ws.close()
      }

      // =========================================================
      // CLOSE / RECONNECT
      // =========================================================

      ws.onclose = () => {
        console.log(
          '[WS] Disconnected'
        )

        if (isMounted) {
          timeoutRef.current =
            setTimeout(
              connect,
              3000
            )
        }
      }
    }

    connect()

    // =========================================================
    // CLEANUP
    // =========================================================

    return () => {
      isMounted = false

      if (timeoutRef.current) {
        clearTimeout(
          timeoutRef.current
        )

        timeoutRef.current = null
      }

      if (wsRef.current) {
        wsRef.current.onclose = null
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [])
}