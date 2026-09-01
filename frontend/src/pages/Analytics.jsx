import React, {
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  Brain,
  TrendingUp,
  RefreshCw,
  Download,
  ShieldCheck,
  Activity,
  CheckCircle,
} from 'lucide-react'

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

import { useIncidentStore } from '../store'
import { useSOCStore } from '../store/socEngine'
import api from '../utils/api'

/*
|--------------------------------------------------------------------------
| ANALYTICS
|--------------------------------------------------------------------------
|
| LIVE FLOW
|
| Dataset Replay
|      ↓
| Dataset-specific MLP
|      ↓
| AttackLog + RiskScore
|      ↓
| WebSocket threat
|      ↓
| Monitoring / SOC Store
|      ↓
| Analytics follows latest AttackLog
|      ↓
| SHAP explains SAME AttackLog
|
| Analytics never calls POST /predict.
|
*/

export default function Analytics() {
  const {
    selectedAttackLogId,
    setSelectedAttackLogId,
  } = useIncidentStore()

  const {
    incidents = [],
    initialized,
    init,
    upsertIncident,
    lastTick,
  } = useSOCStore()

  // -------------------------------------------------------------------------
  // LIVE EVENT
  // -------------------------------------------------------------------------

  const [liveAttackLogId, setLiveAttackLogId] =
    useState(null)

  // -------------------------------------------------------------------------
  // ACTIVE DATA
  // -------------------------------------------------------------------------

  const [activeIncident, setActiveIncident] =
    useState(null)

  const [predResult, setPredResult] =
    useState(null)

  const [shapResult, setShapResult] =
    useState(null)

  const [metrics, setMetrics] =
    useState(null)

  // -------------------------------------------------------------------------
  // LOADING
  // -------------------------------------------------------------------------

  const [loadingInitialData, setLoadingInitialData] =
    useState(false)

  const [loadingShap, setLoadingShap] =
    useState(false)

  const [loadingMetrics, setLoadingMetrics] =
    useState(false)

  // -------------------------------------------------------------------------
  // OTHER
  // -------------------------------------------------------------------------

  const [history, setHistory] =
    useState([])

  const [error, setError] =
    useState(null)

  /*
  |--------------------------------------------------------------------------
  | 1. INITIALIZE SOC STORE
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
    if (!initialized) {
      init()
    }
  }, [initialized, init])

  /*
  |--------------------------------------------------------------------------
  | 2. FOLLOW EVERY LIVE MONITORING EVENT
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
    const handleMlpPrediction = (event) => {
      const data = event?.detail || {}

      if (
        data.attack_log_id === undefined ||
        data.attack_log_id === null
      ) {
        return
      }

      console.log(
        '[Analytics] LIVE EVENT:',
        {
          id: data.attack_log_id,
          dataset: data.dataset,
          label:
            data.prediction_label ??
            data.attack_type,
          risk: data.risk_score,
        }
      )

      const normalizedEvent = {
        attack_log_id:
          data.attack_log_id,

        id:
          data.attack_log_id,

        attack_type:
          data.prediction_label ??
          data.attack_type ??
          'Unknown',

        prediction_label:
          data.prediction_label ??
          data.attack_type ??
          'Unknown',

        confidence:
          Number(data.confidence ?? 0),

        suspicious_score:
          Number(data.confidence ?? 0),

        risk_score:
          Number(data.risk_score ?? 0),

        severity:
          data.severity ?? 'LOW',

        dataset:
          data.dataset ?? 'Unknown',

        dataset_source:
          data.dataset ?? 'Unknown',

        model_version:
          data.model_version ?? 'MLP',

        raw_features:
          data.raw_features ?? {},

        status:
          'DETECTED',

        detected_at:
          data.timestamp ??
          new Date().toISOString(),

        created_at:
          data.timestamp ??
          new Date().toISOString(),

        mitre_id:
          data.mitre_id ?? null,

        mitre_name:
          data.mitre_name ?? null,

        mitre_technique_id:
          data.mitre_id ?? null,

        mitre_technique_name:
          data.mitre_name ?? null,
      }

      /*
       * Update central SOC store.
       */
      upsertIncident(
        normalizedEvent
      )

      /*
       * CRITICAL:
       * Always follow the newest live Monitoring event.
       */
      setLiveAttackLogId(
        data.attack_log_id
      )

      /*
       * Synchronize the application-wide selected AttackLog.
       */
      setSelectedAttackLogId(
        data.attack_log_id
      )
    }

    window.addEventListener(
      'mlp-prediction',
      handleMlpPrediction
    )

    return () => {
      window.removeEventListener(
        'mlp-prediction',
        handleMlpPrediction
      )
    }
  }, [
    upsertIncident,
    setSelectedAttackLogId,
  ])

  /*
  |--------------------------------------------------------------------------
  | 3. BACKEND FALLBACK
  |--------------------------------------------------------------------------
  |
  | Used when Analytics is opened after Monitoring already generated events.
  |
  */

  useEffect(() => {
    let mounted = true

    const loadBackendLogs = async () => {
      try {
        setLoadingInitialData(true)

        const response =
          await api.get(
            '/logs/latest?limit=100'
          )

        if (!mounted) {
          return
        }

        const logs =
          Array.isArray(response?.data)
            ? response.data
            : []

        logs.forEach((log) => {
          upsertIncident(log)
        })

        /*
         * Only use backend data as initial fallback.
         * A live event always has priority afterwards.
         */
        if (
          liveAttackLogId === null &&
          logs.length > 0
        ) {
          const newestId =
            logs[0]?.attack_log_id ??
            logs[0]?.id

          if (
            newestId !== undefined &&
            newestId !== null
          ) {
            setLiveAttackLogId(
              newestId
            )

            setSelectedAttackLogId(
              newestId
            )
          }
        }
      } catch (err) {
        console.error(
          '[Analytics] Failed to load backend logs:',
          err
        )
      } finally {
        if (mounted) {
          setLoadingInitialData(false)
        }
      }
    }

    loadBackendLogs()

    return () => {
      mounted = false
    }
  }, [
    upsertIncident,
    setSelectedAttackLogId,
    liveAttackLogId,
  ])

  /*
  |--------------------------------------------------------------------------
  | 4. ACTIVE ATTACKLOG
  |--------------------------------------------------------------------------
  */

  const activeAttackLogId =
    useMemo(() => {
      /*
       * Live event is always first priority.
       */
      if (
        liveAttackLogId !== null &&
        liveAttackLogId !== undefined
      ) {
        return liveAttackLogId
      }

      /*
       * Saved selection is fallback.
       */
      if (
        selectedAttackLogId !== null &&
        selectedAttackLogId !== undefined &&
        selectedAttackLogId !== ''
      ) {
        return selectedAttackLogId
      }

      /*
       * Finally use latest store event.
       */
      return (
        incidents[0]?.attack_log_id ??
        incidents[0]?.id ??
        null
      )
    }, [
      liveAttackLogId,
      selectedAttackLogId,
      incidents,
      lastTick,
    ])

  /*
  |--------------------------------------------------------------------------
  | 5. FIND EXACT INCIDENT
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
    if (
      activeAttackLogId === null ||
      activeAttackLogId === undefined
    ) {
      setActiveIncident(null)
      return
    }

    const found =
      incidents.find(
        (incident) =>
          String(
            incident.attack_log_id ??
            incident.id
          ) ===
          String(
            activeAttackLogId
          )
      )

    if (found) {
      setActiveIncident(found)
    }
  }, [
    activeAttackLogId,
    incidents,
    lastTick,
  ])

  /*
  |--------------------------------------------------------------------------
  | 6. EXACT BACKEND FALLBACK
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
    let mounted = true

    const fetchExactIncident =
      async () => {
        if (!activeAttackLogId) {
          return
        }

        const existing =
          incidents.find(
            (incident) =>
              String(
                incident.attack_log_id ??
                incident.id
              ) ===
              String(
                activeAttackLogId
              )
          )

        if (existing) {
          setActiveIncident(existing)
          return
        }

        try {
          const response =
            await api.get(
              '/logs/latest?limit=100'
            )

          if (!mounted) {
            return
          }

          const logs =
            Array.isArray(
              response?.data
            )
              ? response.data
              : []

          const exact =
            logs.find(
              (log) =>
                String(
                  log.attack_log_id ??
                  log.id
                ) ===
                String(
                  activeAttackLogId
                )
            )

          if (exact) {
            upsertIncident(exact)
            setActiveIncident(exact)
          }
        } catch (err) {
          console.error(
            '[Analytics] Exact AttackLog lookup failed:',
            err
          )
        }
      }

    fetchExactIncident()

    return () => {
      mounted = false
    }
  }, [
    activeAttackLogId,
    incidents,
    upsertIncident,
  ])

  /*
  |--------------------------------------------------------------------------
  | 7. BUILD MLP RESULT FROM MONITORING
  |--------------------------------------------------------------------------
  |
  | This DOES NOT run prediction again.
  |
  */

  useEffect(() => {
    if (!activeIncident) {
      setPredResult(null)
      setShapResult(null)
      setMetrics(null)
      return
    }

    const predictionLabel =
      activeIncident.prediction_label ??
      activeIncident.attack_type ??
      'Unknown'

    const dataset =
      activeIncident.dataset ??
      activeIncident.dataset_source ??
      'Unknown'

    const confidence =
      Number(
        activeIncident.confidence ??
        activeIncident.suspicious_score ??
        0
      )

    const riskScore =
      Number(
        activeIncident.risk_score ??
        activeIncident.risk ??
        0
      )

    const modelVersion =
      activeIncident.model_version ??
      'MLP'

    const result = {
      ...activeIncident,

      attack_log_id:
        activeIncident.attack_log_id ??
        activeIncident.id,

      prediction_label:
        predictionLabel,

      prediction_type:
        predictionLabel === 'Normal'
          ? 'NORMAL'
          : 'ATTACK',

      confidence:
        Number.isFinite(confidence)
          ? confidence
          : 0,

      risk_score:
        Number.isFinite(riskScore)
          ? riskScore
          : 0,

      dataset,

      model_version:
        modelVersion,

      method:
        'MLP',

      prediction_source:
        'Live Monitoring / Dataset Replay',

      predicted_at:
        activeIncident.detected_at ??
        activeIncident.created_at ??
        new Date().toISOString(),
    }

    setPredResult(result)

    addPredictionToHistory(result)
  }, [activeIncident])

  /*
  |--------------------------------------------------------------------------
  | 8. LOAD REAL MODEL VALIDATION METRICS
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
    let cancelled = false

    const loadMetrics =
      async () => {
        if (!activeIncident) {
          setMetrics(null)
          return
        }

        const currentDataset =
          activeIncident.dataset ??
          activeIncident.dataset_source

        if (
          !currentDataset ||
          currentDataset === 'Unknown'
        ) {
          setMetrics(null)
          return
        }

        setLoadingMetrics(true)

        try {
          console.log(
            '[Analytics] Loading validation metrics:',
            currentDataset
          )

          const response =
            await api.get(
              `/predict/metrics?dataset=${encodeURIComponent(
                currentDataset
              )}`
            )

          if (cancelled) {
            return
          }

          const data =
            response?.data ?? {}

          console.log(
            '[Analytics] Metrics response:',
            data
          )

          /*
           * The API may return:
           *
           * {
           *   precision,
           *   recall,
           *   f1
           * }
           *
           * or:
           *
           * {
           *   metrics: {
           *      precision,
           *      recall,
           *      f1
           *   }
           * }
           *
           * or sklearn-style:
           *
           * {
           *   "weighted avg": {
           *      precision,
           *      recall,
           *      "f1-score"
           *   }
           * }
           */

          const metricRoot =
            data.metrics ??
            data.raw_metrics ??
            data

          const weightedAvg =
            metricRoot['weighted avg'] ??
            data['weighted avg'] ??
            null

          const macroAvg =
            metricRoot['macro avg'] ??
            data['macro avg'] ??
            null

          const accuracy =
            metricRoot.accuracy ??
            data.accuracy ??
            null

          const precision =
            firstValidMetric(
              data.precision,
              data.Precision,
              metricRoot.precision,
              metricRoot.Precision,
              weightedAvg?.precision,
              macroAvg?.precision
            )

          const recall =
            firstValidMetric(
              data.recall,
              data.Recall,
              metricRoot.recall,
              metricRoot.Recall,
              weightedAvg?.recall,
              macroAvg?.recall
            )

          const f1 =
            firstValidMetric(
              data.f1,
              data.f1_score,
              data.F1,
              data.F1_score,
              data['f1-score'],
              metricRoot.f1,
              metricRoot.f1_score,
              metricRoot.F1,
              metricRoot.F1_score,
              metricRoot['f1-score'],
              weightedAvg?.f1,
              weightedAvg?.['f1-score'],
              macroAvg?.f1,
              macroAvg?.['f1-score']
            )

          setMetrics({
            dataset:
              currentDataset,

            precision,

            recall,

            f1,

            accuracy,
          })

          /*
           * Do not show an error if the endpoint responded
           * successfully but one field is absent.
           */
          if (
            precision == null &&
            recall == null &&
            f1 == null
          ) {
            console.warn(
              `[Analytics] No precision/recall/F1 fields found for ${currentDataset}`
            )
          }
        } catch (err) {
          console.error(
            '[Analytics] Model metrics loading failed:',
            err
          )

          if (!cancelled) {
            setMetrics(null)
          }
        } finally {
          if (!cancelled) {
            setLoadingMetrics(false)
          }
        }
      }

    loadMetrics()

    return () => {
      cancelled = true
    }
  }, [
    activeIncident?.dataset,
    activeIncident?.dataset_source,
    activeAttackLogId,
  ])

  /*
  |--------------------------------------------------------------------------
  | 9. AUTOMATIC SHAP
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
    if (
      !predResult?.attack_log_id
    ) {
      setShapResult(null)
      return
    }

    loadShapExplanation(
      predResult.attack_log_id
    )
  }, [
    predResult?.attack_log_id,
    predResult?.prediction_label,
    predResult?.dataset,
  ])

  /*
  |--------------------------------------------------------------------------
  | 10. SHAP REQUEST
  |--------------------------------------------------------------------------
  */

  const loadShapExplanation =
    async (
      attackLogId
    ) => {
      if (!attackLogId) {
        return
      }

      setLoadingShap(true)
      setError(null)

      try {
        const response =
          await api.get(
            `/xai/explain/${attackLogId}`
          )

        const result =
          response?.data

        /*
         * Verify SAME AttackLog.
         */
        if (
          result?.attack_log_id !==
            undefined &&
          String(
            result.attack_log_id
          ) !==
            String(
              attackLogId
            )
        ) {
          throw new Error(
            'SHAP returned a different AttackLog.'
          )
        }

        /*
         * Verify SAME dataset.
         */
        const shapDataset =
          result?.dataset_source ??
          result?.dataset

        if (
          shapDataset &&
          predResult?.dataset &&
          String(shapDataset) !==
            String(
              predResult.dataset
            )
        ) {
          throw new Error(
            'SHAP dataset does not match the MLP dataset.'
          )
        }

        /*
         * Verify SAME prediction.
         */
        if (
          result?.prediction_label &&
          predResult?.prediction_label &&
          String(
            result.prediction_label
          ) !==
            String(
              predResult.prediction_label
            )
        ) {
          throw new Error(
            'SHAP prediction does not match the MLP prediction.'
          )
        }

        setShapResult(result)
      } catch (err) {
        console.error(
          '[Analytics] SHAP failed:',
          err
        )

        setShapResult(null)

        setError(
          err?.response?.data?.detail ||
          err?.message ||
          'MLP detection succeeded, but SHAP explanation failed.'
        )
      } finally {
        setLoadingShap(false)
      }
    }

  /*
  |--------------------------------------------------------------------------
  | 11. HISTORY
  |--------------------------------------------------------------------------
  */

  const addPredictionToHistory =
    (prediction) => {
      if (
        !prediction?.attack_log_id
      ) {
        return
      }

      const item = {
        id:
          String(
            prediction.attack_log_id
          ),

        time:
          prediction.predicted_at
            ? new Date(
                prediction.predicted_at
              ).toLocaleTimeString()
            : new Date().toLocaleTimeString(),

        attack_type:
          prediction.prediction_label ??
          'Unknown',

        prediction_type:
          prediction.prediction_type ??
          'UNKNOWN',

        confidence:
          Number(
            prediction.confidence ?? 0
          ).toFixed(1),

        risk_score:
          Number(
            prediction.risk_score ?? 0
          ).toFixed(1),

        dataset:
          prediction.dataset ??
          'Unknown',

        attack_log_id:
          prediction.attack_log_id,
      }

      setHistory(
        (previous) => {
          const withoutDuplicate =
            previous.filter(
              (existing) =>
                String(
                  existing.attack_log_id
                ) !==
                String(
                  item.attack_log_id
                )
            )

          return [
            item,
            ...withoutDuplicate,
          ].slice(
            0,
            30
          )
        }
      )
    }

  /*
  |--------------------------------------------------------------------------
  | 12. EXPORT
  |--------------------------------------------------------------------------
  */

  const handleExport =
    () => {
      if (!history.length) {
        return
      }

      const rows =
        history.map(
          (item) =>
            [
              item.time,
              item.attack_type,
              item.prediction_type,
              item.confidence,
              item.risk_score,
              item.dataset,
              item.attack_log_id,
            ].join(',')
        )

      const csv =
        [
          [
            'Time',
            'MLP Label',
            'Prediction',
            'Confidence',
            'Risk Score',
            'Dataset',
            'AttackLog ID',
          ].join(','),
          ...rows,
        ].join('\n')

      const blob =
        new Blob(
          [csv],
          {
            type:
              'text/csv;charset=utf-8;',
          }
        )

      const url =
        URL.createObjectURL(
          blob
        )

      const anchor =
        document.createElement(
          'a'
        )

      anchor.href = url

      anchor.download =
        'mlp-prediction-history.csv'

      document.body.appendChild(
        anchor
      )

      anchor.click()

      document.body.removeChild(
        anchor
      )

      URL.revokeObjectURL(
        url
      )
    }

  /*
  |--------------------------------------------------------------------------
  | 13. REFRESH SHAP
  |--------------------------------------------------------------------------
  */

  const refreshExplanation =
    async () => {
      if (!activeAttackLogId) {
        return
      }

      await loadShapExplanation(
        activeAttackLogId
      )
    }

  /*
  |--------------------------------------------------------------------------
  | 14. REAL METRIC FORMATTER
  |--------------------------------------------------------------------------
  */

  const formatMetric =
    (value) => {
      if (
        value === null ||
        value === undefined ||
        value === ''
      ) {
        return 'N/A'
      }

      const numeric =
        Number(value)

      if (
        !Number.isFinite(
          numeric
        )
      ) {
        return 'N/A'
      }

      /*
       * Handles:
       * 0.94 -> 94%
       * 94 -> 94%
       */
      const percentage =
        numeric <= 1
          ? numeric * 100
          : numeric

      return `${percentage.toFixed(2)}%`
    }

  /*
  |--------------------------------------------------------------------------
  | 15. DERIVED VALUES
  |--------------------------------------------------------------------------
  */

  const predictionLabel =
    predResult?.prediction_label ??
    'Unknown'

  const isNormal =
    predictionLabel ===
    'Normal'

  const riskScore =
    Number(
      predResult?.risk_score ?? 0
    )

  const confidence =
    Number(
      predResult?.confidence ?? 0
    )

  const dataset =
    predResult?.dataset ??
    activeIncident?.dataset ??
    activeIncident?.dataset_source ??
    'Unknown'

  const riskColor =
    isNormal
      ? '#a0aec0'
      : riskScore >= 80
        ? '#ff2d55'
        : riskScore >= 60
          ? '#ffd60a'
          : '#00ff88'

  const topFeatures =
    shapResult?.top_features ??
    []

  const riskTrend =
    [...history]
      .reverse()
      .map(
        (item) => ({
          h:
            item.time,

          risk:
            item.prediction_type ===
            'NORMAL'
              ? 0
              : Number(
                  item.risk_score ?? 0
                ),
        })
      )

  const datasetDescription =
    dataset === 'TON_IoT'
      ? 'Network / IoT telemetry'
      : dataset === 'PhiUSIIL'
        ? 'Phishing / URL telemetry'
        : dataset === 'CERT'
          ? 'User / workstation telemetry'
          : 'Dataset-specific telemetry'

  /*
  |--------------------------------------------------------------------------
  | RENDER
  |--------------------------------------------------------------------------
  */

  return (
    <div className="p-6 space-y-6">

      {/* HEADER */}

      <div className="flex items-center justify-between">

        <div>

          <div className="flex items-center gap-2 mb-1">

            <span className="w-2 h-2 rounded-full bg-cyber-cyan pulse-dot" />

            <span className="text-xs font-mono text-cyber-cyan">
              LIVE MLP + SHAP PIPELINE
            </span>

          </div>

          <h1 className="text-2xl font-black text-white">
            MLP Model Analysis
          </h1>

          <p className="text-xs text-gray-500 mt-1">
            Analytics automatically follows the newest
            event received from live Monitoring.
          </p>

        </div>

        <div className="text-right text-xs font-mono text-gray-500">

          <p>
            AttackLog:{' '}
            <span className="text-white">
              {activeAttackLogId || 'Waiting'}
            </span>
          </p>

          <p>
            Dataset:{' '}
            <span className="text-cyber-cyan">
              {dataset}
            </span>
          </p>

          <p>
            Model:{' '}
            <span className="text-white">
              {predResult?.model_version || 'Waiting'}
            </span>
          </p>

        </div>

      </div>

      {/* LIVE FLOW */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-5">

          <div>

            <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
              LIVE EVENT FLOW
            </p>

            <p className="text-xs text-gray-600 font-mono mt-1">
              One AttackLog is followed from Monitoring
              through MLP and SHAP.
            </p>

          </div>

          <Brain
            size={18}
            className="text-cyber-cyan"
          />

        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">

          <PipelineStep
            number="01"
            title="MONITORING"
            subtitle={
              activeIncident
                ? `Detected ${dataset}`
                : loadingInitialData
                  ? 'Loading'
                  : 'Waiting'
            }
            active={
              Boolean(activeIncident)
            }
          />

          <PipelineArrow />

          <PipelineStep
            number="02"
            title="MLP"
            subtitle={
              predResult
                ? `Classified: ${predictionLabel}`
                : 'Waiting'
            }
            active={
              Boolean(predResult)
            }
          />

          <PipelineArrow />

          <PipelineStep
            number="03"
            title="SHAP"
            subtitle={
              shapResult
                ? 'Explanation ready'
                : loadingShap
                  ? 'Calculating'
                  : 'Waiting'
            }
            active={
              Boolean(shapResult)
            }
          />

        </div>

        {activeIncident && (
          <div className="mt-4 p-3 rounded-lg border border-cyber-border bg-cyber-surface/50">

            <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs font-mono">

              <span>
                Dataset:
                <span className="text-cyber-cyan ml-2">
                  {dataset}
                </span>
              </span>

              <span>
                Telemetry:
                <span className="text-white ml-2">
                  {datasetDescription}
                </span>
              </span>

              <span>
                AttackLog:
                <span className="text-white ml-2">
                  #{activeAttackLogId}
                </span>
              </span>

              <span>
                Status:
                <span className="text-cyber-cyan ml-2">
                  {activeIncident.status || 'DETECTED'}
                </span>
              </span>

            </div>

          </div>
        )}

      </div>

      {/* REAL MODEL METRICS */}

      <div className="grid grid-cols-3 gap-4">

        <MetricCard
          title="PRECISION"
          value={
            loadingMetrics
              ? '...'
              : formatMetric(
                  metrics?.precision
                )
          }
          subtitle={
            `${dataset} · Class Validation`
          }
        />

        <MetricCard
          title="RECALL"
          value={
            loadingMetrics
              ? '...'
              : formatMetric(
                  metrics?.recall
                )
          }
          subtitle={
            `${dataset} · True Positive Rate`
          }
          cyan
        />

        <MetricCard
          title="F1 SCORE"
          value={
            loadingMetrics
              ? '...'
              : formatMetric(
                  metrics?.f1
                )
          }
          subtitle={
            `${dataset} · Harmonic Mean`
          }
        />

      </div>

      {/* OPTIONAL MODEL ACCURACY */}

      {metrics?.accuracy !== null &&
        metrics?.accuracy !== undefined && (
          <div className="text-center text-[10px] font-mono text-gray-600">
            Validation Accuracy:{' '}
            {formatMetric(metrics.accuracy)}
            {' · '}
            {dataset}
          </div>
        )}

      {/* RISK TREND */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-4">

          <div>

            <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
              Predictive Risk Trend
            </p>

            <p className="text-xs text-gray-600 font-mono">
              Live MLP risk values
            </p>

          </div>

          <TrendingUp
            size={16}
            className="text-cyber-cyan"
          />

        </div>

        {riskTrend.length > 0 ? (

          <ResponsiveContainer
            width="100%"
            height={160}
          >

            <LineChart
              data={riskTrend}
            >

              <XAxis
                dataKey="h"
                tick={{
                  fill: '#4a5568',
                  fontSize: 10,
                }}
                interval="preserveStartEnd"
              />

              <YAxis
                domain={[0, 100]}
                tick={{
                  fill: '#4a5568',
                  fontSize: 10,
                }}
              />

              <Tooltip
                contentStyle={{
                  background:
                    '#0d1f3c',
                  border:
                    '1px solid #1a3a6e',
                  borderRadius: 8,
                  fontSize: 11,
                }}
              />

              <Line
                type="monotone"
                dataKey="risk"
                stroke="#00e5ff"
                dot
                strokeWidth={2.5}
              />

            </LineChart>

          </ResponsiveContainer>

        ) : (

          <div className="h-40 flex items-center justify-center text-xs text-gray-600 font-mono">
            Waiting for live Monitoring detection...
          </div>

        )}

      </div>

      {/* MLP RESULT */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-4">

          <div className="flex items-center gap-2">

            <Brain
              size={16}
              className="text-cyber-cyan"
            />

            <h3 className="text-sm font-bold text-white font-mono">
              LIVE MLP PREDICTION
            </h3>

          </div>

          {predResult && (
            <span className="text-[10px] font-mono text-cyber-cyan">
              LIVE
            </span>
          )}

        </div>

        {!predResult ? (

          <div className="p-8 rounded-xl border border-gray-800 bg-black/20 text-center">

            <Brain
              size={22}
              className="text-gray-700 mx-auto mb-3"
            />

            <p className="text-sm text-gray-500 font-mono">
              Waiting for Monitoring to detect an event.
            </p>

            <p className="text-xs text-gray-600 font-mono mt-1">
              TON_IoT, PhiUSIIL and CERT are selected
              automatically by the backend.
            </p>

          </div>

        ) : (

          <div
            className="p-4 rounded-lg border"
            style={{
              borderColor:
                `${riskColor}40`,
              background:
                `${riskColor}08`,
            }}
          >

            <div className="flex items-center justify-between mb-3">

              <span className="text-xs font-mono text-gray-400">
                PREDICTION RESULT
              </span>

              <span
                className="text-xs font-mono font-bold"
                style={{
                  color:
                    riskColor,
                }}
              >
                {isNormal
                  ? 'NORMAL TRAFFIC'
                  : `ATTACK — ${predictionLabel}`}
              </span>

            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">

              <ResultItem
                label="RISK SCORE"
                value={`${riskScore.toFixed(1)}/100`}
                valueStyle={{
                  color:
                    riskColor,
                }}
              />

              <ResultItem
                label="MLP LABEL"
                value={predictionLabel}
              />

              <ResultItem
                label="CONFIDENCE"
                value={`${confidence.toFixed(1)}%`}
                cyan
              />

              <ResultItem
                label="DATASET"
                value={dataset}
                purple
              />

              <ResultItem
                label="MODEL"
                value={
                  predResult?.model_version ||
                  'MLP'
                }
              />

            </div>

            <div className="mt-4 flex items-center gap-2">

              {isNormal ? (

                <CheckCircle
                  size={14}
                  className="text-gray-400"
                />

              ) : (

                <ShieldCheck
                  size={14}
                  className="text-cyber-cyan"
                />

              )}

              <p className="text-xs font-mono text-gray-400">
                Prediction received automatically from
                live Monitoring for AttackLog #
                {activeAttackLogId}.
              </p>

            </div>

          </div>

        )}

      </div>

      {/* SHAP */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-4">

          <div>

            <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
              SHAP EXPLAINABILITY
            </p>

            <p className="text-xs text-gray-600 font-mono">
              Explanation of the SAME MLP prediction
            </p>

          </div>

          <div className="flex items-center gap-2">

            {shapResult && (

              <button
                onClick={
                  refreshExplanation
                }
                className="text-[10px] font-mono text-cyber-cyan hover:underline"
              >
                REFRESH
              </button>

            )}

            <Activity
              size={16}
              className="text-cyber-purple"
            />

          </div>

        </div>

        {loadingShap ? (

          <div className="p-8 text-center">

            <RefreshCw
              size={20}
              className="text-cyber-cyan animate-spin mx-auto mb-3"
            />

            <p className="text-sm text-gray-400 font-mono">
              Calculating SHAP explanation...
            </p>

            <p className="text-xs text-gray-600 font-mono mt-1">
              AttackLog #{activeAttackLogId}
            </p>

          </div>

        ) : shapResult ? (

          <>

            <div className="mb-5 p-4 rounded-lg border border-cyber-purple/30 bg-cyber-purple/5">

              <div className="flex flex-wrap items-center gap-4 mb-3">

                <span className="text-[10px] font-mono text-gray-500">
                  METHOD:
                  <span className="text-cyber-purple ml-2">
                    {shapResult.method || 'SHAP'}
                  </span>
                </span>

                <span className="text-[10px] font-mono text-gray-500">
                  DATASET:
                  <span className="text-cyber-cyan ml-2">
                    {shapResult.dataset_source || dataset}
                  </span>
                </span>

                <span className="text-[10px] font-mono text-gray-500">
                  ATTACKLOG:
                  <span className="text-white ml-2">
                    #{activeAttackLogId}
                  </span>
                </span>

              </div>

              <p className="text-xs font-mono text-gray-500 mb-2">
                EXPLANATION
              </p>

              <p className="text-sm text-gray-300 font-mono leading-relaxed">
                {shapResult.explanation_text ||
                  `The MLP classified this event as ${shapResult.prediction_label}.`}
              </p>

            </div>

            {topFeatures.length > 0 ? (

              <div className="space-y-3">

                <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
                  Top Contributing Features
                </p>

                {topFeatures.map(
                  (
                    feature,
                    index
                  ) => {

                    const value =
                      Number(
                        feature?.shap_value ?? 0
                      )

                    const pct =
                      Math.min(
                        100,
                        Math.max(
                          0,
                          Number(
                            feature?.pct ?? 0
                          )
                        )
                      )

                    return (

                      <div
                        key={`${feature?.feature || 'feature'}-${index}`}
                      >

                        <div className="flex justify-between text-xs font-mono mb-1">

                          <span className="text-gray-400 uppercase">
                            {String(
                              feature?.label ??
                              feature?.feature ??
                              'Feature'
                            ).replace(
                              /_/g,
                              ' '
                            )}
                          </span>

                          <span
                            className={
                              value >= 0
                                ? 'text-cyber-cyan'
                                : 'text-red-400'
                            }
                          >
                            {value.toFixed(4)}
                          </span>

                        </div>

                        <div className="h-2 bg-cyber-surface rounded-full overflow-hidden">

                          <div
                            className={`h-full rounded-full transition-all duration-500 ${
                              value >= 0
                                ? 'bg-gradient-to-r from-cyber-cyan to-cyber-blue'
                                : 'bg-gradient-to-r from-red-500 to-orange-500'
                            }`}
                            style={{
                              width:
                                `${pct}%`,
                            }}
                          />

                        </div>

                        <div className="flex justify-between mt-1 text-[10px] font-mono text-gray-600">

                          <span>
                            Raw:{' '}
                            {String(
                              feature?.raw_value ?? ''
                            )}
                          </span>

                          <span>
                            {feature?.direction ||
                              'neutral'}
                          </span>

                        </div>

                      </div>

                    )
                  }
                )}

              </div>

            ) : (

              <p className="text-gray-500 text-xs font-mono">
                SHAP completed, but no feature attribution was returned.
              </p>

            )}

          </>

        ) : (

          <div className="p-8 rounded-xl border border-gray-800 bg-black/20 text-center">

            <Brain
              size={22}
              className="text-gray-700 mx-auto mb-3"
            />

            <p className="text-sm text-gray-500 font-mono">
              No SHAP explanation available.
            </p>

            <p className="text-xs text-gray-600 font-mono mt-1">
              Waiting for the live MLP event.
            </p>

          </div>

        )}

      </div>

      {/* ERROR */}

      {error && (

        <div className="cyber-card p-4 border border-red-500/30">

          <p className="text-xs text-red-400 font-mono">
            {error}
          </p>

        </div>

      )}

      {/* PIPELINE STATUS */}

      <div className="cyber-card p-5 border border-cyber-cyan/20">

        <div className="flex items-start gap-3">

          <ShieldCheck
            size={18}
            className="text-cyber-cyan mt-0.5"
          />

          <div>

            <p className="text-xs font-mono text-cyber-cyan uppercase tracking-widest">
              AUTOMATIC SECURITY PIPELINE
            </p>

            <p className="text-sm text-gray-300 font-mono mt-2">
              Monitoring receives the dataset event.
              The correct dataset-specific MLP produces
              the classification and risk score. SHAP
              explains the same prediction. QIGA then
              generates the response recommendation.
              Execution remains blocked until an authorized
              administrator or analyst approves the recommendation.
            </p>

          </div>

        </div>

      </div>

      {/* HISTORY */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-4">

          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
            LIVE MLP PREDICTION HISTORY
          </p>

          <button
            onClick={
              handleExport
            }
            disabled={
              history.length === 0
            }
            className="flex items-center gap-1 text-xs font-mono text-cyber-cyan hover:underline disabled:opacity-40"
          >
            <Download
              size={12}
            />
            Export CSV
          </button>

        </div>

        <div className="overflow-x-auto">

          <table className="w-full text-xs font-mono">

            <thead>

              <tr className="text-gray-600 border-b border-cyber-border">

                <th className="pb-2 text-left">
                  TIME
                </th>

                <th className="pb-2 text-left">
                  MLP LABEL
                </th>

                <th className="pb-2 text-left">
                  PREDICTION
                </th>

                <th className="pb-2 text-left">
                  CONFIDENCE
                </th>

                <th className="pb-2 text-left">
                  RISK
                </th>

                <th className="pb-2 text-left">
                  DATASET
                </th>

                <th className="pb-2 text-left">
                  ATTACKLOG
                </th>

              </tr>

            </thead>

            <tbody>

              {history.map(
                (row) => {

                  const normal =
                    row.prediction_type ===
                    'NORMAL'

                  return (

                    <tr
                      key={row.id}
                      className="border-b border-cyber-border/30 hover:bg-white/[0.04] transition-colors"
                    >

                      <td className="py-2 text-gray-400">
                        {row.time}
                      </td>

                      <td className="py-2 text-white font-bold">
                        {row.attack_type || 'Unknown'}
                      </td>

                      <td className="py-2">

                        <span
                          className={`px-2 py-0.5 rounded text-xs font-mono ${
                            normal
                              ? 'bg-gray-800 text-gray-400'
                              : 'bg-red-900/30 text-red-400'
                          }`}
                        >
                          {row.prediction_type}
                        </span>

                      </td>

                      <td className="py-2 text-cyber-cyan font-bold">
                        {row.confidence}%
                      </td>

                      <td
                        className="py-2"
                        style={{
                          color:
                            normal
                              ? '#a0aec0'
                              : Number(
                                  row.risk_score
                                ) > 70
                                ? '#ff2d55'
                                : Number(
                                    row.risk_score
                                  ) > 40
                                  ? '#ffd60a'
                                  : '#00ff88',
                        }}
                      >
                        {normal
                          ? '--'
                          : row.risk_score}
                      </td>

                      <td className="py-2 text-purple-400">
                        {row.dataset || 'Unknown'}
                      </td>

                      <td className="py-2 text-gray-400">
                        #{row.attack_log_id}
                      </td>

                    </tr>

                  )
                }
              )}

              {history.length === 0 && (

                <tr>

                  <td
                    colSpan={7}
                    className="text-center py-6 text-gray-600"
                  >
                    Waiting for live Monitoring events...
                  </td>

                </tr>

              )}

            </tbody>

          </table>

        </div>

      </div>

    </div>
  )
}

/* ============================================================================
   HELPERS
============================================================================ */

function firstValidMetric(...values) {
  for (const value of values) {
    if (
      value !== null &&
      value !== undefined &&
      value !== '' &&
      Number.isFinite(Number(value))
    ) {
      return Number(value)
    }
  }

  return null
}

/* ============================================================================
   SMALL UI COMPONENTS
============================================================================ */

function MetricCard({
  title,
  value,
  subtitle,
  cyan = false,
}) {
  return (
    <div className="cyber-card p-4 text-center">

      <p className="text-xs font-mono text-gray-500 mb-1">
        {title}
      </p>

      <p
        className={`text-2xl font-black font-mono ${
          cyan
            ? 'text-cyber-cyan'
            : 'text-white'
        }`}
      >
        {value}
      </p>

      <p className="text-[10px] text-gray-600 font-mono mt-1">
        {subtitle}
      </p>

    </div>
  )
}

function ResultItem({
  label,
  value,
  cyan = false,
  purple = false,
  valueStyle = {},
}) {
  return (
    <div>

      <p className="text-xs text-gray-500 font-mono">
        {label}
      </p>

      <p
        className={`text-sm font-bold font-mono truncate ${
          cyan
            ? 'text-cyber-cyan'
            : purple
              ? 'text-purple-400'
              : 'text-white'
        }`}
        style={valueStyle}
      >
        {value}
      </p>

    </div>
  )
}

function PipelineStep({
  number,
  title,
  subtitle,
  active,
}) {
  return (
    <div
      className={`rounded-lg border p-3 ${
        active
          ? 'border-cyber-cyan/40 bg-cyber-cyan/5'
          : 'border-cyber-border bg-cyber-surface/30'
      }`}
    >

      <div className="flex items-center gap-2">

        <span
          className={`text-[10px] font-mono ${
            active
              ? 'text-cyber-cyan'
              : 'text-gray-600'
          }`}
        >
          {number}
        </span>

        <span
          className={`text-xs font-bold font-mono ${
            active
              ? 'text-white'
              : 'text-gray-600'
          }`}
        >
          {title}
        </span>

      </div>

      <p className="text-[10px] font-mono text-gray-500 mt-2">
        {subtitle}
      </p>

    </div>
  )
}

function PipelineArrow() {
  return (
    <div className="hidden md:flex items-center justify-center text-gray-700 font-mono">
      →
    </div>
  )
}