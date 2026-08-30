import React, { useEffect, useMemo, useState } from 'react'

import {
  Brain,
  Download,
  RefreshCcw,
  Eye,
  Activity,
} from 'lucide-react'

import {
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Cell,
} from 'recharts'

import api from '../utils/api'
import { useIncidentStore, useSOCStore } from '../store'

// =============================================================================
// COLORS
// =============================================================================

const RISK_COLORS = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff9500',
  MEDIUM: '#ffd60a',
  LOW: '#00ff88',
  NORMAL: '#00ff88',
}

const METHOD_COLORS = {
  SHAP: '#00e5ff',
  LIME: '#bf5af2',
  'Permutation Importance': '#ffd60a',
}

// =============================================================================
// HELPERS
// =============================================================================

function toNumber(value, fallback = 0) {
  const n = Number(value)
  return Number.isFinite(n) ? n : fallback
}

function normalizeFeatureList(data) {
  if (!data) return []

  const directArrays = [
    data.top_features,
    data.all_features,
    data.features,
    data.attributions,
    data.feature_importance,
  ]

  for (const value of directArrays) {
    if (Array.isArray(value) && value.length > 0) {
      return value.map((item, index) => {
        if (typeof item === 'object' && item !== null) {
          return {
            ...item,

            feature:
              item.feature ??
              item.name ??
              item.feature_name ??
              item.label ??
              `Feature ${index + 1}`,

            label:
              item.label ??
              item.feature ??
              item.name ??
              item.feature_name ??
              `Feature ${index + 1}`,
          }
        }

        return {
          feature: `Feature ${index + 1}`,
          label: `Feature ${index + 1}`,
          shap_value: toNumber(item),
          abs_value: Math.abs(toNumber(item)),
        }
      })
    }
  }

  if (
    data.shap_values &&
    typeof data.shap_values === 'object' &&
    !Array.isArray(data.shap_values)
  ) {
    return Object.entries(data.shap_values).map(
      ([name, value]) => ({
        feature: name,
        label: name,
        shap_value: toNumber(value),
        abs_value: Math.abs(toNumber(value)),
      })
    )
  }

  if (
    Array.isArray(data.feature_names) &&
    Array.isArray(data.shap_values)
  ) {
    return data.feature_names.map((name, index) => {
      const value = toNumber(data.shap_values[index])

      return {
        feature: String(name),
        label: String(name),
        shap_value: value,
        abs_value: Math.abs(value),
      }
    })
  }

  return []
}

function getFeaturePercentage(feature, allFeatures) {
  const explicit = Number(feature?.pct)

  if (Number.isFinite(explicit)) {
    const percentage =
      Math.abs(explicit) <= 1 && explicit !== 0
        ? Math.abs(explicit) * 100
        : Math.abs(explicit)

    return Math.min(100, percentage)
  }

  const abs = Math.abs(
    toNumber(
      feature?.abs_value ??
        feature?.absolute_contribution ??
        feature?.importance ??
        feature?.shap_value
    )
  )

  const total = allFeatures.reduce(
    (sum, item) =>
      sum +
      Math.abs(
        toNumber(
          item?.abs_value ??
            item?.absolute_contribution ??
            item?.importance ??
            item?.shap_value
        )
      ),
    0
  )

  if (total > 0) {
    return Math.min(100, (abs / total) * 100)
  }

  return 0
}

// =============================================================================
// FEATURE BAR
// =============================================================================

function FeatureBar({ feature, allFeatures }) {
  const shapValue = toNumber(
    feature?.shap_value ??
      feature?.shap ??
      feature?.value ??
      feature?.contribution
  )

  const pct = getFeaturePercentage(feature, allFeatures)

  const increasesRisk = shapValue >= 0

  const color = increasesRisk
    ? '#ff2d55'
    : '#00ff88'

  const label =
    feature?.label ??
    feature?.feature ??
    feature?.name ??
    'Feature'

  return (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-mono text-gray-300 truncate max-w-[60%]">
          {String(label).replace(/_/g, ' ')}
        </span>

        <div className="flex items-center gap-2">
          <span
            className="text-xs font-mono font-bold"
            style={{ color }}
          >
            {pct.toFixed(1)}%
          </span>

          <span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded"
            style={{
              background: `${color}15`,
              color,
              border: `1px solid ${color}40`,
            }}
          >
            {increasesRisk ? '↑ RISK' : '↓ RISK'}
          </span>
        </div>
      </div>

      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${pct}%`,
            background: color,
          }}
        />
      </div>

      <div className="flex justify-between mt-1 text-[10px] font-mono text-gray-600">
        <span>
          SHAP: {shapValue.toFixed(4)}
        </span>

        <span>
          Raw:{' '}
          {String(
            feature?.raw_value ??
              feature?.raw ??
              'N/A'
          )}
        </span>
      </div>
    </div>
  )
}

// =============================================================================
// XAI PAGE
// =============================================================================

export default function XAI() {
  const {
    selectedAttackLogId,
    setSelectedAttackLogId,
  } = useIncidentStore()

  /*
   * IMPORTANT:
   * This assumes your store exports useSOCStore.
   */
  const incidents = useSOCStore(
    (state) => state.incidents || []
  )

  const [
    liveAttackLogId,
    setLiveAttackLogId,
  ] = useState(
    selectedAttackLogId ?? null
  )

  const [loading, setLoading] = useState(false)

  const [xaiResult, setXaiResult] = useState(null)

  const [activeIncident, setActiveIncident] =
    useState(null)

  const [error, setError] = useState(null)

  const [activeTab, setActiveTab] =
    useState('bars')

  // ===========================================================================
  // LIVE MONITORING EVENT
  // ===========================================================================

  useEffect(() => {
    const handleLivePrediction = (event) => {
      const data = event?.detail || {}

      if (
        data.attack_log_id === undefined ||
        data.attack_log_id === null
      ) {
        return
      }

      console.log(
        '[XAI] Live Monitoring event:',
        data
      )

      setLiveAttackLogId(
        data.attack_log_id
      )

      setSelectedAttackLogId(
        data.attack_log_id
      )

      setActiveIncident({
        attack_log_id:
          data.attack_log_id,

        id: data.attack_log_id,

        attack_type:
          data.prediction_label ??
          data.attack_type ??
          'Unknown',

        prediction_label:
          data.prediction_label ??
          data.attack_type ??
          'Unknown',

        confidence: data.confidence,

        risk_score: data.risk_score,

        severity: data.severity,

        dataset: data.dataset,

        dataset_source: data.dataset,

        model_version:
          data.model_version,

        raw_features:
          data.raw_features,

        status: 'DETECTED',

        detected_at:
          data.timestamp ??
          new Date().toISOString(),

        mitre_id: data.mitre_id,

        mitre_name: data.mitre_name,
      })
    }

    window.addEventListener(
      'mlp-prediction',
      handleLivePrediction
    )

    return () => {
      window.removeEventListener(
        'mlp-prediction',
        handleLivePrediction
      )
    }
  }, [setSelectedAttackLogId])

  // ===========================================================================
  // FOLLOW CURRENT SOC INCIDENT
  // ===========================================================================

  useEffect(() => {
    if (
      liveAttackLogId === null ||
      liveAttackLogId === undefined
    ) {
      return
    }

    const found = incidents.find(
      (incident) =>
        String(
          incident.attack_log_id ??
            incident.id
        ) ===
        String(liveAttackLogId)
    )

    if (found) {
      setActiveIncident(found)
    }
  }, [incidents, liveAttackLogId])

  // ===========================================================================
  // INITIAL / FALLBACK LOAD
  // ===========================================================================

  useEffect(() => {
    if (
      liveAttackLogId !== null &&
      liveAttackLogId !== undefined
    ) {
      return
    }

    if (
      selectedAttackLogId !== null &&
      selectedAttackLogId !== undefined
    ) {
      setLiveAttackLogId(
        selectedAttackLogId
      )

      return
    }

    const newest = incidents[0]

    if (!newest) return

    const id =
      newest.attack_log_id ??
      newest.id

    if (
      id !== undefined &&
      id !== null
    ) {
      setLiveAttackLogId(id)

      setSelectedAttackLogId(id)
    }
  }, [
    selectedAttackLogId,
    incidents,
    liveAttackLogId,
    setSelectedAttackLogId,
  ])

  // ===========================================================================
  // LOAD SHAP
  // ===========================================================================

  const loadExplanation = async (
    attackLogId = liveAttackLogId
  ) => {
    if (
      attackLogId === null ||
      attackLogId === undefined ||
      attackLogId === ''
    ) {
      setXaiResult(null)
      setError(null)
      return
    }

    setLoading(true)
    setError(null)

    try {
      console.log(
        '[XAI] Loading SHAP for AttackLog:',
        attackLogId
      )

      const response = await api.get(
        `/xai/explain/${attackLogId}`
      )

      const data = response?.data

      console.log(
        '[XAI] Backend response:',
        data
      )

      if (!data) {
        throw new Error(
          'XAI endpoint returned an empty response.'
        )
      }

      const normalized =
        normalizeFeatureList(data)

      setXaiResult({
        ...data,
        top_features: normalized,
        all_features: normalized,
      })

      if (normalized.length === 0) {
        setError(
          'The XAI endpoint responded, but no SHAP feature values were returned.'
        )
      }
    } catch (err) {
      console.error(
        '[XAI] SHAP error:',
        err
      )

      setXaiResult(null)

      setError(
        err?.response?.data?.detail ||
          err?.message ||
          'Unable to generate SHAP explanation.'
      )
    } finally {
      setLoading(false)
    }
  }

  // ===========================================================================
  // AUTOMATIC SHAP
  // ===========================================================================

  useEffect(() => {
    if (
      liveAttackLogId === null ||
      liveAttackLogId === undefined
    ) {
      return
    }

    loadExplanation(liveAttackLogId)

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveAttackLogId])

  // ===========================================================================
  // FEATURES
  // ===========================================================================

  const topFeatures = useMemo(() => {
    const normalized =
      normalizeFeatureList(xaiResult)

    return [...normalized]
      .sort(
        (a, b) =>
          Math.abs(
            toNumber(
              b?.abs_value ??
                b?.shap_value ??
                b?.value
            )
          ) -
          Math.abs(
            toNumber(
              a?.abs_value ??
                a?.shap_value ??
                a?.value
            )
          )
      )
      .slice(0, 12)
  }, [xaiResult])

  // ===========================================================================
  // RADAR DATA
  // ===========================================================================

  const radarData = useMemo(
    () =>
      topFeatures
        .slice(0, 8)
        .map((feature) => ({
          subject: String(
            feature?.label ??
              feature?.feature ??
              'Feature'
          ).slice(0, 18),

          value: Number(
            getFeaturePercentage(
              feature,
              topFeatures
            ).toFixed(1)
          ),
        })),
    [topFeatures]
  )

  // ===========================================================================
  // BAR DATA
  // ===========================================================================

  const barData = useMemo(
    () =>
      topFeatures
        .slice(0, 10)
        .map((feature) => ({
          name: String(
            feature?.label ??
              feature?.feature ??
              'Feature'
          )
            .replace(/_/g, ' ')
            .slice(0, 20),

          value: Number(
            getFeaturePercentage(
              feature,
              topFeatures
            ).toFixed(1)
          ),

          positive:
            toNumber(
              feature?.shap_value ??
                feature?.shap ??
                feature?.value
            ) >= 0,
        })),
    [topFeatures]
  )

  // ===========================================================================
  // EXPORT
  // ===========================================================================

  const handleExport = () => {
    if (
      !xaiResult ||
      !topFeatures.length
    ) {
      return
    }

    const rows = topFeatures.map(
      (feature) =>
        [
          feature?.feature ?? '',
          feature?.shap_value ?? '',
          feature?.abs_value ?? '',
          feature?.pct ?? '',
          feature?.direction ?? '',
          feature?.raw_value ?? '',
        ]
          .map(
            (value) =>
              `"${String(value).replace(
                /"/g,
                '""'
              )}"`
          )
          .join(',')
    )

    const csv = [
      'FEATURE,SHAP VALUE,ABSOLUTE CONTRIBUTION,PERCENTAGE,DIRECTION,RAW VALUE',
      ...rows,
    ].join('\n')

    const blob = new Blob(
      [csv],
      {
        type:
          'text/csv;charset=utf-8;',
      }
    )

    const url =
      URL.createObjectURL(blob)

    const anchor =
      document.createElement('a')

    anchor.href = url

    anchor.download =
      `shap-explanation-${liveAttackLogId}.csv`

    document.body.appendChild(anchor)

    anchor.click()

    document.body.removeChild(anchor)

    URL.revokeObjectURL(url)
  }

  // ===========================================================================
  // DERIVED VALUES
  // ===========================================================================

  const label =
    xaiResult?.prediction_label ??
    activeIncident?.prediction_label ??
    activeIncident?.attack_type ??
    'Waiting'

  const isAttack =
    label !== 'Normal' &&
    label !== 'Waiting'

  const dataset =
    xaiResult?.dataset ??
    xaiResult?.dataset_source ??
    activeIncident?.dataset ??
    activeIncident?.dataset_source ??
    'Waiting'

  const confidence = toNumber(
    xaiResult?.confidence ??
      activeIncident?.confidence ??
      0
  )

  const riskScore = toNumber(
    xaiResult?.risk_score ??
      activeIncident?.risk_score ??
      0
  )

  const riskBand =
    riskScore >= 80
      ? 'CRITICAL'
      : riskScore >= 60
        ? 'HIGH'
        : riskScore >= 40
          ? 'MEDIUM'
          : 'LOW'

  const riskColor = isAttack
    ? RISK_COLORS[riskBand]
    : RISK_COLORS.NORMAL

  const methodUsed =
    xaiResult?.method ?? 'SHAP'

  const methodColor =
    METHOD_COLORS[methodUsed] ??
    METHOD_COLORS.SHAP

  const modelInfo =
    xaiResult?.model_info ?? {}

  const featureCount =
    xaiResult?.feature_count ??
    modelInfo?.feature_count ??
    topFeatures.length

  const modelVersion =
    modelInfo?.model_version ??
    activeIncident?.model_version ??
    'MLP'

  const baseValue =
    xaiResult?.base_value

  // ===========================================================================
  // UI
  // ===========================================================================

  return (
    <div className="p-6 space-y-6">

      {/* HEADER */}

      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyber-cyan pulse-dot" />

            <span className="text-xs font-mono text-cyber-cyan">
              LIVE XAI ANALYSIS
            </span>
          </div>

          <h1 className="text-2xl font-black text-white">
            Decision Transparency (XAI)
          </h1>

          <p className="text-xs text-gray-500 mt-1">
            SHAP explains the exact MLP prediction produced by live Monitoring.
          </p>
        </div>

        <div className="flex flex-col items-end gap-2">
          <div className="text-right">
            <p className="text-xs text-gray-500 font-mono">
              ATTACKLOG{' '}
              <span className="text-white">
                {liveAttackLogId ?? 'Waiting'}
              </span>
            </p>

            <p className="text-xs text-gray-500 font-mono mt-1">
              DATASET{' '}
              <span className="text-cyber-cyan">
                {dataset}
              </span>
            </p>
          </div>

          <button
            onClick={() =>
              loadExplanation(
                liveAttackLogId
              )
            }
            disabled={
              loading ||
              !liveAttackLogId
            }
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-mono font-bold transition-all disabled:opacity-50"
            style={{
              background: loading
                ? '#1a3a6e'
                : 'linear-gradient(135deg, #0066ff, #00e5ff)',
              color: '#000',
            }}
          >
            {loading ? (
              <>
                <RefreshCcw
                  size={14}
                  className="animate-spin"
                />

                Computing...
              </>
            ) : (
              <>
                <Brain size={14} />

                Refresh SHAP
              </>
            )}
          </button>
        </div>
      </div>

      {/* PIPELINE */}

      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
              SECURITY ANALYSIS PIPELINE
            </p>

            <p className="text-xs text-gray-600 font-mono mt-1">
              Same AttackLog through the complete live analysis.
            </p>
          </div>

          <Activity
            size={16}
            className="text-cyber-cyan"
          />
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">

          <PipelineStep
            number="01"
            title="MONITORING"
            active={Boolean(activeIncident)}
            subtitle={
              activeIncident
                ? `Detected ${dataset}`
                : 'Waiting'
            }
          />

          <PipelineStep
            number="02"
            title="MLP"
            active={Boolean(activeIncident)}
            subtitle={
              activeIncident
                ? `Classified ${label}`
                : 'Waiting'
            }
          />

          <PipelineStep
            number="03"
            title="ATTACKLOG"
            active={Boolean(liveAttackLogId)}
            subtitle={
              liveAttackLogId
                ? `#${liveAttackLogId}`
                : 'Waiting'
            }
          />

          <PipelineStep
            number="04"
            title="SHAP"
            active={Boolean(xaiResult)}
            subtitle={
              loading
                ? 'Calculating'
                : topFeatures.length
                  ? `${topFeatures.length} features ready`
                  : 'Waiting'
            }
          />

        </div>
      </div>

      {/* RESULT CARDS */}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        <div className="cyber-card p-6 text-center">
          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
            MLP PREDICTION
          </p>

          <div
            className="text-3xl font-black font-mono my-3"
            style={{
              color: riskColor,
              textShadow:
                `0 0 20px ${riskColor}60`,
            }}
          >
            {label}
          </div>

          <div
            className="text-xs font-mono px-3 py-1 rounded-full inline-block"
            style={{
              background:
                `${riskColor}20`,
              color: riskColor,
              border:
                `1px solid ${riskColor}40`,
            }}
          >
            {isAttack
              ? 'THREAT DETECTED'
              : label === 'Normal'
                ? 'NORMAL TRAFFIC'
                : 'WAITING FOR LIVE EVENT'}
          </div>

          <div className="grid grid-cols-2 gap-3 mt-5">

            <ResultMini
              label="CONFIDENCE"
              value={`${confidence.toFixed(1)}%`}
            />

            <ResultMini
              label="RISK"
              value={`${riskScore.toFixed(1)}/100`}
            />

          </div>
        </div>

        <div className="cyber-card p-6 text-center">

          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
            SHAP CONTEXT
          </p>

          <div className="text-xl font-bold font-mono text-cyber-cyan my-3">
            {dataset}
          </div>

          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mt-4">
            SHAP BASE VALUE
          </p>

          <div className="text-2xl font-black font-mono text-white mt-2">
            {baseValue !== undefined &&
            baseValue !== null
              ? Number(baseValue).toFixed(4)
              : '—'}
          </div>

          <p className="text-[10px] text-gray-600 font-mono mt-2 leading-relaxed">
            Expected/reference model output before
            this event's feature contributions.
          </p>

        </div>

        <div className="cyber-card p-6">

          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-3">
            XAI METHOD
          </p>

          <div className="flex items-center gap-3 mb-4">

            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center"
              style={{
                background:
                  `${methodColor}20`,
                border:
                  `1px solid ${methodColor}40`,
              }}
            >
              <Eye
                size={20}
                style={{
                  color: methodColor,
                }}
              />
            </div>

            <div>
              <p
                className="text-lg font-black font-mono"
                style={{
                  color: methodColor,
                }}
              >
                {methodUsed}
              </p>

              <p className="text-xs text-gray-500">
                Shapley Additive Explanations
              </p>
            </div>

          </div>

          <p className="text-xs font-mono text-gray-400 leading-relaxed italic">
            "{xaiResult?.explanation_text ??
              'Waiting for the live MLP event and SHAP explanation...'}"
          </p>

        </div>
      </div>

      {/* MODEL INFORMATION */}

      <div className="cyber-card p-5">

        <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">
          LIVE MODEL INFORMATION
        </p>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">

          <InfoCard
            label="DATASET"
            value={dataset}
          />

          <InfoCard
            label="FEATURES"
            value={featureCount || '—'}
          />

          <InfoCard
            label="MODEL VERSION"
            value={modelVersion}
          />

          <InfoCard
            label="ATTACKLOG"
            value={
              liveAttackLogId
                ? `#${liveAttackLogId}`
                : 'Waiting'
            }
          />

        </div>
      </div>

      {/* SHAP FEATURE ATTRIBUTION */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-4">

          <div>
            <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
              SHAP FEATURE ATTRIBUTION
            </p>

            <p className="text-xs text-gray-600 font-mono mt-1">
              Positive values increase the predicted risk; negative values decrease it.
            </p>
          </div>

          <div className="flex gap-2">

            <button
              onClick={() =>
                setActiveTab('bars')
              }
              className="text-xs font-mono px-3 py-1 rounded border"
              style={{
                borderColor:
                  activeTab === 'bars'
                    ? '#00e5ff'
                    : '#1a3a6e',

                background:
                  activeTab === 'bars'
                    ? '#00e5ff15'
                    : 'transparent',

                color:
                  activeTab === 'bars'
                    ? '#00e5ff'
                    : '#4a5568',
              }}
            >
              Bar Chart
            </button>

            <button
              onClick={() =>
                setActiveTab('radar')
              }
              className="text-xs font-mono px-3 py-1 rounded border"
              style={{
                borderColor:
                  activeTab === 'radar'
                    ? '#00e5ff'
                    : '#1a3a6e',

                background:
                  activeTab === 'radar'
                    ? '#00e5ff15'
                    : 'transparent',

                color:
                  activeTab === 'radar'
                    ? '#00e5ff'
                    : '#4a5568',
              }}
            >
              Radar
            </button>

          </div>
        </div>

        {loading ? (

          <div className="h-72 flex items-center justify-center">

            <RefreshCcw
              size={20}
              className="text-cyber-cyan animate-spin mr-3"
            />

            <span className="text-xs font-mono text-gray-500">
              Calculating SHAP values...
            </span>

          </div>

        ) : topFeatures.length === 0 ? (

          <div className="h-72 flex flex-col items-center justify-center text-center border border-cyber-border rounded-lg">

            <Brain
              size={26}
              className="text-cyber-cyan mb-3"
            />

            <p className="text-sm text-gray-400 font-mono">
              No SHAP feature values returned
            </p>

            <p className="text-xs text-gray-600 font-mono mt-2 max-w-lg">
              The page is connected to the XAI endpoint,
              but the response does not contain feature
              attribution data yet.
            </p>

            {error && (
              <p className="text-[10px] text-red-400 font-mono mt-3 max-w-xl">
                {error}
              </p>
            )}

          </div>

        ) : activeTab === 'bars' ? (

          <div>

            <div className="w-full h-[360px]">

              <ResponsiveContainer
                width="100%"
                height="100%"
              >

                <BarChart
                  data={barData}
                  layout="vertical"
                  margin={{
                    top: 10,
                    right: 30,
                    left: 10,
                    bottom: 10,
                  }}
                >

                  <CartesianGrid
                    stroke="#1a3a6e"
                    strokeDasharray="3 3"
                    horizontal={false}
                  />

                  <XAxis
                    type="number"
                    domain={[0, 100]}
                    tick={{
                      fill: '#6b7280',
                      fontSize: 10,
                      fontFamily: 'monospace',
                    }}
                    tickFormatter={(value) =>
                      `${value}%`
                    }
                  />

                  <YAxis
                    type="category"
                    dataKey="name"
                    width={150}
                    tick={{
                      fill: '#9ca3af',
                      fontSize: 10,
                      fontFamily: 'monospace',
                    }}
                  />

                  <Tooltip
                    formatter={(value) => [
                      `${value}%`,
                      'Contribution',
                    ]}
                    contentStyle={{
                      background: '#0d1f3c',
                      border:
                        '1px solid #1a3a6e',
                      borderRadius: 8,
                      fontSize: 11,
                    }}
                  />

                  <Bar
                    dataKey="value"
                    name="SHAP Contribution"
                    radius={[0, 4, 4, 0]}
                    isAnimationActive
                  >
                    {barData.map(
                      (entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={
                            entry.positive
                              ? '#ff2d55'
                              : '#00ff88'
                          }
                        />
                      )
                    )}
                  </Bar>

                </BarChart>

              </ResponsiveContainer>

            </div>

            <div className="flex gap-5 mt-3 pt-4 border-t border-cyber-border">

              <span className="flex items-center gap-2 text-xs font-mono text-gray-500">
                <span className="w-3 h-1.5 rounded bg-red-500" />
                Increases Risk
              </span>

              <span className="flex items-center gap-2 text-xs font-mono text-gray-500">
                <span className="w-3 h-1.5 rounded bg-green-500" />
                Decreases Risk
              </span>

            </div>

            <div className="mt-5">

              {topFeatures.map(
                (feature, index) => (
                  <FeatureBar
                    key={
                      `${feature?.feature ?? 'feature'}-${index}`
                    }
                    feature={feature}
                    allFeatures={topFeatures}
                  />
                )
              )}

            </div>

          </div>

        ) : (

          <div className="w-full h-[360px]">

            {radarData.length >= 3 ? (

              <ResponsiveContainer
                width="100%"
                height="100%"
              >

                <RadarChart
                  data={radarData}
                  outerRadius="72%"
                >

                  <PolarGrid
                    stroke="#1a3a6e"
                  />

                  <PolarAngleAxis
                    dataKey="subject"
                    tick={{
                      fill: '#9ca3af',
                      fontSize: 10,
                      fontFamily: 'monospace',
                    }}
                  />

                  <Radar
                    name="SHAP Attribution"
                    dataKey="value"
                    stroke="#00e5ff"
                    fill="#00e5ff"
                    fillOpacity={0.25}
                  />

                  <Tooltip
                    formatter={(value) => [
                      `${value}%`,
                      'Contribution',
                    ]}
                    contentStyle={{
                      background: '#0d1f3c',
                      border:
                        '1px solid #1a3a6e',
                      borderRadius: 8,
                      fontSize: 11,
                    }}
                  />

                </RadarChart>

              </ResponsiveContainer>

            ) : (

              <div className="h-full flex items-center justify-center text-xs font-mono text-gray-600">
                At least 3 SHAP features are required for the radar chart.
              </div>

            )}

          </div>

        )}

      </div>

      {/* ERROR */}

      {error && topFeatures.length > 0 && (
        <div className="cyber-card p-4 border border-yellow-500/30">

          <p className="text-xs text-yellow-400 font-mono">
            {error}
          </p>

        </div>
      )}

      {/* EXPORT */}

      <div className="grid grid-cols-2 gap-3">

        <button
          onClick={handleExport}
          disabled={!topFeatures.length}
          className="cyber-card p-4 flex items-center justify-center gap-2 text-sm font-mono text-white hover:border-cyber-cyan/40 transition-colors disabled:opacity-40"
        >
          <Download
            size={16}
            className="text-cyber-cyan"
          />

          Export XAI CSV Report
        </button>

        <div className="cyber-card p-4 flex items-center justify-center gap-2 text-sm font-mono text-gray-500">

          <Activity
            size={16}
            className="text-cyber-purple"
          />

          QIGA follows automatically after SHAP

        </div>

      </div>

    </div>
  )
}

// =============================================================================
// SMALL COMPONENTS
// =============================================================================

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

function ResultMini({
  label,
  value,
}) {
  return (
    <div>

      <p className="text-[10px] text-gray-500 font-mono">
        {label}
      </p>

      <p className="text-sm font-bold font-mono text-white mt-1">
        {value}
      </p>

    </div>
  )
}

function InfoCard({
  label,
  value,
}) {
  return (
    <div className="rounded-lg border border-cyber-border bg-black/10 p-3">

      <p className="text-[10px] text-gray-600 font-mono">
        {label}
      </p>

      <p className="text-sm text-white font-bold font-mono mt-1 truncate">
        {value}
      </p>

    </div>
  )
}