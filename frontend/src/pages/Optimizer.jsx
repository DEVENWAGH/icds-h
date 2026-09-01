import React, {
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  Zap,
  RefreshCw,
  Target,
  Cpu,
  Activity,
} from 'lucide-react'

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

import api from '../utils/api'

import {
  useIncidentStore,
} from '../store'

import {
  useSOCStore,
} from '../store/socEngine'


const SEV_COLORS = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff9500',
  MEDIUM: '#ffd60a',
  LOW: '#00ff88',
}


const COST_COLORS = {
  1: '#00ff88',
  2: '#ffd60a',
  3: '#ff9500',
}


const COST_LABELS = {
  1: 'Low',
  2: 'Medium',
  3: 'High',
}


const ACTION_ICONS = {
  ISOLATE: '🔒',
  BLOCK: '🚫',
  RESTORE: '♻️',
  RESET: '🔑',
  LOCK_ACCOUNT: '🔑',
  SEGMENT: '🌐',
  PATCH: '🔧',
  MONITOR: '👁️',
}


const EFFECTIVENESS_COLOR = (value) => {
  if (value > 0.85) {
    return '#00ff88'
  }

  if (value > 0.70) {
    return '#ffd60a'
  }

  return '#ff9500'
}


/*
 * ---------------------------------------------------------
 * Normalize backend QIGA action
 * ---------------------------------------------------------
 *
 * Backend:
 *   {
 *     id,
 *     name,
 *     effectiveness: 0..1,
 *     recovery_time,
 *     cost
 *   }
 *
 * Frontend:
 *   {
 *     type,
 *     title,
 *     effectiveness: 0..100,
 *     recovery_time,
 *     cost
 *   }
 */

function normalizeAction(
  action = {}
) {
  const effectivenessRaw =
    Number(
      action.effectiveness ??
        action.confidence ??
        0
    )

  const effectiveness =
    effectivenessRaw <= 1
      ? effectivenessRaw * 100
      : effectivenessRaw

  return {
    ...action,

    id:
      action.id ??
      action.type ??
      'UNKNOWN',

    type:
      action.type ??
      action.id ??
      'UNKNOWN',

    title:
      action.title ??
      action.name ??
      action.type ??
      action.id ??
      'Response Action',

    effectiveness,

    recovery_time:
      Number(
        action.recovery_time ??
          0
      ),

    cost:
      action.cost ??
      action.resource_cost ??
      'N/A',
  }
}


/*
 * ---------------------------------------------------------
 * Normalize complete QIGA websocket/backend result
 * ---------------------------------------------------------
 */

function normalizeQigaResult(
  data = {},
  attackLogId = null
) {
  const rawActions =
    Array.isArray(
      data.best_actions
    )
      ? data.best_actions
      : Array.isArray(
          data.selected_actions
        )
        ? data.selected_actions
        : []

  const selectedActions =
    rawActions.map(
      normalizeAction
    )

  const convergence =
    Array.isArray(
      data.convergence
    )
      ? data.convergence
      : Array.isArray(
          data.convergence_history
        )
        ? data.convergence_history
        : []

  const effectivenessRaw =
    Number(
      data.combined_effectiveness ??
        data.effectiveness ??
        0
    )

  const effectiveness =
    effectivenessRaw <= 1
      ? effectivenessRaw * 100
      : effectivenessRaw

  const downtime =
    Number(
      data.total_downtime_min ??
        data.downtime ??
        0
    )

  return {
    ...data,

    attack_log_id:
      data.attack_log_id ??
      attackLogId,

    attack_type:
      data.attack_type ??
      'Unknown',

    severity:
      data.severity ??
      'UNKNOWN',

    risk_score:
      Number(
        data.risk_score ??
          0
      ),

    objective_score:
      Number(
        data.objective_score ??
          0
      ),

    effectiveness,

    combined_effectiveness:
      effectiveness,

    combined_cost:
      Number(
        data.combined_cost ??
          data.cost ??
          0
      ),

    downtime,

    total_downtime_min:
      downtime,

    generations:
      Number(
        data.generations ??
          0
      ),

    population_size:
      Number(
        data.population_size ??
          0
      ),

    convergence,
    convergence_history:
      convergence,

    selected_actions:
      selectedActions,

    best_actions:
      selectedActions,
  }
}


/*
 * ---------------------------------------------------------
 * Action row
 * ---------------------------------------------------------
 */

const ActionRow = ({
  action,
  selected,
  rank,
}) => {
  const effectiveness =
    Number(
      action.effectiveness ??
        0
    )

  const effectivenessFraction =
    Math.min(
      1,
      effectiveness / 100
    )

  const costKey =
    Number(
      action.cost
    )

  const costColor =
    COST_COLORS[costKey] ??
    '#00ff88'

  return (
    <tr
      className={`border-b transition-all ${
        selected
          ? 'border-cyber-cyan/40 bg-cyber-cyan/5'
          : 'border-cyber-border/30 hover:bg-white/[0.04] transition-colors'
      }`}
    >

      <td className="py-3 pr-3 font-mono text-xs text-gray-500">
        {rank}
      </td>

      <td className="py-3 pr-3">

        <div className="flex items-center gap-2">

          <span className="text-base">
            {ACTION_ICONS[
              action.type
            ] || '⚡'}
          </span>

          <div>
            <p className="text-xs font-mono font-bold text-white">
              {action.title ||
                action.type}
            </p>

            <p className="text-xs font-mono text-gray-600">
              {action.type}
            </p>
          </div>

          {selected && (
            <span className="ml-1 text-xs font-mono px-2 py-0.5 rounded bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40">
              SELECTED
            </span>
          )}

        </div>

      </td>


      <td className="py-3 pr-3">

        <span
          className="text-xs font-mono px-2 py-0.5 rounded"
          style={{
            background:
              `${costColor}20`,

            color:
              costColor,

            border:
              `1px solid ${costColor}40`,
          }}
        >
          {COST_LABELS[costKey] ??
            action.cost ??
            'N/A'}
        </span>

      </td>


      <td className="py-3 pr-3">

        <div className="flex items-center gap-2">

          <div className="w-16 h-1.5 bg-gray-800 rounded-full">

            <div
              className="h-full rounded-full"
              style={{
                width:
                  `${Math.min(
                    100,
                    Math.max(
                      0,
                      effectiveness
                    )
                  )}%`,

                background:
                  EFFECTIVENESS_COLOR(
                    effectivenessFraction
                  ),
              }}
            />

          </div>

          <span
            className="text-xs font-mono"
            style={{
              color:
                EFFECTIVENESS_COLOR(
                  effectivenessFraction
                ),
            }}
          >
            {effectiveness.toFixed(0)}%
          </span>

        </div>

      </td>


      <td className="py-3 pr-3 text-xs font-mono text-gray-400">

        {action.recovery_time
          ? `${Number(
              action.recovery_time
            ).toFixed(0)} min`
          : 'N/A'}

      </td>


      <td className="py-3 text-xs font-mono font-bold text-cyber-cyan">
        —
      </td>

    </tr>
  )
}


/*
 * =========================================================
 * MAIN COMPONENT
 * =========================================================
 */

export default function Optimizer() {
  const {
    selectedAttackLogId,
  } = useIncidentStore()

  const incidents =
    useSOCStore(
      (s) => s.incidents
    )

  /*
   * Use SAME AttackLog selected by Monitoring.
   */

  const selectedLog =
    incidents.find(
      (incident) =>
        String(
          incident.attack_log_id ??
            incident.id
        ) ===
        String(
          selectedAttackLogId
        )
    )

  const isNormal =
    selectedLog?.attack_type ===
    'Normal'


  const [result, setResult] =
    useState(null)

  const [loading, setLoading] =
    useState(false)

  const [error, setError] =
    useState(null)

  const [animating, setAnimating] =
    useState(false)


  /*
   * -------------------------------------------------------
   * Automatically receive QIGA event from WebSocket
   * -------------------------------------------------------
   */

  useEffect(() => {
    const handleQiga =
      (event) => {
        const data =
          event?.detail ?? {}

        if (
          data.attack_log_id ===
          undefined ||
          data.attack_log_id ===
          null
        ) {
          return
        }

        /*
         * Only accept QIGA results for the selected
         * AttackLog.
         */

        if (
          selectedAttackLogId ===
          null ||
          selectedAttackLogId ===
          undefined
        ) {
          return
        }

        if (
          String(
            data.attack_log_id
          ) !==
          String(
            selectedAttackLogId
          )
        ) {
          return
        }

        console.log(
          '[Optimizer] Automatic QIGA result received:',
          data
        )

        const normalized =
          normalizeQigaResult(
            data,
            selectedAttackLogId
          )

        setResult(
          normalized
        )

        setError(null)
        setAnimating(true)

        setTimeout(
          () => {
            setAnimating(
              false
            )
          },
          1200
        )
      }


    window.addEventListener(
      'qiga-recommendation',
      handleQiga
    )

    return () => {
      window.removeEventListener(
        'qiga-recommendation',
        handleQiga
      )
    }
  }, [
    selectedAttackLogId,
  ])


  /*
   * -------------------------------------------------------
   * When selected AttackLog changes, clear old QIGA result
   * -------------------------------------------------------
   */

  useEffect(() => {
    setResult(null)
    setError(null)
    setAnimating(false)
  }, [
    selectedAttackLogId,
  ])


  /*
   * -------------------------------------------------------
   * Load latest QIGA result when opening the page
   * -------------------------------------------------------
   *
   * The backend /optimize/latest endpoint does not currently
   * return attack_log_id. Therefore this is only a fallback
   * for the currently latest matching threat.
   *
   * The authoritative automatic association is the websocket
   * qiga-recommendation event.
   */

  useEffect(() => {
    if (
      !selectedAttackLogId ||
      !selectedLog ||
      isNormal
    ) {
      return
    }

    let mounted = true

    const loadLatest =
      async () => {
        try {
          const response =
            await api.get(
              '/optimize/latest?limit=10'
            )

          if (
            !mounted
          ) {
            return
          }

          const rows =
            Array.isArray(
              response.data
            )
              ? response.data
              : []

          const matching =
            rows.find(
              (item) =>
                String(
                  item.attack_type
                ) ===
                String(
                  selectedLog.attack_type
                ) &&
                Math.abs(
                  Number(
                    item.risk_score ??
                      0
                  ) -
                  Number(
                    selectedLog.risk_score ??
                      0
                  )
                ) < 0.01
            )

          if (
            matching &&
            !result
          ) {
            setResult(
              normalizeQigaResult(
                matching,
                selectedAttackLogId
              )
            )
          }

        } catch (err) {
          console.warn(
            '[Optimizer] Latest QIGA result unavailable:',
            err
          )
        }
      }

    loadLatest()

    return () => {
      mounted = false
    }
  }, [
    selectedAttackLogId,
    selectedLog,
    isNormal,
    result,
  ])


  /*
   * -------------------------------------------------------
   * Manual refresh
   * -------------------------------------------------------
   *
   * We deliberately DO NOT call POST /optimize here.
   *
   * QIGA is already automatically executed by backend after
   * MLP + SHAP.
   *
   * Refresh simply asks the backend for latest stored results.
   */

  const refreshOptimizer =
    async () => {
      if (
        !selectedAttackLogId ||
        !selectedLog ||
        isNormal
      ) {
        return
      }

      setLoading(true)
      setError(null)

      try {
        const response =
          await api.get(
            '/optimize/latest?limit=10'
          )

        const rows =
          Array.isArray(
            response.data
          )
            ? response.data
            : []

        const matching =
          rows.find(
            (item) =>
              String(
                item.attack_type
              ) ===
              String(
                selectedLog.attack_type
              ) &&
              Math.abs(
                Number(
                  item.risk_score ??
                    0
                ) -
                Number(
                  selectedLog.risk_score ??
                    0
                )
              ) < 0.01
          )

        if (!matching) {
          throw new Error(
            'QIGA result for this event is not available yet.'
          )
        }

        setResult(
          normalizeQigaResult(
            matching,
            selectedAttackLogId
          )
        )

      } catch (err) {
        setError(
          err?.response?.data?.detail ||
            err?.message ||
            'QIGA result is not available yet.'
        )
      } finally {
        setLoading(false)
      }
    }


  /*
   * -------------------------------------------------------
   * Empty state
   * -------------------------------------------------------
   */

  if (
    !selectedAttackLogId
  ) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto pb-20">

        <div className="cyber-card p-10 flex flex-col items-center justify-center text-center">

          <Cpu
            size={48}
            className="text-gray-600 mb-4"
          />

          <h2 className="text-xl font-bold font-mono text-white mb-2">
            Waiting for Live Threat
          </h2>

          <p className="text-gray-400 font-mono text-sm max-w-md">
            Select an event from Monitoring,
            or wait for the next automatic
            dataset replay event.
          </p>

        </div>

      </div>
    )
  }


  /*
   * -------------------------------------------------------
   * Normal traffic
   * -------------------------------------------------------
   */

  if (isNormal) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto pb-20">

        <div className="cyber-card p-10 flex flex-col items-center justify-center text-center">

          <Cpu
            size={48}
            className="text-gray-600 mb-4"
          />

          <h2 className="text-xl font-bold font-mono text-white mb-2">
            QIGA Not Applicable
          </h2>

          <p className="text-gray-400 font-mono text-sm max-w-md">
            AttackLog #
            {selectedAttackLogId}
            {' '}
            is classified as Normal traffic.
            QIGA response optimization is only
            generated for confirmed threats.
          </p>

        </div>

      </div>
    )
  }


  /*
   * -------------------------------------------------------
   * Derived values
   * -------------------------------------------------------
   */

  const selectedActions =
    result?.selected_actions ??
    []

  const convergenceData =
    (
      result?.convergence ??
      result?.convergence_history ??
      []
    ).map(
      (value, index) => ({
        gen:
          index + 1,

        F:
          Number(value ?? 0),
      })
    )


  const combinedEffectiveness =
    Number(
      result?.combined_effectiveness ??
        result?.effectiveness ??
        0
    )


  const combinedCost =
    Number(
      result?.combined_cost ??
        result?.cost ??
        0
    )


  const downtime =
    Number(
      result?.total_downtime_min ??
        result?.downtime ??
        0
    )


  const objBreakdown = [
    {
      name: 'Downtime',
      value: downtime,
      color: '#ff9500',
      weight: 'Minutes',
    },

    {
      name: 'Cost',
      value: combinedCost,
      color: '#bf5af2',
      weight: 'Relative',
    },

    {
      name: 'Effectiveness',
      value:
        combinedEffectiveness,
      color: '#00ff88',
      weight: 'Score %',
    },
  ]


  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto pb-20">

      {/* ================================================= */}
      {/* HEADER                                            */}
      {/* ================================================= */}

      <div className="flex items-center justify-between flex-wrap gap-3">

        <div>

          <p className="text-xs font-mono text-gray-500 mb-1">
            QUANTUM-INSPIRED RESPONSE OPTIMIZATION
          </p>

          <h1 className="text-2xl font-black text-white">
            QIGA Response Optimizer
          </h1>

          <p className="text-xs text-gray-500 mt-1">
            Automatically optimized after live MLP detection
            for the selected AttackLog.
          </p>

        </div>


        <div className="flex items-center gap-3">

          <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded border border-purple-700/40 bg-purple-900/20 text-purple-400">

            <span className="w-2 h-2 rounded-full bg-purple-400 pulse-dot" />

            {result
              ? `QIGA COMPLETE · ${result.generations ?? 0} GENERATIONS`
              : 'QIGA WAITING'}

          </div>


          <button
            onClick={
              refreshOptimizer
            }
            disabled={
              loading ||
              !selectedAttackLogId
            }
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-mono font-bold transition-all disabled:opacity-50"
            style={{
              background:
                loading
                  ? '#1a3a6e'
                  : 'linear-gradient(135deg, #bf5af2, #0066ff)',

              color:
                '#fff',
            }}
          >

            {loading ? (
              <>
                <RefreshCw
                  size={14}
                  className="animate-spin"
                />
                Loading...
              </>
            ) : (
              <>
                <RefreshCw
                  size={14}
                />
                Refresh Result
              </>
            )}

          </button>

        </div>

      </div>


      {/* ================================================= */}
      {/* ERROR                                             */}
      {/* ================================================= */}

      {error && (

        <div className="text-red-400 font-mono text-sm p-4 bg-red-900/20 border border-red-500 rounded">
          {error}
        </div>

      )}


      {/* ================================================= */}
      {/* LIVE THREAT CONTEXT                               */}
      {/* ================================================= */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-4">

          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
            Selected Threat Context
          </p>

          <Activity
            size={15}
            className="text-cyber-cyan"
          />

        </div>


        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">

          <div>
            <p className="text-xs font-mono text-gray-500 mb-2">
              ATTACKLOG
            </p>

            <p className="text-sm font-mono font-bold text-white">
              #{selectedAttackLogId}
            </p>
          </div>


          <div>
            <p className="text-xs font-mono text-gray-500 mb-2">
              DATASET
            </p>

            <p className="text-sm font-mono font-bold text-cyber-cyan">
              {selectedLog?.dataset ||
                'Unknown'}
            </p>
          </div>


          <div>
            <p className="text-xs font-mono text-gray-500 mb-2">
              ATTACK TYPE
            </p>

            <p className="text-sm font-mono font-bold text-white">
              {selectedLog?.attack_type ||
                'Unknown'}
            </p>
          </div>


          <div>
            <p className="text-xs font-mono text-gray-500 mb-2">
              SEVERITY
            </p>

            <p
              className="text-sm font-mono font-bold"
              style={{
                color:
                  SEV_COLORS[
                    selectedLog?.severity
                  ] ||
                  '#ffd60a',
              }}
            >
              {selectedLog?.severity ||
                'Unknown'}
            </p>
          </div>


          <div>
            <p className="text-xs font-mono text-gray-500 mb-2">
              MLP RISK
            </p>

            <p className="text-sm font-mono font-bold text-cyber-red">
              {Number(
                selectedLog?.risk_score ??
                  0
              ).toFixed(1)}
            </p>
          </div>

        </div>


        <div className="mt-4 p-3 rounded-lg border border-cyber-cyan/20 bg-cyber-cyan/5">

          <p className="text-xs text-gray-400 font-mono">

            Flow:
            <span className="text-white ml-2">
              Monitoring
            </span>

            <span className="text-cyber-cyan mx-2">
              →
            </span>

            <span className="text-white">
              MLP
            </span>

            <span className="text-cyber-cyan mx-2">
              →
            </span>

            <span className="text-white">
              SHAP
            </span>

            <span className="text-cyber-cyan mx-2">
              →
            </span>

            <span className="text-purple-400">
              QIGA
            </span>

            <span className="text-cyber-cyan mx-2">
              →
            </span>

            <span className="text-white">
              Admin Approval
            </span>

            <span className="text-cyber-cyan mx-2">
              →
            </span>

            <span className="text-white">
              Recovery
            </span>

          </p>

        </div>

      </div>


      {/* ================================================= */}
      {/* WAITING STATE                                     */}
      {/* ================================================= */}

      {!result && (

        <div className="cyber-card p-10 text-center">

          <RefreshCw
            size={28}
            className="text-cyber-purple animate-spin mx-auto mb-3"
          />

          <p className="text-sm text-gray-300 font-mono">
            Waiting for automatic QIGA optimization...
          </p>

          <p className="text-xs text-gray-600 font-mono mt-2">
            The backend runs QIGA automatically after
            MLP detection and SHAP explanation.
          </p>

        </div>

      )}


      {/* ================================================= */}
      {/* KEY METRICS                                       */}
      {/* ================================================= */}

      {result && (

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">

          <div className="cyber-card p-4 text-center">

            <p className="text-xs font-mono text-gray-500 mb-1">
              OBJECTIVE SCORE F
            </p>

            <p className="text-2xl font-black font-mono text-cyber-cyan">
              {Number(
                result.objective_score ??
                  0
              ).toFixed(4)}
            </p>

            <p className="text-xs font-mono text-gray-600 mt-1">
              Minimized
            </p>

          </div>


          <div className="cyber-card p-4 text-center">

            <p className="text-xs font-mono text-gray-500 mb-1">
              EFFECTIVENESS
            </p>

            <p className="text-2xl font-black font-mono text-green-400">
              {combinedEffectiveness.toFixed(1)}%
            </p>

            <p className="text-xs font-mono text-gray-600 mt-1">
              Combined response
            </p>

          </div>


          <div className="cyber-card p-4 text-center">

            <p className="text-xs font-mono text-gray-500 mb-1">
              RECOVERY TIME
            </p>

            <p className="text-2xl font-black font-mono text-yellow-400">
              {downtime.toFixed(1)} min
            </p>

            <p className="text-xs font-mono text-gray-600 mt-1">
              Estimated downtime
            </p>

          </div>


          <div className="cyber-card p-4 text-center">

            <p className="text-xs font-mono text-gray-500 mb-1">
              ACTIONS SELECTED
            </p>

            <p className="text-2xl font-black font-mono text-purple-400">
              {selectedActions.length}
            </p>

            <p className="text-xs font-mono text-gray-600 mt-1">
              Optimal response set
            </p>

          </div>

        </div>

      )}


      {/* ================================================= */}
      {/* CONVERGENCE + OBJECTIVE                           */}
      {/* ================================================= */}

      {result && (

        <div className="grid lg:grid-cols-2 gap-5">

          <div className="cyber-card p-5">

            <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">
              QIGA Convergence — F per Generation
            </p>

            {convergenceData.length > 0 ? (

              <ResponsiveContainer
                width="100%"
                height={160}
              >

                <LineChart
                  data={
                    convergenceData
                  }
                >

                  <XAxis
                    dataKey="gen"
                    tick={{
                      fill: '#4a5568',
                      fontSize: 9,
                    }}
                  />

                  <YAxis
                    tick={{
                      fill: '#4a5568',
                      fontSize: 9,
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
                    formatter={(value) => [
                      Number(
                        value
                      ).toFixed(4),
                      'F',
                    ]}
                  />

                  <Line
                    type="monotone"
                    dataKey="F"
                    stroke="#bf5af2"
                    strokeWidth={2}
                    dot={false}
                    animationDuration={
                      animating
                        ? 1200
                        : 0
                    }
                  />

                </LineChart>

              </ResponsiveContainer>

            ) : (

              <div className="h-40 flex items-center justify-center text-xs text-gray-600 font-mono">
                Convergence data not returned by this QIGA run.
              </div>

            )}

            <p className="text-xs font-mono text-gray-600 mt-2 text-center">
              Generations:
              {' '}
              {result.generations ??
                0}
              {' · '}
              Population:
              {' '}
              {result.population_size ??
                'N/A'}
            </p>

          </div>


          <div className="cyber-card p-5">

            <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">
              Objective Profile
            </p>

            <div className="space-y-3 mb-4">

              {objBreakdown.map(
                ({
                  name,
                  value,
                  color,
                  weight,
                }) => (

                  <div
                    key={name}
                  >

                    <div className="flex justify-between text-xs font-mono mb-1">

                      <span
                        style={{
                          color,
                        }}
                      >
                        {name}
                        {' '}
                        ({weight})
                      </span>

                      <span className="text-white font-bold">
                        {Number(
                          value
                        ).toFixed(2)}
                      </span>

                    </div>


                    <div className="h-2 bg-gray-800 rounded-full">

                      <div
                        className="h-2 rounded-full transition-all duration-700"
                        style={{
                          width:
                            `${Math.min(
                              100,
                              Math.max(
                                0,
                                Number(
                                  value
                                )
                              )
                            )}%`,

                          background:
                            color,
                        }}
                      />

                    </div>

                  </div>
                )
              )}

            </div>


            <div className="bg-cyber-bg/60 rounded-lg p-3 border border-cyber-border/40 font-mono text-xs">

              <p className="text-gray-500 mb-1">
                Objective Function
              </p>

              <p className="text-cyber-cyan">
                F =
                {' '}
                <span
                  style={{
                    color:
                      '#ff9500',
                  }}
                >
                  α·Downtime
                </span>
                {' + '}
                <span
                  style={{
                    color:
                      '#ff2d55',
                  }}
                >
                  β·DataLoss
                </span>
                {' + '}
                <span
                  style={{
                    color:
                      '#bf5af2',
                  }}
                >
                  γ·Cost
                </span>
              </p>

              <p className="text-gray-600 mt-1">
                Weights:
                {' '}
                α={result.alpha ?? '0.40'}
                {' · '}
                β={result.beta ?? '0.35'}
                {' · '}
                γ={result.gamma ?? '0.25'}
              </p>

            </div>

          </div>

        </div>

      )}


      {/* ================================================= */}
      {/* SELECTED ACTIONS                                 */}
      {/* ================================================= */}

      {result &&
        selectedActions.length >
          0 && (

        <div className="cyber-card p-5 border border-cyber-cyan/30">

          <div className="flex items-center gap-3 mb-4">

            <div className="w-8 h-8 rounded-lg bg-cyber-cyan/20 flex items-center justify-center">

              <Target
                size={16}
                className="text-cyber-cyan"
              />

            </div>

            <div>

              <p className="text-sm font-bold text-white font-mono">
                Optimal Strategy Selected
              </p>

              <p className="text-xs text-gray-500">
                QIGA objective:
                {' '}
                {Number(
                  result.objective_score ??
                    0
                ).toFixed(4)}
              </p>

            </div>

          </div>


          <div className="grid gap-3">

            {selectedActions.map(
              (
                action,
                index
              ) => (

                <div
                  key={
                    action.id ||
                    index
                  }
                  className="flex items-center gap-4 p-3 rounded-lg"
                  style={{
                    background:
                      '#00e5ff08',
                    border:
                      '1px solid #00e5ff30',
                  }}
                >

                  <span className="text-2xl">
                    {ACTION_ICONS[
                      action.type
                    ] || '⚡'}
                  </span>


                  <div className="flex-1">

                    <p className="text-sm font-mono font-bold text-white">
                      {action.title ||
                        action.type}
                    </p>

                    <div className="flex flex-wrap gap-3 mt-1 text-xs font-mono text-gray-500">

                      <span>
                        Cost:
                        {' '}
                        {COST_LABELS[
                          Number(
                            action.cost
                          )
                        ] ??
                          action.cost ??
                          'N/A'}
                      </span>

                      <span>
                        Effectiveness:
                        {' '}
                        {Number(
                          action.effectiveness ??
                            0
                        ).toFixed(0)}%
                      </span>

                      <span>
                        Recovery:
                        {' '}
                        {action.recovery_time
                          ? `${Number(
                              action.recovery_time
                            ).toFixed(0)} min`
                          : 'N/A'}
                      </span>

                    </div>

                  </div>

                </div>

              )
            )}

          </div>

        </div>
      )}


      {/* ================================================= */}
      {/* ACTION BREAKDOWN                                 */}
      {/* ================================================= */}

      {result &&
        selectedActions.length >
          0 && (

        <div className="cyber-card p-5">

          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-4">
            QIGA Selected Response Actions
          </p>

          <div className="overflow-x-auto">

            <table className="w-full text-xs font-mono">

              <thead>

                <tr className="border-b border-cyber-border text-gray-500 uppercase">

                  <th className="pb-2 text-left pr-3">
                    #
                  </th>

                  <th className="pb-2 text-left pr-3">
                    Action
                  </th>

                  <th className="pb-2 text-left pr-3">
                    Cost
                  </th>

                  <th className="pb-2 text-left pr-3">
                    Effectiveness
                  </th>

                  <th className="pb-2 text-left pr-3">
                    Recovery
                  </th>

                  <th className="pb-2 text-left">
                    F Score
                  </th>

                </tr>

              </thead>


              <tbody>

                {selectedActions.map(
                  (
                    action,
                    index
                  ) => (

                    <ActionRow
                      key={
                        action.id ||
                        index
                      }
                      action={
                        action
                      }
                      selected={
                        true
                      }
                      rank={
                        index + 1
                      }
                    />

                  )
                )}

              </tbody>

            </table>

          </div>

        </div>
      )}

    </div>
  )
}

