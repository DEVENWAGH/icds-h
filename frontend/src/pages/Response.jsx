import React, {
  useEffect,
  useRef,
  useState,
} from 'react'

import {
  Zap,
  ShieldOff,
  RotateCcw,
  Key,
  Ban,
  CheckCircle,
  RefreshCw,
  AlertTriangle,
  Terminal,
} from 'lucide-react'

import api from '../utils/api'

import {
  useAuthStore,
  useIncidentStore,
} from '../store'

import {
  useSOCStore,
  LIFECYCLE_STAGES,
} from '../store/socEngine'


const ACTION_ICONS = {
  ISOLATE: ShieldOff,
  RESTORE: RotateCcw,
  RESET: Key,
  BLOCK: Ban,
  PATCH: Zap,
}


const STATUS_STYLE = {
  PENDING:
    'text-gray-400 border-gray-600 bg-gray-900/20',

  IN_PROGRESS:
    'text-yellow-400 border-yellow-600 bg-yellow-900/20',

  COMPLETED:
    'text-green-400 border-green-700 bg-green-900/20',

  FAILED:
    'text-red-400 border-red-700 bg-red-900/20',
}


const LIFECYCLE_STYLE = {
  DETECTED: {
    text: 'text-red-400',
    bg: 'bg-red-900/20',
    border: 'border-red-500/50',
    dot: 'bg-red-400',
  },

  ANALYZING: {
    text: 'text-yellow-400',
    bg: 'bg-yellow-900/20',
    border: 'border-yellow-500/50',
    dot: 'bg-yellow-400',
  },

  CONTAINMENT: {
    text: 'text-orange-400',
    bg: 'bg-orange-900/20',
    border: 'border-orange-500/50',
    dot: 'bg-orange-400',
  },

  RECOVERY: {
    text: 'text-blue-400',
    bg: 'bg-blue-900/20',
    border: 'border-blue-500/50',
    dot: 'bg-blue-400',
  },

  RESOLVED: {
    text: 'text-green-400',
    bg: 'bg-green-900/20',
    border: 'border-green-500/50',
    dot: 'bg-green-400',
  },
}


function recommendationConfidence(value) {
  const numeric = Number(value)

  if (!Number.isFinite(numeric)) {
    return null
  }

  if (numeric <= 1) {
    return Math.round(numeric * 100)
  }

  return Math.round(numeric)
}


function confidenceColor(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return '#6b7280'
  }

  if (value > 90) {
    return '#00ff88'
  }

  if (value > 80) {
    return '#00e5ff'
  }

  return '#ffd60a'
}


export default function Response() {
  const { user } = useAuthStore()

  const {
    selectedAttackLogId,
    setSelectedAttackLogId,
  } = useIncidentStore()

  const incidents = useSOCStore(
    (state) => state.incidents
  )

  /*
   * -------------------------------------------------------
   * ACTIVE REAL THREATS
   * -------------------------------------------------------
   */

  const activeThreats = incidents
    .filter(
      (incident) =>
        incident.is_threat &&
        !incident.resolved &&
        incident.attack_type !== 'Normal'
    )
    .sort(
      (a, b) =>
        Number(b.risk_score || 0) -
        Number(a.risk_score || 0)
    )


  /*
   * -------------------------------------------------------
   * SELECTED ATTACK LOG
   * -------------------------------------------------------
   */

  const selectedLog = incidents.find(
    (incident) => {
      const id =
        incident.attack_log_id ??
        incident.id

      return (
        String(id) ===
        String(selectedAttackLogId)
      )
    }
  )


  const isNormal =
    selectedLog?.attack_type === 'Normal'


  /*
   * IMPORTANT:
   * Backend itself enforces admin/analyst authorization.
   * This frontend check only controls the UI.
   */

  const normalizedRole =
    String(
      user?.role ?? ''
    ).toLowerCase()

  const canApprove =
    normalizedRole === 'admin' ||
    normalizedRole === 'analyst'


  /*
   * -------------------------------------------------------
   * LOCAL STATE
   * -------------------------------------------------------
   */

  const [recs, setRecs] = useState([])
  const [recoveries, setRecoveries] =
    useState([])

  const [loading, setLoading] =
    useState(false)

  const [selectedRecovery, setSelectedRecovery] =
    useState(null)

  const [error, setError] =
    useState(null)

  const [lastQigaRun, setLastQigaRun] =
    useState(null)

  const logRef =
    useRef(null)


  /*
   * -------------------------------------------------------
   * DEFAULT THREAT SELECTION
   * -------------------------------------------------------
   *
   * When Response opens without an explicit selection,
   * use the highest-risk active real threat.
   */

  useEffect(() => {
    if (
      (
        selectedAttackLogId === null ||
        selectedAttackLogId === undefined
      ) &&
      activeThreats.length > 0
    ) {
      const firstThreat =
        activeThreats[0]

      const threatId =
        firstThreat.attack_log_id ??
        firstThreat.id

      setSelectedAttackLogId(
        threatId
      )
    }
  }, [
    selectedAttackLogId,
    activeThreats,
    setSelectedAttackLogId,
  ])


  /*
   * -------------------------------------------------------
   * LOAD DATA FOR EXACT ATTACKLOG
   * -------------------------------------------------------
   *
   * Do NOT fetch every recommendation/recovery in the
   * database. The backend already supports attack_log_id
   * filtering.
   */

  const loadResponseData = async (
    attackLogId,
    showLoading = true
  ) => {
    if (
      attackLogId === null ||
      attackLogId === undefined ||
      attackLogId === ''
    ) {
      return
    }

    if (showLoading) {
      setLoading(true)
    }

    setError(null)

    try {
      const [
        recommendationsResponse,
        recoveryResponse,
      ] = await Promise.all([
        api.get(
          `/recommendations/?attack_log_id=${attackLogId}&limit=100`
        ),

        api.get(
          `/recovery/?attack_log_id=${attackLogId}&limit=100`
        ),
      ])

      const recommendations =
        Array.isArray(
          recommendationsResponse.data
        )
          ? recommendationsResponse.data
          : []

      const recoveryActions =
        Array.isArray(
          recoveryResponse.data
        )
          ? recoveryResponse.data
          : []

      setRecs(
        recommendations
      )

      setRecoveries(
        recoveryActions
      )

      setSelectedRecovery(
        (current) => {
          if (!current) {
            return (
              recoveryActions[0] ??
              null
            )
          }

          const refreshed =
            recoveryActions.find(
              (item) =>
                String(item.id) ===
                String(current.id)
            )

          return (
            refreshed ??
            recoveryActions[0] ??
            null
          )
        }
      )

    } catch (err) {
      console.error(
        '[Response] Failed to load response data:',
        err
      )

      setError(
        err?.response?.data?.detail ||
          'Unable to load QIGA recommendations or recovery actions.'
      )

      setRecs([])
      setRecoveries([])
      setSelectedRecovery(null)
    } finally {
      if (showLoading) {
        setLoading(false)
      }
    }
  }


  /*
   * -------------------------------------------------------
   * LOAD WHEN ATTACKLOG CHANGES
   * -------------------------------------------------------
   */

  useEffect(() => {
    if (
      selectedAttackLogId === null ||
      selectedAttackLogId === undefined ||
      isNormal
    ) {
      setRecs([])
      setRecoveries([])
      setSelectedRecovery(null)
      setLastQigaRun(null)
      setError(null)
      setLoading(false)

      return undefined
    }

    loadResponseData(
      selectedAttackLogId,
      true
    )
  }, [
    selectedAttackLogId,
    isNormal,
  ])


  /*
   * -------------------------------------------------------
   * QIGA WEBSOCKET EVENT
   * -------------------------------------------------------
   *
   * This solves an important timing problem:
   *
   * Monitoring event arrives
   *      ↓
   * Backend runs QIGA
   *      ↓
   * Response page receives qiga-recommendation
   *      ↓
   * Response reloads exact AttackLog recommendations
   */

  useEffect(() => {
    const handleQigaRecommendation = (
      event
    ) => {
      const data =
        event?.detail ?? {}

      const eventAttackLogId =
        data.attack_log_id

      if (
        eventAttackLogId ===
        undefined ||
        eventAttackLogId ===
        null
      ) {
        return
      }

      if (
        selectedAttackLogId === null ||
        selectedAttackLogId ===
        undefined
      ) {
        return
      }

      if (
        String(
          eventAttackLogId
        ) !==
        String(
          selectedAttackLogId
        )
      ) {
        return
      }

      console.log(
        '[Response] QIGA recommendation received for selected AttackLog:',
        eventAttackLogId
      )

      setLastQigaRun(
        data
      )

      loadResponseData(
        selectedAttackLogId,
        false
      )
    }

    window.addEventListener(
      'qiga-recommendation',
      handleQigaRecommendation
    )

    return () => {
      window.removeEventListener(
        'qiga-recommendation',
        handleQigaRecommendation
      )
    }
  }, [
    selectedAttackLogId,
  ])


  /*
   * -------------------------------------------------------
   * REFRESH WHEN LIFECYCLE CHANGES
   * -------------------------------------------------------
   */

  useEffect(() => {
    const handleLifecycleUpdate = (
      event
    ) => {
      const data =
        event?.detail ?? {}

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

      loadResponseData(
        selectedAttackLogId,
        false
      )
    }

    window.addEventListener(
      'lifecycle-update',
      handleLifecycleUpdate
    )

    return () => {
      window.removeEventListener(
        'lifecycle-update',
        handleLifecycleUpdate
      )
    }
  }, [
    selectedAttackLogId,
  ])


  /*
   * -------------------------------------------------------
   * POLL RECOVERY STATUS
   * -------------------------------------------------------
   */

  useEffect(() => {
    if (
      !selectedRecovery?.id
    ) {
      return undefined
    }

    if (
      selectedRecovery.status !==
        'PENDING' &&
      selectedRecovery.status !==
        'IN_PROGRESS'
    ) {
      return undefined
    }

    let mounted = true

    const pollRecovery = async () => {
      try {
        const response =
          await api.get(
            `/recovery/${selectedRecovery.id}`
          )

        if (!mounted) {
          return
        }

        const data =
          response.data

        setSelectedRecovery(
          data
        )

        setRecoveries(
          (previous) =>
            previous.map(
              (item) =>
                String(item.id) ===
                String(data.id)
                  ? data
                  : item
            )
        )

      } catch (err) {
        console.error(
          '[Response] Recovery polling failed:',
          err
        )
      }
    }

    pollRecovery()

    const interval =
      setInterval(
        pollRecovery,
        2000
      )

    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [
    selectedRecovery?.id,
    selectedRecovery?.status,
  ])


  /*
   * -------------------------------------------------------
   * EXECUTION LOG AUTO-SCROLL
   * -------------------------------------------------------
   */

  useEffect(() => {
    if (
      logRef.current
    ) {
      logRef.current.scrollTop =
        logRef.current.scrollHeight
    }
  }, [
    selectedRecovery?.execution_log,
  ])


  /*
   * -------------------------------------------------------
   * APPROVAL
   * -------------------------------------------------------
   *
   * One QIGA recommendation can be authorized.
   *
   * The backend:
   *   - verifies admin/analyst role
   *   - creates RecoveryAction
   *   - changes AttackLog to CONTAINMENT
   *   - starts recovery
   *
   * The frontend does NOT execute recovery itself.
   */

  const approve = async (
    recommendationId
  ) => {
    if (
      !canApprove ||
      !recommendationId ||
      selectedAttackLogId ===
        null ||
      selectedAttackLogId ===
        undefined
    ) {
      return
    }

    /*
     * Do not authorize another action while an
     * existing recovery for this AttackLog is active.
     */

    const hasActiveRecovery =
      recoveries.some(
        (recovery) =>
          (
            recovery.status ===
              'PENDING' ||
            recovery.status ===
              'IN_PROGRESS'
          )
      )

    if (hasActiveRecovery) {
      setError(
        'A recovery workflow is already active for this AttackLog.'
      )
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response =
        await api.patch(
          `/recommendations/${recommendationId}/approve`
        )

      console.log(
        '[Response] Recommendation authorized:',
        response.data
      )

      /*
       * Re-read the exact AttackLog response state.
       */
      await loadResponseData(
        selectedAttackLogId,
        false
      )

    } catch (err) {
      console.error(
        '[Response] Approval failed:',
        err
      )

      setError(
        err?.response?.data?.detail ||
          'Unable to authorize this response action.'
      )
    } finally {
      setLoading(false)
    }
  }


  const reject = async (
    recommendationId
  ) => {
    if (
      !canApprove ||
      !recommendationId ||
      selectedAttackLogId === null ||
      selectedAttackLogId === undefined
    ) {
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response = await api.patch(
        `/recommendations/${recommendationId}/reject`
      )
      console.log(
        '[Response] Recommendation rejected:',
        response.data
      )
      await loadResponseData(
        selectedAttackLogId,
        false
      )
    } catch (err) {
      console.error(
        '[Response] Rejection failed:',
        err
      )
      setError(
        err?.response?.data?.detail ||
          'Unable to reject this response action.'
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    const handleRecoveryProgress = (event) => {
      const data = event?.detail ?? {}
      if (
        selectedRecovery &&
        String(selectedRecovery.id) === String(data.recovery_id)
      ) {
        setSelectedRecovery((prev) => ({
          ...prev,
          progress_percent: data.progress_percent,
          current_step: data.current_step,
          status: data.status,
        }))
      }
      setRecoveries((prev) =>
        prev.map((r) =>
          String(r.id) === String(data.recovery_id)
            ? {
                ...r,
                progress_percent: data.progress_percent,
                current_step: data.current_step,
                status: data.status,
              }
            : r
        )
      )
    }

    window.addEventListener(
      'recovery-progress',
      handleRecoveryProgress
    )
    return () => {
      window.removeEventListener(
        'recovery-progress',
        handleRecoveryProgress
      )
    }
  }, [selectedRecovery?.id])

  /*
   * -------------------------------------------------------
   * DERIVED RESPONSE DATA
   * -------------------------------------------------------
   */

  const pendingRecs = recs.filter(
    (recommendation) =>
      recommendation.status === 'PENDING' ||
      (!recommendation.status && !recommendation.is_approved)
  )

  const primary =
    pendingRecs[0] ??
    recs[0] ??
    null

  const alternatives =
    primary
      ? recs.filter(
          (recommendation) =>
            String(
              recommendation.id
            ) !==
            String(
              primary.id
            )
        )
      : []

  const activeRecoveries =
    recoveries.filter(
      (recovery) =>
        recovery.status ===
          'PENDING' ||
        recovery.status ===
          'IN_PROGRESS'
    )

  const completedRecoveries =
    recoveries.filter(
      (recovery) =>
        recovery.status ===
        'COMPLETED'
    )

  const hasApprovedRecommendation =
    recs.some(
      (recommendation) =>
        recommendation.is_approved
    )

  const hasAnyRecovery =
    recoveries.length > 0

  const approvalLocked =
    hasApprovedRecommendation ||
    hasAnyRecovery ||
    activeRecoveries.length > 0

  const currentStatus =
    selectedLog?.status ||
    'DETECTED'

  const currentStageIndex =
    Math.max(
      0,
      LIFECYCLE_STAGES.indexOf(
        currentStatus
      )
    )

  const primaryConfidence =
    primary
      ? recommendationConfidence(
          primary.confidence_score
        )
      : null

  const statusStyle =
    LIFECYCLE_STYLE[
      currentStatus
    ] ||
    LIFECYCLE_STYLE.DETECTED


  return (
    <div className="p-6 space-y-6">

      {/* ================================================= */}
      {/* HEADER                                            */}
      {/* ================================================= */}

      <div className="flex items-center justify-between">

        <div>
          <h1 className="text-2xl font-black text-white">
            Incident Response &amp; Recovery
          </h1>

          <p className="text-sm text-gray-400 mt-0.5">
            Review QIGA recommendations and authorize
            approved response workflows
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded border border-cyber-cyan/30 bg-cyber-cyan/5 text-cyber-cyan">

          <span className="w-2 h-2 rounded-full bg-cyber-cyan pulse-dot" />

          Decision Engine Active

        </div>

      </div>


      {/* ================================================= */}
      {/* ACTIVE THREAT QUEUE                               */}
      {/* ================================================= */}

      <div className="cyber-card p-5">

        <div className="flex items-center justify-between mb-4">

          <div>
            <h3 className="text-sm font-bold text-white font-mono">
              ACTIVE THREAT QUEUE
            </h3>

            <p className="text-xs text-gray-500 font-mono mt-1">
              Real AttackLogs currently requiring attention
            </p>
          </div>

          <span className="text-xs font-mono text-cyber-red">
            {activeThreats.length} ACTIVE
          </span>

        </div>


        {activeThreats.length === 0 ? (

          <div className="py-8 text-center">

            <CheckCircle
              size={24}
              className="text-gray-700 mx-auto mb-3"
            />

            <p className="text-sm text-gray-500 font-mono">
              No active threats available.
            </p>

          </div>

        ) : (

          <div className="space-y-2">

            {activeThreats
              .slice(0, 10)
              .map((threat) => {

                const threatId =
                  threat.attack_log_id ??
                  threat.id

                const isSelected =
                  String(
                    selectedAttackLogId
                  ) ===
                  String(
                    threatId
                  )

                const risk =
                  Number(
                    threat.risk_score ||
                      0
                  )

                const riskColor =
                  risk > 75
                    ? '#ff2d55'
                    : risk > 45
                      ? '#ffd60a'
                      : '#00ff88'

                return (

                  <button
                    key={threatId}
                    type="button"
                    onClick={() =>
                      setSelectedAttackLogId(
                        threatId
                      )
                    }
                    className={`w-full text-left rounded-lg border p-3 transition-all ${
                      isSelected
                        ? 'border-cyber-cyan bg-cyber-cyan/10'
                        : 'border-cyber-border hover:border-cyber-cyan/40 bg-black/10'
                    }`}
                  >

                    <div className="flex items-center gap-3">

                      <div
                        className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                        style={{
                          background:
                            riskColor,

                          boxShadow:
                            `0 0 8px ${riskColor}`,
                        }}
                      />

                      <div className="flex-1 min-w-0">

                        <div className="flex items-center gap-2 flex-wrap">

                          <span className="text-xs font-mono font-bold text-cyber-cyan">
                            #{threatId}
                          </span>

                          <span className="text-xs font-mono font-bold text-white">
                            {threat.attack_type}
                          </span>

                          <span className="text-[10px] text-purple-400 font-mono">
                            {threat.dataset ||
                              'N/A'}
                          </span>

                        </div>

                        <div className="flex items-center gap-3 mt-1 text-[11px] font-mono text-gray-500">

                          <span>
                            Target:{' '}
                            {threat.asset_name ||
                              threat.dest_ip ||
                              threat.pc ||
                              'N/A'}
                          </span>

                          <span>
                            Status:{' '}
                            {threat.status ||
                              'DETECTED'}
                          </span>

                        </div>

                      </div>

                      <div className="text-right flex-shrink-0">

                        <p
                          className="text-sm font-mono font-bold"
                          style={{
                            color:
                              riskColor,
                          }}
                        >
                          {risk.toFixed(0)}
                        </p>

                        <p className="text-[10px] text-gray-600 font-mono">
                          RISK
                        </p>

                      </div>

                    </div>

                  </button>
                )
              })}

          </div>
        )}

      </div>


      {/* ================================================= */}
      {/* NORMAL                                           */}
      {/* ================================================= */}

      {isNormal && (

        <div className="cyber-card p-10 text-center border-l-4 border-gray-700">

          <CheckCircle
            size={48}
            className="text-gray-600 mx-auto mb-4"
          />

          <h2 className="text-xl font-bold font-mono text-white">
            Normal Traffic
          </h2>

          <p className="text-sm text-gray-500 font-mono max-w-md mx-auto mt-2">
            AttackLog #{selectedAttackLogId}
            {' '}
            is classified as Normal telemetry.
            Response and recovery actions are not applicable.
          </p>

          <div className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-gray-700 bg-gray-900/50 text-xs font-mono text-gray-400">
            LOGGED TELEMETRY · NO RESPONSE REQUIRED
          </div>

        </div>
      )}


      {/* ================================================= */}
      {/* SELECTED THREAT                                  */}
      {/* ================================================= */}

      {!isNormal &&
        selectedLog && (
          <>

            <div className="cyber-card p-5 border-l-4 border-cyber-red">

              <div className="flex items-center justify-between mb-4">

                <div className="flex items-center gap-2">

                  <AlertTriangle
                    size={15}
                    className="text-cyber-red"
                  />

                  <span className="text-xs font-mono text-cyber-red uppercase font-bold">
                    Selected Threat
                  </span>

                </div>

                <span className="text-xs font-mono text-gray-500">
                  AttackLog #
                  {selectedLog.attack_log_id ??
                    selectedLog.id}
                </span>

              </div>


              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">

                <div>
                  <p className="text-gray-500">
                    ATTACK TYPE
                  </p>
                  <p className="text-white font-bold mt-1">
                    {selectedLog.attack_type ||
                      'N/A'}
                  </p>
                </div>

                <div>
                  <p className="text-gray-500">
                    DATASET
                  </p>
                  <p className="text-purple-300 mt-1">
                    {selectedLog.dataset ||
                      'N/A'}
                  </p>
                </div>

                <div>
                  <p className="text-gray-500">
                    SEVERITY
                  </p>
                  <p className="text-orange-400 font-bold mt-1">
                    {selectedLog.severity ||
                      'N/A'}
                  </p>
                </div>

                <div>
                  <p className="text-gray-500">
                    RISK SCORE
                  </p>

                  <p
                    className="font-bold mt-1"
                    style={{
                      color:
                        Number(
                          selectedLog.risk_score ||
                            0
                        ) > 75
                          ? '#ff2d55'
                          : Number(
                                selectedLog.risk_score ||
                                  0
                              ) > 45
                            ? '#ffd60a'
                            : '#00ff88',
                    }}
                  >
                    {selectedLog.risk_score != null
                      ? `${Math.round(
                          Number(
                            selectedLog.risk_score
                          )
                        )}/100`
                      : 'N/A'}
                  </p>
                </div>

                <div>
                  <p className="text-gray-500">
                    CONFIDENCE
                  </p>

                  <p className="text-cyan-400 font-bold mt-1">
                    {selectedLog.confidence != null
                      ? `${Math.round(
                          Number(
                            selectedLog.confidence
                          )
                        )}%`
                      : 'N/A'}
                  </p>
                </div>

                <div>
                  <p className="text-gray-500">
                    TARGET ASSET
                  </p>

                  <p className="text-purple-300 mt-1">
                    {selectedLog.asset_name ||
                      selectedLog.dest_ip ||
                      selectedLog.pc ||
                      'N/A'}
                  </p>
                </div>

                <div>
                  <p className="text-gray-500">
                    DEPARTMENT
                  </p>

                  <p className="text-cyan-400 mt-1">
                    {selectedLog.department ||
                      'N/A'}
                  </p>
                </div>

                <div>
                  <p className="text-gray-500">
                    MITRE TECHNIQUE
                  </p>

                  <p className="text-purple-400 mt-1">
                    {selectedLog.mitre_technique_id ||
                      'N/A'}
                  </p>
                </div>

              </div>


              <div className="mt-4 p-3 rounded-lg bg-purple-900/20 border border-purple-700/40">

                <p className="text-xs text-gray-500 font-mono">
                  MITRE DESCRIPTION
                </p>

                <p className="text-xs text-purple-300 font-mono mt-1">
                  {selectedLog.mitre_technique_name ||
                    'No MITRE technique mapped'}
                </p>

              </div>

            </div>


            {/* ============================================= */}
            {/* LIFECYCLE                                    */}
            {/* ============================================= */}

            <div className="cyber-card p-5">

              <div className="flex items-center justify-between mb-4">

                <div>

                  <h3 className="text-sm font-bold text-white font-mono">
                    RESPONSE LIFECYCLE
                  </h3>

                  <p className="text-xs text-gray-500 font-mono mt-1">
                    Current status:{' '}
                    <span
                      className={
                        statusStyle.text
                      }
                    >
                      {currentStatus}
                    </span>
                  </p>

                </div>

                <span
                  className={`px-3 py-1 rounded-full border text-xs font-mono ${statusStyle.text} ${statusStyle.bg} ${statusStyle.border}`}
                >
                  {currentStatus}
                </span>

              </div>


              <div className="grid grid-cols-5 gap-2">

                {LIFECYCLE_STAGES.map(
                  (
                    stage,
                    index
                  ) => {

                    const reached =
                      currentStageIndex >=
                      index

                    const current =
                      currentStatus ===
                      stage

                    const style =
                      LIFECYCLE_STYLE[
                        stage
                      ]

                    return (

                      <div
                        key={stage}
                        className="relative"
                      >

                        <div
                          className={`rounded-lg border p-3 text-center ${
                            current
                              ? `${style.bg} ${style.border}`
                              : reached
                                ? 'bg-cyber-blue/10 border-cyber-cyan/30'
                                : 'bg-black/20 border-cyber-border/50'
                          }`}
                        >

                          <div
                            className={`w-2.5 h-2.5 rounded-full mx-auto mb-2 ${
                              current
                                ? `${style.dot} pulse-dot`
                                : reached
                                  ? 'bg-cyber-cyan'
                                  : 'bg-gray-700'
                            }`}
                          />

                          <p
                            className={`text-[10px] font-mono font-bold ${
                              current
                                ? style.text
                                : reached
                                  ? 'text-cyber-cyan'
                                  : 'text-gray-600'
                            }`}
                          >
                            {stage}
                          </p>

                        </div>

                      </div>
                    )
                  }
                )}

              </div>

            </div>


            {/* ============================================= */}
            {/* ERROR                                          */}
            {/* ============================================= */}

            {error && (

              <div className="cyber-card p-4 border-l-4 border-red-500 bg-red-950/20">

                <p className="text-xs font-mono text-red-400">
                  {error}
                </p>

              </div>

            )}


            {/* ============================================= */}
            {/* QIGA RECOMMENDATIONS                          */}
            {/* ============================================= */}

            <div className="cyber-card p-5">

              <div className="flex items-center justify-between mb-4">

                <div>

                  <h3 className="text-sm font-bold text-white font-mono">
                    QIGA RESPONSE RECOMMENDATIONS
                  </h3>

                  <p className="text-xs text-gray-500 font-mono mt-1">
                    Recommendations generated for AttackLog #
                    {selectedAttackLogId}
                  </p>

                </div>

                <div className="text-right">

                  {primary && (
                    <span
                      className="text-xs font-mono font-bold"
                      style={{
                        color:
                          confidenceColor(
                            primaryConfidence
                          ),
                      }}
                    >
                      {primaryConfidence !==
                      null
                        ? `${primaryConfidence}%`
                        : 'N/A'}
                    </span>
                  )}

                  {lastQigaRun && (
                    <p className="text-[9px] text-gray-600 font-mono mt-1">
                      QIGA #{lastQigaRun.qiga_id}
                    </p>
                  )}

                </div>

              </div>


              {loading &&
              recs.length === 0 ? (

                <div className="p-8 text-center">

                  <RefreshCw
                    size={22}
                    className="text-cyber-cyan animate-spin mx-auto mb-3"
                  />

                  <p className="text-sm text-white font-mono">
                    Waiting for QIGA recommendation...
                  </p>

                </div>

              ) : primary ? (

                <div className="space-y-4">

                  {/* MAIN QIGA ACTION */}

                  <div className="rounded-xl border border-cyber-cyan/40 bg-cyber-cyan/5 p-5">

                    <div className="flex items-start gap-4">

                      <div className="w-11 h-11 rounded-lg bg-gray-900 border border-cyber-border flex items-center justify-center flex-shrink-0">

                        {(() => {
                          const Icon =
                            ACTION_ICONS[
                              primary.action_type
                            ] || Zap

                          return (
                            <Icon
                              size={20}
                              className="text-cyber-cyan"
                            />
                          )
                        })()}

                      </div>


                      <div className="flex-1">

                        <div className="flex items-center justify-between gap-3">

                          <h4 className="text-lg font-black text-white font-mono">
                            {primary.title ||
                              primary.action_type ||
                              'Recommendation'}
                          </h4>

                          <span className="text-xs font-mono text-cyber-cyan">
                            {primary.action_type ||
                              'N/A'}
                          </span>

                        </div>

                        <p className="text-sm text-gray-400 mt-1">
                          {primary.description ||
                            'No description provided.'}
                        </p>

                      </div>

                    </div>


                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-5 text-xs font-mono">

                      <div>
                        <p className="text-gray-600">
                          CONFIDENCE
                        </p>

                        <p className="text-white font-bold mt-1">
                          {primaryConfidence !==
                          null
                            ? `${primaryConfidence}%`
                            : 'N/A'}
                        </p>
                      </div>

                      <div>
                        <p className="text-gray-600">
                          RESOURCE COST
                        </p>

                        <p className="text-white font-bold mt-1">
                          {primary.resource_cost ||
                            'N/A'}
                        </p>
                      </div>

                      <div>
                        <p className="text-gray-600">
                          LATENCY IMPACT
                        </p>

                        <p className="text-white font-bold mt-1">
                          {primary.latency_impact ||
                            'N/A'}
                        </p>
                      </div>

                      <div>
                        <p className="text-gray-600">
                          APPROVAL
                        </p>

                        <p
                          className={`font-bold mt-1 ${
                            primary.is_approved
                              ? 'text-green-400'
                              : 'text-yellow-400'
                          }`}
                        >
                          {primary.is_approved
                            ? 'APPROVED'
                            : 'PENDING ADMIN/ANALYST'}
                        </p>
                      </div>

                    </div>


                    {primaryConfidence !==
                      null && (
                      <div className="mt-4 h-1 bg-gray-800 rounded-full overflow-hidden">

                        <div
                          className="h-full rounded-full"
                          style={{
                            width:
                              `${Math.min(
                                100,
                                primaryConfidence
                              )}%`,

                            background:
                              confidenceColor(
                                primaryConfidence
                              ),
                          }}
                        />

                      </div>
                    )}


                    {/* APPROVAL & REJECTION BUTTONS */}

                    {primary.status === 'REJECTED' ? (
                      <div className="mt-5 w-full py-3 rounded-lg text-sm font-bold font-mono text-center border border-rose-500/40 bg-rose-950/30 text-rose-400">
                        ✕ REJECTED BY OPERATOR
                      </div>
                    ) : primary.is_approved || primary.status === 'APPROVED' ? (
                      <div className="mt-5 w-full py-3 rounded-lg text-sm font-bold font-mono text-center border border-green-500/40 bg-green-900/20 text-green-400">
                        ✓ AUTHORIZED — RECOVERY WORKFLOW STARTED
                      </div>
                    ) : approvalLocked ? (
                      <div className="mt-5 p-3 rounded-lg border border-yellow-700/30 bg-yellow-900/10 text-center">
                        <p className="text-xs text-yellow-400 font-mono font-bold">
                          RESPONSE AUTHORIZATION LOCKED
                        </p>
                        <p className="text-[11px] text-gray-500 font-mono mt-1">
                          Another response action for this AttackLog has already been authorized or recovery has started.
                        </p>
                      </div>
                    ) : canApprove ? (
                      <div className="flex items-center gap-3 mt-5">
                        <button
                          type="button"
                          onClick={() => approve(primary.id)}
                          disabled={loading}
                          className="flex-1 py-3 rounded-lg text-sm font-bold font-mono transition-all cursor-pointer text-slate-950"
                          style={{
                            background: 'linear-gradient(135deg, #0066ff, #00e5ff)',
                          }}
                        >
                          {loading
                            ? 'AUTHORIZING...'
                            : `AUTHORIZE: ${primary.title || primary.action_type || 'RESPONSE'}`}
                        </button>
                        <button
                          type="button"
                          onClick={() => reject(primary.id)}
                          disabled={loading}
                          className="px-5 py-3 rounded-lg text-sm font-bold font-mono transition-all border border-rose-500/40 bg-rose-950/20 text-rose-400 hover:bg-rose-900/30 cursor-pointer"
                        >
                          REJECT
                        </button>
                      </div>
                    ) : (
                      <div className="mt-5 p-3 rounded-lg border border-gray-700 bg-gray-900/30 text-center">
                        <p className="text-xs text-gray-400 font-mono">
                          RESPONSE AUTHORIZATION LOCKED
                        </p>
                        <p className="text-[11px] text-gray-600 font-mono mt-1">
                          Admin or Analyst approval is required.
                        </p>
                      </div>
                    )}

                  </div>


                  {/* ALTERNATIVES */}

                  {alternatives.length >
                    0 && (

                    <div>

                      <p className="text-xs text-gray-500 font-mono uppercase mb-2">
                        Other QIGA Selected Actions
                      </p>

                      <div className="grid lg:grid-cols-2 gap-3">

                        {alternatives
                          .slice(0, 4)
                          .map(
                            (
                              recommendation
                            ) => {

                              const Icon =
                                ACTION_ICONS[
                                  recommendation
                                    .action_type
                                ] ||
                                Zap

                              const confidence =
                                recommendationConfidence(
                                  recommendation.confidence_score
                                )

                              return (

                                <div
                                  key={
                                    recommendation.id
                                  }
                                  className="rounded-xl border border-cyber-border p-4"
                                >

                                  <div className="flex items-start gap-3">

                                    <div className="w-8 h-8 rounded bg-gray-900 border border-cyber-border flex items-center justify-center">

                                      <Icon
                                        size={15}
                                        className="text-gray-400"
                                      />

                                    </div>


                                    <div className="flex-1">

                                      <div className="flex items-center justify-between gap-2">

                                        <p className="text-sm font-bold text-white">

                                          {recommendation.title ||
                                            recommendation.action_type ||
                                            'Action'}

                                        </p>

                                        <span
                                          className="text-xs font-mono font-bold"
                                          style={{
                                            color:
                                              confidenceColor(
                                                confidence
                                              ),
                                          }}
                                        >
                                          {confidence !==
                                          null
                                            ? `${confidence}%`
                                            : 'N/A'}
                                        </span>

                                      </div>

                                      <p className="text-xs text-gray-500 mt-1">
                                        {recommendation.description ||
                                          'No description provided.'}
                                      </p>

                                    </div>

                                  </div>


                                  {recommendation.is_approved ? (

                                    <p className="mt-3 text-xs font-mono text-green-400">
                                      ✓ Authorized
                                    </p>

                                  ) : approvalLocked ? (

                                    <p className="mt-3 text-xs font-mono text-gray-600">
                                      Locked after another action was authorized.
                                    </p>

                                  ) : canApprove ? (

                                    <button
                                      type="button"
                                      onClick={() =>
                                        approve(
                                          recommendation.id
                                        )
                                      }
                                      disabled={
                                        loading
                                      }
                                      className="mt-3 text-xs font-mono text-cyber-cyan hover:text-white"
                                    >
                                      → Authorize this action
                                    </button>

                                  ) : (

                                    <p className="mt-3 text-xs font-mono text-gray-600">
                                      Admin/Analyst approval required.
                                    </p>

                                  )}

                                </div>
                              )
                            }
                          )}

                      </div>

                    </div>
                  )}

                </div>

              ) : (

                <div className="p-8 rounded-xl border border-gray-800 bg-black/20 text-center">

                  <AlertTriangle
                    size={22}
                    className="text-gray-600 mx-auto mb-3"
                  />

                  <p className="text-sm text-white font-mono">
                    Waiting for QIGA recommendation
                  </p>

                  <p className="text-xs text-gray-500 font-mono mt-1">
                    The selected AttackLog has been detected,
                    but the optimizer result has not arrived yet.
                  </p>

                </div>

              )}

            </div>


            {/* ============================================= */}
            {/* ACTIVE RECOVERY                               */}
            {/* ============================================= */}

            {activeRecoveries.length >
              0 && (

              <div className="cyber-card p-5 border-l-4 border-yellow-500">

                <div className="flex items-center gap-2 mb-3">

                  <RefreshCw
                    size={15}
                    className="text-yellow-400 animate-spin"
                  />

                  <span className="text-sm font-bold text-yellow-400 font-mono">
                    ACTIVE RECOVERY WORKFLOW
                  </span>

                  <span className="ml-auto text-xs text-gray-500 font-mono">
                    {activeRecoveries.length} active
                  </span>

                </div>


                <div className="space-y-2">

                  {activeRecoveries.map(
                    (
                      recovery
                    ) => (

                      <button
                        key={recovery.id}
                        type="button"
                        onClick={() =>
                          setSelectedRecovery(
                            recovery
                          )
                        }
                        className={`w-full text-left p-3 rounded-lg border transition-all ${
                          selectedRecovery?.id ===
                          recovery.id
                            ? 'border-yellow-500 bg-yellow-900/20'
                            : 'border-cyber-border hover:border-yellow-500/40'
                        }`}
                      >

                        <div className="flex items-center justify-between">

                          <span className="text-xs font-mono font-bold text-white">
                            {recovery.action_name ||
                              recovery.action_type ||
                              'Recovery Action'}
                          </span>

                          <span className="text-xs font-mono text-yellow-400">
                            {recovery.status}
                          </span>

                        </div>

                        <p className="text-[11px] text-gray-500 font-mono mt-1">
                          {recovery.action_type ||
                            'N/A'}
                          {' · '}
                          Target:{' '}
                          {recovery.target_node ||
                            'N/A'}
                        </p>

                      </button>
                    )
                  )}

                </div>

              </div>
            )}


            {/* ============================================= */}
            {/* EXECUTION LOG                                 */}
            {/* ============================================= */}

            <div className="cyber-card p-5">

              <div className="flex items-center justify-between mb-4">

                <div className="flex items-center gap-2">

                  <Terminal
                    size={15}
                    className="text-cyber-cyan"
                  />

                  <div>

                    <h3 className="text-sm font-bold text-white font-mono">
                      RECOVERY EXECUTION LOG
                    </h3>

                    <p className="text-xs text-gray-500 font-mono mt-1">
                      Live output from the backend recovery engine
                    </p>

                  </div>

                </div>


                {selectedRecovery && (
                  <span
                    className={`px-2 py-1 rounded border text-[10px] font-mono ${
                      STATUS_STYLE[
                        selectedRecovery.status
                      ] || ''
                    }`}
                  >
                    {selectedRecovery.status}
                  </span>
                )}

              </div>


              {selectedRecovery ? (

                <>

                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4 text-xs font-mono">

                    <div>
                      <p className="text-gray-600">
                        ACTION
                      </p>

                      <p className="text-white mt-1">
                        {selectedRecovery.action_name ||
                          selectedRecovery.action_type ||
                          'N/A'}
                      </p>
                    </div>

                    <div>
                      <p className="text-gray-600">
                        TYPE
                      </p>

                      <p className="text-white mt-1">
                        {selectedRecovery.action_type ||
                          'N/A'}
                      </p>
                    </div>

                    <div>
                      <p className="text-gray-600">
                        TARGET NODE
                      </p>

                      <p className="text-cyan-400 mt-1">
                        {selectedRecovery.target_node ||
                          'N/A'}
                      </p>
                    </div>

                    <div>
                      <p className="text-gray-600">
                        STATUS
                      </p>

                      <p className="text-white mt-1">
                        {selectedRecovery.status ||
                          'PENDING'}
                      </p>
                    </div>

                  </div>

                  {/* RECOVERY PROGRESS BAR */}
                  <div className="mb-4 bg-slate-900/80 p-3.5 rounded-lg border border-cyan-500/20">
                    <div className="flex items-center justify-between text-xs font-mono mb-2">
                      <span className="text-slate-300 flex items-center gap-2">
                        <RefreshCw size={12} className={selectedRecovery.status === 'IN_PROGRESS' ? 'animate-spin text-cyan-400' : 'text-slate-500'} />
                        <span className="truncate max-w-md">{selectedRecovery.current_step || (selectedRecovery.status === 'COMPLETED' ? 'Recovery completed successfully.' : 'Recovery initializing...')}</span>
                      </span>
                      <span className="text-cyber-cyan font-bold">{selectedRecovery.progress_percent ?? (selectedRecovery.status === 'COMPLETED' ? 100 : 0)}%</span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          selectedRecovery.status === 'COMPLETED'
                            ? 'bg-emerald-400'
                            : selectedRecovery.status === 'FAILED'
                              ? 'bg-rose-500'
                              : 'bg-gradient-to-r from-blue-500 via-cyan-400 to-emerald-400'
                        }`}
                        style={{
                          width: `${selectedRecovery.progress_percent ?? (selectedRecovery.status === 'COMPLETED' ? 100 : 0)}%`
                        }}
                      />
                    </div>
                  </div>

                  <div
                    ref={logRef}
                    className="bg-black/70 rounded-lg p-4 font-mono text-xs space-y-1 max-h-64 overflow-y-auto border border-gray-800"
                  >

                    {selectedRecovery.execution_log ? (

                      selectedRecovery.execution_log
                        .split('\n')
                        .map(
                          (
                            line,
                            index
                          ) => {

                            const lower =
                              line.toLowerCase()

                            const lineClass =
                              lower.includes(
                                'error'
                              ) ||
                              lower.includes(
                                'fail'
                              )
                                ? 'text-red-400'
                                : lower.includes(
                                      'verified'
                                    ) ||
                                    lower.includes(
                                      'complete'
                                    ) ||
                                    lower.includes(
                                      'confirmed'
                                    ) ||
                                    lower.includes(
                                      'success'
                                    )
                                  ? 'text-green-400'
                                  : 'text-gray-300'

                            return (
                              <p
                                key={
                                  index
                                }
                                className={
                                  lineClass
                                }
                              >
                                {line}
                              </p>
                            )
                          }
                        )

                    ) : (

                      <p className="text-gray-600">
                        Waiting for recovery execution...
                      </p>

                    )}


                    {selectedRecovery.status ===
                      'IN_PROGRESS' && (

                      <p className="text-yellow-400 animate-pulse">
                        ▌
                      </p>

                    )}

                  </div>


                  {selectedRecovery.status ===
                    'COMPLETED' && (

                    <div className="mt-3 flex items-center gap-2 text-xs font-mono text-green-400">

                      <CheckCircle
                        size={14}
                      />

                      Recovery action completed successfully.

                    </div>

                  )}


                  {selectedRecovery.status ===
                    'FAILED' && (

                    <div className="mt-3 flex items-center gap-2 text-xs font-mono text-red-400">

                      <AlertTriangle
                        size={14}
                      />

                      Recovery action failed.

                    </div>

                  )}

                </>

              ) : (

                <div className="p-8 rounded-xl border border-gray-800 bg-black/20 text-center">

                  <Terminal
                    size={22}
                    className="text-gray-700 mx-auto mb-3"
                  />

                  <p className="text-sm text-gray-500 font-mono">
                    No recovery action selected.
                  </p>

                  <p className="text-xs text-gray-600 font-mono mt-1">
                    Authorize a QIGA recommendation to start
                    the backend recovery workflow.
                  </p>

                </div>

              )}

            </div>


            {/* ============================================= */}
            {/* COMPLETED RECOVERY HISTORY                    */}
            {/* ============================================= */}

            {completedRecoveries.length >
              0 && (

              <div className="cyber-card p-5">

                <div className="flex items-center gap-2 mb-4">

                  <CheckCircle
                    size={15}
                    className="text-green-400"
                  />

                  <h3 className="text-sm font-bold text-white font-mono">
                    COMPLETED RECOVERY ACTIONS
                  </h3>

                </div>


                <div className="space-y-2">

                  {completedRecoveries
                    .slice(0, 5)
                    .map(
                      (
                        recovery
                      ) => (

                        <button
                          key={
                            recovery.id
                          }
                          type="button"
                          onClick={() =>
                            setSelectedRecovery(
                              recovery
                            )
                          }
                          className="w-full text-left rounded-lg border border-cyber-border p-3 hover:border-green-700/40 transition-colors"
                        >

                          <div className="flex items-center gap-3">

                            <CheckCircle
                              size={14}
                              className="text-green-400 flex-shrink-0"
                            />

                            <div className="flex-1">

                              <p className="text-xs font-mono text-white">
                                {recovery.action_name ||
                                  recovery.action_type ||
                                  'Recovery Action'}
                              </p>

                              <p className="text-xs text-gray-500 mt-1">
                                {recovery.action_type ||
                                  'N/A'}
                                {' · '}
                                {recovery.target_node ||
                                  'N/A'}
                                {' · '}
                                Completed{' '}
                                {recovery.completed_at
                                  ? new Date(
                                      recovery.completed_at
                                    ).toLocaleTimeString()
                                  : 'N/A'}
                              </p>

                            </div>

                            <span className="text-[10px] font-mono text-green-400 border border-green-500/50 px-2 py-1 rounded">
                              VIEW LOG
                            </span>

                          </div>

                        </button>

                      )
                    )}

                </div>

              </div>

            )}

          </>
        )}

    </div>
  )
}

