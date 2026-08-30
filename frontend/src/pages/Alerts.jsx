import React, { useEffect, useMemo, useState } from 'react'
import {
  Bell,
  RotateCcw,
  AlertTriangle,
  CheckCircle,
  Settings,
  ExternalLink,
} from 'lucide-react'

import { useNavigate } from 'react-router-dom'
import { useSOCStore } from '../store/socEngine'
import { useIncidentStore } from '../store'

const SEV_COLOR = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff9500',
  MEDIUM: '#ffd60a',
  LOW: '#00ff88',
}

const SEV_TABS = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
]

const LIFECYCLE_STAGES = [
  'Detected',
  'Analyzing',
  'Containment',
  'Recovery',
  'Resolved',
]

const STAGES = [
  'DETECTED',
  'ANALYZING',
  'CONTAINMENT',
  'RECOVERY',
  'RESOLVED',
]

export default function Alerts() {
  const incidents = useSOCStore(
    (s) => s.incidents
  )

  const navigate = useNavigate()

  const {
    selectedAttackLogId,
    setSelectedAttackLogId,
  } = useIncidentStore()

  const [activeTab, setActiveTab] =
    useState('CRITICAL')

  const [pushEnabled, setPushEnabled] =
    useState(true)

  const [soundEnabled, setSoundEnabled] =
    useState(false)

  /*
   * Only real threats belong in Alerts.
   * Normal telemetry remains visible in Monitoring
   * but is not shown as a security alert.
   */
  const threatIncidents = useMemo(
    () =>
      incidents.filter(
        (incident) =>
          incident.attack_type !== 'Normal' &&
          incident.is_threat !== false
      ),
    [incidents]
  )

  /*
   * Active threats.
   */
  const activeAlerts = useMemo(
    () =>
      threatIncidents.filter(
        (incident) =>
          !incident.resolved &&
          incident.status !== 'RESOLVED'
      ),
    [threatIncidents]
  )

  /*
   * Counts by severity.
   */
  const counts = useMemo(
    () => ({
      CRITICAL:
        activeAlerts.filter(
          (incident) =>
            incident.severity === 'CRITICAL'
        ).length,

      HIGH:
        activeAlerts.filter(
          (incident) =>
            incident.severity === 'HIGH'
        ).length,

      MEDIUM:
        activeAlerts.filter(
          (incident) =>
            incident.severity === 'MEDIUM'
        ).length,
    }),
    [activeAlerts]
  )

  const totalActive =
    activeAlerts.length

  /*
   * Alerts shown under the selected severity tab.
   */
  const filteredAlerts = useMemo(
    () =>
      activeAlerts.filter(
        (incident) =>
          incident.severity === activeTab
      ),
    [
      activeAlerts,
      activeTab,
    ]
  )

  /*
   * Primary alert:
   * 1. Explicitly selected AttackLog
   * 2. First alert in current severity tab
   * 3. Latest active threat
   */
  const primary = useMemo(() => {
    if (
      selectedAttackLogId !== null &&
      selectedAttackLogId !== undefined
    ) {
      const selected =
        threatIncidents.find(
          (incident) =>
            String(
              incident.attack_log_id ??
                incident.id
            ) ===
            String(
              selectedAttackLogId
            )
        )

      if (selected) {
        return selected
      }
    }

    return (
      filteredAlerts[0] ??
      activeAlerts[0] ??
      null
    )
  }, [
    selectedAttackLogId,
    threatIncidents,
    filteredAlerts,
    activeAlerts,
  ])

  /*
   * Automatically synchronize the active alert selection
   * with the currently displayed primary threat.
   *
   * This does NOT execute any response action.
   */
  useEffect(() => {
    if (!primary) {
      return
    }

    const id =
      primary.attack_log_id ??
      primary.id

    if (
      id === undefined ||
      id === null
    ) {
      return
    }

    /*
     * Only automatically select when there is
     * no explicit user selection.
     */
    if (
      selectedAttackLogId === null ||
      selectedAttackLogId === undefined
    ) {
      setSelectedAttackLogId(id)
    }
  }, [
    primary,
    selectedAttackLogId,
    setSelectedAttackLogId,
  ])

  /*
   * Everything except the primary alert.
   */
  const otherAlerts =
    filteredAlerts.filter(
      (alert) =>
        String(
          alert.attack_log_id ??
            alert.id
        ) !==
        String(
          primary?.attack_log_id ??
            primary?.id
        )
    )

  const getStageIndex = (
    status
  ) => {
    const normalized =
      String(
        status ?? 'DETECTED'
      ).toUpperCase()

    const index =
      STAGES.indexOf(
        normalized
      )

    return index >= 0
      ? index
      : 0
  }

  /*
   * User selects an alert.
   *
   * This only changes the selected AttackLog context.
   * It does NOT isolate, block, reset, or recover anything.
   */
  const selectAlert = (
    attackLogId
  ) => {
    if (
      attackLogId === undefined ||
      attackLogId === null
    ) {
      return
    }

    setSelectedAttackLogId(
      attackLogId
    )
  }

  /*
   * Open Response page through the existing application
   * route/navigation mechanism.
   *
   * The Response page is responsible for recommendation
   * approval and actual recovery execution.
   */
  const openResponse = (
    attackLogId
  ) => {
    if (
      attackLogId === undefined ||
      attackLogId === null
    ) {
      return
    }

    setSelectedAttackLogId(
      attackLogId
    )

    window.dispatchEvent(
      new CustomEvent(
        'open-response',
        {
          detail: {
            attack_log_id:
              attackLogId,
          },
        }
      )
    )

    navigate('/app/response')
  }

  return (
    <div className="p-6 space-y-6">

      {/* ===================================================== */}
      {/* HEADER                                                */}
      {/* ===================================================== */}

      <div>
        <h1 className="text-2xl font-black text-white">
          Critical Incident Center
        </h1>

        <div className="flex items-center gap-2 mt-1">
          <span className="w-2 h-2 rounded-full bg-cyber-red pulse-dot" />

          <span className="text-xs font-mono text-cyber-red">
            {totalActive} ACTIVE THREATS DETECTED
          </span>
        </div>

        <p className="text-xs text-gray-600 font-mono mt-2">
          Alerts are generated from live Monitoring
          detections. Response execution requires
          authorized approval.
        </p>
      </div>

      {/* ===================================================== */}
      {/* SEVERITY TABS                                         */}
      {/* ===================================================== */}

      <div className="flex gap-2">
        {[
          {
            sev: 'CRITICAL',
            color:
              'text-red-400 bg-red-900/30 border-red-700',
          },
          {
            sev: 'HIGH',
            color:
              'text-orange-400 bg-orange-900/20 border-orange-700/50',
          },
          {
            sev: 'MEDIUM',
            color:
              'text-yellow-400 bg-yellow-900/20 border-yellow-700/50',
          },
        ].map(
          ({
            sev,
            color,
          }) => (
            <button
              key={sev}
              onClick={() =>
                setActiveTab(sev)
              }
              className={`px-4 py-2 rounded border text-xs font-mono font-bold transition-all ${
                activeTab === sev
                  ? color
                  : 'text-gray-500 bg-transparent border-cyber-border hover:border-gray-500'
              }`}
            >
              {sev} ({counts[sev]})
            </button>
          )
        )}
      </div>

      {/* ===================================================== */}
      {/* PRIMARY ALERT                                         */}
      {/* ===================================================== */}

      {primary && (
        <div className="cyber-card p-5 border border-red-800/50 glow-red">

          <div className="flex items-center justify-between mb-3">

            <div className="flex items-center gap-2">

              <AlertTriangle
                size={16}
                className="text-cyber-red"
              />

              <span className="text-xs font-mono text-cyber-red uppercase tracking-widest font-bold">
                {primary.severity} Severity ·{' '}
                {primary.attack_type}
              </span>

            </div>

            <span className="text-xs font-mono text-cyber-cyan">
              #{primary.attack_log_id}
            </span>

          </div>

          <h2 className="text-xl font-black text-white mb-1">
            {primary.attack_type}{' '}
            Attack Detected
          </h2>

          <p className="text-sm text-gray-400 mb-4">
            {primary.dataset ===
            'PhiUSIIL'
              ? `${primary.url || primary.domain || 'Phishing telemetry'} detected by the PhiUSIIL MLP model.`
              : primary.dataset ===
                'CERT'
                ? `${primary.user || 'User'} on ${primary.pc || 'workstation'} generated suspicious CERT activity.`
                : `${primary.source_ip || 'Unknown source'} is targeting ${primary.asset_name || primary.dest_ip || 'Unknown target'}.`}
          </p>

          {/* ================================================= */}
          {/* FULL DETAIL GRID                                  */}
          {/* ================================================= */}

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4 text-xs font-mono">

            <div>
              <p className="text-gray-500 mb-0.5">
                AttackLog
              </p>
              <p className="text-cyber-cyan font-bold">
                #{primary.attack_log_id}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Dataset
              </p>
              <p className="text-purple-400 font-bold">
                {primary.dataset ||
                  'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Model
              </p>
              <p className="text-white">
                {primary.model_version ||
                  'MLP'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Source / Origin
              </p>
              <p className="text-red-400 font-bold">
                {primary.dataset ===
                'PhiUSIIL'
                  ? primary.url ||
                    primary.domain ||
                    'N/A'
                  : primary.dataset ===
                    'CERT'
                    ? primary.user ||
                      'N/A'
                    : primary.source_ip ||
                      'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Target / Context
              </p>
              <p className="text-green-400 font-bold">
                {primary.dataset ===
                'PhiUSIIL'
                  ? primary.domain ||
                    primary.url ||
                    'N/A'
                  : primary.dataset ===
                    'CERT'
                    ? primary.pc ||
                      'N/A'
                    : primary.dest_ip ||
                      'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Protocol
              </p>
              <p className="text-white">
                {primary.protocol ||
                  'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Port
              </p>
              <p className="text-white">
                {primary.port ||
                  'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Department
              </p>
              <p className="text-cyan-400">
                {primary.department ||
                  'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Affected Asset
              </p>
              <p className="text-purple-300">
                {primary.asset_name ||
                  primary.dest_ip ||
                  primary.pc ||
                  'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                MITRE Technique
              </p>
              <p className="text-purple-400">
                {primary.mitre_technique_id ||
                  primary.mitre_id ||
                  'N/A'}
                {' · '}
                {primary.mitre_technique_name ||
                  primary.mitre_name ||
                  'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Confidence
              </p>
              <p className="text-cyan-400 font-bold">
                {primary.confidence !==
                  null &&
                primary.confidence !==
                  undefined
                  ? `${Number(
                      primary.confidence
                    ).toFixed(1)}%`
                  : 'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Risk Score
              </p>

              <p
                className="font-bold"
                style={{
                  color:
                    Number(
                      primary.risk_score ||
                        0
                    ) > 75
                      ? '#ff2d55'
                      : Number(
                            primary.risk_score ||
                              0
                          ) > 45
                        ? '#ffd60a'
                        : '#00ff88',
                }}
              >
                {primary.risk_score !==
                null &&
                primary.risk_score !==
                  undefined
                  ? `${Math.round(
                      Number(
                        primary.risk_score
                      )
                    )}/100`
                  : 'N/A'}
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Current Stage
              </p>

              <p className="text-yellow-400">
                {
                  LIFECYCLE_STAGES[
                    getStageIndex(
                      primary.status
                    )
                  ]
                }
              </p>
            </div>

            <div>
              <p className="text-gray-500 mb-0.5">
                Detected
              </p>

              <p className="text-gray-300">
                {primary.detected_at
                  ? new Date(
                      primary.detected_at
                    ).toLocaleTimeString()
                  : 'N/A'}
              </p>
            </div>

          </div>

          {/* ================================================= */}
          {/* RESPONSE STATUS                                   */}
          {/* ================================================= */}

          <div className="p-3 rounded-lg bg-purple-900/20 border border-purple-700/40 mb-4">

            <p className="text-xs font-mono text-purple-300 uppercase mb-1">
              Response Status
            </p>

            <p className="text-sm text-white font-mono">
              {primary.status ===
              'RESOLVED'
                ? 'Incident resolved.'
                : 'QIGA recommendation is available through the Response workflow. Approval is required before execution.'}
            </p>

          </div>

          {/* ================================================= */}
          {/* TIMELINE                                          */}
          {/* ================================================= */}

          <div className="space-y-2 mb-5 pl-4 border-l-2 border-red-800/50">

            {LIFECYCLE_STAGES
              .slice(
                0,
                getStageIndex(
                  primary.status
                ) + 1
              )
              .map(
                (
                  stage,
                  index
                ) => (
                  <div
                    key={stage}
                    className="relative"
                  >

                    <span
                      className={`absolute -left-5 top-0.5 w-2 h-2 rounded-full ${
                        index ===
                        getStageIndex(
                          primary.status
                        )
                          ? 'bg-cyber-red pulse-dot'
                          : 'bg-gray-600'
                      }`}
                    />

                    <p className="text-xs font-mono text-gray-500">
                      {stage}
                    </p>

                    <p className="text-xs text-gray-400">
                      {stage ===
                      'Detected'
                        ? `MLP detected ${primary.attack_type} from the live ${primary.dataset || 'dataset'} event.`
                        : stage ===
                          'Analyzing'
                          ? 'Event is available for analysis and SHAP explanation.'
                          : stage ===
                            'Containment'
                            ? 'Authorized response has entered containment.'
                            : stage ===
                              'Recovery'
                              ? 'Approved recovery action is executing.'
                              : 'Incident closed — recovery workflow completed.'}
                    </p>

                  </div>
                )
              )}

          </div>

          {/* ================================================= */}
          {/* SAFE RESPONSE BUTTON                              */}
          {/* ================================================= */}

          <div className="flex gap-3">

            <button
              onClick={() =>
                openResponse(
                  primary.attack_log_id
                )
              }
              className="btn-primary flex items-center gap-2 flex-1 justify-center"
            >
              <ExternalLink
                size={14}
              />

              Review QIGA Response
            </button>

            <button
              onClick={() =>
                selectAlert(
                  primary.attack_log_id
                )
              }
              className="flex items-center justify-center gap-2 px-4 py-2 rounded border border-cyber-border text-xs font-mono text-gray-400 hover:text-white hover:border-cyber-cyan transition-colors"
            >
              Select Event
            </button>

          </div>

        </div>
      )}

      {/* ===================================================== */}
      {/* OTHER ALERTS                                         */}
      {/* ===================================================== */}

      {otherAlerts.length > 0 && (
        <div>

          <div className="flex items-center justify-between mb-3">

            <h3 className="text-sm font-bold text-white font-mono">
              {activeTab}{' '}
              PRIORITY ALERTS
            </h3>

          </div>

          <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1">

            {otherAlerts.map(
              (alert) => {

                const alertId =
                  alert.attack_log_id ??
                  alert.id

                return (
                  <div
                    key={`alert-${alertId}`}
                    onClick={() =>
                      selectAlert(
                        alertId
                      )
                    }
                    className="cyber-card p-4 flex items-start gap-3 hover:border-orange-700/50 transition-colors cursor-pointer"
                  >

                    <div className="w-8 h-8 rounded-lg bg-cyber-blue/20 flex items-center justify-center flex-shrink-0">
                      <Bell
                        size={14}
                        className="text-cyber-cyan"
                      />
                    </div>

                    <div className="flex-1">

                      <div className="flex items-center gap-2 mb-1">

                        <p className="text-sm font-bold text-white">
                          {alertId} ·{' '}
                          {alert.attack_type}
                        </p>

                        <span
                          className="text-xs font-mono px-1.5 py-0.5 rounded"
                          style={{
                            color:
                              SEV_COLOR[
                                alert.severity
                              ] ||
                              '#fff',

                            background:
                              `${
                                SEV_COLOR[
                                  alert.severity
                                ] ||
                                '#fff'
                              }20`,

                            border:
                              `1px solid ${
                                SEV_COLOR[
                                  alert.severity
                                ] ||
                                '#fff'
                              }40`,
                          }}
                        >
                          {alert.severity}
                        </span>

                      </div>

                      <div className="text-xs font-mono text-gray-500 space-y-0.5">

                        <p>
                          Dataset:{' '}
                          <span className="text-purple-400">
                            {alert.dataset ||
                              'N/A'}
                          </span>
                        </p>

                        <p>
                          {alert.dataset ===
                          'PhiUSIIL'
                            ? `${alert.url || alert.domain || 'N/A'} → ${alert.domain || 'N/A'}`
                            : alert.dataset ===
                              'CERT'
                              ? `${alert.user || 'N/A'} → ${alert.pc || 'N/A'}`
                              : `${alert.source_ip || 'N/A'} → ${alert.dest_ip || 'N/A'}`}
                        </p>

                        <p>
                          Asset:{' '}
                          {alert.asset_name ||
                            alert.dest_ip ||
                            alert.pc ||
                            'N/A'}
                          {' · '}
                          Dept:{' '}
                          {alert.department ||
                            'N/A'}
                        </p>

                        <p className="text-purple-400">
                          {alert.mitre_technique_id ||
                            alert.mitre_id ||
                            'N/A'}
                          {' · '}
                          Confidence:{' '}
                          {alert.confidence !==
                          null &&
                          alert.confidence !==
                            undefined
                            ? `${Number(
                                alert.confidence
                              ).toFixed(
                                1
                              )}%`
                            : 'N/A'}
                          {' · '}
                          Risk:{' '}
                          {alert.risk_score !==
                          null &&
                          alert.risk_score !==
                            undefined
                            ? Math.round(
                                Number(
                                  alert.risk_score
                                )
                              )
                            : 'N/A'}
                        </p>

                        <p className="text-purple-300 italic">
                          Response:
                          {' '}
                          QIGA recommendation pending approval
                        </p>

                      </div>

                    </div>

                    <div className="text-right flex-shrink-0">

                      <p className="text-xs font-mono text-gray-500">
                        {
                          LIFECYCLE_STAGES[
                            getStageIndex(
                              alert.status
                            )
                          ]
                        }
                      </p>

                    </div>

                  </div>
                )
              }
            )}

          </div>

        </div>
      )}

      {/* ===================================================== */}
      {/* EMPTY STATE                                           */}
      {/* ===================================================== */}

      {filteredAlerts.length === 0 && (
        <div className="cyber-card p-8 text-center">

          <CheckCircle
            size={32}
            className="text-green-400 mx-auto mb-2"
          />

          <p className="text-sm text-gray-400 font-mono">
            No {activeTab} alerts currently active
          </p>

          <p className="text-xs text-gray-600 font-mono mt-1">
            Monitoring continues to receive
            live MLP predictions.
          </p>

        </div>
      )}

      {/* ===================================================== */}
      {/* ARCHIVE                                               */}
      {/* ===================================================== */}

      <div className="cyber-card p-4 flex items-center justify-between">

        <div className="flex items-center gap-3">

          <RotateCcw
            size={16}
            className="text-gray-500"
          />

          <span className="text-sm text-gray-300">
            Resolved Incident Archive (
            {
              threatIncidents.filter(
                (incident) =>
                  incident.resolved
              ).length
            } incidents)
          </span>

        </div>

        <span className="text-gray-600">
          ›
        </span>

      </div>

      {/* ===================================================== */}
      {/* NOTIFICATION PREFS                                   */}
      {/* ===================================================== */}

      <div className="cyber-card p-5">

        <div className="flex items-center gap-2 mb-4">

          <Settings
            size={14}
            className="text-gray-500"
          />

          <p className="text-xs font-mono text-gray-500 uppercase tracking-widest">
            Notification Preferences
          </p>

        </div>

        {[
          {
            label:
              'Push Notifications',

            sub:
              'Real-time critical alerts',

            state:
              pushEnabled,

            toggle:
              setPushEnabled,
          },

          {
            label:
              'Sound Overrides',

            sub:
              'Priority bypass for sleep mode',

            state:
              soundEnabled,

            toggle:
              setSoundEnabled,
          },
        ].map(
          ({
            label,
            sub,
            state,
            toggle,
          }) => (
            <div
              key={label}
              className="flex items-center justify-between py-3 border-b border-cyber-border last:border-0"
            >

              <div>

                <p className="text-sm text-white">
                  {label}
                </p>

                <p className="text-xs text-gray-600">
                  {sub}
                </p>

              </div>

              <button
                onClick={() =>
                  toggle(!state)
                }
                className={`w-12 h-6 rounded-full transition-all duration-300 relative ${
                  state
                    ? 'bg-cyber-cyan'
                    : 'bg-gray-700'
                }`}
              >

                <span
                  className={`absolute top-1 w-4 h-4 rounded-full bg-white shadow transition-all duration-300 ${
                    state
                      ? 'left-7'
                      : 'left-1'
                  }`}
                />

              </button>

            </div>
          )
        )}

      </div>

    </div>
  )
}

