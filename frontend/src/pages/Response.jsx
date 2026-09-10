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
  AlertOctagon,
  Terminal,
  Shield,
  Search,
  ChevronLeft,
  ChevronRight,
  UserCheck,
  User,
  Radio,
  Lock,
  Check,
  X,
  Play,
  ArrowRight,
  Layers,
  Activity,
} from 'lucide-react'
import api from '../utils/api'
import { useAuthStore, useIncidentStore } from '../store'
import { useSOCStore, LIFECYCLE_STAGES } from '../store/socEngine'

/*
 * =============================================================================
 * OFFICIAL ICDS-H THREAT RESPONSE MATRIX
 * (Tailored mitigation actions as per attack type)
 * =============================================================================
 */
const ATTACK_RESPONSES_TABLE = {
  Injection: [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block malicious injection payload traffic and drop source packets at perimeter firewall.', cost: '1', latency: '5 min', eff: 88, icon: Ban, color: '#ff2d55' },
    { id: 'WAF_RULE', name: 'Deploy WAF Rule', desc: 'Deploy specialized Web Application Firewall rule to sanitize SQLi and code injection attempts.', cost: '1', latency: '3 min', eff: 84, icon: Shield, color: '#50e3c2' },
    { id: 'PATCH', name: 'Apply Security Patch', desc: 'Apply security patch to vulnerable database connector and backend endpoint.', cost: '2', latency: '20 min', eff: 80, icon: Zap, color: '#a855f7' },
  ],
  'SQL Injection': [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block malicious injection payload traffic and drop source packets at perimeter firewall.', cost: '1', latency: '5 min', eff: 88, icon: Ban, color: '#ff2d55' },
    { id: 'WAF_RULE', name: 'Deploy WAF Rule', desc: 'Deploy specialized Web Application Firewall rule to sanitize SQLi attempts.', cost: '1', latency: '3 min', eff: 84, icon: Shield, color: '#50e3c2' },
    { id: 'PATCH', name: 'Apply Security Patch', desc: 'Apply security patch to vulnerable database connector.', cost: '2', latency: '20 min', eff: 80, icon: Zap, color: '#a855f7' },
  ],
  XSS: [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block client session traffic from cross-site scripting attack origin.', cost: '1', latency: '5 min', eff: 86, icon: Ban, color: '#ff2d55' },
    { id: 'WAF_RULE', name: 'Deploy WAF Rule', desc: 'Inject WAF payload rule to strip malicious script tags and reflect sanitization.', cost: '1', latency: '3 min', eff: 83, icon: Shield, color: '#50e3c2' },
    { id: 'PATCH', name: 'Apply Security Patch', desc: 'Apply application patch to enforce contextual output encoding across web inputs.', cost: '2', latency: '20 min', eff: 79, icon: Zap, color: '#a855f7' },
  ],
  DDoS: [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Push rate-drop and IP block rules to edge router to suppress volumetric traffic flood.', cost: '1', latency: '5 min', eff: 90, icon: Ban, color: '#ff2d55' },
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Isolate targeted hospital gateway node to protect internal clinical cluster.', cost: '2', latency: '15 min', eff: 78, icon: ShieldOff, color: '#ff9500' },
  ],
  DoS: [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block flood attack source addresses at perimeter firewall.', cost: '1', latency: '5 min', eff: 90, icon: Ban, color: '#ff2d55' },
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Isolate targeted hospital device to prevent resource exhaustion.', cost: '2', latency: '15 min', eff: 78, icon: ShieldOff, color: '#ff9500' },
  ],
  Ransomware: [
    { id: 'RESTORE', name: 'Restore Backup', desc: 'Mount verified uncorrupted backup snapshot and restore encrypted patient records.', cost: '4', latency: '120 min', eff: 95, icon: RotateCcw, color: '#0070f3' },
    { id: 'PATCH', name: 'Apply Security Patch', desc: 'Apply emergency patch for SMB/RDP exploit vector across hospital subnet.', cost: '2', latency: '20 min', eff: 82, icon: Zap, color: '#a855f7' },
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Isolate infected medical workstation to immediately prevent lateral cryptographic spread.', cost: '2', latency: '15 min', eff: 80, icon: ShieldOff, color: '#ff9500' },
  ],
  Phishing: [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block fraudulent domain/URL and reverse-proxy C2 address at gateway.', cost: '1', latency: '5 min', eff: 87, icon: Ban, color: '#ff2d55' },
    { id: 'WAF_RULE', name: 'Deploy WAF Rule', desc: 'Deploy proxy header inspection rule to drop credential harvester requests.', cost: '1', latency: '3 min', eff: 82, icon: Shield, color: '#50e3c2' },
    { id: 'PATCH', name: 'Apply Security Patch', desc: 'Update mail gateway anti-spoofing definitions and browser security policies.', cost: '2', latency: '20 min', eff: 80, icon: Zap, color: '#a855f7' },
    { id: 'RESET', name: 'Reset Account / Credentials', desc: 'Force immediate credential reset and invalidate compromised session tokens.', cost: '1', latency: '10 min', eff: 75, icon: Key, color: '#ffd60a' },
  ],
  'Insider Threat': [
    { id: 'RESET', name: 'Reset Account / Credentials', desc: 'Revoke privileged user credentials, API keys, and invalidate active sessions.', cost: '1', latency: '10 min', eff: 85, icon: Key, color: '#ffd60a' },
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Isolate suspect user workstation from internal hospital electronic health record network.', cost: '2', latency: '15 min', eff: 78, icon: ShieldOff, color: '#ff9500' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Engage continuous deep packet telemetry and audit user file-access activities.', cost: '1', latency: '0 min', eff: 72, icon: Radio, color: '#00ff88' },
  ],
  Scanning: [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block reconnaissance scanner IP address probing hospital IoT telemetry ports.', cost: '1', latency: '5 min', eff: 88, icon: Ban, color: '#ff2d55' },
    { id: 'WAF_RULE', name: 'Deploy WAF Rule', desc: 'Deploy anti-scanner fingerprint detection rule in reverse proxy.', cost: '1', latency: '3 min', eff: 81, icon: Shield, color: '#50e3c2' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Enable honeypot decoys and enhanced port telemetry across scanned network ranges.', cost: '1', latency: '0 min', eff: 68, icon: Radio, color: '#00ff88' },
  ],
  'Port Scan': [
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block port scanner IP address across edge firewalls.', cost: '1', latency: '5 min', eff: 88, icon: Ban, color: '#ff2d55' },
    { id: 'WAF_RULE', name: 'Deploy WAF Rule', desc: 'Deploy probe detection filter to drop TCP SYN scanning attempts.', cost: '1', latency: '3 min', eff: 81, icon: Shield, color: '#50e3c2' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Enable high-frequency telemetry on targeted IP range.', cost: '1', latency: '0 min', eff: 68, icon: Radio, color: '#00ff88' },
  ],
  MITM: [
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Isolate rogue ARP-spoofing machine or compromised gateway on hospital LAN.', cost: '2', latency: '15 min', eff: 84, icon: ShieldOff, color: '#ff9500' },
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block intercepted rogue MAC and DNS redirection traffic.', cost: '1', latency: '5 min', eff: 82, icon: Ban, color: '#ff2d55' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Enforce dynamic ARP inspection and 802.1X certificate validation.', cost: '1', latency: '0 min', eff: 72, icon: Radio, color: '#00ff88' },
  ],
  Backdoor: [
    { id: 'RESTORE', name: 'Restore Backup', desc: 'Reimage compromised hospital workstation from verified clean backup snapshot.', cost: '4', latency: '120 min', eff: 95, icon: RotateCcw, color: '#0070f3' },
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Isolate infected host immediately to sever C2 command and control connection.', cost: '2', latency: '15 min', eff: 82, icon: ShieldOff, color: '#ff9500' },
    { id: 'PATCH', name: 'Apply Security Patch', desc: 'Patch persistence vector and rootkit vulnerability on affected node.', cost: '2', latency: '20 min', eff: 80, icon: Zap, color: '#a855f7' },
  ],
  'Password Attack': [
    { id: 'RESET', name: 'Reset Account / Credentials', desc: 'Lock targeted account, invalidate password hash, and require biometric re-auth.', cost: '1', latency: '10 min', eff: 88, icon: Key, color: '#ffd60a' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Enable threshold brute-force monitoring and IP velocity anomaly tracking.', cost: '1', latency: '0 min', eff: 70, icon: Radio, color: '#00ff88' },
  ],
  'Brute Force': [
    { id: 'RESET', name: 'Reset Account / Credentials', desc: 'Lock targeted user account and trigger immediate credential rotation.', cost: '1', latency: '10 min', eff: 88, icon: Key, color: '#ffd60a' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Enable failed-login threshold alerting and rate limiting on auth endpoints.', cost: '1', latency: '0 min', eff: 70, icon: Radio, color: '#00ff88' },
  ],
  'Anomaly/Zero-Day': [
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Quarantine anomalous node into secure containment VLAN to isolate unknown zero-day.', cost: '2', latency: '15 min', eff: 85, icon: ShieldOff, color: '#ff9500' },
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block anomalous outbound traffic signature and destination IP.', cost: '1', latency: '5 min', eff: 82, icon: Ban, color: '#ff2d55' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Engage deep kernel memory telemetry and live process capture for sandbox analysis.', cost: '1', latency: '0 min', eff: 75, icon: Radio, color: '#00ff88' },
  ],
  'Anomaly (Zero-Day)': [
    { id: 'ISOLATE', name: 'Isolate Device', desc: 'Quarantine anomalous node into secure containment VLAN to isolate unknown zero-day.', cost: '2', latency: '15 min', eff: 85, icon: ShieldOff, color: '#ff9500' },
    { id: 'BLOCK', name: 'Block Traffic', desc: 'Block anomalous outbound traffic signature and destination IP.', cost: '1', latency: '5 min', eff: 82, icon: Ban, color: '#ff2d55' },
    { id: 'MONITOR_ENHANCED', name: 'Enhanced Monitoring', desc: 'Engage deep kernel memory telemetry and live process capture for sandbox analysis.', cost: '1', latency: '0 min', eff: 75, icon: Radio, color: '#00ff88' },
  ],
}

const ACTION_ICONS = {
  ISOLATE: ShieldOff,
  RESTORE: RotateCcw,
  RESET: Key,
  BLOCK: Ban,
  PATCH: Zap,
  WAF_RULE: Shield,
  MONITOR_ENHANCED: Radio,
}

const STATUS_STYLE = {
  PENDING: 'text-gray-400 border-gray-600 bg-gray-900/20',
  IN_PROGRESS: 'text-yellow-400 border-yellow-600 bg-yellow-900/20',
  COMPLETED: 'text-green-400 border-green-700 bg-green-900/20',
  FAILED: 'text-red-400 border-red-700 bg-red-900/20',
}

const LIFECYCLE_STYLE = {
  DETECTED: {
    text: 'text-red-400',
    bg: 'bg-red-900/20',
    border: 'border-red-500/50',
    dot: 'bg-red-400',
    description: 'Threat identified by ML telemetry engine. Awaiting analyst triage.',
  },
  ACKNOWLEDGED: {
    text: 'text-cyan-400',
    bg: 'bg-cyan-900/20',
    border: 'border-cyan-500/50',
    dot: 'bg-cyan-400',
    description: 'Certified analyst has reviewed and claimed the security incident.',
  },
  ANALYZING: {
    text: 'text-yellow-400',
    bg: 'bg-yellow-900/20',
    border: 'border-yellow-500/50',
    dot: 'bg-yellow-400',
    description: 'Deep-dive root cause, MITRE tactic mapping, and QIGA optimization active.',
  },
  CONTAINMENT: {
    text: 'text-orange-400',
    bg: 'bg-orange-900/20',
    border: 'border-orange-500/50',
    dot: 'bg-orange-400',
    description: 'Isolation boundaries established. Perimeter and node controls engaged.',
  },
  RECOVERY: {
    text: 'text-blue-400',
    bg: 'bg-blue-900/20',
    border: 'border-blue-500/50',
    dot: 'bg-blue-400',
    description: 'System restoration, patch verification, or backup reload in progress.',
  },
  RESOLVED: {
    text: 'text-green-400',
    bg: 'bg-green-900/20',
    border: 'border-green-500/50',
    dot: 'bg-green-400',
    description: 'Threat neutralized, clinical availability verified, incident signed off.',
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
  if (value === null || value === undefined) return '#6b7280'
  if (value >= 85) return '#00ff88'
  if (value >= 75) return '#00e5ff'
  return '#ffd60a'
}

export default function Response() {
  const { user } = useAuthStore()
  const { selectedAttackLogId, setSelectedAttackLogId } = useIncidentStore()
  const incidents = useSOCStore((state) => state.incidents)
  const updateLifecycleStore = useSOCStore((state) => state.updateLifecycle)

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
        incident.status !== 'RESOLVED' &&
        incident.attack_type !== 'Normal'
    )
    .sort(
      (a, b) =>
        Number(b.risk_score || 0) - Number(a.risk_score || 0)
    )

  /*
   * -------------------------------------------------------
   * SELECTED ATTACK LOG
   * -------------------------------------------------------
   */
  const selectedLog =
    incidents.find((incident) => {
      const id = incident.attack_log_id ?? incident.id
      return String(id) === String(selectedAttackLogId)
    }) ||
    activeThreats[0] ||
    null

  const threatId = selectedLog ? selectedLog.attack_log_id ?? selectedLog.id : null
  const isNormal = selectedLog?.attack_type === 'Normal'

  /*
   * -------------------------------------------------------
   * ANALYST CLEARANCE ROLE CHECK
   * -------------------------------------------------------
   */
  const normalizedRole = String(user?.role ?? '').toLowerCase()
  const canApprove =
    normalizedRole === 'admin' ||
    normalizedRole === 'analyst' ||
    !user?.role // default analyst session

  /*
   * -------------------------------------------------------
   * LOCAL STATE
   * -------------------------------------------------------
   */
  const [recs, setRecs] = useState([])
  const [recoveries, setRecoveries] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedRecovery, setSelectedRecovery] = useState(null)
  const [error, setError] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)
  const [lastQigaRun, setLastQigaRun] = useState(null)

  // Stage transition in flight
  const [stageUpdating, setStageUpdating] = useState(false)

  // Manual actions in flight
  const [actionLoading, setActionLoading] = useState(false)

  const logRef = useRef(null)

  /*
   * -------------------------------------------------------
   * DEFAULT THREAT SELECTION
   * -------------------------------------------------------
   */
  useEffect(() => {
    if (!selectedAttackLogId && activeThreats.length > 0) {
      const firstThreat = activeThreats[0]
      const tId = firstThreat.attack_log_id ?? firstThreat.id
      setSelectedAttackLogId(tId)
    }
  }, [selectedAttackLogId, activeThreats, setSelectedAttackLogId])

  /*
   * -------------------------------------------------------
   * LOAD DATA FOR EXACT ATTACKLOG
   * -------------------------------------------------------
   */
  const loadResponseData = async (attackLogId, showLoading = true) => {
    if (attackLogId === null || attackLogId === undefined || attackLogId === '') {
      return
    }

    if (showLoading) {
      setLoading(true)
    }
    setError(null)

    try {
      const [recommendationsResponse, recoveryResponse] = await Promise.all([
        api.get(`/recommendations/?attack_log_id=${attackLogId}&limit=100`),
        api.get(`/recovery/?attack_log_id=${attackLogId}&limit=100`),
      ])

      const recommendations = Array.isArray(recommendationsResponse.data)
        ? recommendationsResponse.data
        : []

      const recoveryActions = Array.isArray(recoveryResponse.data)
        ? recoveryResponse.data
        : []

      setRecs(recommendations)
      setRecoveries(recoveryActions)

      setSelectedRecovery((current) => {
        if (!current) {
          return recoveryActions[0] ?? null
        }
        const refreshed = recoveryActions.find(
          (item) => String(item.id) === String(current.id)
        )
        return refreshed ?? recoveryActions[0] ?? null
      })
    } catch (err) {
      console.error('[Response] Failed to load response data:', err)
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

  useEffect(() => {
    if (threatId === null || threatId === undefined || isNormal) {
      setRecs([])
      setRecoveries([])
      setSelectedRecovery(null)
      setLastQigaRun(null)
      setError(null)
      setLoading(false)
      return undefined
    }

    loadResponseData(threatId, true)
  }, [threatId, isNormal])

  /*
   * -------------------------------------------------------
   * WEBSOCKET EVENT LISTENERS
   * -------------------------------------------------------
   */
  useEffect(() => {
    const handleQigaRecommendation = (event) => {
      const data = event?.detail ?? {}
      if (String(data.attack_log_id) !== String(threatId)) return
      setLastQigaRun(data)
      loadResponseData(threatId, false)
    }

    const handleLifecycleUpdate = (event) => {
      const data = event?.detail ?? {}
      if (String(data.attack_log_id) !== String(threatId)) return
      if (data.status) {
        updateLifecycleStore(threatId, data.status)
      }
      loadResponseData(threatId, false)
    }

    const handleRecoveryProgress = (event) => {
      const data = event?.detail ?? {}
      if (selectedRecovery && String(selectedRecovery.id) === String(data.recovery_id)) {
        setSelectedRecovery((prev) => ({
          ...prev,
          progress_percent: data.progress_percent,
          current_step: data.current_step,
          status: data.status,
          execution_log: data.execution_log || prev?.execution_log,
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
                execution_log: data.execution_log || r.execution_log,
              }
            : r
        )
      )
    }

    window.addEventListener('qiga-recommendation', handleQigaRecommendation)
    window.addEventListener('lifecycle-update', handleLifecycleUpdate)
    window.addEventListener('recovery-progress', handleRecoveryProgress)

    return () => {
      window.removeEventListener('qiga-recommendation', handleQigaRecommendation)
      window.removeEventListener('lifecycle-update', handleLifecycleUpdate)
      window.removeEventListener('recovery-progress', handleRecoveryProgress)
    }
  }, [threatId, selectedRecovery?.id, updateLifecycleStore])

  /*
   * -------------------------------------------------------
   * POLL RECOVERY STATUS
   * -------------------------------------------------------
   */
  useEffect(() => {
    if (!selectedRecovery?.id) return undefined
    if (
      selectedRecovery.status !== 'PENDING' &&
      selectedRecovery.status !== 'IN_PROGRESS'
    ) {
      return undefined
    }

    let mounted = true
    const pollRecovery = async () => {
      try {
        const response = await api.get(`/recovery/${selectedRecovery.id}`)
        if (!mounted) return
        const data = response.data
        setSelectedRecovery(data)
        setRecoveries((previous) =>
          previous.map((item) =>
            String(item.id) === String(data.id) ? data : item
          )
        )
      } catch (err) {
        console.error('[Response] Recovery polling failed:', err)
      }
    }

    pollRecovery()
    const interval = setInterval(pollRecovery, 2000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [selectedRecovery?.id, selectedRecovery?.status])

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [selectedRecovery?.execution_log])

  /*
   * -------------------------------------------------------
   * MANUAL STAGE CONTROL (ALL 6 STAGES HANDLED BY ANALYST)
   * -------------------------------------------------------
   */
  const handleManualStageTransition = async (targetStage) => {
    if (!threatId || !canApprove || stageUpdating) return
    setStageUpdating(true)
    setError(null)

    try {
      const response = await api.patch(`/logs/${threatId}/stage`, {
        stage: targetStage,
      })

      // Update in SOC Store
      updateLifecycleStore(threatId, targetStage)

      setSuccessMsg(`✓ Threat #${threatId} successfully moved to stage: ${targetStage}`)
      setTimeout(() => setSuccessMsg(null), 3500)

      await loadResponseData(threatId, false)
    } catch (err) {
      console.error('[Response] Stage update failed:', err)
      setError(err?.response?.data?.detail || `Failed to transition stage to ${targetStage}`)
    } finally {
      setStageUpdating(false)
    }
  }

  /*
   * -------------------------------------------------------
   * MANUAL ACTION AUTHORIZATION BY ANALYST
   * -------------------------------------------------------
   */
  const approveRecommendation = async (recommendationId) => {
    if (!canApprove || !recommendationId || threatId == null) return

    setActionLoading(true)
    setError(null)

    try {
      const response = await api.patch(`/recommendations/${recommendationId}/approve`)
      setSuccessMsg('✓ Mitigation action manually authorized by analyst.')
      setTimeout(() => setSuccessMsg(null), 3500)
      updateLifecycleStore(threatId, 'CONTAINMENT')
      await loadResponseData(threatId, false)
    } catch (err) {
      console.error('[Response] Approval failed:', err)
      setError(err?.response?.data?.detail || 'Unable to authorize this mitigation.')
    } finally {
      setActionLoading(false)
    }
  }

  const rejectRecommendation = async (recommendationId) => {
    if (!canApprove || !recommendationId || threatId == null) return

    setActionLoading(true)
    setError(null)

    try {
      await api.patch(`/recommendations/${recommendationId}/reject`)
      setSuccessMsg('Mitigation recommendation rejected.')
      setTimeout(() => setSuccessMsg(null), 3000)
      await loadResponseData(threatId, false)
    } catch (err) {
      console.error('[Response] Rejection failed:', err)
      setError(err?.response?.data?.detail || 'Unable to reject this recommendation.')
    } finally {
      setActionLoading(false)
    }
  }

  /*
   * Direct trigger from the attack-specific response palette
   */
  const triggerDirectMitigation = async (actionType, actionTitle) => {
    if (!canApprove || !threatId || actionLoading) return

    setActionLoading(true)
    setError(null)

    try {
      const response = await api.post('/recommendations/manual-action', {
        attack_log_id: threatId,
        action_type: actionType,
        title: actionTitle,
      })

      setSuccessMsg(`✓ Mitigation "${actionTitle}" manually authorized and executing.`)
      setTimeout(() => setSuccessMsg(null), 3500)
      updateLifecycleStore(threatId, 'CONTAINMENT')
      await loadResponseData(threatId, false)
    } catch (err) {
      console.error('[Response] Direct mitigation failed:', err)
      setError(err?.response?.data?.detail || `Unable to execute mitigation: ${actionTitle}`)
    } finally {
      setActionLoading(false)
    }
  }

  /*
   * -------------------------------------------------------
   * DERIVED DATA
   * -------------------------------------------------------
   */
  const currentStatus = selectedLog?.status || 'DETECTED'
  const currentStageIndex = Math.max(0, LIFECYCLE_STAGES.indexOf(currentStatus))
  const statusStyle = LIFECYCLE_STYLE[currentStatus] || LIFECYCLE_STYLE.DETECTED

  // Get matching attack-specific responses from official matrix
  const attackType = selectedLog?.attack_type || 'Anomaly/Zero-Day'
  const attackResponses =
    ATTACK_RESPONSES_TABLE[attackType] ||
    ATTACK_RESPONSES_TABLE['Anomaly/Zero-Day']

  const pendingRecs = recs.filter(
    (r) => r.status === 'PENDING' || (!r.status && !r.is_approved)
  )
  const primary = pendingRecs[0] ?? recs[0] ?? null
  const alternatives = primary
    ? recs.filter((r) => String(r.id) !== String(primary.id))
    : []

  const activeRecoveries = recoveries.filter(
    (r) => r.status === 'PENDING' || r.status === 'IN_PROGRESS'
  )
  const completedRecoveries = recoveries.filter(
    (r) => r.status === 'COMPLETED'
  )

  const currentIndex = activeThreats.findIndex(
    (t) => String(t.attack_log_id ?? t.id) === String(threatId)
  )

  const handlePrev = () => {
    if (currentIndex > 0) {
      const prev = activeThreats[currentIndex - 1]
      setSelectedAttackLogId(prev.attack_log_id ?? prev.id)
    }
  }

  const handleNext = () => {
    if (currentIndex < activeThreats.length - 1) {
      const next = activeThreats[currentIndex + 1]
      setSelectedAttackLogId(next.attack_log_id ?? next.id)
    }
  }

  return (
    <div className="p-6 space-y-6 bg-black min-h-screen text-slate-100 font-sans">
      {/* ─── HEADER ──────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#262626] pb-4">
        <div>
          <h1 className="text-2xl font-black font-mono tracking-wide text-white flex items-center gap-2.5">
            <Shield className="text-cyber-cyan" size={24} />
            THREAT ORCHESTRATION &amp; MITIGATION
          </h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Manual security orchestrator. All lifecycle stages are analyst-controlled; response mitigations are tailored to attack classifications.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-300">
            <span className="w-2 h-2 rounded-full bg-cyan-400 pulse-dot" />
            ANALYST-CONTROLLED STAGES
          </div>
          <div className="text-xs font-mono text-slate-400 bg-black/40 px-3 py-1.5 rounded border border-white/10">
            Analyst: <span className="text-white font-bold">{user?.full_name || user?.username || 'Analyst'}</span> ({user?.role || 'analyst'})
          </div>
        </div>
      </div>

      {/* ─── COMPACT THREAT SELECTOR ──────────────────────────────────────── */}
      <div className="cyber-card p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-l-4 border-cyber-cyan">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-red-950/60 border border-red-500/40 flex items-center justify-center">
            <AlertOctagon className="text-red-400" size={20} />
          </div>
          <div>
            <div className="text-xs font-mono font-bold text-white uppercase tracking-wider">
              Hospital Threat Queue
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
              {activeThreats.length} active incident{activeThreats.length !== 1 ? 's' : ''} currently awaiting analyst mitigation
            </div>
          </div>
        </div>

        {activeThreats.length > 0 ? (
          <div className="flex items-center gap-2 w-full md:w-auto">
            <button
              onClick={handlePrev}
              disabled={currentIndex <= 0}
              className="p-1.5 rounded bg-black/50 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition cursor-pointer"
              title="Previous threat"
            >
              <ChevronLeft size={16} />
            </button>

            <select
              value={threatId || ''}
              onChange={(e) => setSelectedAttackLogId(e.target.value)}
              className="bg-black/80 border border-cyan-500/40 text-cyan-300 text-xs font-mono rounded-lg px-3 py-2 focus:border-cyber-cyan focus:outline-none w-full md:w-96 font-semibold cursor-pointer"
            >
              {activeThreats.map((t) => {
                const id = t.attack_log_id ?? t.id
                return (
                  <option key={id} value={id}>
                    #{id} · {t.attack_type} [{t.severity || 'HIGH'}] · Risk {Math.round(t.risk_score || 0)}/100 · {t.status || 'DETECTED'}
                  </option>
                )
              })}
            </select>

            <button
              onClick={handleNext}
              disabled={currentIndex >= activeThreats.length - 1}
              className="p-1.5 rounded bg-black/50 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition cursor-pointer"
              title="Next threat"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        ) : (
          <div className="text-xs font-mono text-slate-500">
            Zero active threats in network stream
          </div>
        )}
      </div>

      {/* ─── TOAST / STATUS ALERTS ────────────────────────────────────────── */}
      {successMsg && (
        <div className="p-3 rounded-lg border border-emerald-500/50 bg-emerald-950/40 text-emerald-300 font-mono text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
          <CheckCircle size={15} className="text-emerald-400 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-lg border border-red-500/50 bg-red-950/40 text-red-300 font-mono text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
          <AlertTriangle size={15} className="text-red-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* ─── NORMAL TRAFFIC EMPTY STATE ───────────────────────────────────── */}
      {isNormal && (
        <div className="cyber-card p-10 text-center border-l-4 border-gray-700">
          <CheckCircle size={48} className="text-gray-600 mx-auto mb-4" />
          <h2 className="text-xl font-bold font-mono text-white">
            Normal Traffic Telemetry
          </h2>
          <p className="text-sm text-gray-400 font-mono max-w-md mx-auto mt-2">
            AttackLog #{threatId} is classified as baseline normal network telemetry. Response mitigation is not required.
          </p>
        </div>
      )}

      {/* ─── MAIN ORCHESTRATION BODY ──────────────────────────────────────── */}
      {!isNormal && selectedLog && (
        <div className="space-y-6">
          {/* 1. SELECTED THREAT METADATA CARD */}
          <div className="cyber-card p-5 border-l-4 border-cyber-red">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle size={16} className="text-cyber-red" />
                <span className="text-xs font-mono text-cyber-red uppercase font-bold tracking-wider">
                  Target Telemetry &amp; Incident Context
                </span>
              </div>
              <span className="text-xs font-mono text-gray-400">
                AttackLog #{threatId}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs font-mono">
              <div>
                <p className="text-gray-500">ATTACK CLASSIFICATION</p>
                <p className="text-white font-bold mt-1 text-sm">{selectedLog.attack_type || 'N/A'}</p>
              </div>

              <div>
                <p className="text-gray-500">DATASET</p>
                <p className="text-purple-300 font-bold mt-1">{selectedLog.dataset || 'TON_IoT'}</p>
              </div>

              <div>
                <p className="text-gray-500">SEVERITY</p>
                <p className="text-orange-400 font-bold mt-1">{selectedLog.severity || 'HIGH'}</p>
              </div>

              <div>
                <p className="text-gray-500">RISK SCORE</p>
                <p
                  className="font-bold mt-1 text-sm"
                  style={{
                    color:
                      Number(selectedLog.risk_score || 0) > 75
                        ? '#ff2d55'
                        : Number(selectedLog.risk_score || 0) > 45
                        ? '#ffd60a'
                        : '#00ff88',
                  }}
                >
                  {selectedLog.risk_score != null
                    ? `${Math.round(Number(selectedLog.risk_score))}/100`
                    : 'N/A'}
                </p>
              </div>

              <div>
                <p className="text-gray-500">CONFIDENCE</p>
                <p className="text-cyan-400 font-bold mt-1">
                  {selectedLog.confidence != null
                    ? `${Math.round(Number(selectedLog.confidence))}%`
                    : 'N/A'}
                </p>
              </div>

              <div>
                <p className="text-gray-500">TARGET ASSET</p>
                <p className="text-purple-300 font-bold mt-1 truncate" title={selectedLog.asset_name || selectedLog.dest_ip || selectedLog.pc || 'Hospital Node'}>
                  {selectedLog.asset_name || selectedLog.dest_ip || selectedLog.pc || 'Hospital Node'}
                </p>
              </div>
            </div>
          </div>

          {/* 2. INTERACTIVE INCIDENT LIFECYCLE (ALL 6 STAGES ANALYST-CONTROLLED) */}
          <div className="cyber-card p-5 border-t-2 border-cyber-cyan">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <Layers size={16} className="text-cyber-cyan" />
                  INCIDENT RESPONSE LIFECYCLE (INTERACTIVE STAGES)
                </h3>
                <p className="text-xs text-gray-400 font-mono mt-0.5">
                  Click any stage card or use the analyst transition controls below to advance the threat lifecycle.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-gray-500">CURRENT:</span>
                <span
                  className={`px-3 py-1 rounded-full border text-xs font-mono font-bold ${statusStyle.text} ${statusStyle.bg} ${statusStyle.border} shadow-[0_0_10px_rgba(80,227,194,0.15)]`}
                >
                  {currentStatus}
                </span>
              </div>
            </div>

            {/* Clickable 6-Stage Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
              {LIFECYCLE_STAGES.map((stage, index) => {
                const reached = currentStageIndex >= index
                const isCurrent = currentStatus === stage
                const style = LIFECYCLE_STYLE[stage] || LIFECYCLE_STYLE.DETECTED

                return (
                  <button
                    key={stage}
                    type="button"
                    onClick={() => handleManualStageTransition(stage)}
                    disabled={stageUpdating || !canApprove}
                    className={`relative rounded-xl border p-3.5 text-left transition-all duration-200 cursor-pointer disabled:cursor-not-allowed group ${
                      isCurrent
                        ? `${style.bg} ${style.border} ring-2 ring-cyber-cyan shadow-[0_0_15px_rgba(80,227,194,0.25)] scale-[1.02]`
                        : reached
                        ? 'bg-cyan-950/20 border-cyan-500/40 hover:border-cyan-400'
                        : 'bg-black/40 border-[#262626] hover:border-gray-600 opacity-70 hover:opacity-100'
                    }`}
                    title={`Click to manually transition Threat #${threatId} to ${stage}`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono text-gray-500 font-bold">
                        0{index + 1}
                      </span>
                      <div
                        className={`w-2.5 h-2.5 rounded-full ${
                          isCurrent
                            ? `${style.dot} pulse-dot`
                            : reached
                            ? 'bg-cyber-cyan'
                            : 'bg-gray-700'
                        }`}
                      />
                    </div>

                    <p
                      className={`text-xs font-mono font-black tracking-wider ${
                        isCurrent
                          ? style.text
                          : reached
                          ? 'text-cyber-cyan'
                          : 'text-gray-400'
                      }`}
                    >
                      {stage}
                    </p>

                    <p className="text-[10px] text-gray-500 mt-1 line-clamp-2 leading-tight">
                      {style.description}
                    </p>

                    <div className="mt-2 pt-2 border-t border-white/5 flex items-center justify-between text-[9px] font-mono">
                      <span className={isCurrent ? style.text : 'text-gray-600 group-hover:text-gray-400'}>
                        {isCurrent ? '● CURRENT' : '→ SET STAGE'}
                      </span>
                      {stageUpdating && isCurrent && (
                        <RefreshCw size={10} className="animate-spin text-cyan-400" />
                      )}
                    </div>
                  </button>
                )
              })}
            </div>

            {/* Manual Stage Fast-Action Toolbar */}
            <div className="mt-4 pt-4 border-t border-[#262626] flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-slate-400">
                  STAGE WORKFLOW TRANSITIONS:
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {currentStatus !== 'ACKNOWLEDGED' && (
                  <button
                    onClick={() => handleManualStageTransition('ACKNOWLEDGED')}
                    disabled={stageUpdating || !canApprove}
                    className="px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-300 font-mono text-xs font-bold transition cursor-pointer disabled:opacity-50"
                  >
                    ✓ Acknowledge
                  </button>
                )}

                {currentStatus !== 'ANALYZING' && (
                  <button
                    onClick={() => handleManualStageTransition('ANALYZING')}
                    disabled={stageUpdating || !canApprove}
                    className="px-3 py-1.5 rounded-lg border border-yellow-500/40 bg-yellow-950/40 hover:bg-yellow-900/60 text-yellow-300 font-mono text-xs font-bold transition cursor-pointer disabled:opacity-50"
                  >
                    🔍 Analyzing
                  </button>
                )}

                {currentStatus !== 'CONTAINMENT' && (
                  <button
                    onClick={() => handleManualStageTransition('CONTAINMENT')}
                    disabled={stageUpdating || !canApprove}
                    className="px-3 py-1.5 rounded-lg border border-orange-500/40 bg-orange-950/40 hover:bg-orange-900/60 text-orange-300 font-mono text-xs font-bold transition cursor-pointer disabled:opacity-50"
                  >
                    🛡️ Containment
                  </button>
                )}

                {currentStatus !== 'RECOVERY' && (
                  <button
                    onClick={() => handleManualStageTransition('RECOVERY')}
                    disabled={stageUpdating || !canApprove}
                    className="px-3 py-1.5 rounded-lg border border-blue-500/40 bg-blue-950/40 hover:bg-blue-900/60 text-blue-300 font-mono text-xs font-bold transition cursor-pointer disabled:opacity-50"
                  >
                    🔄 Recovery
                  </button>
                )}

                {currentStatus !== 'RESOLVED' && (
                  <button
                    onClick={() => handleManualStageTransition('RESOLVED')}
                    disabled={stageUpdating || !canApprove}
                    className="px-3 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 font-mono text-xs font-bold transition cursor-pointer disabled:opacity-50 shadow-[0_0_10px_rgba(16,185,129,0.3)]"
                  >
                    ✓ Mark Resolved
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* 3. TAILORED ATTACK RESPONSE MITIGATION SUITE */}
          <div className="cyber-card p-5 border-l-4 border-cyber-cyan">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div>
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <Zap size={16} className="text-cyber-cyan" />
                  RESPONSE MITIGATIONS FOR: <span className="text-cyber-cyan">{selectedLog.attack_type}</span>
                </h3>
                <p className="text-xs text-gray-400 font-mono mt-0.5">
                  Official mitigation strategies configured for {selectedLog.attack_type} threats. Analyst authorization required to execute.
                </p>
              </div>

              <span className="text-xs font-mono text-purple-300 px-3 py-1 rounded bg-purple-950/40 border border-purple-500/30">
                {attackResponses.length} Tailored Actions Available
              </span>
            </div>

            {/* Instant Action Palette for this Attack */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
              {attackResponses.map((action) => {
                const Icon = action.icon || ACTION_ICONS[action.id] || Zap
                const isApproved = recs.some((r) => r.action_type === action.id && r.is_approved)

                return (
                  <div
                    key={action.id}
                    className={`rounded-xl border p-4 transition-all duration-200 ${
                      isApproved
                        ? 'border-emerald-500/60 bg-emerald-950/20'
                        : 'border-[#262626] bg-black/50 hover:border-cyber-cyan/50'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                        style={{
                          backgroundColor: `${action.color}15`,
                          border: `1px solid ${action.color}40`,
                        }}
                      >
                        <Icon size={20} style={{ color: action.color }} />
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-1">
                          <h4 className="text-xs font-bold text-white font-mono truncate">
                            {action.name}
                          </h4>
                          <span
                            className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                            style={{
                              color: action.color,
                              backgroundColor: `${action.color}15`,
                              border: `1px solid ${action.color}30`,
                            }}
                          >
                            {action.id}
                          </span>
                        </div>

                        <p className="text-[11px] text-gray-400 mt-1 line-clamp-2 leading-tight">
                          {action.desc}
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-white/5 text-[10px] font-mono text-gray-400">
                      <div>
                        <span className="text-gray-600 block">EFFICIENCY</span>
                        <span className="text-white font-bold">{action.eff}%</span>
                      </div>
                      <div>
                        <span className="text-gray-600 block">COST</span>
                        <span className="text-white font-bold">{action.cost} Units</span>
                      </div>
                      <div>
                        <span className="text-gray-600 block">LATENCY</span>
                        <span className="text-white font-bold">{action.latency}</span>
                      </div>
                    </div>

                    {/* Authorize Button */}
                    <div className="mt-3.5">
                      {isApproved ? (
                        <div className="w-full py-2 rounded text-center text-xs font-mono font-bold text-emerald-400 bg-emerald-950/40 border border-emerald-500/40 flex items-center justify-center gap-1.5">
                          <CheckCircle size={13} />
                          <span>✓ AUTHORIZED &amp; EXECUTING</span>
                        </div>
                      ) : (
                        <button
                          type="button"
                          onClick={() => triggerDirectMitigation(action.id, action.name)}
                          disabled={actionLoading || !canApprove}
                          className="w-full py-2 rounded text-xs font-mono font-bold transition-all cursor-pointer flex items-center justify-center gap-1.5 shadow-[0_0_10px_rgba(80,227,194,0.15)] hover:brightness-110 active:scale-[0.99] disabled:opacity-50"
                          style={{
                            background: `linear-gradient(135deg, ${action.color}cc, ${action.color})`,
                            color: '#000000',
                          }}
                        >
                          <Play size={12} className="fill-black" />
                          <span>AUTHORIZE: {action.name}</span>
                        </button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* 4. ACTIVE RECOVERY WORKFLOW & PROGRESS */}
          {activeRecoveries.length > 0 && (
            <div className="cyber-card p-5 border-l-4 border-yellow-500">
              <div className="flex items-center gap-2 mb-3">
                <RefreshCw size={15} className="text-yellow-400 animate-spin" />
                <span className="text-xs font-bold text-yellow-400 font-mono uppercase tracking-wider">
                  ACTIVE MITIGATION WORKFLOW IN FLIGHT
                </span>
                <span className="ml-auto text-xs text-gray-500 font-mono">
                  {activeRecoveries.length} active
                </span>
              </div>

              <div className="space-y-2">
                {activeRecoveries.map((recovery) => (
                  <button
                    key={recovery.id}
                    type="button"
                    onClick={() => setSelectedRecovery(recovery)}
                    className={`w-full text-left p-3 rounded-lg border transition-all cursor-pointer ${
                      selectedRecovery?.id === recovery.id
                        ? 'border-yellow-500 bg-yellow-900/20'
                        : 'border-[#262626] hover:border-yellow-500/40 bg-black/30'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-white">
                        {recovery.action_name || recovery.action_type || 'Recovery Action'}
                      </span>
                      <span className="text-xs font-mono text-yellow-400 font-bold">
                        {recovery.status} ({recovery.progress_percent || 0}%)
                      </span>
                    </div>
                    <p className="text-[11px] text-gray-400 font-mono mt-1">
                      Type: {recovery.action_type || 'N/A'} · Target: {recovery.target_node || 'N/A'} · {recovery.current_step || 'In progress...'}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* 5. LIVE RECOVERY EXECUTION TERMINAL */}
          <div className="cyber-card p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Terminal size={18} className="text-cyber-cyan" />
                <div>
                  <h3 className="text-sm font-bold text-white font-mono">
                    RECOVERY EXECUTION LOG CONSOLE
                  </h3>
                  <p className="text-xs text-gray-500 font-mono mt-0.5">
                    Real-time execution telemetry from the mitigation engine
                  </p>
                </div>
              </div>

              {selectedRecovery && (
                <span
                  className={`px-2.5 py-1 rounded border text-[10px] font-mono font-bold uppercase ${
                    STATUS_STYLE[selectedRecovery.status] || ''
                  }`}
                >
                  {selectedRecovery.status}
                </span>
              )}
            </div>

            {selectedRecovery ? (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4 text-xs font-mono border-b border-[#262626] pb-3">
                  <div>
                    <p className="text-gray-500">ACTION</p>
                    <p className="text-white font-bold mt-1">
                      {selectedRecovery.action_name || selectedRecovery.action_type || 'N/A'}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-500">TYPE</p>
                    <p className="text-white font-bold mt-1">
                      {selectedRecovery.action_type || 'N/A'}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-500">TARGET NODE</p>
                    <p className="text-cyan-400 font-bold mt-1 truncate">
                      {selectedRecovery.target_node || 'N/A'}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-500">STATUS</p>
                    <p className="text-white font-bold mt-1">
                      {selectedRecovery.status || 'PENDING'}
                    </p>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="mb-4 bg-slate-900/80 p-3 rounded-lg border border-cyan-500/20">
                  <div className="flex items-center justify-between text-xs font-mono mb-2">
                    <span className="text-slate-300 flex items-center gap-2 truncate max-w-md">
                      <RefreshCw
                        size={12}
                        className={
                          selectedRecovery.status === 'IN_PROGRESS'
                            ? 'animate-spin text-cyan-400'
                            : 'text-slate-500'
                        }
                      />
                      <span>
                        {selectedRecovery.current_step ||
                          (selectedRecovery.status === 'COMPLETED'
                            ? 'Mitigation executed and verified successfully.'
                            : 'Awaiting execution thread...')}
                      </span>
                    </span>
                    <span className="text-cyber-cyan font-bold">
                      {selectedRecovery.progress_percent ??
                        (selectedRecovery.status === 'COMPLETED' ? 100 : 0)}%
                    </span>
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
                        width: `${
                          selectedRecovery.progress_percent ??
                          (selectedRecovery.status === 'COMPLETED' ? 100 : 0)
                        }%`,
                      }}
                    />
                  </div>
                </div>

                {/* Terminal Console Box */}
                <div
                  ref={logRef}
                  className="bg-black/90 rounded-lg p-4 font-mono text-xs space-y-1.5 max-h-64 overflow-y-auto border border-[#262626] shadow-inner"
                >
                  {selectedRecovery.execution_log ? (
                    selectedRecovery.execution_log.split('\n').map((line, idx) => {
                      const lower = line.toLowerCase()
                      const lineClass =
                        lower.includes('error') || lower.includes('fail')
                          ? 'text-red-400 font-bold'
                          : lower.includes('verified') ||
                            lower.includes('complete') ||
                            lower.includes('confirmed') ||
                            lower.includes('success')
                          ? 'text-green-400'
                          : lower.includes('executing') || lower.includes('step')
                          ? 'text-cyan-300'
                          : 'text-gray-300'

                      return (
                        <p key={idx} className={lineClass}>
                          {line}
                        </p>
                      )
                    })
                  ) : (
                    <p className="text-gray-600">Waiting for recovery execution telemetry...</p>
                  )}

                  {selectedRecovery.status === 'IN_PROGRESS' && (
                    <p className="text-yellow-400 animate-pulse">▌</p>
                  )}
                </div>

                {selectedRecovery.status === 'COMPLETED' && (
                  <div className="mt-3 flex items-center gap-2 text-xs font-mono text-green-400 font-bold">
                    <CheckCircle size={15} />
                    <span>Mitigation action executed and verified successfully.</span>
                  </div>
                )}
              </>
            ) : (
              <div className="p-8 rounded-xl border border-gray-800 bg-black/20 text-center">
                <Terminal size={24} className="text-gray-700 mx-auto mb-3" />
                <p className="text-sm text-gray-400 font-mono">
                  No mitigation workflow active.
                </p>
                <p className="text-xs text-gray-500 font-mono mt-1">
                  Click "Authorize" on any of the response actions above to launch the mitigation workflow under analyst supervision.
                </p>
              </div>
            )}
          </div>

          {/* 6. COMPLETED RECOVERY ACTIONS HISTORY */}
          {completedRecoveries.length > 0 && (
            <div className="cyber-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <CheckCircle size={16} className="text-green-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  COMPLETED MITIGATION ACTIONS ({completedRecoveries.length})
                </h3>
              </div>

              <div className="space-y-2">
                {completedRecoveries.slice(0, 6).map((recovery) => (
                  <button
                    key={recovery.id}
                    type="button"
                    onClick={() => setSelectedRecovery(recovery)}
                    className="w-full text-left rounded-lg border border-[#262626] p-3 hover:border-green-700/40 bg-black/30 transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <CheckCircle size={15} className="text-green-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-mono text-white font-bold">
                          {recovery.action_name || recovery.action_type || 'Recovery Action'}
                        </p>
                        <p className="text-[11px] text-gray-400 mt-0.5">
                          Type: {recovery.action_type || 'N/A'} · Target: {recovery.target_node || 'N/A'} · Completed:{' '}
                          {recovery.completed_at
                            ? new Date(recovery.completed_at).toLocaleTimeString()
                            : 'N/A'}
                        </p>
                      </div>
                      <span className="text-[10px] font-mono text-green-400 border border-green-500/50 px-2 py-1 rounded hover:bg-green-900/20">
                        INSPECT LOG
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
