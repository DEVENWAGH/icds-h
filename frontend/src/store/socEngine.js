import { create } from 'zustand'
import api from '../utils/api'

export const LIFECYCLE_STAGES = [
'DETECTED',
'ANALYZING',
'CONTAINMENT',
'RECOVERY',
'RESOLVED',
]

const THREAT_TYPES = new Set([
'DDoS',
'Ransomware',
'Phishing',
'Insider Threat',
])

/*

* Simulated hospital environment.
*
* These assets provide contextual hospital information only.
* Actual security telemetry continues to come from the backend
* datasets and MLP prediction pipeline.
  */
  const SIMULATED_ASSETS = [
  {
  asset_name: 'Hospital Core Server',
  asset_type: 'Server',
  department: 'IT Infrastructure',
  criticality: 'CRITICAL',
  status: 'ONLINE',
  },
  {
  asset_name: 'EHR Database',
  asset_type: 'Database',
  department: 'Health Information',
  criticality: 'CRITICAL',
  status: 'ONLINE',
  },
  {
  asset_name: 'Clinical Workstation',
  asset_type: 'Workstation',
  department: 'Emergency Department',
  criticality: 'HIGH',
  status: 'ONLINE',
  },
  {
  asset_name: 'Medical Device Gateway',
  asset_type: 'Medical Device',
  department: 'ICU',
  criticality: 'CRITICAL',
  status: 'MONITORING',
  },
  {
  asset_name: 'Pharmacy Server',
  asset_type: 'Server',
  department: 'Pharmacy',
  criticality: 'HIGH',
  status: 'ONLINE',
  },
  {
  asset_name: 'Laboratory Information Server',
  asset_type: 'Server',
  department: 'Laboratory',
  criticality: 'HIGH',
  status: 'ONLINE',
  },
  {
  asset_name: 'Radiology Workstation',
  asset_type: 'Workstation',
  department: 'Radiology',
  criticality: 'HIGH',
  status: 'ONLINE',
  },
  {
  asset_name: 'Patient Monitoring Gateway',
  asset_type: 'Medical Device',
  department: 'ICU',
  criticality: 'CRITICAL',
  status: 'MONITORING',
  },
  {
  asset_name: 'Hospital Network Gateway',
  asset_type: 'Network Device',
  department: 'Network Operations',
  criticality: 'CRITICAL',
  status: 'ONLINE',
  },
  ]

/*

* Deterministic hash.
* No Math.random().
  */
  const deterministicHash = (value = '') => {
  const text = String(value)
  let hash = 0

for (let i = 0; i < text.length; i += 1) {
hash = (hash * 31 + text.charCodeAt(i)) >>> 0
}

return hash
}

/*

* Build a deterministic asset context from the actual event.
  */
  const getAssetContextKey = (log, raw) => {
  const dataset = String(
  log?.dataset ??
  log?.dataset_source ??
  ''
  )

if (dataset === 'TON_IoT') {
return (
raw?.dst_ip ??
raw?.dest_ip ??
log?.dest_ip ??
log?.dst_ip ??
'TON_IoT'
)
}

if (dataset === 'PhiUSIIL') {
return (
raw?.Domain ??
raw?.domain ??
raw?.URL ??
raw?.url ??
'PhiUSIIL'
)
}

if (dataset === 'CERT') {
return (
raw?.pc ??
raw?.user ??
'CERT'
)
}

return (
raw?.dst_ip ??
raw?.dest_ip ??
raw?.Domain ??
raw?.URL ??
raw?.pc ??
raw?.user ??
log?.id ??
'ICDS-H'
)
}

const getSimulatedAsset = (
log,
rawFeatures = {}
) => {
const key = getAssetContextKey(
log,
rawFeatures
)

const index =
deterministicHash(key) %
SIMULATED_ASSETS.length

return SIMULATED_ASSETS[index]
}

/*

* Normalize backend AttackLog / WebSocket telemetry.
*
* Central identifier:
* ```
  attack_log_id
  ```
*
* This ID must remain unchanged through:
*
* MLP
* ↓
* SHAP
* ↓
* QIGA
* ↓
* Recommendation
* ↓
* Admin approval
* ↓
* Recovery
  */
  const normalizeIncident = (
  log = {}
  ) => {
  const raw =
  log.raw_features ?? {}

const dataset =
log.dataset ??
log.dataset_source ??
'Unknown'

const attackType =
log.attack_type ??
log.prediction_label ??
'Unknown'

const status =
String(
log.status ??
'DETECTED'
).toUpperCase()

const stageIndex =
LIFECYCLE_STAGES.indexOf(
status
)

const confidenceValue =
log.confidence ??
log.suspicious_score ??
null

const riskValue =
log.risk_score ??
log.risk ??
null

const confidence =
confidenceValue !== null &&
Number.isFinite(
Number(confidenceValue)
)
? Number(confidenceValue)
: null

const riskScore =
riskValue !== null &&
Number.isFinite(
Number(riskValue)
)
? Number(riskValue)
: null

const asset =
getSimulatedAsset(
log,
raw
)

const sourceIp =
log.source_ip ??
raw.src_ip ??
null

const destIp =
log.dest_ip ??
raw.dst_ip ??
raw.dest_ip ??
null

const protocol =
log.protocol ??
raw.proto ??
null

const port =
log.port ??
raw.dst_port ??
null

const url =
raw.URL ??
raw.url ??
log.url ??
null

const domain =
raw.Domain ??
raw.domain ??
log.domain ??
null

const user =
raw.user ??
log.user ??
null

const pc =
raw.pc ??
log.pc ??
null

const activity =
raw.activity ??
log.activity ??
null

const date =
raw.date ??
log.date ??
log.detected_at ??
log.created_at ??
null

return {
...log,

   /** Canonical ID.*/
attack_log_id:
  log.attack_log_id ??
  log.id ??
  log.attack_id,

 /** Classification.*/
attack_type:
  attackType,

dataset,

is_normal:
  attackType === 'Normal',

is_threat:
  THREAT_TYPES.has(
    attackType
  ),

/*
 * Prediction values produced by MLP.
 */
confidence,
risk_score: riskScore,

/*
 * Lifecycle.
 */
status,

stage:
  stageIndex >= 0
    ? stageIndex
    : 0,

resolved:
  status === 'RESOLVED',

/*
 * Network telemetry.
 */
source_ip:
  sourceIp,

dest_ip:
  destIp,

protocol,

port,

/*
 * Phishing telemetry.
 */
url,
domain,

/*
 * CERT telemetry.
 */
user,
pc,
activity,
event_date: date,

/*
 * Simulated healthcare context.
 */
asset_name:
  log.asset_name ??
  asset.asset_name,

asset_type:
  log.asset_type ??
  asset.asset_type,

department:
  log.department ??
  asset.department,

asset_criticality:
  log.asset_criticality ??
  asset.criticality,

asset_status:
  log.asset_status ??
  asset.status,

/*
 * Preserve the exact backend feature payload.
 */
raw_features:
  raw,
}
}

 /** Normalize a QIGA recommendation event.** This does NOT approve anything.*/
const normalizeQIGARecommendation = (data = {}) => {
  const attackLogId =
  data.attack_log_id ??
  data.id ??
  null

const selectedActions =
Array.isArray(
data.selected_actions
)
? data.selected_actions.map(
(action) => ({
id:
action?.id ??
null,

        title:
          action?.title ??
          action?.name ??
          'Response Action',

        confidence:
          Number(
            action?.confidence ??
              0
          ),

        is_approved:
          Boolean(
            action?.is_approved ??
              false
          ),
      })
    )
  : []


return {
attack_log_id:
attackLogId,


attack_type:
  data.attack_type ??
  null,

risk_score:
  Number(
    data.risk_score ?? 0
  ),

qiga_id:
  data.qiga_id ??
  null,

objective_score:
  Number(
    data.objective_score ??
      0
  ),

selected_actions:
  selectedActions,

/*
 * Important:
 * QIGA only recommends.
 * It does not authorize execution.
 */
approval_required:
  true,

approved:
  selectedActions.some(
    (action) =>
      action.is_approved
  ),

created_at:
  new Date().toISOString(),

}
}

export const useSOCStore = create(
(set, get) => ({
/*
* Main SOC incident collection.
*/
incidents: [],

/*
 * QIGA recommendations grouped by AttackLog ID.
 *
 * Example:
 * {
 *   "42": {
 *      attack_log_id: 42,
 *      ...
 *   }
 * }
 */
 qigaRecommendations: {},

 initialized: false,

 loading: false,

 lastTick: null,

/*
 * Current top incident.
 */
topIncident: null,

// =========================================================
// INITIAL BACKEND LOAD
// =========================================================

init: async () => {
  if (
    get().initialized
  ) {
    return
  }

  set({
    initialized: true,
    loading: true,
  })

  try {
    const {
      data,
    } = await api.get(
      '/logs/latest?limit=100'
    )

    const rawLogs =
      Array.isArray(data)
        ? data
        : []

    const incidents =
      rawLogs.map(
        normalizeIncident
      )

    set({
      incidents,
      loading: false,
      lastTick:
        Date.now(),
    })

    console.log(
      `[SOC] Loaded ${incidents.length} backend logs`
    )
  } catch (
    error
  ) {
    console.error(
      '[SOC] Failed to load latest logs:',
      error
    )

    set({
      incidents: [],
      loading: false,
      lastTick:
        Date.now(),
    })
  }
},

// =========================================================
// NEW MLP THREAT EVENT
// =========================================================

upsertIncident: (
  rawIncident
) => {
  if (!rawIncident) {
    return
  }

  const incident =
    normalizeIncident(
      rawIncident
    )

  const incidentId =
    incident.attack_log_id ??
    incident.id

  if (
    incidentId ===
      undefined ||
    incidentId === null
  ) {
    console.warn(
      '[SOC] Received event without attack_log_id:',
      rawIncident
    )

    return
  }

  set(
    (state) => {
      const index =
        state.incidents.findIndex(
          (item) =>
            String(
              item.attack_log_id ??
                item.id
            ) ===
            String(
              incidentId
            )
        )

      /*
       * New AttackLog.
       */
      if (
        index === -1
      ) {
        return {
          incidents: [
            incident,
            ...state.incidents,
          ].slice(
            0,
            100
          ),

          lastTick:
            Date.now(),
        }
      }

      /*
       * Same AttackLog.
       *
       * Merge instead of replacing so fields such as
       * raw_features aren't lost.
       */
      const updated =
        [
          ...state.incidents,
        ]

      updated[index] = {
        ...updated[index],
        ...incident,

        raw_features:
          incident.raw_features ??
          updated[index]
            .raw_features,
      }

      return {
        incidents:
          updated.slice(
            0,
            100
          ),

        lastTick:
          Date.now(),
      }
    }
  )
},

// =========================================================
// QIGA → RECOMMENDATION EVENT
// =========================================================

upsertQIGARecommendation: (
  rawRecommendation
) => {
  if (
    !rawRecommendation
  ) {
    return
  }

  const recommendation =
    normalizeQIGARecommendation(
      rawRecommendation
    )

  const attackLogId =
    recommendation.attack_log_id

  if (
    attackLogId ===
      undefined ||
    attackLogId === null
  ) {
    console.warn(
      '[SOC] QIGA recommendation has no attack_log_id:',
      rawRecommendation
    )

    return
  }

  set(
    (state) => ({
      qigaRecommendations: {
        ...state.qigaRecommendations,

        [String(
          attackLogId
        )]:
          recommendation,
      },

      lastTick:
        Date.now(),
    })
  )

  console.log(
    '[SOC] QIGA recommendation stored for AttackLog:',
    attackLogId
  )
},

// =========================================================
// REMOVE QIGA DATA FOR A RESOLVED EVENT
// =========================================================

clearQIGARecommendation: (
  attackLogId
) => {
  if (
    attackLogId ===
      undefined ||
    attackLogId === null
  ) {
    return
  }

  set(
    (state) => {
      const updated =
        {
          ...state.qigaRecommendations,
        }

      delete updated[
        String(
          attackLogId
        )
      ]

      return {
        qigaRecommendations:
          updated,

        lastTick:
          Date.now(),
      }
    }
  )
},

// =========================================================
// REFRESH INCIDENTS FROM BACKEND
// =========================================================

refreshIncidents: async () => {
  try {
    const { data } = await api.get('/logs/latest?limit=100')
    const rawLogs = Array.isArray(data) ? data : []
    set({
      incidents: rawLogs.map(normalizeIncident),
      lastTick: Date.now(),
    })
  } catch (error) {
    console.error('[SOC] Failed to refresh logs:', error)
  }
},

// =========================================================
// ANALYST MITIGATION (RESOLVE + ACK ALERTS)
// =========================================================

mitigateAttack: async (attackLogId, { autoBlock = false } = {}) => {
  if (attackLogId == null) return false
  try {
    await api.patch(
      `/logs/${attackLogId}/mitigate?auto_block=${autoBlock ? 'true' : 'false'}`
    )
    get().updateLifecycle(attackLogId, 'RESOLVED')
    return true
  } catch (error) {
    console.error('[SOC] Mitigation failed:', error)
    return false
  }
},

// =========================================================
// LIFECYCLE UPDATE
// =========================================================

updateLifecycle: (
  attackLogId,
  status
) => {
  if (
    attackLogId ===
      undefined ||
    attackLogId === null
  ) {
    return
  }

  const normalizedStatus =
    String(
      status ?? ''
    ).toUpperCase()

  if (
    !LIFECYCLE_STAGES.includes(
      normalizedStatus
    )
  ) {
    console.warn(
      '[SOC] Unknown lifecycle status:',
      normalizedStatus
    )

    return
  }

  set(
    (state) => ({
      incidents:
        state.incidents.map(
          (incident) => {
            const id =
              incident.attack_log_id ??
              incident.id

            if (
              String(id) !==
              String(
                attackLogId
              )
            ) {
              return incident
            }

            return {
              ...incident,

              status:
                normalizedStatus,

              stage:
                LIFECYCLE_STAGES.indexOf(
                  normalizedStatus
                ),

              resolved:
                normalizedStatus ===
                'RESOLVED',
            }
          }
        ),

      lastTick:
        Date.now(),
    })
  )

  /*
   * A resolved event no longer needs an active
   * frontend recommendation state.
   *
   * The recommendation itself remains persisted
   * in the database.
   */
  if (
    normalizedStatus ===
    'RESOLVED'
  ) {
    get()
      .clearQIGARecommendation(
        attackLogId
      )
  }
},

// =========================================================
// SELECTED / TOP INCIDENT
// =========================================================

setTopIncident: (
  incident
) => {
  set({
    topIncident:
      incident ?? null,
  })
},

// =========================================================
// GET ONE INCIDENT
// =========================================================

getIncidentById: (
  attackLogId
) => {
  if (
    attackLogId ===
      undefined ||
    attackLogId === null
  ) {
    return null
  }

  return (
    get().incidents.find(
      (incident) =>
        String(
          incident.attack_log_id ??
            incident.id
        ) ===
        String(
          attackLogId
        )
    ) ?? null
  )
},

// =========================================================
// GET QIGA RECOMMENDATION FOR ONE ATTACK
// =========================================================

getQIGARecommendation: (
  attackLogId
) => {
  if (
    attackLogId ===
      undefined ||
    attackLogId === null
  ) {
    return null
  }

  return (
    get()
      .qigaRecommendations[
      String(
        attackLogId
      )
    ] ?? null
  )
},

// =========================================================
// QUERY HELPERS
// =========================================================

getThreats: () =>
  get().incidents.filter(
    (incident) =>
      incident.is_threat
  ),

getNormalTraffic: () =>
  get().incidents.filter(
    (incident) =>
      incident.is_normal
  ),

getActiveThreats: () =>
  get().incidents.filter(
    (incident) =>
      incident.is_threat &&
      !incident.resolved
  ),

getSimulatedAssets:
  () =>
    SIMULATED_ASSETS,

})
)

export {
SIMULATED_ASSETS,
normalizeIncident,
normalizeQIGARecommendation,
}
