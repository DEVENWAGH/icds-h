import { create } from 'zustand'
import { persist } from 'zustand/middleware'


/* ============================================================================
   AUTH STORE
   ========================================================================== */

export const useAuthStore = create(
  persist(
    (set) => ({
      user: null,
      token: null,

      setAuth: (user, token) => {
        set({
          user,
          token,
        })
      },

      logout: () => {
        set({
          user: null,
          token: null,
        })
      },
    }),
    {
      name: 'icds-auth',
    }
  )
)


/* ============================================================================
   ALERT STORE
   ========================================================================== */

export const useAlertStore = create((set) => ({
  unreadCount: 0,

  setUnreadCount: (count) => {
    set({
      unreadCount:
        Number(count) || 0,
    })
  },

  liveThreats: [],

  addLiveThreat: (threat) => {
    if (!threat) {
      return
    }

    const attackLogId =
      threat.attack_log_id ??
      threat.id ??
      null

    set((state) => {
      /*
       * Avoid duplicate live threats for the same AttackLog.
       */
      const filtered =
        attackLogId !== null
          ? state.liveThreats.filter(
              (item) =>
                String(
                  item.attack_log_id ??
                    item.id
                ) !==
                String(
                  attackLogId
                )
            )
          : state.liveThreats

      return {
        liveThreats: [
          threat,
          ...filtered,
        ].slice(0, 30),
      }
    })
  },

  liveMetrics: {},

  setLiveMetrics: (metrics) => {
    set({
      liveMetrics:
        metrics || {},
    })
  },
}))


/* ============================================================================
   DASHBOARD STORE
   ========================================================================== */

export const useDashboardStore = create((set) => ({
  dashboardData: null,

  setDashboardData: (data) => {
    set({
      dashboardData: data,
    })
  },

  recoveryActions: [],

  setRecoveryActions: (actions) => {
    set({
      recoveryActions:
        Array.isArray(actions)
          ? actions
          : [],
    })
  },

  latestAttacks: [],

  setLatestAttacks: (attacks) => {
    set({
      latestAttacks:
        Array.isArray(attacks)
          ? attacks
          : [],
    })
  },
}))


/* ============================================================================
   INCIDENT / ATTACKLOG SELECTION STORE

   IMPORTANT:
   selectedAttackLogId is intentionally NOT persisted.

   Reason:
   The application follows LIVE monitoring events.

   Persisting an old AttackLog ID can cause this problem:

       Old AttackLog ID
            ↓
       Analytics opens
            ↓
       No matching live event
            ↓
       Dataset = Unknown
       Monitoring = Waiting
       MLP = Waiting

   The current live event should become the active selection.
   ========================================================================== */

export const useIncidentStore = create((set) => ({
  selectedAttackLogId: null,

  /*
   * Explicit user selection from Monitoring / Logs.
   */
  setSelectedAttackLogId: (id) => {
    const normalized =
      id === undefined ||
      id === null ||
      id === ''
        ? null
        : id

    console.log(
      '[IncidentStore] Selected AttackLog:',
      normalized
    )

    set({
      selectedAttackLogId:
        normalized,
    })
  },

  /*
   * Used by the live WebSocket pipeline.

   * This selects the newly detected event automatically,
   * but only when there is no user-selected AttackLog.
   */
  selectLiveAttack: (id) => {
    const normalized =
      id === undefined ||
      id === null ||
      id === ''
        ? null
        : id

    if (normalized === null) {
      return
    }

    set((state) => {
      /*
       * Do not overwrite an explicitly selected event.
       */
      if (
        state.selectedAttackLogId !==
          null &&
        state.selectedAttackLogId !==
          undefined
      ) {
        return state
      }

      console.log(
        '[IncidentStore] Auto-selected live AttackLog:',
        normalized
      )

      return {
        selectedAttackLogId:
          normalized,
      }
    })
  },

  /*
   * Force the currently arriving live event to become active.

   * Useful when the application should always follow
   * the newest Monitoring detection.
   */
  followLiveAttack: (id) => {
    const normalized =
      id === undefined ||
      id === null ||
      id === ''
        ? null
        : id

    if (normalized === null) {
      return
    }

    console.log(
      '[IncidentStore] Following live AttackLog:',
      normalized
    )

    set({
      selectedAttackLogId:
        normalized,
    })
  },

  /*
   * Clear current selection.
   */
  clearSelected: () => {
    set({
      selectedAttackLogId:
        null,
    })
  },
}))
export { useSOCStore } from './socStore'
