import { create } from 'zustand'
import api from '../utils/api'

export const useSOCStore = create((set) => ({
  incidents: [],
  loading: false,
  initialized: false,

  init: async () => {
    set({
      loading: true,
    })

    try {
      const { data } = await api.get('/logs/latest?limit=100')

      const incidents = Array.isArray(data)
        ? data
        : []

      set({
        incidents,
        loading: false,
        initialized: true,
      })
    } catch (error) {
      console.error(
        '[SOC] Failed to load incidents:',
        error
      )

      set({
        incidents: [],
        loading: false,
        initialized: true,
      })
    }
  },

  upsertIncident: (incident) => {
    if (!incident) return

    const id =
      incident.attack_log_id ??
      incident.id

    if (id === undefined || id === null) {
      return
    }

    set((state) => {
      const index = state.incidents.findIndex(
        (item) =>
          String(
            item.attack_log_id ?? item.id
          ) === String(id)
      )

      if (index === -1) {
        return {
          incidents: [
            incident,
            ...state.incidents,
          ].slice(0, 100),
        }
      }

      const updated = [
        ...state.incidents,
      ]

      updated[index] = {
        ...updated[index],
        ...incident,
      }

      return {
        incidents: updated,
      }
    })
  },

  clearIncidents: () => {
    set({
      incidents: [],
    })
  },
}))