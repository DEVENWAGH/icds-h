import axios from 'axios'
import { useAuthStore } from '../store'

const api = axios.create({
  baseURL: '/api',
  timeout: 15000,           // 15 second timeout
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    // Network error (backend not running)
    if (!err.response && err.code === 'ERR_NETWORK') {
      err.isNetworkError = true
      return Promise.reject(err)
    }

    if (err.code === 'ECONNABORTED') {
      err.isTimeout = true
      return Promise.reject(err)
    }

    // Auth failure - redirect to login
    if (err.response?.status === 401) {
      const currentPath = window.location.pathname
      if (!currentPath.includes('/login') && !currentPath.includes('/auth')) {
        useAuthStore.getState().logout()
        window.location.href = '/login'
      }
    }

    if (err.response?.status === 403) {
      const detail = String(err.response?.data?.detail || '').toLowerCase()
      if (detail.includes('disabled') || detail.includes('account is')) {
        useAuthStore.getState().logout()
        window.location.href = '/login'
      }
    }

    return Promise.reject(err)
  }
)

export default api
