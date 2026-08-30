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
      console.error('[API] Network error - backend may not be running')
      err.isNetworkError = true
      return Promise.reject(err)
    }

    // Timeout
    if (err.code === 'ECONNABORTED') {
      console.error('[API] Request timeout')
      err.isTimeout = true
      return Promise.reject(err)
    }

    // Auth failure - redirect to login
    if (err.response?.status === 401) {
      const currentPath = window.location.pathname
      // Don't redirect if already on login/auth pages
      if (!currentPath.includes('/login') && !currentPath.includes('/auth')) {
        useAuthStore.getState().logout()
        window.location.href = '/login'
      }
    }

    return Promise.reject(err)
  }
)

export default api
