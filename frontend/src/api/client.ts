import axios from 'axios'
import { useAuthStore } from '@/stores/authStore'

export const api = axios.create({
  baseURL: '/api/v1',
})

// Unauthenticated axios instance — no JWT, no 401 redirect (used for public endpoints)
const publicApi = axios.create({ baseURL: '/api/v1' })

export interface AuthConfigResponse {
  authentik_oidc_enabled: boolean
  allow_local_login: boolean
  setup_pending: boolean
}

export interface SetupStatusResponse {
  setup_pending: boolean
  requires_setup_secret: boolean
  issuer_url_hint: string
  client_id_hint: string
  redirect_uri_hint: string
  public_app_hint: string
}

export interface CompleteSetupPayload {
  authentik_issuer_url: string
  authentik_client_id: string
  authentik_client_secret: string
  authentik_redirect_uri: string
  public_app_url: string
}

export interface AuthSettingsRead {
  allow_local_login: boolean
  authentik_oidc_enabled: boolean
  authentik_issuer_url: string
  authentik_client_id: string
  authentik_redirect_uri: string
  public_app_url: string
  client_secret_configured: boolean
}

export interface AuthSettingsWrite {
  allow_local_login?: boolean
  authentik_oidc_enabled?: boolean
  authentik_issuer_url?: string
  authentik_client_id?: string
  authentik_client_secret?: string
  authentik_redirect_uri?: string
  public_app_url?: string
}

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) useAuthStore.getState().logout()
    return Promise.reject(err)
  }
)

export const authApi = {
  login: (username: string, password: string) =>
    api.post<{ access_token: string }>('/auth/login', { username, password }),

  fetchConfig: () => publicApi.get<AuthConfigResponse>('/auth/config'),
}

export const setupApi = {
  status: () => publicApi.get<SetupStatusResponse>('/setup/status'),
  complete: (payload: CompleteSetupPayload, setupSecret?: string) =>
    publicApi.post<{ status: string }>('/setup/complete', payload, {
      headers: setupSecret ? { 'X-Homelabable-Setup-Secret': setupSecret } : undefined,
    }),
}

export const canvasApi = {
  load: () => api.get('/canvas'),
  save: (payload: {
    nodes: object[]
    edges: object[]
    viewport: object
    custom_style?: object | null
  }) => api.post('/canvas/save', payload),
}

export const nodesApi = {
  create: (data: object) => api.post('/nodes', data),
  update: (id: string, data: object) => api.patch(`/nodes/${id}`, data),
  delete: (id: string) => api.delete(`/nodes/${id}`),
}

export const edgesApi = {
  create: (data: object) => api.post('/edges', data),
  delete: (id: string) => api.delete(`/edges/${id}`),
}

export const liveviewApi = {
  load: (key: string) => publicApi.get('/liveview', { params: { key } }),
}

export const scanApi = {
  trigger: () => api.post('/scan/trigger'),
  pending: () => api.get('/scan/pending'),
  hidden: () => api.get('/scan/hidden'),
  runs: () => api.get('/scan/runs'),
  clearPending: () => api.delete('/scan/pending'),
  approve: (id: string, nodeData: object) => api.post(`/scan/pending/${id}/approve`, nodeData),
  hide: (id: string) => api.post(`/scan/pending/${id}/hide`),
  ignore: (id: string) => api.post(`/scan/pending/${id}/ignore`),
  bulkApprove: (ids: string[]) =>
    api.post<{ approved: number; node_ids: string[]; device_ids: string[]; skipped: number }>(
      '/scan/pending/bulk-approve',
      { device_ids: ids },
    ),
  bulkHide: (ids: string[]) => api.post<{ hidden: number; skipped: number }>('/scan/pending/bulk-hide', { device_ids: ids }),
  stop: (runId: string) => api.post(`/scan/${runId}/stop`),
  getConfig: () => api.get<{ ranges: string[] }>('/scan/config'),
  saveConfig: (data: { ranges: string[] }) => api.post('/scan/config', data),
}

export const settingsApi = {
  get: () => api.get<{ interval_seconds: number }>('/settings'),
  save: (data: { interval_seconds: number }) => api.post<{ interval_seconds: number }>('/settings', data),
  authGet: () => api.get<AuthSettingsRead>('/settings/auth'),
  authPut: (body: AuthSettingsWrite) => api.put<{ status: string }>('/settings/auth', body),
}
