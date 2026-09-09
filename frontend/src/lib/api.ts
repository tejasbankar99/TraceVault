import axios from 'axios'
import { useAuthStore } from '@/stores/authStore'
import type {
  AuthToken, User, Case, CaseListResponse, AnalysisResult, EmailHeaders,
  RelayHop, IOC, IOCListResponse, BlockchainEntry, BlockchainVerifyResult,
  GeoIntelligence, Campaign, DashboardStats, CytoscapeGraph, CaseListParams,
  IOCListParams, SSEEvent,
} from '@/types'

const BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

// ── Request interceptor: attach JWT ──────────────────────────
apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ── Response interceptor: handle 401 ────────────────────────
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().clearAuth()
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// ── Auth API ─────────────────────────────────────────────────
export const authAPI = {
  login: async (username: string, password: string): Promise<AuthToken> => {
    const form = new URLSearchParams()
    form.append('username', username)
    form.append('password', password)
    const res = await apiClient.post<AuthToken>('/auth/login', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    return res.data
  },

  register: async (data: {
    email: string; username: string; password: string; full_name: string; role?: string
  }): Promise<User> => {
    const res = await apiClient.post<User>('/auth/register', data)
    return res.data
  },

  me: async (): Promise<User> => {
    const res = await apiClient.get<User>('/auth/me')
    return res.data
  },
}

// ── Cases API ────────────────────────────────────────────────
export const casesAPI = {
  upload: async (file: File | null, rawText?: string): Promise<Case> => {
    const formData = new FormData()
    if (file) {
      formData.append('file', file)
    } else if (rawText) {
      formData.append('raw_email_text', rawText)
    }
    const res = await apiClient.post<Case>('/cases/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return res.data
  },

  list: async (params: CaseListParams = {}): Promise<CaseListResponse> => {
    const res = await apiClient.get<CaseListResponse>('/cases', { params })
    return res.data
  },

  get: async (caseId: string): Promise<Case> => {
    const res = await apiClient.get<Case>(`/cases/${caseId}`)
    return res.data
  },

  delete: async (caseId: string): Promise<void> => {
    await apiClient.delete(`/cases/${caseId}`)
  },
}

// ── Analysis API ─────────────────────────────────────────────
export const analysisAPI = {
  trigger: async (caseId: string): Promise<{ message: string; sse_url: string }> => {
    const res = await apiClient.post<{ message: string; sse_url: string }>(
      `/analysis/${caseId}/analyze`
    )
    return res.data
  },

  get: async (caseId: string): Promise<AnalysisResult> => {
    const res = await apiClient.get<AnalysisResult>(`/analysis/${caseId}/analysis`)
    return res.data
  },

  getHeaders: async (caseId: string): Promise<EmailHeaders> => {
    const res = await apiClient.get<EmailHeaders>(`/analysis/${caseId}/headers`)
    return res.data
  },

  getRelayPath: async (caseId: string): Promise<RelayHop[]> => {
    const res = await apiClient.get<RelayHop[]>(`/analysis/${caseId}/relay-path`)
    return res.data
  },

  /**
   * Opens an EventSource SSE connection to stream analysis progress.
   * Returns a cleanup function to close the connection.
   */
  streamAnalysis: (
    caseId: string,
    onEvent: (event: SSEEvent) => void,
    onComplete: () => void,
    onError: (err: Event) => void
  ): (() => void) => {
    const token = useAuthStore.getState().token
    const url = `${BASE_URL}/analysis/${caseId}/analysis/stream${token ? `?token=${token}` : ''}`
    const eventSource = new EventSource(url)

    eventSource.onmessage = (e) => {
      try {
        const data: SSEEvent = JSON.parse(e.data)
        onEvent(data)
        if (data.step === 'complete' || data.step === 'error') {
          eventSource.close()
          onComplete()
        }
      } catch {
        // ignore parse errors on keepalive comments
      }
    }

    eventSource.onerror = (e) => {
      eventSource.close()
      onError(e)
    }

    return () => eventSource.close()
  },
}

// ── IOCs API ─────────────────────────────────────────────────
export const iocsAPI = {
  list: async (params: IOCListParams = {}): Promise<IOCListResponse> => {
    const res = await apiClient.get<IOCListResponse>('/iocs', { params })
    return res.data
  },

  getForCase: async (caseId: string): Promise<IOC[]> => {
    const res = await apiClient.get<IOCListResponse>('/iocs', { params: { case_id: caseId, per_page: 200 } })
    return res.data.items ?? []
  },

  search: async (q: string): Promise<IOC[]> => {
    const res = await apiClient.get<IOC[]>('/iocs/search', { params: { q } })
    return res.data
  },

  exportCSV: (caseId?: string): void => {
    const token = useAuthStore.getState().token
    const url = caseId
      ? `${BASE_URL}/iocs/export?case_id=${caseId}&token=${token}`
      : `${BASE_URL}/iocs/export?token=${token}`
    window.open(url, '_blank')
  },
}

// ── Blockchain API ───────────────────────────────────────────
export const blockchainAPI = {
  getForCase: async (caseId: string): Promise<BlockchainEntry[]> => {
    const res = await apiClient.get<BlockchainEntry[]>(`/blockchain/cases/${caseId}/blockchain`)
    return res.data
  },

  getAll: async (params?: { page?: number; case_id?: string }): Promise<{
    entries: BlockchainEntry[]; total: number
  }> => {
    const res = await apiClient.get('/blockchain', { params })
    return res.data
  },

  verify: async (caseId: string): Promise<BlockchainVerifyResult> => {
    const res = await apiClient.post<BlockchainVerifyResult>(
      `/blockchain/cases/${caseId}/blockchain/verify`
    )
    return res.data
  },

  verifyAll: async (): Promise<BlockchainVerifyResult> => {
    const res = await apiClient.post<BlockchainVerifyResult>('/blockchain/verify-all')
    return res.data
  },
}

// ── Reports API ──────────────────────────────────────────────
export const reportsAPI = {
  downloadPDF: async (caseId: string): Promise<void> => {
    const token = useAuthStore.getState().token
    const response = await fetch(`${BASE_URL}/reports/${caseId}/report`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!response.ok) throw new Error('Failed to generate report')
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `TraceVault-Report-${caseId}.pdf`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  },

  getPreviewURL: (caseId: string): string => {
    return `${BASE_URL}/reports/${caseId}/report/preview`
  },
}

// ── Geo API ──────────────────────────────────────────────────
export const geoAPI = {
  getForCase: async (caseId: string): Promise<GeoIntelligence[]> => {
    const res = await apiClient.get<GeoIntelligence[]>(`/analysis/${caseId}/geo`)
    return res.data ?? []
  },
}

// ── Graph API ────────────────────────────────────────────────
export const graphAPI = {
  getGlobal: async (): Promise<CytoscapeGraph> => {
    const res = await apiClient.get<CytoscapeGraph>('/graph')
    return res.data
  },

  getForCase: async (caseId: string): Promise<CytoscapeGraph> => {
    const res = await apiClient.get<CytoscapeGraph>(`/graph/${caseId}`)
    return res.data
  },
}

// ── Campaigns API ────────────────────────────────────────────
export const campaignsAPI = {
  list: async (): Promise<Campaign[]> => {
    const res = await apiClient.get<Campaign[]>('/campaigns')
    return res.data
  },

  get: async (campaignId: string): Promise<Campaign> => {
    const res = await apiClient.get<Campaign>(`/campaigns/${campaignId}`)
    return res.data
  },
}

// ── Stats API ────────────────────────────────────────────────
export const statsAPI = {
  get: async (): Promise<DashboardStats> => {
    const res = await apiClient.get<DashboardStats>('/stats')
    return res.data
  },
}
