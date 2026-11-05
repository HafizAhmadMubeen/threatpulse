import type {
  Alert,
  AlertDetailResponse,
  Decision,
  FimChange,
  Report,
  RequestAction,
  Stats,
} from './types'

const API_URL = 'http://127.0.0.1:8000'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_URL}${path}`, init)
  } catch {
    throw new ApiError(0, 'The backend is not reachable. Is it running on 127.0.0.1:8000?')
  }
  if (!response.ok) {
    const body: { detail?: unknown } = await response.json().catch(() => ({}))
    const detail = typeof body.detail === 'string' ? body.detail : 'The request was refused'
    throw new ApiError(response.status, detail)
  }
  return response.json() as Promise<T>
}

function post<T>(path: string, body: object): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

const segment = encodeURIComponent

export const getAlerts = () => request<Alert[]>('/alerts')
export const getAlert = (id: string) => request<AlertDetailResponse>(`/alerts/${segment(id)}`)
export const getDecisions = () => request<Decision[]>('/decisions')
export const getFimChanges = () => request<FimChange[]>('/fim/changes')
export const getStats = () => request<Stats>('/stats')

/** A missing report is normal: only high-risk alerts get one. */
export async function getReport(alertId: string): Promise<Report | null> {
  try {
    return await request<Report>(`/reports/${segment(alertId)}`)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null
    throw error
  }
}

export function reviewAction(
  decisionId: string,
  action: RequestAction,
  reviewedBy: string,
  verdict: 'approve' | 'reject',
) {
  return post<Decision>(`/decisions/${segment(decisionId)}/${verdict}`, {
    reviewed_by: reviewedBy,
    action,
  })
}

export function approveFimChange(eventId: string, reviewedBy: string) {
  return post<FimChange>(`/fim/changes/${segment(eventId)}/approve`, { reviewed_by: reviewedBy })
}
