import type { ReactNode } from 'react'
import type { Loaded } from './hooks'
import type { Action, ActionStatus } from './types'

export function formatTime(ts: string | null | undefined): string {
  return ts ? `${ts.slice(0, 19).replace('T', ' ')} UTC` : '—'
}

/** Attacker-controlled text. JSX escapes it, so it can only ever appear as text. */
export function Telemetry({ value }: { value: string | number | null | undefined }) {
  if (value === null || value === undefined || value === '') {
    return <span className="muted">—</span>
  }
  return <code className="telemetry">{value}</code>
}

/** 0 is a real score, so the check must be for null and not for falsy. */
export function RiskScore({ score }: { score: number | null }) {
  if (score === null) return <span className="muted">not scored</span>
  const level = score >= 0.8 ? 'risk-high' : score >= 0.5 ? 'risk-medium' : 'risk-low'
  return <span className={`risk ${level}`}>{score.toFixed(2)}</span>
}

const STATUS_LABELS: Record<ActionStatus, string> = {
  executed: 'executed',
  failed: 'failed',
  skipped: 'skipped',
  awaiting_approval: 'awaiting approval',
  approved: 'approved',
  rejected: 'rejected',
}

export function StatusBadge({ status }: { status: ActionStatus | 'pending' }) {
  const label = status === 'pending' ? 'pending' : STATUS_LABELS[status]
  return <span className={`badge badge-${status}`}>{label}</span>
}

export function ReviewLine({ action }: { action: Pick<Action, 'reviewed_by' | 'reviewed_at'> }) {
  if (!action.reviewed_by) return <span className="muted">—</span>
  return (
    <>
      <Telemetry value={action.reviewed_by} />
      <span className="muted"> at {formatTime(action.reviewed_at)}</span>
    </>
  )
}

export function Load<T>({ state, children }: { state: Loaded<T>; children: (data: T) => ReactNode }) {
  if (state.error) return <p className="error" role="alert">{state.error}</p>
  if (state.data === null) return <p className="muted">Loading…</p>
  return <>{children(state.data)}</>
}

export function AnalystField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <label className="analyst">
      Analyst name
      <input
        value={value}
        maxLength={64}
        placeholder="Needed to approve or reject"
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  )
}
