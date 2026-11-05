import type { ReactNode } from 'react'
import type { Loaded } from './hooks'
import type { Action, ActionStatus, Alert } from './types'

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

export type Severity = 'Confirmed' | 'High' | 'Medium' | 'Low' | 'Not scored'

/**
 * What an analyst should read first. For display only: enforcement comes from the policy
 * engine and never from this.
 *
 * A hash match or a changed protected item is a fact, whatever the behaviour model thinks
 * of the process around it, so it ranks above any score. The EICAR sample is the reason:
 * a confirmed match with a risk score of 0.12 must not look safe.
 */
export function severityOf(alert: Pick<Alert, 'layer' | 'risk_score' | 'object'>): Severity {
  if (alert.layer === 'signature') return 'Confirmed'
  if (alert.layer === 'fim' && alert.object.zone !== 'none') return 'Confirmed'
  const score = alert.risk_score
  if (score === null) return 'Not scored'  // 0 is a real score, so this is not a falsy check
  if (score >= 0.8) return 'High'
  return score >= 0.5 ? 'Medium' : 'Low'
}

const SEVERITY_CLASSES: Record<Severity, string> = {
  Confirmed: 'severity-confirmed',
  High: 'severity-high',
  Medium: 'severity-medium',
  Low: 'severity-low',
  'Not scored': 'severity-none',
}

/** The score stays uncoloured, so the badge alone carries the meaning. */
export function RiskScore({ alert }: { alert: Pick<Alert, 'layer' | 'risk_score' | 'object'> }) {
  const severity = severityOf(alert)
  const score = alert.risk_score
  return (
    <span className="risk">
      {score !== null && <span className="score">{score.toFixed(2)}</span>}
      {score === null && severity !== 'Not scored' && <span className="muted">not scored</span>}
      <span className={`badge ${SEVERITY_CLASSES[severity]}`}>{severity}</span>
    </span>
  )
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
