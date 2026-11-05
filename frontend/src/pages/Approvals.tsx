import { useState } from 'react'
import { Link } from 'react-router-dom'
import { getAlerts, getDecisions, reviewAction } from '../api'
import { AnalystField, Load, ReviewLine, StatusBadge, Telemetry } from '../components'
import { useAnalystName, useData } from '../hooks'
import type { Action, Alert, Decision, RequestAction } from '../types'

interface Row {
  decision: Decision
  action: Action & { action: RequestAction }
  alert: Alert | undefined
}

function requestRows(decisions: Decision[], alerts: Alert[]): Row[] {
  return decisions.flatMap((decision) =>
    decision.actions
      .filter((action): action is Row['action'] => !action.automatic)
      .map((action) => ({
        decision,
        action,
        alert: alerts.find((alert) => alert.alert_id === decision.alert_id),
      })),
  )
}

function Context({ row }: { row: Row }) {
  return (
    <>
      <td className="nowrap"><Link to={`/alerts/${encodeURIComponent(row.decision.alert_id)}`}>{row.decision.alert_id}</Link></td>
      <td>{row.action.action}</td>
      <td><Telemetry value={row.alert?.subject.image} /></td>
    </>
  )
}

export function Approvals() {
  const state = useData(async () => {
    const [decisions, alerts] = await Promise.all([getDecisions(), getAlerts()])
    return requestRows(decisions, alerts)
  })
  const [analyst, setAnalyst] = useAnalystName()
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const name = analyst.trim()

  async function review({ decision, action }: Row, verdict: 'approve' | 'reject') {
    const question = `Approve ${action.action} for ${decision.alert_id}?`
    if (verdict === 'approve' && !window.confirm(question)) return
    setBusy(true)
    setFailure(null)
    try {
      await reviewAction(decision.decision_id, action.action, name, verdict)
    } catch (error) {
      setFailure((error as Error).message)
    }
    setBusy(false)
    state.reload()
  }

  return (
    <>
      <h1>Approvals</h1>
      <p className="muted">
        Kill and delete only happen with analyst approval. Approving records your decision. The
        policy engine carries it out.
      </p>
      <AnalystField value={analyst} onChange={setAnalyst} />
      {failure && <p className="error" role="alert">{failure}</p>}
      <Load state={state}>
        {(rows) => {
          const pending = rows.filter((row) => row.action.status === 'awaiting_approval')
          const reviewed = rows.filter((row) => row.action.status !== 'awaiting_approval')
          return (
            <>
              <h2>Pending</h2>
              {pending.length === 0 ? (
                <p className="muted">Nothing is waiting for approval.</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr><th>Alert</th><th>Action</th><th>Process</th><th>Review</th></tr>
                    </thead>
                    <tbody>
                      {pending.map((row) => (
                        <tr key={`${row.decision.decision_id}-${row.action.action}`}>
                          <Context row={row} />
                          <td className="buttons">
                            <button disabled={busy || !name} onClick={() => review(row, 'approve')}>
                              Approve
                            </button>
                            <button
                              className="secondary"
                              disabled={busy || !name}
                              onClick={() => review(row, 'reject')}
                            >
                              Reject
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <h2>Reviewed</h2>
              {reviewed.length === 0 ? (
                <p className="muted">Nothing has been reviewed yet.</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr><th>Alert</th><th>Action</th><th>Process</th><th>Status</th><th>Reviewed by</th></tr>
                    </thead>
                    <tbody>
                      {reviewed.map((row) => (
                        <tr key={`${row.decision.decision_id}-${row.action.action}`}>
                          <Context row={row} />
                          <td>
                            <StatusBadge status={row.action.status} />
                            {row.action.status === 'approved' && (
                              <div className="muted">Waiting for the policy engine</div>
                            )}
                          </td>
                          <td><ReviewLine action={row.action} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )
        }}
      </Load>
    </>
  )
}
