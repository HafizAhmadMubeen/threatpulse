import { useState } from 'react'
import { Link } from 'react-router-dom'
import { approveFimChange, getFimChanges } from '../api'
import { AnalystField, Load, ReviewLine, StatusBadge, Telemetry, formatTime } from '../components'
import { useAnalystName, useData } from '../hooks'
import type { FimChange } from '../types'

export function FimChanges() {
  const changes = useData(getFimChanges)
  const [analyst, setAnalyst] = useAnalystName()
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const name = analyst.trim()

  async function approve(change: FimChange) {
    if (!window.confirm(`Accept change ${change.event_id} as legitimate?`)) return
    setBusy(true)
    setFailure(null)
    try {
      await approveFimChange(change.event_id, name)
    } catch (error) {
      setFailure((error as Error).message)
    }
    setBusy(false)
    changes.reload()
  }

  return (
    <>
      <h1>FIM changes</h1>
      <p className="muted">
        Changes in the persistence zone. Unapproved changes are restored automatically. Approving
        records that a change is legitimate. Updating the baseline and re-applying the change are
        not connected yet.
      </p>
      <AnalystField value={analyst} onChange={setAnalyst} />
      {failure && <p className="error" role="alert">{failure}</p>}
      <Load state={changes}>
        {(items) =>
          items.length === 0 ? (
            <p className="muted">No changes.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Item</th>
                    <th>Change</th>
                    <th>Old value</th>
                    <th>New value</th>
                    <th>Alert</th>
                    <th>Status</th>
                    <th>Review</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((change) => (
                    <tr key={change.event_id}>
                      <td className="nowrap">{formatTime(change.ts)}</td>
                      <td><Telemetry value={change.registry_key ?? change.path} /></td>
                      <td>{change.change.kind}</td>
                      <td><Telemetry value={change.change.old_value} /></td>
                      <td><Telemetry value={change.change.new_value} /></td>
                      <td className="nowrap">
                        {change.alert_id ? (
                          <Link to={`/alerts/${encodeURIComponent(change.alert_id)}`}>{change.alert_id}</Link>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td><StatusBadge status={change.status} /></td>
                      <td>
                        {change.status === 'approved' ? (
                          <ReviewLine action={change} />
                        ) : (
                          <button disabled={busy || !name} onClick={() => approve(change)}>
                            Approve
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </Load>
    </>
  )
}
