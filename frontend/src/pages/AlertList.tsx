import { Link } from 'react-router-dom'
import { getAlerts } from '../api'
import { Load, RiskScore, Telemetry, formatTime } from '../components'
import { useData } from '../hooks'
import type { Alert } from '../types'

const newestFirst = (a: Alert, b: Alert) => b.ts.localeCompare(a.ts)

export function AlertList() {
  const alerts = useData(getAlerts)
  return (
    <>
      <h1>Alerts</h1>
      <Load state={alerts}>
        {(items) =>
          items.length === 0 ? (
            <p className="muted">No alerts.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Time</th>
                    <th>Zone</th>
                    <th>Layer</th>
                    <th>Risk score</th>
                    <th>Rule</th>
                    <th>Process</th>
                  </tr>
                </thead>
                <tbody>
                  {[...items].sort(newestFirst).map((alert) => (
                    <tr key={alert.alert_id}>
                      <td className="nowrap"><Link to={`/alerts/${encodeURIComponent(alert.alert_id)}`}>{alert.alert_id}</Link></td>
                      <td className="nowrap">{formatTime(alert.ts)}</td>
                      <td>{alert.object.zone}</td>
                      <td>{alert.layer}</td>
                      <td className="nowrap"><RiskScore alert={alert} /></td>
                      <td>{alert.rule_id}</td>
                      <td><Telemetry value={alert.subject.image} /></td>
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
