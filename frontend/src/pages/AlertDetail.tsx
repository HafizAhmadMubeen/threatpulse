import { Link, useParams } from 'react-router-dom'
import { getAlert, getDecisions, getReport } from '../api'
import { Load, ReviewLine, RiskScore, StatusBadge, Telemetry, formatTime } from '../components'
import { useData } from '../hooks'
import type { Alert, Decision, Event, Report } from '../types'

function targetSummary(event: Event): string | null {
  const { path, old_path, registry_key, pid, access_rights, dest_ip, dest_port, change } = event.target
  const parts: string[] = []
  if (old_path) parts.push(`${old_path} -> ${path}`)
  else if (path) parts.push(path)
  if (registry_key) parts.push(registry_key)
  if (pid !== null) parts.push(`pid ${pid}`)
  if (access_rights?.length) parts.push(access_rights.join(', '))
  if (dest_ip) parts.push(`${dest_ip}:${dest_port ?? '?'}`)
  if (change) parts.push(`${change.kind}: ${change.new_value ?? change.old_value ?? ''}`)
  return parts.length > 0 ? parts.join(' | ') : null
}

function AlertFacts({ alert }: { alert: Alert }) {
  const { subject, object } = alert
  return (
    <dl className="facts">
      <dt>Time</dt>
      <dd>{formatTime(alert.ts)}</dd>
      <dt>Zone</dt>
      <dd>{object.zone}</dd>
      <dt>Layer</dt>
      <dd>{alert.layer}</dd>
      <dt>Risk score</dt>
      <dd><RiskScore alert={alert} /></dd>
      <dt>Rule</dt>
      <dd>{alert.rule_id}</dd>
      {alert.static_analysis && (
        <>
          <dt>Static analysis</dt>
          <dd>
            {alert.static_analysis.score !== null && (
              <div>Score {alert.static_analysis.score.toFixed(2)}</div>
            )}
            <ul className="plain">
              {alert.static_analysis.reasons.map((reason, index) => (
                <li key={index}><Telemetry value={reason} /></li>
              ))}
            </ul>
          </dd>
        </>
      )}
      <dt>Techniques</dt>
      <dd>{alert.technique_ids.length > 0 ? alert.technique_ids.join(', ') : '—'}</dd>
      <dt>Process</dt>
      <dd>
        <Telemetry value={subject.image} />
        <div className="muted">
          pid {subject.pid}, {subject.signed ? 'signed' : 'not signed'}
          {subject.trusted_path ? ', trusted path' : ''}
        </div>
      </dd>
      <dt>Signer</dt>
      <dd><Telemetry value={subject.signer} /></dd>
      <dt>Parents</dt>
      <dd>
        {subject.ancestors.length === 0 ? (
          <span className="muted">—</span>
        ) : (
          <ol className="plain">
            {subject.ancestors.map((ancestor) => (
              <li key={ancestor.pid}><Telemetry value={ancestor.image} /></li>
            ))}
          </ol>
        )}
      </dd>
      <dt>Path</dt>
      <dd><Telemetry value={object.path} /></dd>
      <dt>Registry key</dt>
      <dd><Telemetry value={object.registry_key} /></dd>
      <dt>Access</dt>
      <dd><Telemetry value={object.access.join(', ')} /></dd>
      <dt>File SHA-256</dt>
      <dd><Telemetry value={object.file_sha256} /></dd>
    </dl>
  )
}

function Evidence({ events }: { events: Event[] }) {
  return (
    <section>
      <h2>Evidence events</h2>
      {events.length === 0 ? (
        <p className="muted">This alert has no evidence events.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Type</th>
                <th>Process</th>
                <th>Command line</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.event_id}>
                  <td className="nowrap">{formatTime(event.ts)}</td>
                  <td>{event.source}</td>
                  <td>{event.event_type}</td>
                  <td><Telemetry value={event.process.image} /></td>
                  <td><Telemetry value={event.process.cmdline} /></td>
                  <td><Telemetry value={targetSummary(event)} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function DecisionView({ decision }: { decision: Decision | undefined }) {
  return (
    <section>
      <h2>Decision</h2>
      {!decision ? (
        <p className="muted">No decision for this alert.</p>
      ) : (
        <>
          <p>
            {decision.decision_id} at {formatTime(decision.ts)}.{' '}
            {decision.policy_rules.length > 0
              ? `Rules: ${decision.policy_rules.join(', ')}`
              : 'No rule fired, so the default applied.'}
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Reason</th>
                  <th>Executed</th>
                  <th>Reviewed by</th>
                </tr>
              </thead>
              <tbody>
                {decision.actions.map((action) => (
                  <tr key={action.action}>
                    <td>{action.action}</td>
                    <td>{action.automatic ? 'automatic' : 'needs analyst'}</td>
                    <td><StatusBadge status={action.status} /></td>
                    <td>{action.reason ?? <span className="muted">—</span>}</td>
                    <td className="nowrap">{formatTime(action.executed_at)}</td>
                    <td><ReviewLine action={action} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <h3>Attributes behind this decision</h3>
          <dl className="facts">
            {Object.entries(decision.attributes).map(([name, value]) => (
              <div className="contents" key={name}>
                <dt>{name}</dt>
                <dd><Telemetry value={value === null ? 'null' : String(value)} /></dd>
              </div>
            ))}
          </dl>
        </>
      )}
    </section>
  )
}

function ReportView({ report }: { report: Report | null }) {
  return (
    <section>
      <h2>Report</h2>
      {!report ? (
        <p className="muted">No report. Only high-risk alerts get one.</p>
      ) : (
        <>
          {!report.validated && (
            <p className="error">The technique IDs in this report have not been validated.</p>
          )}
          <p className="report-text">{report.summary}</p>
          <h3>Techniques</h3>
          <ul>
            {report.techniques.map((technique) => (
              <li key={technique.id}>
                <strong>{technique.id} {technique.name}.</strong>{' '}
                <span className="report-text">{technique.evidence}</span>
              </li>
            ))}
          </ul>
          <h3>Timeline</h3>
          <ol>
            {report.timeline.map((line, index) => (
              <li key={index} className="report-text">{line}</li>
            ))}
          </ol>
        </>
      )}
    </section>
  )
}

export function AlertDetail() {
  const { alertId = '' } = useParams()
  const detail = useData(async () => {
    const [response, decisions, report] = await Promise.all([
      getAlert(alertId),
      getDecisions(),
      getReport(alertId),
    ])
    return { ...response, report, decision: decisions.find((d) => d.alert_id === alertId) }
  }, alertId)

  return (
    <>
      <p><Link to="/">Back to alerts</Link></p>
      <h1>Alert {alertId}</h1>
      <Load state={detail}>
        {({ alert, evidence_events, decision, report }) => (
          <>
            <AlertFacts alert={alert} />
            <Evidence events={evidence_events} />
            <DecisionView decision={decision} />
            <ReportView report={report} />
          </>
        )}
      </Load>
    </>
  )
}
