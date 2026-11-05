import { getStats } from '../api'
import { Load } from '../components'
import { useData } from '../hooks'

function Counts({ title, counts }: { title: string; counts: Record<string, number> }) {
  return (
    <section className="count-group">
      <h2>{title}</h2>
      <table>
        <tbody>
          {Object.entries(counts).map(([name, count]) => (
            <tr key={name}>
              <th scope="row">{name.replaceAll('_', ' ')}</th>
              <td className="number">{count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

export function Stats() {
  const stats = useData(getStats)
  return (
    <>
      <h1>Stats</h1>
      <Load state={stats}>
        {(s) => {
          const skipped = Object.values(s.skipped_records).reduce((sum, count) => sum + count, 0)
          return (
            <>
              {skipped > 0 && (
                <p className="error" role="alert">
                  {skipped} record(s) were skipped because they are unreadable or fail their schema.
                </p>
              )}
              <div className="count-grid">
                <Counts
                  title="Overview"
                  counts={{
                    events: s.events_total,
                    events_filtered_before_llm: s.events_filtered_before_llm,
                    alerts: s.alerts_total,
                    alerts_not_scored: s.alerts_not_scored,
                    reports: s.reports_total,
                    pending_approvals: s.pending_approvals,
                    fim_changes_pending: s.fim_changes_pending,
                  }}
                />
                <Counts title="Alerts by layer" counts={s.alerts_by_layer} />
                <Counts title="Alerts by zone" counts={s.alerts_by_zone} />
                <Counts title="Actions by status" counts={s.actions_by_status} />
              </div>
            </>
          )
        }}
      </Load>
    </>
  )
}
